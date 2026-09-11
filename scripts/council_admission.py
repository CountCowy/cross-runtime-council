"""Read-only lifecycle admission and process-owned broker.lock exclusion.

C1 consumes only the envelope/receipt binding. It neither writes lifecycle
metadata nor implements or certifies a transaction/recovery format.
"""

import contextlib
import fcntl
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading

import council_protocol as protocol

PACKAGE_ID = "d4e0f25287c8e92ca6925e856000eb7f98fee5525d5353d8b47c7d5b7ff98afa"
RUNTIME_COHORT = "8181ae63906b42e4af670df1613dede4d194c48991594e3b8ea9b961877831b5"
NAMESPACE = ".council-lifecycle"
_LEASE_PROOF = object()
MAX_METADATA_BYTES = 1024 * 1024
RETENTION_MAX_DAYS = 3650
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}\Z")
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


class AdmissionError(ValueError):
    reason = "maintenance_required"

    def __init__(self, *args, retryable=False):
        super().__init__(*args)
        self.retryable = retryable


def identity(details):
    return details.st_dev, details.st_ino


def finite_number(value):
    import math

    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def validated_name(value, field):
    if not isinstance(value, str) or not NAME_PATTERN.fullmatch(value):
        raise AdmissionError(
            "%s must match [A-Za-z0-9][A-Za-z0-9_.-]{0,79}" % field
        )
    return value


def validated_text(value, field):
    try:
        invalid = (
            not isinstance(value, str)
            or not value.strip()
            or len(value.encode("utf-8")) > protocol.MAX_TEXT_BYTES
        )
    except UnicodeError as error:
        raise AdmissionError("%s must contain valid Unicode" % field) from error
    if invalid:
        raise AdmissionError("%s must be nonempty bounded text" % field)
    return value


def validated_hash(value, field):
    if not isinstance(value, str) or not HASH_PATTERN.fullmatch(value):
        raise AdmissionError("%s must be a lowercase SHA-256 digest" % field)
    return value


def validate_retention_config(config):
    if not isinstance(config, dict):
        raise AdmissionError("retention configuration must be an object")
    days = config.get("days")
    if type(days) is not int or not 1 <= days <= RETENTION_MAX_DAYS:
        raise AdmissionError(
            "retention days must be an integer between 1 and %d"
            % RETENTION_MAX_DAYS
        )
    return days


def validate_router_config(config):
    if not isinstance(config, dict):
        raise AdmissionError("Council router configuration is invalid")
    result = dict(config)
    result["target_thread_id"] = validated_name(
        config.get("target_thread_id"), "router target_thread_id"
    )
    capability = config.get("capability_hash")
    if capability is not None:
        validated_hash(capability, "Council router capability configuration")
    return result


def validate_opencode_config(config):
    if not isinstance(config, dict):
        raise AdmissionError("OpenCode configuration must be an object")
    executable = validated_text(config.get("executable"), "OpenCode executable")
    if not Path(executable).is_absolute():
        raise AdmissionError("OpenCode executable must be an absolute path")
    validated_hash(config.get("sha256"), "OpenCode executable hash")
    cdhash = validated_text(config.get("cdhash"), "OpenCode executable cdhash")
    if not re.fullmatch(r"[0-9a-f]+", cdhash):
        raise AdmissionError("OpenCode executable cdhash must be lowercase hexadecimal")
    if type(config.get("configured_at_epoch")) is not int:
        raise AdmissionError("OpenCode configured_at_epoch must be an integer")
    return dict(config)


def validate_persisted_registration(route):
    """Pure persisted-route validator shared by the broker and inspector."""
    if not isinstance(route, dict):
        raise AdmissionError("registration route must be an object")
    runtime = validated_text(route.get("runtime"), "runtime").lower()
    if runtime not in ("claude", "codex", "opencode"):
        raise AdmissionError("runtime must be claude, codex, or opencode")
    participant = validated_name(route.get("participant"), "participant")
    lease_minutes = route.get("lease_minutes")
    if (
        type(lease_minutes) is not int
        or not 1 <= lease_minutes <= protocol.MAX_LEASE_MINUTES
    ):
        raise AdmissionError("invalid persisted lease_minutes")
    expiry = route.get("lease_expires_epoch")
    if not finite_number(expiry):
        raise AdmissionError("invalid persisted lease expiry")
    generation = route.get("binding_generation")
    if generation is not None:
        generation = validated_name(generation, "persisted binding_generation")
    cohort = route.get("runtime_cohort")
    if cohort is not None:
        validated_hash(cohort, "persisted runtime cohort")
    registration = {
        "runtime": runtime,
        "participant": participant,
        "label": validated_text(route.get("label"), "label"),
        "project": validated_text(route.get("project"), "project"),
        "bound_at": validated_text(route.get("bound_at"), "bound_at"),
        "lease_minutes": lease_minutes,
        "lease_expires_epoch": float(expiry),
        "capability_hash": validated_hash(
            route.get("capability_hash"), "persisted registration capability"
        ),
        "binding_generation": generation,
        "runtime_cohort": cohort,
    }
    if runtime == "codex":
        registration["target_thread_id"] = validated_name(
            route.get("target_thread_id"), "target_thread_id"
        )
        return registration
    expected_transport = (
        "claude_mcp_child_relay"
        if runtime == "claude"
        else "opencode_plugin_relay"
    )
    if route.get("transport") != expected_transport:
        raise AdmissionError("persisted session relay transport is invalid")
    relay_path = Path(validated_text(route.get("relay_path"), "relay_path")).expanduser()
    if not relay_path.is_absolute():
        raise AdmissionError("persisted session relay path must be absolute")
    relay_pid = route.get("relay_pid")
    relay_start = route.get("relay_process_start_epoch")
    if (
        type(relay_pid) is not int
        or relay_pid <= 1
        or type(relay_start) is not int
    ):
        raise AdmissionError("persisted relay process identity is invalid")
    registration.update(
        transport=expected_transport,
        relay_path=str(relay_path),
        relay_pid=relay_pid,
        relay_process_start_epoch=relay_start,
    )
    if runtime == "claude":
        registration["relay_owner_hash"] = validated_hash(
            route.get("relay_owner_hash"), "persisted Claude relay owner"
        )
    else:
        registration["target_session_id"] = validated_name(
            route.get("target_session_id"), "target_session_id"
        )
    return registration


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionError("duplicate JSON key")
        result[key] = value
    return result


def parse_json(data):
    try:
        return json.loads(data, object_pairs_hook=no_duplicates)
    except RecursionError as error:
        raise AdmissionError("JSON nesting exceeds parser limit") from error


def read_regular(path, limit=MAX_METADATA_BYTES):
    """Bounded no-follow read, including parent components; never repair."""
    path = Path(path).absolute()
    for parent in reversed(path.parents):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise AdmissionError("metadata parent is not a physical directory")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise AdmissionError("metadata is nonregular or oversized")
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if identity(opened) != identity(before) or not stat.S_ISREG(opened.st_mode):
            raise AdmissionError("metadata changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        if (
            len(data) > limit
            or fingerprint(before) != fingerprint(after)
            or fingerprint(path.lstat()) != fingerprint(after)
        ):
            raise AdmissionError("metadata changed while reading")
        return data, fingerprint(after)
    finally:
        os.close(fd)


def fingerprint(details):
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def read_object(path):
    data, _ = read_regular(path)
    value = parse_json(data)
    if not isinstance(value, dict):
        raise AdmissionError("metadata must be a JSON object")
    return value


def inspect_admission(state_root, payload_root=None, opencode_root=None):
    """Return bounded public facts. Namespace existence always fails closed."""
    root = Path(state_root).expanduser().resolve()
    namespace = root / NAMESPACE
    result = {
        "managed": False,
        "status": "unmanaged",
        "envelope_valid": False,
        "receipt_bound": False,
        "writer_admitted": False,
    }
    try:
        namespace.lstat()
    except FileNotFoundError:
        return result
    except OSError:
        return dict(
            result, managed=True, status="invalid", error="namespace_unreadable"
        )
    result.update(managed=True, status="invalid")
    try:
        if not stat.S_ISDIR(namespace.lstat().st_mode):
            raise AdmissionError("namespace must be a physical directory")
        envelope = read_object(namespace / "admission.json")
        if (
            set(envelope)
            != {
                "format",
                "namespace_version",
                "roots",
                "status",
                "transaction_id",
                "committed",
            }
            or type(envelope["format"]) is not int
            or envelope["format"] != 1
            or type(envelope["namespace_version"]) is not int
            or envelope["namespace_version"] != 1
        ):
            raise AdmissionError("unsupported admission format")
        roots = {
            "state": str(root),
            "payload": str(
                Path(payload_root or Path.home() / ".claude/skills/council")
                .expanduser()
                .resolve()
            ),
            "opencode": str(
                Path(opencode_root or Path.home() / ".config/opencode")
                .expanduser()
                .resolve()
            ),
        }
        if envelope["roots"] != roots:
            raise AdmissionError("admission roots do not match")
        status = envelope["status"]
        transaction = envelope["transaction_id"]
        if status not in ("committed", "recovery_required", "uninstalled"):
            raise AdmissionError("unsupported admission status")
        if status == "recovery_required":
            if not isinstance(transaction, str) or not ID_PATTERN.fullmatch(
                transaction
            ):
                raise AdmissionError("invalid transaction identifier")
        elif transaction is not None:
            raise AdmissionError("inactive admission has a transaction")
        summary = envelope["committed"]
        if summary is None:
            if status == "committed":
                raise AdmissionError("committed admission lacks receipt")
        else:
            if (
                not isinstance(summary, dict)
                or set(summary)
                != {"receipt_id", "receipt_sha256", "package_id", "runtime_cohort"}
                or not isinstance(summary["receipt_id"], str)
                or not ID_PATTERN.fullmatch(summary["receipt_id"])
                or any(
                    not isinstance(summary[key], str)
                    or not HASH_PATTERN.fullmatch(summary[key])
                    for key in ("receipt_sha256", "package_id", "runtime_cohort")
                )
            ):
                raise AdmissionError("invalid committed summary")
            receipt, _ = read_regular(
                namespace / "v1/receipts" / (summary["receipt_id"] + ".json")
            )
            if hashlib.sha256(receipt).hexdigest() != summary["receipt_sha256"]:
                raise AdmissionError("receipt digest mismatch")
            result.update(
                receipt_bound=True,
                runtime_cohort=summary["runtime_cohort"],
                package_id=summary["package_id"],
            )
        result.update(status=status, envelope_valid=True)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        # No metadata values or filesystem exception paths enter diagnostics.
        result["error"] = (
            str(error)
            if isinstance(error, AdmissionError)
            else "metadata_unreadable_or_malformed"
        )
    return result


class WriterLease:
    """Exclusive lifetime lease. Owner closes; callers borrow without re-flocking.

    Never unlock in a forked child: flock's open-file description is shared with
    its parent. close waits for all operations, without holding a broker RLock.
    """

    def __init__(self, root, fd, *, _proof=None):
        if _proof is not _LEASE_PROOF:
            raise AdmissionError("use acquire_writer_lease to obtain exclusion")
        self.root = root
        self.fd = fd
        self.pid = os.getpid()
        self.root_identity = identity(root.stat())
        self.lock_identity = identity(os.fstat(fd))
        self.closed = False
        self.closing = False
        self._condition = threading.Condition()
        self._active = 0
        self._local = threading.local()

    def validate(self, state_root=None):
        if self.closed or self.pid != os.getpid():
            raise AdmissionError("writer lease is closed or belongs to another process")
        if (
            state_root is not None
            and Path(state_root).expanduser().resolve() != self.root
        ):
            raise AdmissionError("writer lease belongs to another state root")
        try:
            if (
                identity(self.root.stat()) != self.root_identity
                or self.root.resolve() != self.root
                or not stat.S_ISDIR(self.root.lstat().st_mode)
                or identity(os.fstat(self.fd)) != self.lock_identity
                or not stat.S_ISREG((self.root / "broker.lock").lstat().st_mode)
                or identity((self.root / "broker.lock").lstat()) != self.lock_identity
            ):
                raise AdmissionError("writer lease root or lock inode changed")
        except OSError as error:
            raise AdmissionError(
                "writer lease descriptor or path is unavailable"
            ) from error
        return self

    @contextlib.contextmanager
    def operation(self):
        # No re-lock, probe, admission parse or inventory on nested method calls.
        if self.closed or self.pid != os.getpid():
            raise AdmissionError("writer lease is closed or belongs to another process")
        depth = getattr(self._local, "depth", 0)
        if not depth:
            self.validate()
            with self._condition:
                if self.closing:
                    raise AdmissionError("writer lease is closing")
                self._active += 1
        self._local.depth = depth + 1
        try:
            yield self
        finally:
            self._local.depth = depth
            if not depth:
                if self.pid != os.getpid():
                    raise AdmissionError(
                        "writer lease operation belongs to another process"
                    )
                with self._condition:
                    self._active -= 1
                    self._condition.notify_all()

    def close(self):
        if self.closed:
            return
        if self.pid != os.getpid():
            # Child drops only its descriptor; it must not LOCK_UN the parent.
            os.close(self.fd)
            self.closed = True
            return
        if getattr(self._local, "depth", 0):
            raise AdmissionError("cannot close a lease from its active operation")
        with self._condition:
            self.closing = True
            while self._active:
                self._condition.wait()
            if not self.closed:
                try:
                    # The owner's explicit unlock releases the shared open-file
                    # description even when an unrelated fork inherited the fd.
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                finally:
                    os.close(self.fd)
                    self.closed = True

    def __enter__(self):
        return self.validate()

    def __exit__(self, *_):
        self.close()


def acquire_writer_lease(state_root):
    root = Path(state_root).expanduser().resolve()
    # Creation of the control anchor is bootstrap, never durable-state repair.
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(
            str(root / "broker.lock"),
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
    except OSError as error:
        raise AdmissionError(
            "broker lifetime lock root or file is unavailable"
        ) from error
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AdmissionError("broker lock is not a regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise AdmissionError(
                "broker lifetime lock is already held or unavailable",
                retryable=True,
            ) from error
        lease = WriterLease(root, fd, _proof=_LEASE_PROOF)
        lease.validate()
        return lease
    except BaseException:
        os.close(fd)
        raise


def admit_runtime_writer(lease, loaded_runtime_cohort):
    if not isinstance(lease, WriterLease):
        raise AdmissionError("an acquired WriterLease is required")
    lease.validate()
    with lease.operation():
        result = inspect_admission(lease.root)
        lease.validate()
    if result["managed"] and not (
        result["status"] == "committed"
        and result["envelope_valid"]
        and result["receipt_bound"]
        and result.get("runtime_cohort") == loaded_runtime_cohort
    ):
        raise AdmissionError(
            "managed Council state requires compatible committed artifacts or lifecycle recovery"
        )
    result["writer_admitted"] = True
    return result


def lease_methods(cls):
    """All supported public broker operations retain exclusion until return."""
    for name, method in list(vars(cls).items()):
        if name.startswith("_") or name == "close" or not callable(method):
            continue

        @functools.wraps(method)
        def guarded(self, *args, __method=method, **kwargs):
            if self._lease.pid != os.getpid():
                raise AdmissionError("broker belongs to another process")
            actor = threading.get_ident()
            with self._calls:
                if self._closed or (self._closing and actor not in self._call_counts):
                    raise AdmissionError("broker is closed or closing")
                self._call_counts[actor] = self._call_counts.get(actor, 0) + 1
            try:
                with self._lease.operation():
                    return __method(self, *args, **kwargs)
            finally:
                if self._lease.pid != os.getpid():
                    raise AdmissionError("broker belongs to another process")
                with self._calls:
                    self._call_counts[actor] -= 1
                    if not self._call_counts[actor]:
                        del self._call_counts[actor]
                    self._calls.notify_all()

        setattr(cls, name, guarded)
    return cls
