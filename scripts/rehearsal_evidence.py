#!/usr/bin/env python3
"""File-only evidence handling for the assisted live-rehearsal runner.

This module deliberately has no broker, host, runtime, process, or network
integration.  It consumes explicit files and fixed JSON records, copies selected
bytes into one private run root, and evaluates collector evidence conservatively.
"""

import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path


METADATA_LIMIT_BYTES = 8 * 1024 * 1024
EVIDENCE_LIMIT_BYTES = 1024 * 1024 * 1024
TOTAL_EVIDENCE_LIMIT_BYTES = 8 * 1024 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 4096
MAX_COLLECTOR_EVENTS = 100000
MAX_SOURCE_FORMS = 32
MAX_LIST_ITEMS = 100000
MAX_OBSERVATION_COUNT = 2**31 - 1

PRIVATE_INDEX_FORMAT = "rehearsal-private-index/v1"
IMPORT_FORMAT = "rehearsal-import/v1"
COLLECTOR_RESULT_FORMAT = "collector-result/v1"
COLLECTOR_QUALIFICATION_FORMAT = "collector-qualification/v1"

RESULTS = {"pass", "fail", "unobserved", "skipped"}
CLASSIFICATIONS = {"redacted_record", "private_capture"}
CONTENT_KINDS = {
    "capture",
    "support_record",
    "collector_result",
    "collector_qualification",
    "roster_mapping",
    "redacted_record",
}
TRANSFORMATIONS = {"none", "redact_allowlist", "normalize_collector_result"}
EVENT_TYPES = {
    "native_arrival",
    "quote",
    "ui_repeat",
    "tool_projection",
    "local_retry",
}
SOURCE_FORM_KINDS = {
    "primary",
    "sibling",
    "sidechain",
    "queued",
    "paginated",
    "rotated",
}
QUALIFICATION_PROPERTIES = {
    "source_universe",
    "interval_coverage",
    "event_semantics",
    "target_and_transform_binding",
    "omission_validation",
}
OPAQUE_REF_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$"
)


class EvidenceError(ValueError):
    """An input or evidence-integrity refusal safe for public diagnostics."""

    def __init__(self, code, field=""):
        self.code = code
        self.field = field
        message = code if not field else "%s at %s" % (code, field)
        super().__init__(message)


def _reject_constant(_value):
    raise EvidenceError("nonfinite-number")


def _object_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate-key", key)
        result[key] = value
    return result


def strict_json_bytes(data, field="json"):
    """Parse UTF-8 JSON while rejecting duplicate keys and nonfinite numbers."""
    if not isinstance(data, bytes):
        raise EvidenceError("bytes-required", field)
    if len(data) > METADATA_LIMIT_BYTES:
        raise EvidenceError("metadata-too-large", field)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("invalid-utf8", field) from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_no_duplicates,
            parse_constant=_reject_constant,
        )
    except EvidenceError:
        raise
    except (TypeError, ValueError) as error:
        raise EvidenceError("invalid-json", field) from error


def strict_load_json(path, field="json"):
    """Read one regular, non-symlink JSON file within the metadata bound."""
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as error:
        raise EvidenceError("unreadable-file", field) from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EvidenceError("regular-file-required", field)
    if info.st_size > METADATA_LIMIT_BYTES:
        raise EvidenceError("metadata-too-large", field)
    try:
        return strict_json_bytes(path.read_bytes(), field)
    except OSError as error:
        raise EvidenceError("unreadable-file", field) from error


def canonical_json_bytes(value):
    """Return deterministic UTF-8 JSON bytes with a terminal newline."""
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        raise EvidenceError("not-canonical-json") from error
    return (encoded + "\n").encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def is_sha256(value):
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def is_nonnegative_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def require_nonnegative_int(value, field):
    if not is_nonnegative_int(value):
        raise EvidenceError("nonnegative-integer-required", field)
    return value


def require_bool(value, field):
    if not isinstance(value, bool):
        raise EvidenceError("boolean-required", field)
    return value


def require_string(value, field, allow_empty=False, limit=512):
    if not isinstance(value, str):
        raise EvidenceError("string-required", field)
    if (not allow_empty and not value) or len(value.encode("utf-8")) > limit:
        raise EvidenceError("invalid-string", field)
    return value


def require_ref(value, field):
    if not isinstance(value, str) or OPAQUE_REF_RE.fullmatch(value) is None:
        raise EvidenceError("invalid-opaque-ref", field)
    return value


def require_sha256(value, field):
    if not is_sha256(value):
        raise EvidenceError("invalid-sha256", field)
    return value


def require_utc(value, field):
    require_string(value, field, limit=64)
    if UTC_RE.fullmatch(value) is None:
        raise EvidenceError("absolute-utc-required", field)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise EvidenceError("absolute-utc-required", field) from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise EvidenceError("absolute-utc-required", field)
    return parsed


def require_keys(value, required, optional=(), field="object"):
    if not isinstance(value, dict):
        raise EvidenceError("object-required", field)
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - set(value))
    unknown = sorted(set(value) - allowed)
    if missing:
        raise EvidenceError("missing-field", "%s.%s" % (field, missing[0]))
    if unknown:
        raise EvidenceError("unknown-field", "%s.%s" % (field, unknown[0]))
    return value


def require_list(value, field, maximum=MAX_LIST_ITEMS, nonempty=False):
    if not isinstance(value, list):
        raise EvidenceError("array-required", field)
    if len(value) > maximum or (nonempty and not value):
        raise EvidenceError("invalid-array-length", field)
    return value


def require_unique(values, field):
    if len(values) != len(set(values)):
        raise EvidenceError("duplicate-value", field)


def safe_relative_name(value, field):
    require_string(value, field, limit=128)
    candidate = Path(value)
    if candidate.is_absolute() or len(candidate.parts) != 1 or value in {".", ".."}:
        raise EvidenceError("unsafe-relative-name", field)
    if "/" in value or "\\" in value or "\x00" in value:
        raise EvidenceError("unsafe-relative-name", field)
    return value


def _regular_mode(path, expected, field):
    try:
        info = Path(path).lstat()
    except OSError as error:
        raise EvidenceError("unreadable-file", field) from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EvidenceError("regular-file-required", field)
    if stat.S_IMODE(info.st_mode) != expected:
        raise EvidenceError("unsafe-file-mode", field)
    return info


def _directory_mode(path, expected, field):
    try:
        info = Path(path).lstat()
    except OSError as error:
        raise EvidenceError("unreadable-directory", field) from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EvidenceError("directory-required", field)
    if stat.S_IMODE(info.st_mode) != expected:
        raise EvidenceError("unsafe-directory-mode", field)
    return info


def write_new_private(path, data):
    """Create one immutable-by-convention 0600 file without replacing a target."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(str(path), flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise EvidenceError("short-write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(str(path), 0o600)


def atomic_write_private(path, data):
    """Durably replace one 0600 file in an existing 0700 directory."""
    path = Path(path)
    _directory_mode(path.parent, 0o700, "destination-parent")
    descriptor, temporary = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise EvidenceError("short-write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, str(path))
        directory_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def empty_private_index():
    return {"format": PRIVATE_INDEX_FORMAT, "items": []}


def _validate_private_item(item, field):
    require_keys(
        item,
        (
            "ref",
            "object_name",
            "source_path",
            "source_identity",
            "classification",
            "content_kind",
            "sha256",
            "bytes",
            "collected_utc",
            "transformations",
            "qualification_refs",
        ),
        field=field,
    )
    require_ref(item["ref"], field + ".ref")
    safe_relative_name(item["object_name"], field + ".object_name")
    source = require_string(item["source_path"], field + ".source_path", limit=4096)
    if not Path(source).is_absolute():
        raise EvidenceError("absolute-path-required", field + ".source_path")
    require_string(item["source_identity"], field + ".source_identity", limit=1024)
    if item["classification"] not in CLASSIFICATIONS:
        raise EvidenceError("unknown-classification", field + ".classification")
    if item["content_kind"] not in CONTENT_KINDS:
        raise EvidenceError("unknown-content-kind", field + ".content_kind")
    require_sha256(item["sha256"], field + ".sha256")
    require_nonnegative_int(item["bytes"], field + ".bytes")
    if item["bytes"] > EVIDENCE_LIMIT_BYTES:
        raise EvidenceError("evidence-too-large", field + ".bytes")
    require_utc(item["collected_utc"], field + ".collected_utc")
    transformations = require_list(item["transformations"], field + ".transformations", 16)
    for index, transformation in enumerate(transformations):
        if transformation not in TRANSFORMATIONS:
            raise EvidenceError(
                "unknown-transformation", "%s.transformations[%d]" % (field, index)
            )
    refs = require_list(item["qualification_refs"], field + ".qualification_refs", 64)
    for index, ref in enumerate(refs):
        require_ref(ref, "%s.qualification_refs[%d]" % (field, index))


def validate_private_index(index):
    require_keys(index, ("format", "items"), field="private_index")
    if index["format"] != PRIVATE_INDEX_FORMAT:
        raise EvidenceError("unsupported-format", "private_index.format")
    items = require_list(index["items"], "private_index.items", MAX_EVIDENCE_ITEMS)
    refs = []
    names = []
    sources = []
    for position, item in enumerate(items):
        field = "private_index.items[%d]" % position
        _validate_private_item(item, field)
        refs.append(item["ref"])
        names.append(item["object_name"])
        sources.append(item["source_path"])
    if sum(item["bytes"] for item in items) > TOTAL_EVIDENCE_LIMIT_BYTES:
        raise EvidenceError("total-evidence-too-large", "private_index.items")
    require_unique(refs, "private_index.items.ref")
    require_unique(names, "private_index.items.object_name")
    require_unique(sources, "private_index.items.source_path")
    known = set(refs)
    for position, item in enumerate(items):
        for ref in item["qualification_refs"]:
            if ref not in known:
                raise EvidenceError(
                    "dangling-reference",
                    "private_index.items[%d].qualification_refs" % position,
                )
    return index


def load_private_index(run_root):
    path = Path(run_root) / "private-index.json"
    _regular_mode(path, 0o600, "private_index")
    index = strict_load_json(path, "private_index")
    return validate_private_index(index)


def _validate_import_item(item, field):
    require_keys(
        item,
        (
            "source",
            "source_identity",
            "classification",
            "content_kind",
            "transformations",
            "qualification_refs",
            "selection_scope",
            "reviewed_safe",
        ),
        field=field,
    )
    source = require_string(item["source"], field + ".source", limit=4096)
    if not Path(source).is_absolute():
        raise EvidenceError("absolute-path-required", field + ".source")
    require_string(item["source_identity"], field + ".source_identity", limit=1024)
    if item["classification"] not in CLASSIFICATIONS:
        raise EvidenceError("unknown-classification", field + ".classification")
    if item["content_kind"] not in CONTENT_KINDS:
        raise EvidenceError("unknown-content-kind", field + ".content_kind")
    transformations = require_list(item["transformations"], field + ".transformations", 16)
    for position, transformation in enumerate(transformations):
        if transformation not in TRANSFORMATIONS:
            raise EvidenceError(
                "unknown-transformation",
                "%s.transformations[%d]" % (field, position),
            )
    refs = require_list(item["qualification_refs"], field + ".qualification_refs", 64)
    for position, ref in enumerate(refs):
        require_ref(ref, "%s.qualification_refs[%d]" % (field, position))
    if item["selection_scope"] != "test_dialogue":
        raise EvidenceError("unapproved-selection-scope", field + ".selection_scope")
    if item["reviewed_safe"] is not True:
        raise EvidenceError("safety-review-required", field + ".reviewed_safe")


def validate_import_spec(spec):
    require_keys(spec, ("format", "collected_utc", "items"), field="import")
    if spec["format"] != IMPORT_FORMAT:
        raise EvidenceError("unsupported-format", "import.format")
    require_utc(spec["collected_utc"], "import.collected_utc")
    items = require_list(spec["items"], "import.items", MAX_EVIDENCE_ITEMS, nonempty=True)
    sources = []
    for position, item in enumerate(items):
        _validate_import_item(item, "import.items[%d]" % position)
        sources.append(item["source"])
    require_unique(sources, "import.items.source")
    return spec


def _open_source(path, field):
    path = Path(path)
    try:
        path_info = path.lstat()
    except OSError as error:
        raise EvidenceError("unreadable-source", field) from error
    if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISREG(path_info.st_mode):
        raise EvidenceError("regular-source-required", field)
    if path_info.st_size > EVIDENCE_LIMIT_BYTES:
        raise EvidenceError("evidence-too-large", field)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
    except OSError as error:
        raise EvidenceError("unreadable-source", field) from error
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode):
        os.close(descriptor)
        raise EvidenceError("regular-source-required", field)
    identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    path_identity = (
        path_info.st_dev,
        path_info.st_ino,
        path_info.st_size,
        path_info.st_mtime_ns,
    )
    if identity != path_identity:
        os.close(descriptor)
        raise EvidenceError("source-changed", field)
    return descriptor, identity


def _copy_source_to_object(source, destination, field):
    descriptor, before = _open_source(source, field)
    digest = hashlib.sha256()
    total = 0
    destination_fd = -1
    try:
        destination_fd = os.open(
            str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > EVIDENCE_LIMIT_BYTES:
                raise EvidenceError("evidence-too-large", field)
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise EvidenceError("short-write", field)
                view = view[written:]
        os.fsync(destination_fd)
        after = os.fstat(descriptor)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        try:
            path_info = Path(source).lstat()
            path_identity = (
                path_info.st_dev,
                path_info.st_ino,
                path_info.st_size,
                path_info.st_mtime_ns,
            )
        except OSError as error:
            raise EvidenceError("source-changed", field) from error
        if before != after_identity or before != path_identity or total != before[2]:
            raise EvidenceError("source-changed", field)
    except Exception:
        try:
            Path(destination).unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)
        if destination_fd >= 0:
            os.close(destination_fd)
    os.chmod(str(destination), 0o600)
    return digest.hexdigest(), total


def _new_evidence_ref(existing):
    for _attempt in range(32):
        candidate = "ev-" + secrets.token_hex(16)
        if candidate not in existing:
            return candidate
    raise EvidenceError("opaque-ref-collision")


def import_evidence(run_root, spec):
    """Copy allowlisted files and atomically publish an updated private index."""
    run_root = Path(run_root)
    _directory_mode(run_root, 0o700, "run_root")
    objects = run_root / "objects"
    _directory_mode(objects, 0o700, "objects")
    spec = validate_import_spec(spec)
    index = load_private_index(run_root)
    if len(index["items"]) + len(spec["items"]) > MAX_EVIDENCE_ITEMS:
        raise EvidenceError("too-many-evidence-items")
    existing_refs = {item["ref"] for item in index["items"]}
    existing_sources = {item["source_path"] for item in index["items"]}
    staged = []
    new_refs = set()
    try:
        for position, item in enumerate(spec["items"]):
            field = "import.items[%d]" % position
            if item["source"] in existing_sources:
                raise EvidenceError("duplicate-import", field + ".source")
            source = Path(item["source"])
            if item["content_kind"] == "collector_result":
                validate_collector_result(strict_load_json(source, field + ".source"))
            elif item["content_kind"] == "collector_qualification":
                validate_collector_qualification(strict_load_json(source, field + ".source"))
            reference = _new_evidence_ref(existing_refs)
            existing_refs.add(reference)
            new_refs.add(reference)
            object_name = reference
            destination = objects / object_name
            digest, byte_count = _copy_source_to_object(source, destination, field + ".source")
            staged.append(destination)
            entry = {
                "ref": reference,
                "object_name": object_name,
                "source_path": str(source),
                "source_identity": item["source_identity"],
                "classification": item["classification"],
                "content_kind": item["content_kind"],
                "sha256": digest,
                "bytes": byte_count,
                "collected_utc": spec["collected_utc"],
                "transformations": list(item["transformations"]),
                "qualification_refs": list(item["qualification_refs"]),
            }
            index["items"].append(entry)
            existing_sources.add(item["source"])
        validate_private_index(index)
        atomic_write_private(run_root / "private-index.json", canonical_json_bytes(index))
    except Exception:
        published = False
        try:
            current = load_private_index(run_root)
            published = new_refs.issubset({item["ref"] for item in current["items"]})
        except EvidenceError:
            # An uncertain publication retains copied bytes for operator review.
            published = True
        if not published:
            for path in staged:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
        raise
    return [public_evidence_item(item) for item in index["items"][-len(spec["items"]) :]]


def public_evidence_item(item):
    """Allowlisted public projection; private paths and identities never cross it."""
    return {
        "ref": item["ref"],
        "sha256": item["sha256"],
        "bytes": item["bytes"],
        "collected_utc": item["collected_utc"],
        "classification": item["classification"],
    }


def verify_evidence(run_root, public_inventory=None):
    """Verify private-index modes, object hashes, and optional public metadata."""
    run_root = Path(run_root)
    _directory_mode(run_root, 0o700, "run_root")
    _directory_mode(run_root / "objects", 0o700, "objects")
    _regular_mode(run_root / "private-index.json", 0o600, "private_index")
    index = load_private_index(run_root)
    public_by_ref = None
    if public_inventory is not None:
        if not isinstance(public_inventory, list):
            raise EvidenceError("array-required", "evidence")
        public_by_ref = {}
        for position, item in enumerate(public_inventory):
            field = "evidence[%d]" % position
            require_keys(
                item,
                ("ref", "sha256", "bytes", "collected_utc", "classification"),
                field=field,
            )
            require_ref(item["ref"], field + ".ref")
            require_sha256(item["sha256"], field + ".sha256")
            require_nonnegative_int(item["bytes"], field + ".bytes")
            if item["bytes"] > EVIDENCE_LIMIT_BYTES:
                raise EvidenceError("evidence-too-large", field + ".bytes")
            require_utc(item["collected_utc"], field + ".collected_utc")
            if item["classification"] not in CLASSIFICATIONS:
                raise EvidenceError("unknown-classification", field + ".classification")
            if item["ref"] in public_by_ref:
                raise EvidenceError("duplicate-value", "evidence.ref")
            public_by_ref[item["ref"]] = item
    verified = []
    index_refs = {item["ref"] for item in index["items"]}
    if public_by_ref is not None and set(public_by_ref) != index_refs:
        raise EvidenceError("inventory-mismatch", "evidence")
    for position, item in enumerate(index["items"]):
        field = "private_index.items[%d]" % position
        object_path = run_root / "objects" / item["object_name"]
        info = _regular_mode(object_path, 0o600, field + ".object")
        if info.st_size != item["bytes"]:
            raise EvidenceError("byte-count-mismatch", field + ".object")
        digest = hashlib.sha256()
        with open(object_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != item["sha256"]:
            raise EvidenceError("hash-mismatch", field + ".object")
        if public_by_ref is not None and public_by_ref[item["ref"]] != public_evidence_item(item):
            raise EvidenceError("inventory-mismatch", "evidence.%s" % item["ref"])
        verified.append(public_evidence_item(item))
    return {"index": index, "public_inventory": verified}


def read_imported_json(run_root, reference, expected_kind, verified_index=None):
    require_ref(reference, "evidence_ref")
    index = verified_index
    if index is None:
        index = verify_evidence(run_root)["index"]
    matches = [item for item in index["items"] if item["ref"] == reference]
    if not matches:
        raise EvidenceError("dangling-reference", "evidence_ref")
    item = matches[0]
    if item["content_kind"] != expected_kind:
        raise EvidenceError("evidence-kind-mismatch", "evidence_ref")
    return strict_load_json(Path(run_root) / "objects" / item["object_name"], "evidence_object")


def _validate_runtime(value, field):
    require_keys(value, ("name", "version", "build"), field=field)
    require_ref(value["name"], field + ".name")
    require_string(value["version"], field + ".version", limit=128)
    require_string(value["build"], field + ".build", limit=128)


def _validate_source_format(value, field):
    require_keys(value, ("id", "version"), field=field)
    require_ref(value["id"], field + ".id")
    require_string(value["version"], field + ".version", limit=128)


def _validate_contract(value, field):
    require_keys(value, ("id", "version", "sha256", "evidence_ref"), field=field)
    require_ref(value["id"], field + ".id")
    require_string(value["version"], field + ".version", limit=128)
    require_sha256(value["sha256"], field + ".sha256")
    require_ref(value["evidence_ref"], field + ".evidence_ref")


def _validate_target(value, field):
    require_keys(value, ("seat_ref", "session_ref", "generation_ref"), field=field)
    require_ref(value["seat_ref"], field + ".seat_ref")
    require_ref(value["session_ref"], field + ".session_ref")
    require_ref(value["generation_ref"], field + ".generation_ref")


def validate_collector_result(record):
    require_keys(
        record,
        (
            "format",
            "collector_contract",
            "implementation_sha256",
            "implementation_evidence_ref",
            "runtime",
            "source_format",
            "target",
            "claim",
            "source_refs",
            "inventory_ref",
            "coverage_ref",
            "transform_ledger",
            "events",
        ),
        field="collector_result",
    )
    if record["format"] != COLLECTOR_RESULT_FORMAT:
        raise EvidenceError("unsupported-format", "collector_result.format")
    _validate_contract(record["collector_contract"], "collector_result.collector_contract")
    require_sha256(record["implementation_sha256"], "collector_result.implementation_sha256")
    require_ref(
        record["implementation_evidence_ref"],
        "collector_result.implementation_evidence_ref",
    )
    _validate_runtime(record["runtime"], "collector_result.runtime")
    _validate_source_format(record["source_format"], "collector_result.source_format")
    _validate_target(record["target"], "collector_result.target")
    claim = require_keys(
        record["claim"],
        (
            "envelope_ref",
            "start_utc",
            "end_utc",
            "expected_count",
            "unit",
            "variant",
        ),
        field="collector_result.claim",
    )
    require_ref(claim["envelope_ref"], "collector_result.claim.envelope_ref")
    start = require_utc(claim["start_utc"], "collector_result.claim.start_utc")
    end = require_utc(claim["end_utc"], "collector_result.claim.end_utc")
    if end < start:
        raise EvidenceError("invalid-time-order", "collector_result.claim")
    require_nonnegative_int(claim["expected_count"], "collector_result.claim.expected_count")
    if claim["expected_count"] > MAX_OBSERVATION_COUNT:
        raise EvidenceError("count-too-large", "collector_result.claim.expected_count")
    if claim["unit"] != "native_arrival":
        raise EvidenceError("unknown-count-unit", "collector_result.claim.unit")
    if claim["variant"] not in {"surviving_relay", "replacement_session"}:
        raise EvidenceError("unknown-variant", "collector_result.claim.variant")
    source_refs = require_list(record["source_refs"], "collector_result.source_refs", MAX_EVIDENCE_ITEMS, True)
    for position, reference in enumerate(source_refs):
        require_ref(reference, "collector_result.source_refs[%d]" % position)
    require_unique(source_refs, "collector_result.source_refs")
    require_ref(record["inventory_ref"], "collector_result.inventory_ref")
    require_ref(record["coverage_ref"], "collector_result.coverage_ref")
    ledger = require_list(record["transform_ledger"], "collector_result.transform_ledger", 1024)
    for position, entry in enumerate(ledger):
        field = "collector_result.transform_ledger[%d]" % position
        require_keys(entry, ("operation", "input_refs", "output_refs", "reason"), field=field)
        if entry["operation"] not in {"filter", "normalize", "join", "omit"}:
            raise EvidenceError("unknown-transform-operation", field + ".operation")
        for key in ("input_refs", "output_refs"):
            refs = require_list(entry[key], field + "." + key, 256)
            for index, reference in enumerate(refs):
                require_ref(reference, "%s.%s[%d]" % (field, key, index))
        require_string(entry["reason"], field + ".reason", limit=1024)
    events = require_list(record["events"], "collector_result.events", MAX_COLLECTOR_EVENTS)
    projection_ids = []
    for position, event in enumerate(events):
        field = "collector_result.events[%d]" % position
        require_keys(
            event,
            (
                "native_event_id",
                "projection_id",
                "source_ref",
                "native_record_key",
                "byte_offset",
                "target",
                "event_type",
                "accepted",
                "envelope_ref",
                "capture_refs",
                "verification_refs",
            ),
            field=field,
        )
        require_ref(event["native_event_id"], field + ".native_event_id")
        projection_ids.append(require_ref(event["projection_id"], field + ".projection_id"))
        require_ref(event["source_ref"], field + ".source_ref")
        require_string(event["native_record_key"], field + ".native_record_key", limit=512)
        require_nonnegative_int(event["byte_offset"], field + ".byte_offset")
        if event["byte_offset"] > EVIDENCE_LIMIT_BYTES:
            raise EvidenceError("evidence-offset-too-large", field + ".byte_offset")
        _validate_target(event["target"], field + ".target")
        if event["event_type"] not in EVENT_TYPES:
            raise EvidenceError("unknown-event-type", field + ".event_type")
        require_bool(event["accepted"], field + ".accepted")
        require_ref(event["envelope_ref"], field + ".envelope_ref")
        for key in ("capture_refs", "verification_refs"):
            refs = require_list(event[key], field + "." + key, 64, nonempty=True)
            for index, reference in enumerate(refs):
                require_ref(reference, "%s.%s[%d]" % (field, key, index))
    require_unique(projection_ids, "collector_result.events.projection_id")
    return record


def qualification_inventory_digest(source_forms):
    return sha256_bytes(canonical_json_bytes(source_forms))


def validate_collector_qualification(record):
    require_keys(
        record,
        (
            "format",
            "collector_contract",
            "implementation_sha256",
            "implementation_evidence_ref",
            "runtime",
            "source_format",
            "provenance",
            "reviewed",
            "review_checkpoint_ref",
            "validation_evidence_refs",
            "event_definition_ref",
            "enumeration_contract_ref",
            "properties",
            "source_forms",
            "inventory_sha256",
            "limitations",
        ),
        field="collector_qualification",
    )
    if record["format"] != COLLECTOR_QUALIFICATION_FORMAT:
        raise EvidenceError("unsupported-format", "collector_qualification.format")
    _validate_contract(record["collector_contract"], "collector_qualification.collector_contract")
    require_sha256(record["implementation_sha256"], "collector_qualification.implementation_sha256")
    require_ref(
        record["implementation_evidence_ref"],
        "collector_qualification.implementation_evidence_ref",
    )
    _validate_runtime(record["runtime"], "collector_qualification.runtime")
    _validate_source_format(record["source_format"], "collector_qualification.source_format")
    if record["provenance"] not in {"real_capture", "fixture", "candidate"}:
        raise EvidenceError("unknown-provenance", "collector_qualification.provenance")
    require_bool(record["reviewed"], "collector_qualification.reviewed")
    require_ref(record["review_checkpoint_ref"], "collector_qualification.review_checkpoint_ref")
    for key in (
        "validation_evidence_refs",
        "limitations",
    ):
        values = require_list(record[key], "collector_qualification." + key, 1024)
        for position, value in enumerate(values):
            if key == "validation_evidence_refs":
                require_ref(value, "collector_qualification.%s[%d]" % (key, position))
            else:
                require_string(value, "collector_qualification.%s[%d]" % (key, position), limit=2048)
    require_ref(record["event_definition_ref"], "collector_qualification.event_definition_ref")
    require_ref(record["enumeration_contract_ref"], "collector_qualification.enumeration_contract_ref")
    properties = require_keys(
        record["properties"],
        QUALIFICATION_PROPERTIES,
        field="collector_qualification.properties",
    )
    for name in sorted(QUALIFICATION_PROPERTIES):
        field = "collector_qualification.properties.%s" % name
        entry = require_keys(properties[name], ("result", "evidence_refs"), field=field)
        if entry["result"] not in RESULTS:
            raise EvidenceError("unknown-result", field + ".result")
        refs = require_list(entry["evidence_refs"], field + ".evidence_refs", 256)
        for position, reference in enumerate(refs):
            require_ref(reference, "%s.evidence_refs[%d]" % (field, position))
    forms = require_list(record["source_forms"], "collector_qualification.source_forms", MAX_SOURCE_FORMS)
    kinds = []
    for position, form in enumerate(forms):
        field = "collector_qualification.source_forms[%d]" % position
        require_keys(
            form,
            ("kind", "applicable", "applicability_evidence_refs", "omission_test"),
            field=field,
        )
        if form["kind"] not in SOURCE_FORM_KINDS:
            raise EvidenceError("unknown-source-form", field + ".kind")
        kinds.append(form["kind"])
        require_bool(form["applicable"], field + ".applicable")
        applicability = require_list(
            form["applicability_evidence_refs"], field + ".applicability_evidence_refs", 64
        )
        for index, reference in enumerate(applicability):
            require_ref(reference, "%s.applicability_evidence_refs[%d]" % (field, index))
        omission = require_keys(
            form["omission_test"], ("result", "evidence_refs"), field=field + ".omission_test"
        )
        if omission["result"] not in {"detected", "not_detected", "not_applicable"}:
            raise EvidenceError("unknown-omission-result", field + ".omission_test.result")
        omission_refs = require_list(
            omission["evidence_refs"], field + ".omission_test.evidence_refs", 64
        )
        for index, reference in enumerate(omission_refs):
            require_ref(reference, "%s.omission_test.evidence_refs[%d]" % (field, index))
    require_unique(kinds, "collector_qualification.source_forms.kind")
    require_sha256(record["inventory_sha256"], "collector_qualification.inventory_sha256")
    if qualification_inventory_digest(forms) != record["inventory_sha256"]:
        raise EvidenceError("inventory-hash-mismatch", "collector_qualification.inventory_sha256")
    return record


def qualification_status(qualification, context_kind="live"):
    """Return a fixed completeness decision without trusting a complete flag."""
    validate_collector_qualification(qualification)
    limitations = []
    qualified = True
    if qualification["provenance"] != "real_capture":
        if not (context_kind == "fixture" and qualification["provenance"] == "fixture"):
            qualified = False
            limitations.append("qualification-provenance-is-not-reviewed-real-capture")
    if context_kind == "live" and qualification["provenance"] == "fixture":
        qualified = False
        limitations.append("fixture-qualification-cannot-support-live-claim")
    if qualification["provenance"] == "candidate":
        qualified = False
        limitations.append("collector-remains-candidate")
    if not qualification["reviewed"]:
        qualified = False
        limitations.append("qualification-review-missing")
    if not qualification["validation_evidence_refs"]:
        qualified = False
        limitations.append("real-capture-validation-evidence-missing")
    for name in sorted(QUALIFICATION_PROPERTIES):
        entry = qualification["properties"][name]
        if entry["result"] != "pass" or not entry["evidence_refs"]:
            qualified = False
            limitations.append("qualification-property-not-passed:%s" % name)
    by_kind = {form["kind"]: form for form in qualification["source_forms"]}
    for kind in sorted(SOURCE_FORM_KINDS):
        form = by_kind.get(kind)
        if form is None:
            qualified = False
            limitations.append("source-form-not-inventoried:%s" % kind)
            continue
        if not form["applicability_evidence_refs"]:
            qualified = False
            limitations.append("source-form-applicability-unproved:%s" % kind)
        expected = "detected" if form["applicable"] else "not_applicable"
        omission = form["omission_test"]
        if omission["result"] != expected or not omission["evidence_refs"]:
            qualified = False
            limitations.append("source-form-omission-control-failed:%s" % kind)
    return {"complete": qualified, "limitations": sorted(set(limitations))}


def collector_tuple_matches(result, qualification):
    validate_collector_result(result)
    validate_collector_qualification(qualification)
    fields = (
        "collector_contract",
        "implementation_sha256",
        "implementation_evidence_ref",
        "runtime",
        "source_format",
    )
    mismatches = [field for field in fields if result[field] != qualification[field]]
    return {"matches": not mismatches, "mismatches": mismatches}


def collector_evidence_refs(result, qualification=None):
    """Return every byte/provenance reference used by fixed collector records."""
    validate_collector_result(result)
    refs = {
        result["collector_contract"]["evidence_ref"],
        result["implementation_evidence_ref"],
        result["inventory_ref"],
        result["coverage_ref"],
    }
    refs.update(result["source_refs"])
    for event in result["events"]:
        refs.add(event["source_ref"])
        refs.update(event["capture_refs"])
        refs.update(event["verification_refs"])
    for entry in result["transform_ledger"]:
        refs.update(entry["input_refs"])
    if qualification is not None:
        validate_collector_qualification(qualification)
        refs.update(
            {
                qualification["collector_contract"]["evidence_ref"],
                qualification["implementation_evidence_ref"],
                qualification["review_checkpoint_ref"],
                qualification["event_definition_ref"],
                qualification["enumeration_contract_ref"],
            }
        )
        refs.update(qualification["validation_evidence_refs"])
        for item in qualification["properties"].values():
            refs.update(item["evidence_refs"])
        for form in qualification["source_forms"]:
            refs.update(form["applicability_evidence_refs"])
            refs.update(form["omission_test"]["evidence_refs"])
    return refs


def require_collector_evidence_links(result, qualification, available_refs):
    missing = sorted(collector_evidence_refs(result, qualification) - set(available_refs))
    if missing:
        raise EvidenceError("dangling-collector-evidence-reference", "collector_records")


def normalized_arrivals(result, available_refs=None):
    """Count stable native events and retain mapping conflicts as limitations."""
    validate_collector_result(result)
    target = result["target"]
    envelope_ref = result["claim"]["envelope_ref"]
    identities = {}
    conflicts = []
    excluded = {name: 0 for name in sorted(EVENT_TYPES - {"native_arrival"})}
    wrong_target = 0
    unverified = 0
    for event in result["events"]:
        if event["event_type"] != "native_arrival" or not event["accepted"]:
            if event["event_type"] in excluded:
                excluded[event["event_type"]] += 1
            continue
        if event["target"] != target or event["envelope_ref"] != envelope_ref:
            wrong_target += 1
            continue
        if available_refs is not None:
            required_refs = {
                event["source_ref"],
                *event["capture_refs"],
                *event["verification_refs"],
            }
            if not required_refs.issubset(set(available_refs)):
                unverified += 1
                continue
        identity = event["native_event_id"]
        mapping = (
            event["source_ref"],
            event["native_record_key"],
            event["byte_offset"],
        )
        previous = identities.get(identity)
        if previous is None:
            identities[identity] = mapping
        elif previous != mapping:
            conflicts.append(identity)
    return {
        "verified_lower_bound": len(identities),
        "native_event_ids": sorted(identities),
        "mapping_conflicts": sorted(set(conflicts)),
        "wrong_target_events": wrong_target,
        "unverified_arrival_events": unverified,
        "excluded_event_counts": excluded,
    }


def assess_arrival_count(
    result,
    qualification,
    context_kind="live",
    recovery_delivery_attempted=False,
    fresh_control_passed=False,
    available_refs=None,
):
    """Apply the G3 lower-bound/completeness decision table."""
    if available_refs is not None:
        require_collector_evidence_links(result, qualification, available_refs)
    normalized = normalized_arrivals(result, available_refs=available_refs)
    expected = result["claim"]["expected_count"]
    tuple_match = collector_tuple_matches(result, qualification)
    status = qualification_status(qualification, context_kind=context_kind)
    limitations = list(status["limitations"])
    if not tuple_match["matches"]:
        limitations.extend("collector-tuple-mismatch:%s" % name for name in tuple_match["mismatches"])
    if normalized["mapping_conflicts"]:
        limitations.append("conflicting-native-event-mapping")
    actual = normalized["verified_lower_bound"]
    if actual > expected:
        verdict = "fail"
        reason = "verified-native-arrival-lower-bound-exceeds-expected-count"
    elif not tuple_match["matches"] or not status["complete"] or normalized["mapping_conflicts"]:
        verdict = "unobserved"
        reason = "complete-source-qualification-unavailable"
    elif actual != expected:
        verdict = "fail"
        reason = "qualified-native-arrival-count-contradicts-expectation"
    elif not recovery_delivery_attempted:
        verdict = "unobserved"
        reason = "recovery-delivery-attempt-not-evidenced"
    elif not fresh_control_passed:
        verdict = "unobserved"
        reason = "fresh-receiving-path-control-not-passed"
    else:
        verdict = "pass"
        reason = "qualified-native-arrival-count-matches-expectation"
    return {
        "result": verdict,
        "reason": reason,
        "expected_count": expected,
        "verified_lower_bound": actual,
        "complete_source": status["complete"] and tuple_match["matches"],
        "native_event_ids": normalized["native_event_ids"],
        "mapping_conflicts": normalized["mapping_conflicts"],
        "wrong_target_events": normalized["wrong_target_events"],
        "unverified_arrival_events": normalized["unverified_arrival_events"],
        "excluded_event_counts": normalized["excluded_event_counts"],
        "limitations": sorted(set(limitations)),
    }


def private_markers(index):
    """Return nonempty private strings that must not occur in public exports."""
    validate_private_index(index)
    markers = set()
    for item in index["items"]:
        for value in (item["source_path"], item["source_identity"]):
            if value:
                markers.add(value)
    return markers


def assert_no_private_markers(public_bytes, index):
    try:
        text = public_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("invalid-public-utf8") from error
    for marker in private_markers(index):
        if marker in text:
            raise EvidenceError("private-marker-in-public-export")
