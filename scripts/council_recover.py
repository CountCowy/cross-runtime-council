#!/usr/bin/env python3
"""Standalone Council artifact recovery executor (Python 3.9 stdlib only)."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import signal
import stat
import subprocess
import sys
import time
import types
import unicodedata
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


RECOVERY_FORMAT = 1
PLAN_FORMAT = 1
RECEIPT_FORMAT = 1
JOURNAL_FORMAT = 1
ADMISSION_FORMAT = 1
NAMESPACE_VERSION = 1
REGISTRATION_PLAN_FORMAT = 2
REGISTRATION_RECEIPT_FORMAT = 2
REGISTRATION_JOURNAL_FORMAT = 2
REGISTRATION_RECOVERY_FORMAT = 2
REGISTRATION_EXTENSION_FORMAT = 1
NATIVE_PLAN_FORMAT = 3
NATIVE_RECEIPT_FORMAT = 3
NATIVE_JOURNAL_FORMAT = 3
NATIVE_RECOVERY_FORMAT = 3
NATIVE_EXTENSION_FORMAT = 1
MAX_METADATA_BYTES = 1024 * 1024
MAX_ARTIFACTS = 16384
MAX_PATH_COMPONENTS = 64
MAX_TEXT_BYTES = 4096
ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}"
HASH_PATTERN = r"[0-9a-f]{64}"
UNIT_IDS = (
    "payload",
    "opencode-plugin",
    "opencode-protocol",
    "opencode-registry",
    "opencode-tool",
)
EXTERNAL_DESTINATIONS = {
    "opencode-plugin": "council-plugin.ts",
    "opencode-protocol": "council_protocol.ts",
    "opencode-registry": "opencode_delivery_registry.ts",
    "opencode-tool": "tools/council.ts",
}
EXTERNAL_MANIFEST_PATHS = {
    "opencode-plugin": "opencode/council-plugin.ts",
    "opencode-protocol": "opencode/council_protocol.ts",
    "opencode-registry": "opencode/opencode_delivery_registry.ts",
    "opencode-tool": "opencode/tools/council.ts",
}
OPENCODE_SOURCES = {
    "council-plugin.ts": "scripts/opencode_council_plugin.ts",
    "council_protocol.ts": "scripts/council_protocol.ts",
    "opencode_delivery_registry.ts": "scripts/opencode_delivery_registry.ts",
    "tools/council.ts": "scripts/tools/council.ts",
}
REQUIRED_OPERATIONS = (
    "classify-filesystem-v1",
    "preserve-initial-v1",
    "materialize-selected-v1",
    "activate-five-units-v1",
    "verify-receipt-v1",
    "publish-admission-v1",
)
REGISTRATION_REQUIRED_OPERATIONS = REQUIRED_OPERATIONS + (
    "classify-registration-v1",
    "replace-registration-v1",
    "verify-registration-receipt-v1",
)
REGISTRATION_OPERATIONS = {
    "opencode_global_plugin_ensure",
    "opencode_global_plugin_remove",
}
NATIVE_OPERATIONS = {
    "claude_user_stdio_ensure",
    "claude_user_stdio_remove",
    "codex_user_stdio_ensure",
    "codex_user_stdio_remove",
}
NATIVE_REQUIRED_OPERATIONS = REQUIRED_OPERATIONS + (
    "classify-native-registration-v1",
    "supervise-native-attempt-v1",
    "verify-native-registration-receipt-v1",
)
NATIVE_ATTEMPT_STATES = {
    "prepared",
    "issued",
    "spawn_generation_recorded",
    "release_authorized",
    "observed_target",
    "observed_prior",
    "unknown",
}
NATIVE_RECOVERY_MODULES = (
    "council_recover.py",
    "council_registration.py",
    "council_registration_qualification.py",
)
REGISTRATION_OWNERSHIP = {
    "created",
    "already_owned",
    "matching_preexisting_unowned",
    "adopted_by_explicit_plan",
}
KINDS = {"install", "upgrade", "rollback", "uninstall", "registration"}
OWNERSHIP = {"absent", "created", "already_owned", "matching_preexisting_unowned"}
IDENTITY_BINDING_FORMAT = 1
VOLATILE_STATE_NAMES = {"broker.lock", "broker.sock", "broker.log"}
PREPARATION_ROOT_NAME = ".council-lifecycle-preparations"


class RecoveryError(Exception):
    pass


Failpoint = Optional[Callable[[str], None]]


def _event(failpoint: Failpoint, name: str) -> None:
    if failpoint is not None:
        failpoint(name)


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RecoveryError("expected a single-linked regular file: %s" % path)
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RecoveryError("expected a single-linked regular file: %s" % path)
        if (details.st_dev, details.st_ino) != (before.st_dev, before.st_ino):
            raise RecoveryError("file identity changed while opening: %s" % path)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                after = path.lstat()
                if (stat.S_ISLNK(after.st_mode) or after.st_nlink != 1 or
                        (after.st_dev, after.st_ino) != (details.st_dev, details.st_ino)):
                    raise RecoveryError("file identity changed while hashing: %s" % path)
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _verified_module_bytes(path: Path, expected: Dict[str, Any]) -> bytes:
    """Read one constant-named v3 recovery module without ambient fallback."""
    if not isinstance(expected, dict):
        raise RecoveryError("native recovery module identity must be an object")
    exact_keys(
        expected,
        ("name", "sha256", "size", "mode", "owner_uid"),
        "native recovery module identity",
    )
    if path.name != expected["name"] or path.name not in NATIVE_RECOVERY_MODULES:
        raise RecoveryError("native recovery module name is not fixed")
    checked_hash(expected["sha256"], "native recovery module sha256")
    expected_size = exact_int(expected["size"], "native recovery module size")
    if expected_size > MAX_METADATA_BYTES:
        raise RecoveryError("native recovery module exceeds the metadata limit")
    if expected["mode"] != 0o600 or expected["owner_uid"] != os.getuid():
        raise RecoveryError("native recovery module owner or mode is unsupported")
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != expected["mode"]
        or before.st_uid != expected["owner_uid"]
        or before.st_size != expected_size
    ):
        raise RecoveryError("native recovery module filesystem identity differs")
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or (details.st_dev, details.st_ino) != (before.st_dev, before.st_ino)
            or stat.S_IMODE(details.st_mode) != expected["mode"]
            or details.st_uid != expected["owner_uid"]
            or details.st_size != expected_size
        ):
            raise RecoveryError("native recovery module changed while opening")
        data = bytearray()
        while len(data) <= MAX_METADATA_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_METADATA_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) != expected_size or len(data) > MAX_METADATA_BYTES:
        raise RecoveryError("native recovery module size differs")
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
    ):
        raise RecoveryError("native recovery module changed while reading")
    if sha256_bytes(bytes(data)) != expected["sha256"]:
        raise RecoveryError("native recovery module digest differs")
    return bytes(data)


def _verified_native_recovery_sources(
    directory: Path, manifest: Dict[str, Any]
) -> Dict[str, bytes]:
    """Read and verify the closed native-v3 module set without executing it."""
    if not isinstance(manifest, dict):
        raise RecoveryError("native recovery closure must be an object")
    exact_keys(
        manifest,
        ("format", "implementation_identity_sha256", "modules"),
        "native recovery closure",
    )
    if exact_int(manifest["format"], "native recovery closure format", 1) != 1:
        raise RecoveryError("unsupported native recovery closure format")
    checked_hash(
        manifest["implementation_identity_sha256"],
        "native implementation identity sha256",
    )
    modules = manifest["modules"]
    if not isinstance(modules, list) or [item.get("name") for item in modules] != list(
        NATIVE_RECOVERY_MODULES
    ):
        raise RecoveryError("native recovery closure modules are not fixed")
    directory = Path(directory)
    details = directory.lstat()
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISDIR(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_uid != os.getuid()
    ):
        raise RecoveryError("native recovery closure directory is unsafe")
    return {
        item["name"]: _verified_module_bytes(directory / item["name"], item)
        for item in modules
    }


def _load_native_recovery_closure(directory: Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Execute only the already verified native-v3 closure bytes."""
    sources = _verified_native_recovery_sources(directory, manifest)
    loaded = {}
    prior_registration = sys.modules.get("council_registration")
    try:
        for filename, module_name in (
            ("council_registration.py", "council_registration"),
            (
                "council_registration_qualification.py",
                "council_registration_qualification",
            ),
        ):
            module = types.ModuleType(module_name)
            module.__file__ = str(directory / filename)
            module.__cached__ = None
            module.__package__ = None
            if module_name == "council_registration":
                sys.modules[module_name] = module
            exec(
                compile(
                    sources[filename],
                    str(directory / filename),
                    "exec",
                    dont_inherit=True,
                    optimize=sys.flags.optimize,
                ),
                module.__dict__,
            )
            loaded[filename] = module
    finally:
        if prior_registration is None:
            sys.modules.pop("council_registration", None)
        else:
            sys.modules["council_registration"] = prior_registration
    return loaded


def _no_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RecoveryError("duplicate JSON key: %s" % key)
        value[key] = item
    return value


def _invalid_constant(value: str) -> None:
    raise RecoveryError("non-finite JSON number: %s" % value)


def parse_json_bytes(data: bytes, label: str) -> Any:
    if len(data) > MAX_METADATA_BYTES:
        raise RecoveryError("%s exceeds the 1 MiB metadata limit" % label)
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise RecoveryError("invalid %s JSON: %s" % (label, error)) from error


def read_regular(path: Path, label: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RecoveryError("%s must be a single-linked regular file" % label)
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RecoveryError("%s must be a single-linked regular file" % label)
        if (details.st_dev, details.st_ino) != (before.st_dev, before.st_ino):
            raise RecoveryError("%s identity changed while opening" % label)
        if details.st_size > MAX_METADATA_BYTES:
            raise RecoveryError("%s exceeds the 1 MiB metadata limit" % label)
        chunks = []
        remaining = MAX_METADATA_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_METADATA_BYTES:
            raise RecoveryError("%s exceeds the 1 MiB metadata limit" % label)
        after = path.lstat()
        if (stat.S_ISLNK(after.st_mode) or after.st_nlink != 1 or
                (after.st_dev, after.st_ino) != (details.st_dev, details.st_ino)):
            raise RecoveryError("%s identity changed while reading" % label)
        return data
    finally:
        os.close(descriptor)


def read_object(path: Path, label: str) -> Tuple[Dict[str, Any], bytes]:
    data = read_regular(path, label)
    value = parse_json_bytes(data, label)
    if not isinstance(value, dict):
        raise RecoveryError("%s must be a JSON object" % label)
    return value, data


def exact_keys(value: Dict[str, Any], keys: Iterable[str], label: str) -> None:
    expected = set(keys)
    actual = set(value)
    if actual != expected:
        raise RecoveryError(
            "unexpected %s keys: %s" % (label, sorted(actual ^ expected)))


def exact_int(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise RecoveryError("%s must be an integer >= %d" % (label, minimum))
    return value


def bounded_text(value: Any, label: str, limit: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise RecoveryError("%s must be nonempty bounded text" % label)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise RecoveryError("%s is not valid UTF-8 text" % label) from error
    if len(encoded) > limit:
        raise RecoveryError("%s must be nonempty bounded text" % label)
    return value


def checked_id(value: Any, label: str) -> str:
    value = bounded_text(value, label, 96)
    if not re.fullmatch(ID_PATTERN, value):
        raise RecoveryError("%s has an unsupported identifier" % label)
    return value


def checked_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(HASH_PATTERN, value):
        raise RecoveryError("%s must be a lowercase SHA256" % label)
    return value


def checked_mode(value: Any, label: str) -> int:
    value = exact_int(value, label)
    if value > 0o777:
        raise RecoveryError("%s contains unsupported mode bits" % label)
    return value


def checked_relative(value: Any, label: str, allow_dot: bool = False) -> str:
    value = bounded_text(value, label)
    if "\\" in value or "\x00" in value or unicodedata.normalize("NFC", value) != value:
        raise RecoveryError("%s is not a normalized POSIX path" % label)
    path = PurePosixPath(value)
    parts = path.parts
    if path.is_absolute() or len(parts) > MAX_PATH_COMPONENTS:
        raise RecoveryError("%s is outside the supported path boundary" % label)
    if allow_dot and value == ".":
        return value
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise RecoveryError("%s contains an unsafe component" % label)
    if str(path) != value:
        raise RecoveryError("%s is not canonical" % label)
    return value


def checked_absolute(value: Any, label: str) -> Path:
    value = bounded_text(value, label)
    if "\x00" in value or "\\" in value or unicodedata.normalize("NFC", value) != value:
        raise RecoveryError("%s is not a normalized absolute path" % label)
    path = Path(value)
    if (not path.is_absolute() or str(path) != value or len(path.parts) > MAX_PATH_COMPONENTS
            or any(part in (".", "..") for part in path.parts)):
        raise RecoveryError("%s must be a canonical absolute path" % label)
    return path


def physical_identity(path: Path) -> Dict[str, int]:
    details = path.stat()
    return {"device": details.st_dev, "inode": details.st_ino}


def _stat_token(details: os.stat_result) -> Tuple[int, ...]:
    return (
        details.st_dev, details.st_ino, details.st_mode, details.st_nlink,
        details.st_size, details.st_mtime_ns, details.st_ctime_ns,
    )


def _entry_token(descriptor: int, name: str) -> Optional[Tuple[int, ...]]:
    try:
        return _stat_token(os.stat(name, dir_fd=descriptor, follow_symlinks=False))
    except FileNotFoundError:
        return None


def _entry_identity(descriptor: int, name: str) -> Optional[Tuple[int, int, int]]:
    try:
        details = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return details.st_dev, details.st_ino, details.st_mode


def _opened_directory(path: Path, label: str) -> Tuple[int, Dict[str, int]]:
    descriptor = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    details = os.fstat(descriptor)
    identity = {"device": details.st_dev, "inode": details.st_ino}
    if directory_identity(path, label) != identity:
        os.close(descriptor)
        raise RecoveryError("%s changed while opening" % label)
    return descriptor, identity


def _require_open_directory(path: Path, descriptor: int,
                            identity: Dict[str, int], label: str) -> None:
    details = os.fstat(descriptor)
    if ({"device": details.st_dev, "inode": details.st_ino} != identity or
            directory_identity(path, label) != identity):
        raise RecoveryError("%s changed before mutation" % label)


def _sync_open_directory(descriptor: int, failpoint: Failpoint, label: str) -> None:
    _event(failpoint, "before:fsync-directory:" + label)
    os.fsync(descriptor)
    _event(failpoint, "after:fsync-directory:" + label)


def directory_identity(path: Path, label: str) -> Dict[str, int]:
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise RecoveryError("%s must be a real directory" % label)
    return {"device": details.st_dev, "inode": details.st_ino}


def lock_path_identity(path: Path) -> Dict[str, int]:
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise RecoveryError("broker.lock must be a single-linked regular file")
    return {"device": details.st_dev, "inode": details.st_ino}


def validate_identity(value: Any, label: str) -> Dict[str, int]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(value, ("device", "inode"), label)
    return {
        "device": exact_int(value["device"], label + " device", 1),
        "inode": exact_int(value["inode"], label + " inode", 1),
    }


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        common = Path(os.path.commonpath((str(first), str(second))))
    except ValueError:
        return False
    return common == first or common == second


def validate_roots(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise RecoveryError("roots must be an object")
    exact_keys(value, ("state", "payload", "opencode"), "roots")
    paths = {name: checked_absolute(value[name], "root %s" % name) for name in value}
    for index, first in enumerate(paths.values()):
        for second in list(paths.values())[index + 1 :]:
            if _paths_overlap(first, second):
                raise RecoveryError("lifecycle roots must not overlap")
    return {name: str(path) for name, path in paths.items()}


def _validate_collision_free(paths: Iterable[str], label: str) -> None:
    seen = set()
    for path in paths:
        key = unicodedata.normalize("NFC", path).casefold()
        if key in seen:
            raise RecoveryError("%s contains a case/Unicode destination collision" % label)
        seen.add(key)


def _inventory_digest(artifacts: List[Dict[str, Any]]) -> str:
    return sha256_bytes(
        json.dumps(artifacts, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    )


def absent_state(kind: str) -> Dict[str, Any]:
    return {"exists": False, "kind": kind, "sha256": None, "mode": None, "artifacts": []}


def capture_state(path: Path, kind: str) -> Dict[str, Any]:
    if kind not in ("file", "directory"):
        raise RecoveryError("unsupported artifact kind")
    try:
        root = path.lstat()
    except FileNotFoundError:
        return absent_state(kind)
    if stat.S_ISLNK(root.st_mode):
        raise RecoveryError("artifact path is a symlink: %s" % path)
    if kind == "file":
        if not stat.S_ISREG(root.st_mode) or root.st_nlink != 1:
            raise RecoveryError("artifact is not a single-linked regular file: %s" % path)
        return {
            "exists": True,
            "kind": "file",
            "sha256": sha256_file(path),
            "mode": stat.S_IMODE(root.st_mode),
            "artifacts": [],
        }
    if not stat.S_ISDIR(root.st_mode):
        raise RecoveryError("artifact is not a directory: %s" % path)
    artifacts: List[Dict[str, Any]] = []
    stack = [path]
    while stack:
        parent = stack.pop()
        try:
            entries = sorted(os.scandir(parent), key=lambda entry: entry.name)
        except OSError as error:
            raise RecoveryError("cannot enumerate artifact directory: %s" % parent) from error
        for entry in entries:
            relative = entry.path[len(str(path)) + 1 :]
            checked_relative(relative, "artifact relative path")
            details = entry.stat(follow_symlinks=False)
            if entry.is_symlink():
                raise RecoveryError("artifact tree contains a symlink: %s" % entry.path)
            if stat.S_ISDIR(details.st_mode):
                artifacts.append(
                    {"path": relative, "kind": "directory", "sha256": None,
                     "mode": stat.S_IMODE(details.st_mode)}
                )
                stack.append(Path(entry.path))
            elif stat.S_ISREG(details.st_mode) and details.st_nlink == 1:
                artifacts.append(
                    {"path": relative, "kind": "file", "sha256": sha256_file(Path(entry.path)),
                     "mode": stat.S_IMODE(details.st_mode)}
                )
            else:
                raise RecoveryError("artifact tree contains a nonregular or hard-linked entry: %s" % entry.path)
            if len(artifacts) > MAX_ARTIFACTS:
                raise RecoveryError("artifact inventory exceeds its bound")
    artifacts.sort(key=lambda item: item["path"])
    _validate_collision_free((item["path"] for item in artifacts), "artifact inventory")
    return {
        "exists": True,
        "kind": "directory",
        "sha256": _inventory_digest(artifacts),
        "mode": stat.S_IMODE(root.st_mode),
        "artifacts": artifacts,
    }


def git_stop_state(path: Path) -> Optional[Dict[str, Any]]:
    """Report a real top-level ``.git`` entry from a bounded scan, without inventorying
    the tree. A README source clone commonly carries symlinks, hard links, or more
    entries than ``capture_state`` accepts, so the ownership stop has to be observable
    before the full inventory is attempted."""
    try:
        root = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    if stat.S_ISLNK(root.st_mode) or not stat.S_ISDIR(root.st_mode):
        return None
    try:
        details = (path / ".git").lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    if stat.S_ISLNK(details.st_mode):
        return None
    if stat.S_ISDIR(details.st_mode):
        kind = "directory"
    elif stat.S_ISREG(details.st_mode):
        kind = "file"
    else:
        return None
    return {
        "exists": True,
        "kind": "directory",
        "sha256": None,
        "mode": stat.S_IMODE(root.st_mode),
        "artifacts": [
            {"path": ".git", "kind": kind, "sha256": None,
             "mode": stat.S_IMODE(details.st_mode)}
        ],
    }


def validate_state(value: Any, label: str, kind: str, clean: bool = False) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(value, ("exists", "kind", "sha256", "mode", "artifacts"), label)
    if type(value["exists"]) is not bool or value["kind"] != kind or not isinstance(value["artifacts"], list):
        raise RecoveryError("%s has an invalid state shape" % label)
    if not value["exists"]:
        if value["sha256"] is not None or value["mode"] is not None or value["artifacts"]:
            raise RecoveryError("%s absent state contains artifact data" % label)
        return value
    checked_hash(value["sha256"], label + " sha256")
    mode = checked_mode(value["mode"], label + " mode")
    if kind == "file":
        if value["artifacts"]:
            raise RecoveryError("%s file state has a nested inventory" % label)
        if clean and mode != 0o644:
            raise RecoveryError("%s active file mode must be 0644" % label)
        return value
    paths = []
    for index, artifact in enumerate(value["artifacts"]):
        item_label = "%s artifact %d" % (label, index)
        if not isinstance(artifact, dict):
            raise RecoveryError("%s must be an object" % item_label)
        exact_keys(artifact, ("path", "kind", "sha256", "mode"), item_label)
        path = checked_relative(artifact["path"], item_label + " path")
        paths.append(path)
        if PurePosixPath(path).parts[0] == ".git":
            raise RecoveryError("%s contains a source clone ownership stop" % label)
        if artifact["kind"] not in ("file", "directory"):
            raise RecoveryError("%s has an invalid kind" % item_label)
        artifact_mode = checked_mode(artifact["mode"], item_label + " mode")
        if artifact["kind"] == "file":
            checked_hash(artifact["sha256"], item_label + " sha256")
            if clean and (artifact_mode != 0o644 or "__pycache__" in PurePosixPath(path).parts
                          or path.endswith((".pyc", ".pyo"))):
                raise RecoveryError("%s contains an active cache or nondeterministic mode" % label)
        elif artifact["sha256"] is not None:
            raise RecoveryError("%s directory has a content hash" % item_label)
        elif clean and artifact_mode != 0o700:
            raise RecoveryError("%s active directory mode must be 0700" % label)
    if len(paths) > MAX_ARTIFACTS:
        raise RecoveryError("%s exceeds the artifact limit" % label)
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise RecoveryError("%s inventory must be sorted and unique" % label)
    _validate_collision_free(paths, label)
    if value["sha256"] != _inventory_digest(value["artifacts"]):
        raise RecoveryError("%s inventory digest mismatch" % label)
    if clean and mode != 0o700:
        raise RecoveryError("%s active payload mode must be 0700" % label)
    return value


def state_matches(path: Path, expected: Dict[str, Any]) -> bool:
    try:
        return capture_state(path, expected["kind"]) == expected
    except (RecoveryError, OSError):
        return False


def _unit_destination(roots: Dict[str, str], unit_id: str) -> Path:
    if unit_id == "payload":
        return Path(roots["payload"])
    return Path(roots["opencode"]) / EXTERNAL_DESTINATIONS[unit_id]


def _unit_objects(destination: Path, transaction_id: str, unit_id: str) -> Dict[str, str]:
    prefix = ".council-lifecycle-%s-%s" % (transaction_id, unit_id)
    parent = destination.parent
    return {
        "target": str(parent / (prefix + "-target")),
        "prior": str(parent / (prefix + "-prior")),
        "backup": str(parent / (prefix + "-backup")),
        "stage": str(parent / (prefix + "-stage")),
        "partial": str(parent / (prefix + "-partial")),
        "displaced": str(parent / (prefix + "-displaced")),
    }


def validate_admission(value: Any, roots: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("admission must be an object")
    exact_keys(value, ("format", "namespace_version", "roots", "status", "transaction_id", "committed"), "admission")
    if (exact_int(value["format"], "admission format", 1) != ADMISSION_FORMAT or
            exact_int(value["namespace_version"], "admission namespace_version", 1) != NAMESPACE_VERSION):
        raise RecoveryError("unsupported admission format")
    parsed_roots = validate_roots(value["roots"])
    if roots is not None and parsed_roots != roots:
        raise RecoveryError("admission roots differ from the plan")
    status_value = value["status"]
    if status_value not in ("committed", "recovery_required", "uninstalled"):
        raise RecoveryError("unsupported admission status")
    if status_value == "recovery_required":
        checked_id(value["transaction_id"], "admission transaction_id")
    elif value["transaction_id"] is not None:
        raise RecoveryError("terminal admission must not name an active transaction")
    committed = value["committed"]
    if committed is not None:
        if not isinstance(committed, dict):
            raise RecoveryError("committed summary must be an object or null")
        exact_keys(committed, ("receipt_id", "receipt_sha256", "package_id", "runtime_cohort"), "committed summary")
        checked_id(committed["receipt_id"], "committed receipt_id")
        for name in ("receipt_sha256", "package_id", "runtime_cohort"):
            checked_hash(committed[name], "committed %s" % name)
    if status_value == "committed" and committed is None:
        raise RecoveryError("committed admission requires a receipt summary")
    return value


def validate_reader_support(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("reader_support must be an object")
    exact_keys(
        value,
        ("source_sha256", "package_id", "runtime_cohort",
         "import_closure_sha256", "fixture_corpus_sha256", "features", "state_reader",
         "managed_writer_admission", "external_recoverer", "formats"),
        "reader_support",
    )
    for name in ("source_sha256", "package_id", "runtime_cohort",
                 "import_closure_sha256", "fixture_corpus_sha256"):
        checked_hash(value[name], "reader_support %s" % name)
    if not isinstance(value["features"], list) or not value["features"] or len(value["features"]) > 128:
        raise RecoveryError("reader_support features must be a bounded nonempty list")
    features = [bounded_text(item, "reader feature", 128) for item in value["features"]]
    if features != sorted(features) or len(features) != len(set(features)):
        raise RecoveryError("reader_support features must be sorted and unique")
    for name in ("state_reader", "managed_writer_admission", "external_recoverer"):
        if value[name] != "pass":
            raise RecoveryError("reader_support %s is not an accepted result" % name)
    formats = value["formats"]
    if not isinstance(formats, dict):
        raise RecoveryError("reader_support formats must be an object")
    exact_keys(formats, ("admission", "plan", "journal", "receipt", "recovery"), "reader_support formats")
    expected = {"admission": 1, "plan": 1, "journal": 1, "receipt": 1, "recovery": 1}
    if any(exact_int(formats[name], "reader_support %s format" % name, 1) != expected[name]
           for name in expected):
        raise RecoveryError("reader_support formats are unsupported")
    return value


def validate_release_manifest(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("source manifest must be an object")
    exact_keys(
        value,
        ("format", "package_id", "runtime_cohort", "runtime_sources", "artifacts",
         "opencode_sources"),
        "source manifest",
    )
    if exact_int(value["format"], "source manifest format", 1) != 1:
        raise RecoveryError("unsupported source manifest format")
    checked_hash(value["package_id"], "manifest package_id")
    checked_hash(value["runtime_cohort"], "manifest runtime_cohort")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, dict) or not artifacts or len(artifacts) > MAX_ARTIFACTS:
        raise RecoveryError("manifest artifacts must be a bounded object")
    paths = []
    for name, digest in artifacts.items():
        checked_relative(name, "manifest artifact")
        checked_hash(digest, "manifest artifact hash")
        paths.append(name)
    if paths != sorted(paths):
        raise RecoveryError("manifest artifacts must be sorted")
    _validate_collision_free(paths, "manifest artifacts")
    if value["opencode_sources"] != OPENCODE_SOURCES:
        raise RecoveryError("manifest OpenCode source mapping is unsupported")
    runtime_sources = value["runtime_sources"]
    if (not isinstance(runtime_sources, list) or not runtime_sources or
            len(runtime_sources) > MAX_ARTIFACTS):
        raise RecoveryError("manifest runtime_sources must be a bounded nonempty list")
    checked_sources = [checked_relative(item, "manifest runtime source") for item in runtime_sources]
    if len(checked_sources) != len(set(checked_sources)):
        raise RecoveryError("manifest runtime_sources must be unique")
    _validate_collision_free(checked_sources, "manifest runtime_sources")
    if any("payload/" + item not in artifacts for item in checked_sources):
        raise RecoveryError("manifest runtime source is absent from payload artifacts")
    external = {name for name in artifacts if name.startswith("opencode/")}
    if external != set(EXTERNAL_MANIFEST_PATHS.values()):
        raise RecoveryError("manifest must contain exactly four OpenCode artifacts")
    if not any(name.startswith("payload/") for name in artifacts):
        raise RecoveryError("manifest has no payload inventory")
    if "payload/release_manifest.json" in artifacts:
        raise RecoveryError("source manifest is provenance, not a payload member")
    return value


def _leaf_state(state_value: Dict[str, Any], relative: str) -> Dict[str, Any]:
    if relative == ".":
        return {"exists": state_value["exists"], "sha256": state_value["sha256"] if state_value["kind"] == "file" else None,
                "mode": state_value["mode"], "kind": state_value["kind"]}
    artifact = next((item for item in state_value["artifacts"] if item["path"] == relative), None)
    if artifact is None:
        return {"exists": False, "sha256": None, "mode": None, "kind": None}
    return {"exists": True, "sha256": artifact["sha256"], "mode": artifact["mode"], "kind": artifact["kind"]}


def _receipt_artifact_keys(units: List[Dict[str, Any]], goal: str = "target") -> List[Tuple[str, str]]:
    keys = []
    for unit in units:
        relatives = {"."}
        if unit["unit_id"] == "payload":
            relatives.update(item["path"] for item in unit["initial"]["artifacts"])
            relatives.update(item["path"] for item in unit[goal]["artifacts"])
        keys.extend((unit["unit_id"], relative) for relative in sorted(relatives))
    return keys


def _validate_leaf(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(value, ("exists", "sha256", "mode", "kind"), label)
    if type(value["exists"]) is not bool:
        raise RecoveryError("%s existence must be boolean" % label)
    if not value["exists"]:
        if value["sha256"] is not None or value["mode"] is not None or value["kind"] not in (None, "file", "directory"):
            raise RecoveryError("%s absent state is malformed" % label)
        return value
    if value["kind"] not in ("file", "directory"):
        raise RecoveryError("%s kind is invalid" % label)
    checked_mode(value["mode"], label + " mode")
    if value["kind"] == "file":
        checked_hash(value["sha256"], label + " sha256")
    elif value["sha256"] is not None:
        raise RecoveryError("%s directory must not have a file hash" % label)
    return value


def _validate_registration_receipt(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(
        value,
        (
            "operation_id", "operation", "runtime", "source_path",
            "resulting_sha256", "resulting_entry_sha256", "ownership_origin",
            "stored_config_result", "effective_scope", "host_restart",
            "authenticated_readiness",
        ),
        label,
    )
    checked_id(value["operation_id"], label + " operation_id")
    if value["operation"] not in REGISTRATION_OPERATIONS or value["runtime"] != "opencode":
        raise RecoveryError("%s operation/runtime is unsupported" % label)
    checked_absolute(value["source_path"], label + " source_path")
    checked_hash(value["resulting_sha256"], label + " resulting_sha256")
    if value["resulting_entry_sha256"] is not None:
        checked_hash(value["resulting_entry_sha256"], label + " resulting_entry_sha256")
    if value["ownership_origin"] not in REGISTRATION_OWNERSHIP:
        raise RecoveryError("%s ownership is unsupported" % label)
    if value["stored_config_result"] not in (
        "stored_config_verified", "stored_config_absent_verified"
    ):
        raise RecoveryError("%s stored result is unsupported" % label)
    if value["effective_scope"] != "unknown":
        raise RecoveryError("%s effective scope is overclaimed" % label)
    if value["host_restart"] != "required":
        raise RecoveryError("%s host restart result is unsupported" % label)
    if value["authenticated_readiness"] != "unobserved":
        raise RecoveryError("%s authenticated readiness is overclaimed" % label)
    return value


def _validate_native_closure_manifest(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(
        value,
        ("format", "implementation_identity_sha256", "modules"),
        label,
    )
    if exact_int(value["format"], label + " format", 1) != 1:
        raise RecoveryError("unsupported native recovery closure format")
    checked_hash(
        value["implementation_identity_sha256"],
        label + " implementation identity sha256",
    )
    modules = value["modules"]
    if not isinstance(modules, list) or len(modules) != len(NATIVE_RECOVERY_MODULES):
        raise RecoveryError("%s module count is invalid" % label)
    for index, item in enumerate(modules):
        item_label = "%s module %d" % (label, index)
        if not isinstance(item, dict):
            raise RecoveryError("%s must be an object" % item_label)
        exact_keys(item, ("name", "sha256", "size", "mode", "owner_uid"), item_label)
        if item["name"] != NATIVE_RECOVERY_MODULES[index]:
            raise RecoveryError("%s module order is not fixed" % label)
        checked_hash(item["sha256"], item_label + " sha256")
        if exact_int(item["size"], item_label + " size") > MAX_METADATA_BYTES:
            raise RecoveryError("%s exceeds the metadata limit" % item_label)
        if item["mode"] != 0o600 or item["owner_uid"] != os.getuid():
            raise RecoveryError("%s owner or mode is invalid" % item_label)
    return value


def _validate_native_receipt(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(
        value,
        (
            "operation_id",
            "operation",
            "runtime",
            "source_path",
            "source_scope",
            "semantic_result_identity",
            "attempt_family",
            "runtime_tuple",
            "qualification_admission_sha256",
            "implementation_identity_sha256",
            "stored_config_result",
            "effective_scope",
            "host_restart",
            "authenticated_readiness",
        ),
        label,
    )
    checked_id(value["operation_id"], label + " operation_id")
    operation = value["operation"]
    runtime = value["runtime"]
    if operation not in NATIVE_OPERATIONS or runtime not in ("claude", "codex"):
        raise RecoveryError("%s operation/runtime is unsupported" % label)
    if not operation.startswith(runtime + "_"):
        raise RecoveryError("%s operation/runtime differs" % label)
    checked_absolute(value["source_path"], label + " source_path")
    expected_scope = "claude_user" if runtime == "claude" else "codex_user"
    if value["source_scope"] != expected_scope:
        raise RecoveryError("%s source scope is unsupported" % label)
    result = value["semantic_result_identity"]
    if not isinstance(result, dict):
        raise RecoveryError("%s semantic result identity must be an object" % label)
    exact_keys(result, ("record", "sha256"), label + " semantic result identity")
    if not isinstance(result["record"], dict):
        raise RecoveryError("%s semantic result record must be an object" % label)
    checked_hash(result["sha256"], label + " semantic result sha256")
    if sha256_bytes(
        json.dumps(result["record"], sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ) != result["sha256"]:
        raise RecoveryError("%s semantic result digest differs" % label)
    _validate_digest_record(value["attempt_family"], label + " attempt family")
    _validate_digest_record(value["runtime_tuple"], label + " runtime tuple")
    for name in (
        "qualification_admission_sha256",
        "implementation_identity_sha256",
    ):
        checked_hash(value[name], label + " " + name)
    if value["stored_config_result"] not in (
        "stored_config_verified",
        "stored_config_absent_verified",
    ):
        raise RecoveryError("%s stored result is unsupported" % label)
    if value["effective_scope"] != "unknown":
        raise RecoveryError("%s effective scope is overclaimed" % label)
    if value["host_restart"] != "required":
        raise RecoveryError("%s host restart result is unsupported" % label)
    if value["authenticated_readiness"] != "unobserved":
        raise RecoveryError("%s authenticated readiness is overclaimed" % label)
    return value


def validate_receipt_shape(value: Any, label: str = "receipt") -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    receipt_format = exact_int(value.get("receipt_format"), label + " format", 1)
    keys = (
        "receipt_format", "receipt_id", "transaction_id", "outcome", "roots",
        "root_identities", "lock_identity", "package_id", "runtime_cohort",
        "source_manifest_sha256", "prior_receipt", "recovery",
        "reader_support_sha256", "artifacts",
    )
    if receipt_format == REGISTRATION_RECEIPT_FORMAT:
        keys = keys + ("registration_format", "registrations")
    elif receipt_format == NATIVE_RECEIPT_FORMAT:
        keys = keys + (
            "native_registration_format",
            "native_registrations",
            "native_closure",
        )
    elif receipt_format != RECEIPT_FORMAT:
        raise RecoveryError("unsupported receipt format")
    exact_keys(value, keys, label)
    checked_id(value["receipt_id"], label + " receipt_id")
    checked_id(value["transaction_id"], label + " transaction_id")
    if value["outcome"] not in ("committed", "uninstalled"):
        raise RecoveryError("%s outcome is unsupported" % label)
    validate_roots(value["roots"])
    root_identities = value["root_identities"]
    if not isinstance(root_identities, dict):
        raise RecoveryError("%s root_identities must be an object" % label)
    exact_keys(root_identities, ("state", "payload_parent", "opencode"), label + " root_identities")
    for name in root_identities:
        validate_identity(root_identities[name], "%s %s identity" % (label, name))
    validate_identity(value["lock_identity"], label + " lock_identity")
    for name in ("package_id", "runtime_cohort", "source_manifest_sha256", "reader_support_sha256"):
        checked_hash(value[name], "%s %s" % (label, name))
    prior = value["prior_receipt"]
    if prior is not None:
        if not isinstance(prior, dict):
            raise RecoveryError("%s prior_receipt must be an object or null" % label)
        exact_keys(prior, ("receipt_id", "receipt_sha256"), label + " prior_receipt")
        checked_id(prior["receipt_id"], label + " prior receipt_id")
        checked_hash(prior["receipt_sha256"], label + " prior receipt_sha256")
    recovery = value["recovery"]
    if not isinstance(recovery, dict):
        raise RecoveryError("%s recovery must be an object" % label)
    recovery_keys = ("format", "tool_sha256")
    if receipt_format == NATIVE_RECEIPT_FORMAT:
        recovery_keys = recovery_keys + ("native_closure_sha256",)
    exact_keys(recovery, recovery_keys, label + " recovery")
    expected_recovery = (
        REGISTRATION_RECOVERY_FORMAT
        if receipt_format == REGISTRATION_RECEIPT_FORMAT
        else NATIVE_RECOVERY_FORMAT
        if receipt_format == NATIVE_RECEIPT_FORMAT
        else RECOVERY_FORMAT
    )
    if exact_int(recovery["format"], label + " recovery format", 1) != expected_recovery:
        raise RecoveryError("%s recovery format is unsupported" % label)
    checked_hash(recovery["tool_sha256"], label + " recovery tool_sha256")
    if receipt_format == NATIVE_RECEIPT_FORMAT:
        checked_hash(
            recovery["native_closure_sha256"],
            label + " recovery native closure sha256",
        )
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) > MAX_ARTIFACTS:
        raise RecoveryError("%s artifacts must be a bounded list" % label)
    seen = []
    unit_order = {unit_id: index for index, unit_id in enumerate(UNIT_IDS)}
    for index, artifact in enumerate(artifacts):
        item_label = "%s artifact %d" % (label, index)
        if not isinstance(artifact, dict):
            raise RecoveryError("%s must be an object" % item_label)
        exact_keys(artifact, ("unit_id", "path", "destination", "prior", "intended", "ownership", "local_change"), item_label)
        if artifact["unit_id"] not in UNIT_IDS:
            raise RecoveryError("%s has an unknown unit" % item_label)
        relative = checked_relative(artifact["path"], item_label + " path", allow_dot=True)
        checked_absolute(artifact["destination"], item_label + " destination")
        _validate_leaf(artifact["prior"], item_label + " prior")
        _validate_leaf(artifact["intended"], item_label + " intended")
        if artifact["ownership"] not in OWNERSHIP or artifact["local_change"] != "none":
            raise RecoveryError("%s has unsupported ownership/local-change disposition" % item_label)
        if artifact["ownership"] == "absent" and (
            artifact["prior"]["exists"] or artifact["intended"]["exists"]
        ):
            raise RecoveryError("%s absent disposition contains an artifact" % item_label)
        if artifact["ownership"] == "created" and (
            artifact["prior"]["exists"] or not artifact["intended"]["exists"]
        ):
            raise RecoveryError("%s created disposition is inconsistent" % item_label)
        seen.append((unit_order[artifact["unit_id"]], relative))
    if seen != sorted(seen) or len(seen) != len(set(seen)):
        raise RecoveryError("%s artifacts must be in fixed unique order" % label)
    _validate_collision_free(
        ("%d/%s" % item for item in seen), label + " artifacts"
    )
    if receipt_format == REGISTRATION_RECEIPT_FORMAT:
        if exact_int(value["registration_format"], label + " registration format", 1) != REGISTRATION_EXTENSION_FORMAT:
            raise RecoveryError("unsupported registration receipt format")
        registrations = value["registrations"]
        if not isinstance(registrations, list) or not registrations:
            raise RecoveryError("registration receipt must contain operations")
        ids = []
        for index, registration in enumerate(registrations):
            registration = _validate_registration_receipt(
                registration, "%s registration %d" % (label, index)
            )
            ids.append(registration["operation_id"])
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise RecoveryError("receipt registrations must be sorted and unique")
    elif receipt_format == NATIVE_RECEIPT_FORMAT:
        if exact_int(
            value["native_registration_format"],
            label + " native registration format",
            1,
        ) != NATIVE_EXTENSION_FORMAT:
            raise RecoveryError("unsupported native registration receipt format")
        closure = _validate_native_closure_manifest(
            value["native_closure"], label + " native closure"
        )
        if sha256_bytes(json_bytes(closure)) != recovery["native_closure_sha256"]:
            raise RecoveryError("receipt native closure digest differs")
        registrations = value["native_registrations"]
        if not isinstance(registrations, list) or not registrations:
            raise RecoveryError("native receipt must contain operations")
        ids = []
        for index, registration in enumerate(registrations):
            registration = _validate_native_receipt(
                registration, "%s native registration %d" % (label, index)
            )
            if (
                registration["implementation_identity_sha256"]
                != closure["implementation_identity_sha256"]
            ):
                raise RecoveryError("native receipt implementation identity differs")
            ids.append(registration["operation_id"])
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise RecoveryError("native receipt registrations must be sorted and unique")
    return value


def _native_receipt_has_only_absent_entries(receipt: Dict[str, Any]) -> bool:
    if receipt.get("receipt_format") != NATIVE_RECEIPT_FORMAT:
        return False
    registrations = receipt.get("native_registrations")
    return bool(registrations) and all(
        item.get("semantic_result_identity", {}).get("record", {}).get(
            "intended_state"
        ) == "absent"
        for item in registrations
    )


def _receipt_provenance_paths(state_root: Path, receipt_id: str) -> Tuple[Path, Path]:
    receipts = state_root / ".council-lifecycle/v1/receipts"
    return (
        receipts / (receipt_id + ".manifest.json"),
        receipts / (receipt_id + ".reader-support.json"),
    )


def _receipt_unit_states(receipt: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    roots = validate_roots(receipt["roots"])
    grouped = {unit_id: [] for unit_id in UNIT_IDS}
    for artifact in receipt["artifacts"]:
        grouped[artifact["unit_id"]].append(artifact)
    states = {}
    for unit_id in UNIT_IDS:
        records = grouped[unit_id]
        roots_found = [item for item in records if item["path"] == "."]
        if len(roots_found) != 1:
            raise RecoveryError("terminal receipt must contain one root record per unit")
        destination = _unit_destination(roots, unit_id)
        for item in records:
            expected_destination = destination if item["path"] == "." else destination / item["path"]
            if item["destination"] != str(expected_destination):
                raise RecoveryError("terminal receipt artifact escapes its fixed unit")
            if item["ownership"] == "matching_preexisting_unowned":
                if unit_id == "payload" or item["prior"] != item["intended"] or not item["intended"]["exists"]:
                    raise RecoveryError("terminal receipt has invalid unowned preservation")
            elif receipt["outcome"] == "uninstalled" and item["intended"]["exists"]:
                raise RecoveryError("uninstalled receipt retains an owned artifact")
        root = roots_found[0]["intended"]
        kind = "directory" if unit_id == "payload" else "file"
        if root["kind"] not in (kind, None):
            raise RecoveryError("terminal receipt unit kind is invalid")
        if unit_id != "payload":
            if len(records) != 1:
                raise RecoveryError("external terminal unit must have one artifact record")
            states[unit_id] = (
                {"exists": True, "kind": "file", "sha256": root["sha256"],
                 "mode": root["mode"], "artifacts": []}
                if root["exists"] else absent_state("file")
            )
            continue
        if not root["exists"]:
            if any(item["intended"]["exists"] for item in records[1:]):
                raise RecoveryError("absent payload receipt contains present children")
            states[unit_id] = absent_state("directory")
            continue
        artifacts = []
        for item in records:
            if item["path"] == "." or not item["intended"]["exists"]:
                continue
            leaf = item["intended"]
            artifacts.append(
                {"path": item["path"], "kind": leaf["kind"],
                 "sha256": leaf["sha256"], "mode": leaf["mode"]}
            )
        artifacts.sort(key=lambda item: item["path"])
        states[unit_id] = {
            "exists": True,
            "kind": "directory",
            "sha256": _inventory_digest(artifacts),
            "mode": root["mode"],
            "artifacts": artifacts,
        }
        validate_state(states[unit_id], "terminal payload", "directory", clean=True)
    return states


def _payload_without_known_caches(state_value: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    caches = []
    artifacts = []
    for item in state_value["artifacts"]:
        if "__pycache__" in PurePosixPath(item["path"]).parts:
            if item["kind"] == "file" and not item["path"].endswith((".pyc", ".pyo")):
                raise RecoveryError("payload cache contains an unknown file type")
            caches.append(item)
        else:
            artifacts.append(item)
    cleaned = {
        "exists": state_value["exists"],
        "kind": state_value["kind"],
        "sha256": _inventory_digest(artifacts) if state_value["exists"] else None,
        "mode": state_value["mode"],
        "artifacts": artifacts,
    }
    return cleaned, caches


def _terminal_states_match(roots: Dict[str, str], states: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    actual_payload = capture_state(Path(roots["payload"]), "directory")
    clean_payload, caches = _payload_without_known_caches(actual_payload)
    if clean_payload != states["payload"]:
        raise RecoveryError("terminal artifact set is not coherent: payload")
    for unit_id in UNIT_IDS[1:]:
        if not state_matches(_unit_destination(roots, unit_id), states[unit_id]):
            raise RecoveryError("terminal artifact set is not coherent: %s" % unit_id)
    return caches


def _validate_receipt_provenance(state_root: Path, receipt: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    receipt_id = receipt["receipt_id"]
    manifest_path, support_path = _receipt_provenance_paths(state_root, receipt_id)
    manifest, manifest_data = read_object(manifest_path, "terminal source manifest")
    support, support_data = read_object(support_path, "terminal reader support")
    if sha256_bytes(manifest_data) != receipt["source_manifest_sha256"]:
        raise RecoveryError("terminal source manifest digest mismatch")
    if sha256_bytes(support_data) != receipt["reader_support_sha256"]:
        raise RecoveryError("terminal reader support digest mismatch")
    manifest = validate_release_manifest(manifest)
    support = validate_reader_support(support)
    if (manifest["package_id"] != receipt["package_id"] or
            manifest["runtime_cohort"] != receipt["runtime_cohort"] or
            support["package_id"] != receipt["package_id"] or
            support["runtime_cohort"] != receipt["runtime_cohort"]):
        raise RecoveryError("terminal provenance identity differs from receipt")
    tool_path = state_root / ".council-lifecycle/v1/recovery" / (
        receipt["recovery"]["tool_sha256"] + ".py"
    )
    if sha256_file(tool_path) != receipt["recovery"]["tool_sha256"]:
        raise RecoveryError("terminal recovery tool digest mismatch")
    return manifest, support


def _identity_binding_path(state_root: Path) -> Path:
    return state_root / ".council-lifecycle/v1/identity-binding.json"


def validate_identity_binding(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("identity binding must be an object")
    exact_keys(
        value,
        ("format", "receipt_id", "receipt_sha256", "root_identities", "lock_identity"),
        "identity binding",
    )
    if exact_int(value["format"], "identity binding format", 1) != IDENTITY_BINDING_FORMAT:
        raise RecoveryError("unsupported identity binding record")
    checked_id(value["receipt_id"], "identity binding receipt_id")
    checked_hash(value["receipt_sha256"], "identity binding receipt_sha256")
    identities = value["root_identities"]
    if not isinstance(identities, dict):
        raise RecoveryError("identity binding root_identities must be an object")
    exact_keys(
        identities, ("state", "payload_parent", "opencode"),
        "identity binding root_identities",
    )
    for name in identities:
        validate_identity(identities[name], "identity binding %s identity" % name)
    validate_identity(value["lock_identity"], "identity binding lock_identity")
    return value


def authorized_identities(state_root: Path, receipt_id: str, receipt_sha256: str,
                          own_roots: Dict[str, Any],
                          own_lock: Dict[str, int]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Identities certified for the terminal receipt named by receipt_id/sha256. A
    receipt binds (device, inode) for the three fixed roots and broker.lock, which a
    remount, a restore, or a cleared stale lock changes without touching one byte of
    the installation. The operator re-binds those fields with ``rebind``; the record
    names the receipt it was verified against, so it never carries over to a later
    transaction. Falls back to the caller's own recorded identities."""
    own = (own_roots, own_lock)
    try:
        value, _data = read_object(_identity_binding_path(state_root), "identity binding")
        value = validate_identity_binding(value)
    except (RecoveryError, OSError):
        return own
    if value["receipt_id"] != receipt_id or value["receipt_sha256"] != receipt_sha256:
        # A record left behind by an earlier receipt grants nothing; the receipt now
        # in force records its own identities, so the binding can never wedge.
        return own
    return value["root_identities"], value["lock_identity"]


def _verify_terminal_receipt(state_root: Path, summary: Dict[str, Any], *,
                             bind_identities: bool = True) -> Dict[str, Any]:
    receipt_id = summary["receipt_id"]
    receipt_path = state_root / ".council-lifecycle/v1/receipts" / (receipt_id + ".json")
    receipt, receipt_data = read_object(receipt_path, "terminal receipt")
    validate_receipt_shape(receipt, "terminal receipt")
    if sha256_bytes(receipt_data) != summary["receipt_sha256"]:
        raise RecoveryError("terminal receipt digest mismatch")
    if (receipt["receipt_id"] != receipt_id or receipt["package_id"] != summary["package_id"]
            or receipt["runtime_cohort"] != summary["runtime_cohort"]):
        raise RecoveryError("terminal receipt summary mismatch")
    roots = validate_roots(receipt["roots"])
    if roots["state"] != str(state_root):
        raise RecoveryError("terminal receipt belongs to another state root")
    actual_identities = {
        "state": directory_identity(state_root, "state root"),
        "payload_parent": directory_identity(Path(roots["payload"]).parent, "payload parent"),
        "opencode": directory_identity(Path(roots["opencode"]), "OpenCode root"),
    }
    actual_lock = lock_path_identity(state_root / "broker.lock")
    if bind_identities:
        expected_roots, expected_lock = authorized_identities(
            state_root, receipt["receipt_id"], summary["receipt_sha256"],
            receipt["root_identities"], receipt["lock_identity"],
        )
        if actual_identities != expected_roots:
            raise RecoveryError("terminal receipt root identity changed")
        if actual_lock != expected_lock:
            raise RecoveryError("terminal receipt broker.lock identity changed")
    manifest, _support = _validate_receipt_provenance(state_root, receipt)
    states = _receipt_unit_states(receipt)
    _terminal_states_match(roots, states)
    if receipt["outcome"] == "committed":
        payload_files = {
            "payload/" + item["path"]: item["sha256"]
            for item in states["payload"]["artifacts"]
            if item["kind"] == "file"
        }
        manifest_payload = {
            name: value for name, value in manifest["artifacts"].items()
            if name.startswith("payload/")
        }
        if payload_files != manifest_payload:
            raise RecoveryError("terminal payload differs from source manifest")
        for unit_id, manifest_name in EXTERNAL_MANIFEST_PATHS.items():
            if (not states[unit_id]["exists"] or
                    states[unit_id]["sha256"] != manifest["artifacts"][manifest_name]):
                raise RecoveryError("terminal external artifact differs from source manifest")
    if receipt["receipt_format"] == REGISTRATION_RECEIPT_FORMAT:
        for registration in receipt["registrations"]:
            _verify_terminal_registration(registration)
    elif receipt["receipt_format"] == NATIVE_RECEIPT_FORMAT:
        closure = receipt["native_closure"]
        directory = (
            state_root
            / ".council-lifecycle/v1/recovery/native-v3"
            / closure["implementation_identity_sha256"]
        )
        modules = _load_native_recovery_closure(directory, closure)
        for native_registration in receipt["native_registrations"]:
            _verify_terminal_native_registration(native_registration, modules)
    return receipt


def _verify_terminal_registration(registration: Dict[str, Any]) -> None:
    path = Path(registration["source_path"])
    data = read_regular(path, "terminal registration config")
    value = parse_json_bytes(data, "terminal registration config")
    if not isinstance(value, dict):
        raise RecoveryError("terminal OpenCode config must be an object")
    plugin = value.get("plugin", [])
    if not isinstance(plugin, list):
        raise RecoveryError("terminal OpenCode plugin setting is invalid")
    exact = []
    aliases = []
    for item in plugin:
        options_tuple = (
            isinstance(item, list)
            and len(item) == 2
            and isinstance(item[0], str)
            and isinstance(item[1], dict)
        )
        selected = item[0] if options_tuple else item
        if not isinstance(selected, str):
            raise RecoveryError("terminal OpenCode plugin member is invalid")
        normalized = posixpath.normpath(selected)
        if selected == "./council-plugin.ts" and not options_tuple:
            exact.append(selected)
        elif posixpath.basename(normalized) == "council-plugin.ts":
            aliases.append(selected)
    expected = registration["resulting_entry_sha256"]
    if expected is None:
        if exact or aliases:
            raise RecoveryError("terminal unregistered config contains a Council identity")
        return
    marker = b'"./council-plugin.ts"'
    if len(exact) != 1 or aliases or data.count(marker) != 1:
        raise RecoveryError("terminal owned Council registration is ambiguous or changed")
    if sha256_bytes(marker) != expected:
        raise RecoveryError("terminal owned Council registration representation changed")


def _verify_terminal_native_registration(
    value: Dict[str, Any], modules: Dict[str, Any]
) -> None:
    registration = modules["council_registration.py"]
    qualification = modules["council_registration_qualification.py"]
    family_value = dict(value["attempt_family"]["record"])
    for name in ("argv", "write_set", "environment_keys"):
        family_value[name] = tuple(family_value[name])
    family = qualification.NativeAttemptFamilyIdentity(**family_value)
    if family.digest() != value["attempt_family"]["sha256"]:
        raise RecoveryError("terminal native attempt family differs")
    semantic = qualification.SemanticNativeResultIdentity(
        **value["semantic_result_identity"]["record"]
    )
    runtime_tuple = qualification.RuntimeTuple(**value["runtime_tuple"]["record"])
    if (
        semantic.digest() != value["semantic_result_identity"]["sha256"]
        or semantic.attempt_family_sha256 != family.digest()
        or family.qualification_admission_sha256
        != value["qualification_admission_sha256"]
        or family.implementation_sha256
        != value["implementation_identity_sha256"]
        or runtime_tuple.digest() != value["runtime_tuple"]["sha256"]
        or runtime_tuple.digest() != family.runtime_tuple_sha256
    ):
        raise RecoveryError("terminal native semantic identity differs")
    path = Path(family.source_path)
    data = read_regular(path, "terminal native registration config")
    document = registration.ConfigDocument(
        family.source_path, family.source_scope, data
    )
    stdio = registration.StdioSpec(
        family.python_executable, family.adapter_path
    )
    observation = (
        registration.observe_claude_config(
            document, stdio, scope_inputs_complete=True
        )
        if family.runtime == "claude"
        else registration.observe_codex_config(
            document, stdio, layer_inputs_complete=True
        )
    )
    if (
        observation.state != semantic.intended_state
        or observation.entry_sha256 != semantic.intended_entry_sha256
        or observation.complement_sha256 != semantic.expected_complement_sha256
        or _native_source_identity(path) != family.source_identity_sha256
        or not _native_runtime_matches(runtime_tuple)
    ):
        raise RecoveryError("terminal native registration differs")


def inspect_terminal_ownership(state_root: Path, payload_root: Path,
                               opencode_root: Path) -> Dict[str, Any]:
    """Read-only receipt-backed ownership view; final execution still revalidates under lease."""
    state_root = Path(state_root).resolve(strict=True)
    opencode_root = Path(opencode_root).resolve(strict=True)
    payload_input = Path(payload_root)
    payload_parent = payload_input.parent.resolve(strict=True)
    payload_root = payload_parent / payload_input.name
    if payload_root.is_symlink():
        raise RecoveryError("payload root must not be a symlink")
    roots = validate_roots(
        {"state": str(state_root), "payload": str(payload_root), "opencode": str(opencode_root)}
    )
    lifecycle = state_root / ".council-lifecycle"
    if not lifecycle.exists() and not lifecycle.is_symlink():
        return {
            "status": "legacy_unmanaged",
            "certified": False,
            "reason": "lifecycle namespace is absent",
            "roots": roots,
            "summary": None,
            "receipt": None,
            "payload_cache": [],
        }
    if lifecycle.is_symlink() or not lifecycle.is_dir():
        raise RecoveryError("lifecycle namespace must be a real directory")
    admission_path = lifecycle / "admission.json"
    admission, admission_data = read_object(admission_path, "admission")
    admission = validate_admission(admission, roots)
    if admission["status"] == "recovery_required":
        raise RecoveryError("ownership planning is blocked while recovery is required")
    summary = admission["committed"]
    if summary is None:
        return {
            "status": admission["status"],
            "certified": False,
            "reason": "terminal lifecycle marker has no certifying ownership receipt",
            "roots": roots,
            "summary": None,
            "receipt": None,
            "payload_cache": [],
        }
    try:
        receipt = _verify_terminal_receipt(state_root, summary)
        if receipt["outcome"] != admission["status"]:
            raise RecoveryError("terminal receipt outcome differs from admission status")
        states = _receipt_unit_states(receipt)
        caches = _terminal_states_match(roots, states)
    except (RecoveryError, OSError) as error:
        # Inspection reports what it found; it does not refuse. Every drift the
        # blocker list documents - a changed, missing, or extra artifact, or a
        # re-created root or lock - leaves the installation uncertified, and
        # planning then records its blocker. Mutation stays strict: an uncertified
        # installation is ineligible for every operation.
        return {
            "status": admission["status"],
            "certified": False,
            "reason": "terminal ownership is not certified: %s" % error,
            "roots": roots,
            "summary": summary,
            "receipt": None,
            "payload_cache": [],
        }
    current, current_data = read_object(admission_path, "admission")
    if current_data != admission_data or validate_admission(current, roots) != admission:
        raise RecoveryError("admission changed during ownership inspection")
    return {
        "status": admission["status"],
        "certified": True,
        "reason": None,
        "roots": roots,
        "summary": summary,
        "receipt": receipt,
        "payload_cache": caches,
    }


def rebind_terminal_identity(state_root: Path, payload_root: Path,
                             opencode_root: Path) -> Dict[str, Any]:
    """Re-certify an otherwise byte-identical managed installation whose fixed roots
    or broker.lock were re-created. Only the volatile (device, inode) fields are
    re-bound, and only once everything a certification checks - receipt digest,
    provenance, recovery tool, and every artifact - still verifies unchanged."""
    _validate_compatible_python()
    state_root = Path(state_root).resolve(strict=True)
    opencode_root = Path(opencode_root).resolve(strict=True)
    payload_input = Path(payload_root)
    payload_root = payload_input.parent.resolve(strict=True) / payload_input.name
    if payload_root.is_symlink():
        raise RecoveryError("payload root must not be a symlink")
    roots = validate_roots(
        {"state": str(state_root), "payload": str(payload_root), "opencode": str(opencode_root)}
    )
    lifecycle = state_root / ".council-lifecycle"
    if lifecycle.is_symlink() or not lifecycle.is_dir():
        raise RecoveryError("lifecycle namespace must be a real directory")
    admission, _admission_data = read_object(lifecycle / "admission.json", "admission")
    admission = validate_admission(admission, roots)
    summary = admission["committed"]
    if summary is None:
        raise RecoveryError("identity re-bind requires a certifying terminal receipt")
    receipt = _verify_terminal_receipt(state_root, summary, bind_identities=False)
    if receipt["outcome"] != admission["status"]:
        raise RecoveryError("terminal receipt outcome differs from admission status")
    binding = {
        "format": IDENTITY_BINDING_FORMAT,
        "receipt_id": receipt["receipt_id"],
        "receipt_sha256": summary["receipt_sha256"],
        "root_identities": {
            "state": directory_identity(state_root, "state root"),
            "payload_parent": directory_identity(
                Path(roots["payload"]).parent, "payload parent"
            ),
            "opencode": directory_identity(Path(roots["opencode"]), "OpenCode root"),
        },
        "lock_identity": lock_path_identity(state_root / "broker.lock"),
    }
    validate_identity_binding(binding)
    _atomic_json(
        _identity_binding_path(state_root), binding, None, "identity-binding"
    )
    return {
        "rebind_format": IDENTITY_BINDING_FORMAT,
        "receipt_id": binding["receipt_id"],
        "root_identities": binding["root_identities"],
        "lock_identity": binding["lock_identity"],
    }


def _quiescent_recovery_flags(plan_sha256: str) -> List[str]:
    """Confirmation flags a registration recovery invocation must carry.

    The digest is the registration plan's, not plan.json's, and the invocation
    ID is a placeholder the operator replaces with a fresh one after again
    closing the named host.
    """
    return [
        "--quiescent-edit",
        "--confirm-plan",
        plan_sha256,
        "--invocation-id",
        "<fresh-invocation-id>",
    ]


def inspect_pending_status(state_root: Path, payload_root: Path,
                           opencode_root: Path) -> Dict[str, Any]:
    """Validate and describe one pending transaction without acquiring its lease."""
    _validate_compatible_python()
    state_root = Path(state_root).resolve(strict=True)
    opencode_root = Path(opencode_root).resolve(strict=True)
    payload_input = Path(payload_root)
    payload_parent = payload_input.parent.resolve(strict=True)
    payload_root = payload_parent / payload_input.name
    if payload_root.is_symlink():
        raise RecoveryError("payload root must not be a symlink")
    roots = validate_roots(
        {"state": str(state_root), "payload": str(payload_root), "opencode": str(opencode_root)}
    )
    admission_path = state_root / ".council-lifecycle/admission.json"
    admission, admission_data = read_object(admission_path, "pending admission")
    admission = validate_admission(admission, roots)
    if admission["status"] != "recovery_required":
        raise RecoveryError("pending status requires a recovery_required admission")
    transaction_id = admission["transaction_id"]
    plan_path = (
        state_root / ".council-lifecycle/v1/transactions" / transaction_id / "plan.json"
    )
    plan, plan_data, _receipt, _receipt_data = validate_plan(
        plan_path, pre_intent=False, require_executing_tool=False
    )
    if (plan["transaction_id"] != transaction_id or
            plan["prior_admission"]["committed"] != admission["committed"] or
            plan["roots"] != admission["roots"]):
        raise RecoveryError("pending admission does not bind the prepared plan")
    current, current_data = read_object(admission_path, "pending admission")
    if current_data != admission_data or validate_admission(current, roots) != admission:
        raise RecoveryError("pending admission changed during status inspection")
    current_units = []
    for unit in plan["units"]:
        state = capture_state(
            Path(unit["destination"]),
            "directory" if unit["unit_id"] == "payload" else "file",
        )
        current_units.append(
            {"unit_id": unit["unit_id"], "exists": state["exists"], "sha256": state["sha256"]}
        )
    result = {
        "status_format": 1,
        "roots": roots,
        "management": {
            "status": "recovery_required",
            "certified": False,
            "reason": "a validated lifecycle transaction requires recovery",
            "summary": admission["committed"],
        },
        "payload_cache_count": 0,
        "units": current_units,
        "pending_recovery": {
            "transaction_id": transaction_id,
            "plan_sha256": sha256_bytes(plan_data),
            "recovery_command": [
                str(Path(sys.executable).resolve(strict=True)),
                "-I",
                "-B",
                str(Path(plan["recovery"]["tool_path"])),
                "recover",
                "--state-root",
                str(state_root),
            ],
            "python_contract": {
                "implementation": "CPython",
                "minimum": [3, 9],
                "required_flags": ["-I", "-B"],
                "recorded_path": plan["recovery"]["python_path"],
                "recorded_version": plan["recovery"]["python_version"],
            },
        },
    }
    progress = plan["_progress"]
    result["registrations"] = []
    command = result["pending_recovery"]["recovery_command"]
    if plan["plan_format"] == REGISTRATION_PLAN_FORMAT:
        command.extend(
            _quiescent_recovery_flags(
                plan["registration"]["quiescent_decision"]["plan_sha256"]
            )
        )
        phases = {
            item["operation_id"]: item["phase"]
            for item in progress["registrations"]
        }
        result["registrations"] = [
            {
                "operation_id": item["operation_id"],
                "runtime": item["runtime"],
                "source_path": item["source_path"],
                "ownership_origin": item["ownership_origin"],
                "stored_config_result": "pending_recovery",
                "effective_scope": "unknown",
                "host_restart": "required",
                "authenticated_readiness": "unobserved",
                "recovery_state": phases[item["operation_id"]],
            }
            for item in plan["registration"]["operations"]
        ]
    elif plan["plan_format"] == NATIVE_PLAN_FORMAT:
        command.extend(
            _quiescent_recovery_flags(
                plan["native_registration"]["quiescent_decision"]["plan_sha256"]
            )
            + ["--sequence", "<next-sequence>"]
        )
        execution = plan["native_registration"]["_execution"]
        attempts = progress["native_registrations"][0]["attempts"]
        result["registrations"] = [
            {
                "operation_id": execution["operation_id"],
                "runtime": execution["runtime"],
                "source_path": execution["source_path"],
                "ownership_origin": execution["semantic_result_identity"]["record"][
                    "ownership"
                ],
                "stored_config_result": "pending_recovery",
                "effective_scope": "unknown",
                "host_restart": "required",
                "authenticated_readiness": "unobserved",
                "recovery_state": attempts[-1]["state"],
            }
        ]
    return result


def validate_receipt(value: Any, plan: Dict[str, Any], goal: str = "target") -> Dict[str, Any]:
    validate_receipt_shape(value, "receipt")
    receipt_id = value["receipt_id"]
    expected_id = (
        plan["target_receipt_id"] if goal == "target"
        else plan["outcomes"]["prior"]["committed"]["receipt_id"]
    )
    if receipt_id != expected_id or value["transaction_id"] != plan["transaction_id"]:
        raise RecoveryError("receipt identity differs from plan")
    if value["outcome"] != plan["outcomes"][goal]["status"]:
        raise RecoveryError("receipt outcome differs from plan")
    if validate_roots(value["roots"]) != plan["roots"]:
        raise RecoveryError("receipt roots differ from plan")
    expected_root_identities = {
        name: plan["root_identities"][name]
        for name in ("state", "payload_parent", "opencode")
    }
    if value["root_identities"] != expected_root_identities or value["lock_identity"] != plan["lock_identity"]:
        raise RecoveryError("receipt root/lock identities differ from plan")
    manifest = plan["_manifest"]
    if value["package_id"] != manifest["package_id"] or value["runtime_cohort"] != manifest["runtime_cohort"]:
        raise RecoveryError("receipt package identity differs from source manifest")
    if value["source_manifest_sha256"] != plan["source_manifest"]["sha256"]:
        raise RecoveryError("receipt source manifest digest differs from plan")
    if value["reader_support_sha256"] != plan["reader_support"]["sha256"]:
        raise RecoveryError("receipt reader evidence differs from plan")
    prior = value["prior_receipt"]
    committed = plan["prior_admission"]["committed"]
    expected_prior = None if committed is None else {
        "receipt_id": committed["receipt_id"], "receipt_sha256": committed["receipt_sha256"]
    }
    if prior != expected_prior:
        raise RecoveryError("receipt prior binding differs from plan")
    recovery = value["recovery"]
    expected_recovery_format = (
        REGISTRATION_RECOVERY_FORMAT
        if plan["plan_format"] == REGISTRATION_PLAN_FORMAT
        else NATIVE_RECOVERY_FORMAT
        if plan["plan_format"] == NATIVE_PLAN_FORMAT
        else RECOVERY_FORMAT
    )
    expected_recovery = {
        "format": expected_recovery_format,
        "tool_sha256": plan["recovery"]["tool_sha256"],
    }
    if plan["plan_format"] == NATIVE_PLAN_FORMAT:
        expected_recovery["native_closure_sha256"] = sha256_bytes(
            json_bytes(plan["recovery"]["native_closure"])
        )
    if recovery != expected_recovery:
        raise RecoveryError("receipt recovery identity differs from plan")
    artifacts = value["artifacts"]
    expected_keys = _receipt_artifact_keys(plan["units"], goal)
    if not isinstance(artifacts, list) or len(artifacts) != len(expected_keys):
        raise RecoveryError("receipt artifact closure differs from plan")
    unit_map = {unit["unit_id"]: unit for unit in plan["units"]}
    seen = []
    for index, artifact in enumerate(artifacts):
        label = "receipt artifact %d" % index
        unit_id = artifact["unit_id"]
        relative = checked_relative(artifact["path"], label + " path", allow_dot=True)
        seen.append((unit_id, relative))
        unit = unit_map[unit_id]
        destination = Path(unit["destination"]) if relative == "." else Path(unit["destination"]) / relative
        if artifact["destination"] != str(destination):
            raise RecoveryError("%s destination differs from the fixed unit path" % label)
        prior_leaf = _leaf_state(unit["initial"], relative)
        target_leaf = _leaf_state(unit[goal], relative)
        if artifact["prior"] != prior_leaf or artifact["intended"] != target_leaf:
            raise RecoveryError("%s state differs from the plan" % label)
        if artifact["ownership"] not in OWNERSHIP or artifact["local_change"] != "none":
            raise RecoveryError("%s has unsupported ownership/local-change disposition" % label)
        if artifact["ownership"] == "created" and prior_leaf["exists"]:
            raise RecoveryError("%s cannot call an existing artifact created" % label)
        if artifact["ownership"] == "created" and not target_leaf["exists"]:
            raise RecoveryError("%s cannot create an absent artifact" % label)
        if artifact["ownership"] == "absent" and (prior_leaf["exists"] or target_leaf["exists"]):
            raise RecoveryError("%s absent disposition contains an artifact" % label)
        if artifact["ownership"] == "matching_preexisting_unowned" and prior_leaf != target_leaf:
            raise RecoveryError("%s would mutate an unowned artifact" % label)
        if artifact["ownership"] == "matching_preexisting_unowned" and unit_id == "payload":
            raise RecoveryError("the payload directory cannot be treated as pre-existing unowned content")
        if (plan["prior_admission"]["status"] == "uninstalled" and prior_leaf["exists"]
                and artifact["ownership"] != "matching_preexisting_unowned"):
            raise RecoveryError("%s claims ownership without a prior managed receipt" % label)
    if seen != expected_keys:
        raise RecoveryError("receipt artifacts are not in fixed unit/path order")
    if plan["plan_format"] == REGISTRATION_PLAN_FORMAT:
        if value["receipt_format"] != REGISTRATION_RECEIPT_FORMAT:
            raise RecoveryError("registration plan requires a registration receipt")
        operations = plan["registration"]["operations"]
        registrations = value["registrations"]
        if len(registrations) != len(operations):
            raise RecoveryError("receipt registration closure differs from plan")
        for operation, registration in zip(operations, registrations):
            expected_sha = operation[goal + "_sha256"]
            expected_entry = operation[goal + "_entry_sha256"]
            if (
                registration["operation_id"] != operation["operation_id"]
                or registration["operation"] != operation["operation"]
                or registration["runtime"] != operation["runtime"]
                or registration["source_path"] != operation["source_path"]
                or registration["resulting_sha256"] != expected_sha
                or registration["resulting_entry_sha256"] != expected_entry
                or registration["ownership_origin"] != operation["ownership_origin"]
            ):
                raise RecoveryError("receipt registration differs from plan")
            expected_result = (
                "stored_config_absent_verified"
                if expected_entry is None
                else "stored_config_verified"
            )
            if registration["stored_config_result"] != expected_result:
                raise RecoveryError("receipt stored registration result differs")
    elif plan["plan_format"] == NATIVE_PLAN_FORMAT:
        if value["receipt_format"] != NATIVE_RECEIPT_FORMAT:
            raise RecoveryError("native plan requires a native receipt")
        if value["native_closure"] != plan["recovery"]["native_closure"]:
            raise RecoveryError("native receipt closure differs from the plan")
        registrations = value["native_registrations"]
        if len(registrations) != 1:
            raise RecoveryError("native receipt closure differs from plan")
        registration = registrations[0]
        execution = plan["native_registration"]["_execution"]
        core = plan["native_registration"]["_core"]
        if (
            registration["operation_id"] != execution["operation_id"]
            or registration["operation"] != execution["operation"]
            or registration["runtime"] != execution["runtime"]
            or registration["source_path"] != execution["source_path"]
            or registration["source_scope"] != execution["source_scope"]
            or registration["semantic_result_identity"]
            != execution["semantic_result_identity"]
            or registration["attempt_family"] != execution["attempt_family"]
            or registration["runtime_tuple"]
            != core["records"]["runtime_tuple"]
            or registration["qualification_admission_sha256"]
            != core["records"]["qualification_admission"]["sha256"]
            or registration["implementation_identity_sha256"]
            != core["records"]["implementation_identity"]["sha256"]
        ):
            raise RecoveryError("native receipt registration differs from plan")
    elif value["receipt_format"] != RECEIPT_FORMAT:
        raise RecoveryError("artifact-only plan requires an artifact-only receipt")
    return value


def _validate_prior_ownership(plan: Dict[str, Any], prior_receipt: Optional[Dict[str, Any]],
                              proposed_receipt: Dict[str, Any]) -> None:
    if prior_receipt is None:
        return
    if validate_roots(prior_receipt["roots"]) != plan["roots"]:
        raise RecoveryError("prior receipt roots differ from the plan")
    unit_map = {unit["unit_id"]: unit for unit in plan["units"]}
    previous = {}
    for artifact in prior_receipt["artifacts"]:
        unit = unit_map[artifact["unit_id"]]
        relative = artifact["path"]
        destination = Path(unit["destination"]) if relative == "." else Path(unit["destination"]) / relative
        if artifact["destination"] != str(destination):
            raise RecoveryError("prior receipt contains a destination outside the fixed unit set")
        if artifact["intended"] != _leaf_state(unit["initial"], relative):
            raise RecoveryError("current artifacts differ from the prior ownership receipt")
        previous[(artifact["unit_id"], relative)] = artifact
    proposed = {(item["unit_id"], item["path"]): item for item in proposed_receipt["artifacts"]}
    for key in _receipt_artifact_keys(plan["units"]):
        current = _leaf_state(unit_map[key[0]]["initial"], key[1])
        if current["exists"] and key not in previous:
            cache_path = PurePosixPath(key[1])
            known_cache = key[0] == "payload" and (
                "__pycache__" in cache_path.parts or key[1].endswith((".pyc", ".pyo"))
            )
            if not known_cache:
                raise RecoveryError("current artifact is absent from the prior ownership receipt")
        if key not in previous:
            continue
        old_ownership = previous[key]["ownership"]
        new_ownership = proposed[key]["ownership"]
        if old_ownership == "matching_preexisting_unowned" and new_ownership != old_ownership:
            # Authorized adoption is the one permitted departure from an unowned
            # class, and only in the shape the blocker it resolves can produce: the
            # artifact becomes owned, it stays present, the release actually changes
            # it, and the loop above already proved it still holds exactly the bytes
            # the prior receipt recorded. Nothing unowned is deleted or claimed idly.
            if (new_ownership != "already_owned" or
                    not proposed[key]["intended"]["exists"] or
                    proposed[key]["intended"] == previous[key]["intended"]):
                raise RecoveryError("new plan attempts to adopt a previously unowned artifact")
        if old_ownership != "matching_preexisting_unowned" and new_ownership == "matching_preexisting_unowned":
            raise RecoveryError("new plan drops established artifact ownership")


def _validate_progress(value: Any, plan: Dict[str, Any], plan_digest: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("progress must be an object")
    registration_plan = plan["plan_format"] == REGISTRATION_PLAN_FORMAT
    native_plan = plan["plan_format"] == NATIVE_PLAN_FORMAT
    keys = ("journal_format", "transaction_id", "plan_sha256", "sequence", "goal", "units")
    if registration_plan:
        keys = keys + ("registrations",)
    elif native_plan:
        keys = keys + ("current_attempt_sequence", "native_registrations")
    exact_keys(value, keys, "progress")
    expected_format = (
        REGISTRATION_JOURNAL_FORMAT
        if registration_plan
        else NATIVE_JOURNAL_FORMAT
        if native_plan
        else JOURNAL_FORMAT
    )
    if (exact_int(value["journal_format"], "journal format", 1) != expected_format or
            value["transaction_id"] != plan["transaction_id"]):
        raise RecoveryError("unsupported or mismatched progress journal")
    if value["plan_sha256"] != plan_digest:
        raise RecoveryError("progress does not bind the exact plan")
    exact_int(value["sequence"], "progress sequence")
    if value["goal"] not in plan["allowed_goals"]:
        raise RecoveryError("progress selects an unsupported recovery goal")
    units = value["units"]
    if not isinstance(units, list) or len(units) != len(UNIT_IDS):
        raise RecoveryError("progress must cover exactly five units")
    for index, unit in enumerate(units):
        if not isinstance(unit, dict):
            raise RecoveryError("progress unit must be an object")
        exact_keys(unit, ("unit_id", "phase"), "progress unit")
        if unit["unit_id"] != UNIT_IDS[index] or unit["phase"] not in ("pending", "complete"):
            raise RecoveryError("progress unit order/phase is invalid")
    if registration_plan:
        registrations = value["registrations"]
        operations = plan["registration"]["operations"]
        if not isinstance(registrations, list) or len(registrations) != len(operations):
            raise RecoveryError("progress registration closure differs from plan")
        for index, registration in enumerate(registrations):
            if not isinstance(registration, dict):
                raise RecoveryError("progress registration must be an object")
            exact_keys(registration, ("operation_id", "phase"), "progress registration")
            if (registration["operation_id"] != operations[index]["operation_id"] or
                    registration["phase"] not in ("pending", "complete")):
                raise RecoveryError("progress registration order/phase is invalid")
    elif native_plan:
        registrations = value["native_registrations"]
        execution = plan["native_registration"]["_execution"]
        if not isinstance(registrations, list) or len(registrations) != 1:
            raise RecoveryError("native progress must contain one operation")
        item = registrations[0]
        if not isinstance(item, dict):
            raise RecoveryError("native progress operation must be an object")
        exact_keys(
            item,
            (
                "operation_id",
                "attempt_family",
                "semantic_result_identity",
                "attempts",
            ),
            "native progress operation",
        )
        if item["operation_id"] != execution["operation_id"]:
            raise RecoveryError("native progress operation differs from the plan")
        if (
            item["attempt_family"] != execution["attempt_family"]
            or item["semantic_result_identity"]
            != execution["semantic_result_identity"]
        ):
            raise RecoveryError("native progress stable identity differs")
        _validate_digest_record(item["attempt_family"], "native progress family")
        _validate_digest_record(
            item["semantic_result_identity"], "native progress semantic result"
        )
        attempts = item["attempts"]
        if not isinstance(attempts, list) or not 1 <= len(attempts) <= 2:
            raise RecoveryError("native progress attempt count is invalid")
        for index, attempt in enumerate(attempts):
            if not isinstance(attempt, dict):
                raise RecoveryError("native progress attempt must be an object")
            exact_keys(
                attempt,
                (
                    "sequence",
                    "invocation_id",
                    "state",
                    "journal_sha256",
                    "supervisor",
                    "result",
                    "execution_admission",
                    "attempt_binding",
                    "previous_attempt_terminal_sha256",
                ),
                "native progress attempt",
            )
            if attempt["sequence"] != index:
                raise RecoveryError("native progress sequence is not contiguous")
            checked_id(attempt["invocation_id"], "native progress invocation_id")
            _validate_digest_record(
                attempt["execution_admission"],
                "native progress execution admission",
            )
            _validate_digest_record(
                attempt["attempt_binding"], "native progress attempt binding"
            )
            binding = attempt["attempt_binding"]["record"]
            execution_admission = attempt["execution_admission"]["record"]
            if (
                binding.get("sequence") != index
                or binding.get("attempt_family_sha256")
                != item["attempt_family"]["sha256"]
                or binding.get("execution_admission_sha256")
                != attempt["execution_admission"]["sha256"]
                or binding.get("quiescent_decision_sha256")
                != execution_admission.get("quiescent_decision_sha256")
                or binding.get("previous_attempt_terminal_sha256")
                != attempt["previous_attempt_terminal_sha256"]
            ):
                raise RecoveryError("native progress attempt identity differs")
            expected_previous = (
                None
                if index == 0
                else _native_terminal_summary_digest(
                    item["attempt_family"]["sha256"], attempts[0]
                )
            )
            if attempt["previous_attempt_terminal_sha256"] != expected_previous:
                raise RecoveryError("native progress prior sequence link differs")
            state = attempt["state"]
            if state not in NATIVE_ATTEMPT_STATES:
                raise RecoveryError("native progress state is unsupported")
            if state == "prepared":
                if any(
                    attempt[name] is not None
                    for name in ("journal_sha256", "supervisor", "result")
                ):
                    raise RecoveryError("prepared native progress carries evidence")
            else:
                checked_hash(
                    attempt["journal_sha256"], "native progress journal sha256"
                )
            if state == "issued" and (
                attempt["supervisor"] is not None or attempt["result"] is not None
            ):
                raise RecoveryError("issued native progress carries later evidence")
            if state in {"spawn_generation_recorded", "release_authorized"}:
                _validate_native_supervisor(attempt["supervisor"])
                if attempt["result"] is not None:
                    raise RecoveryError("active native progress carries a result")
            if state in {"observed_target", "observed_prior", "unknown"}:
                if attempt["supervisor"] is not None:
                    _validate_native_supervisor(attempt["supervisor"])
                _validate_digest_record(
                    attempt["result"], "native progress result"
                )
        if value["current_attempt_sequence"] != attempts[-1]["sequence"]:
            raise RecoveryError("native progress current sequence differs")
    return value


def _native_terminal_summary_digest(
    attempt_family_sha256: str, attempt: Dict[str, Any]
) -> str:
    if attempt["state"] not in {"observed_target", "observed_prior", "unknown"}:
        raise RecoveryError("native prior sequence is not terminal")
    summary = {
        "attempt_family_sha256": attempt_family_sha256,
        "sequence": attempt["sequence"],
        "invocation_id": attempt["invocation_id"],
        "attempt_binding_sha256": attempt["attempt_binding"]["sha256"],
        "execution_admission_sha256": attempt["execution_admission"]["sha256"],
        "quiescent_decision_sha256": attempt["attempt_binding"]["record"][
            "quiescent_decision_sha256"
        ],
        "journal_sha256": attempt["journal_sha256"],
        "supervisor": attempt["supervisor"],
        "result_sha256": attempt["result"]["sha256"],
        "classification": attempt["state"],
    }
    return sha256_bytes(
        json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _validate_native_supervisor(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("native supervisor identity must be an object")
    exact_keys(
        value,
        (
            "pid",
            "pgid",
            "start_generation_sha256",
            "attempt_lock_identity",
            "observer_session_sha256",
        ),
        "native supervisor identity",
    )
    if exact_int(value["pid"], "native supervisor pid", 1) != exact_int(
        value["pgid"], "native supervisor pgid", 1
    ):
        raise RecoveryError("native supervisor must lead its process group")
    checked_hash(
        value["start_generation_sha256"], "native supervisor start generation"
    )
    validate_identity(
        value["attempt_lock_identity"], "native supervisor attempt lock"
    )
    checked_hash(
        value["observer_session_sha256"], "native supervisor observer session"
    )
    return value


def retained_state_fingerprint(state_root: Path,
                               control_root: Optional[Path] = None) -> Dict[str, Any]:
    ignored = ".council-lifecycle"
    if control_root is not None:
        control_root = Path(control_root)
        if control_root.parent != state_root:
            raise RecoveryError("retained-state control root is outside state root")
        ignored = control_root.name
    records = []
    for parent, dirs, files in os.walk(state_root, topdown=True, followlinks=False):
        relative_parent = Path(parent).relative_to(state_root)
        if relative_parent == Path("."):
            dirs[:] = sorted(
                name for name in dirs
                if name not in {ignored, PREPARATION_ROOT_NAME}
            )
            files = sorted(name for name in files if name not in VOLATILE_STATE_NAMES)
        else:
            dirs.sort()
            files.sort()
        for name in list(dirs):
            path = Path(parent) / name
            details = path.lstat()
            relative = str(path.relative_to(state_root).as_posix())
            if stat.S_ISLNK(details.st_mode):
                records.append({"path": relative, "kind": "symlink", "value": os.readlink(path)})
                dirs.remove(name)
            elif stat.S_ISDIR(details.st_mode):
                records.append({"path": relative, "kind": "directory", "mode": stat.S_IMODE(details.st_mode)})
            else:
                records.append({"path": relative, "kind": "other"})
                dirs.remove(name)
        for name in files:
            path = Path(parent) / name
            details = path.lstat()
            if stat.S_ISSOCK(details.st_mode):
                continue
            relative = str(path.relative_to(state_root).as_posix())
            if stat.S_ISREG(details.st_mode) and details.st_nlink == 1:
                records.append({"path": relative, "kind": "file", "sha256": sha256_file(path),
                                "mode": stat.S_IMODE(details.st_mode)})
            elif stat.S_ISLNK(details.st_mode):
                records.append({"path": relative, "kind": "symlink", "value": os.readlink(path)})
            else:
                records.append({"path": relative, "kind": "other"})
        if len(records) > MAX_ARTIFACTS:
            raise RecoveryError("retained-state fingerprint exceeds its bound")
    records.sort(key=lambda item: item["path"])
    return {"format": 1, "entry_count": len(records), "sha256": _inventory_digest(records)}


def validate_retained_state(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("retained_state must be an object")
    exact_keys(value, ("format", "entry_count", "sha256"), "retained_state")
    if exact_int(value["format"], "retained_state format", 1) != 1:
        raise RecoveryError("unsupported retained-state fingerprint")
    exact_int(value["entry_count"], "retained_state entry_count")
    checked_hash(value["sha256"], "retained_state sha256")
    return value


def _validate_unit(value: Any, index: int, plan: Dict[str, Any]) -> Dict[str, Any]:
    label = "unit %d" % index
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(value, ("unit_id", "destination", "parent_identity", "initial", "prior", "target", "objects"), label)
    unit_id = value["unit_id"]
    if unit_id != UNIT_IDS[index]:
        raise RecoveryError("units must use the fixed five-unit order")
    destination = _unit_destination(plan["roots"], unit_id)
    if value["destination"] != str(destination):
        raise RecoveryError("%s destination is not fixed by the roots" % label)
    validate_identity(value["parent_identity"], label + " parent_identity")
    kind = "directory" if unit_id == "payload" else "file"
    validate_state(value["initial"], label + " initial", kind)
    validate_state(value["prior"], label + " prior", kind, clean=True)
    validate_state(value["target"], label + " target", kind, clean=True)
    objects = value["objects"]
    if not isinstance(objects, dict):
        raise RecoveryError("%s objects must be an object" % label)
    exact_keys(objects, ("target", "prior", "backup", "stage", "partial", "displaced"), label + " objects")
    if objects != _unit_objects(destination, plan["transaction_id"], unit_id):
        raise RecoveryError("%s recovery object paths are not fixed" % label)
    return value


def _manifest_target_matches(plan: Dict[str, Any]) -> None:
    manifest = plan["_manifest"]
    artifacts = manifest["artifacts"]
    unit_map = {unit["unit_id"]: unit for unit in plan["units"]}
    selected = "initial" if plan["kind"] == "uninstall" else "target"
    payload = unit_map["payload"][selected]
    if not payload["exists"]:
        raise RecoveryError("source manifest has no matching payload state")
    payload_files = {
        "payload/" + item["path"]: item["sha256"]
        for item in payload["artifacts"]
        if item["kind"] == "file"
        and "__pycache__" not in PurePosixPath(item["path"]).parts
        and not item["path"].endswith((".pyc", ".pyo"))
    }
    manifest_payload = {name: digest for name, digest in artifacts.items() if name.startswith("payload/")}
    if payload_files != manifest_payload:
        raise RecoveryError("payload state differs from source manifest closure")
    for unit_id, manifest_path in EXTERNAL_MANIFEST_PATHS.items():
        state_value = unit_map[unit_id][selected]
        if not state_value["exists"] or state_value["sha256"] != artifacts[manifest_path]:
            raise RecoveryError("%s differs from source manifest" % unit_id)


def _root_identity_checks(plan: Dict[str, Any]) -> None:
    roots = {name: Path(value) for name, value in plan["roots"].items()}
    expected = plan["root_identities"]
    lifecycle = Path(plan.get("_control_root", roots["state"] / ".council-lifecycle"))
    transaction = lifecycle / "v1/transactions" / plan["transaction_id"]
    actual = {
        "state": directory_identity(roots["state"], "state root"),
        "payload_parent": directory_identity(roots["payload"].parent, "payload parent"),
        "opencode": directory_identity(roots["opencode"], "OpenCode root"),
        "lifecycle": directory_identity(lifecycle, "lifecycle root"),
        "v1": directory_identity(lifecycle / "v1", "lifecycle v1 root"),
        "receipts": directory_identity(lifecycle / "v1/receipts", "receipt root"),
        "recovery": directory_identity(lifecycle / "v1/recovery", "recovery root"),
        "transactions": directory_identity(lifecycle / "v1/transactions", "transaction root"),
        "transaction": directory_identity(transaction, "transaction directory"),
    }
    if actual != expected:
        raise RecoveryError("lifecycle root identity changed")
    for unit in plan["units"]:
        parent = Path(unit["destination"]).parent
        if directory_identity(parent, "unit parent") != unit["parent_identity"]:
            raise RecoveryError("unit parent identity changed: %s" % unit["unit_id"])


def _require_control_directory(path: Path, label: str) -> None:
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise RecoveryError("%s must be a real directory" % label)
    if stat.S_IMODE(details.st_mode) != 0o700:
        raise RecoveryError("%s must have mode 0700" % label)


def _validate_compatible_python() -> None:
    """Refuse interpreters that cannot honor the copied recoverer's safety contract."""
    if platform.python_implementation() != "CPython":
        raise RecoveryError("recovery requires CPython")
    if sys.version_info[:2] < (3, 9) or sys.version_info[0] != 3:
        raise RecoveryError("recovery requires CPython 3.9 or newer")
    required_constants = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required_constants):
        raise RecoveryError("recovery Python lacks required no-follow filesystem support")
    dir_fd_functions = (os.open, os.stat, os.unlink, os.rmdir)
    if any(function not in os.supports_dir_fd for function in dir_fd_functions):
        raise RecoveryError("recovery Python lacks required descriptor-relative filesystem support")
    if os.stat not in os.supports_follow_symlinks:
        raise RecoveryError("recovery Python lacks required no-follow stat support")


def _validate_registration_patch(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(value, ("start", "end", "replacement_hex"), label)
    start = exact_int(value["start"], label + " start")
    end = exact_int(value["end"], label + " end")
    if start > end or end > MAX_METADATA_BYTES:
        raise RecoveryError("%s bounds are invalid" % label)
    replacement = value["replacement_hex"]
    if not isinstance(replacement, str) or len(replacement) > 2 * MAX_METADATA_BYTES:
        raise RecoveryError("%s replacement is invalid" % label)
    try:
        bytes.fromhex(replacement)
    except ValueError as error:
        raise RecoveryError("%s replacement is not hexadecimal" % label) from error
    return value


def _validate_registration_operation(value: Any, roots: Dict[str, str],
                                     label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(
        value,
        (
            "operation_id", "operation", "runtime", "source_path", "source_scope",
            "prior_sha256", "target_sha256", "prior_entry_sha256",
            "target_entry_sha256", "entry_disposition", "ownership_origin", "candidate_outcome",
            "forward_patch", "inverse_patch", "automatic_apply_eligible",
        ),
        label,
    )
    checked_id(value["operation_id"], label + " operation_id")
    if (value["operation"] not in REGISTRATION_OPERATIONS or
            value["runtime"] != "opencode" or
            value["source_scope"] != "opencode_global" or
            value["automatic_apply_eligible"] is not True):
        raise RecoveryError("%s is not an admitted OpenCode operation" % label)
    source_path = checked_absolute(value["source_path"], label + " source_path")
    opencode_root = Path(roots["opencode"])
    if source_path.parent != opencode_root or source_path.name not in (
        "opencode.json", "opencode.jsonc"
    ):
        raise RecoveryError("%s source is outside the fixed OpenCode config" % label)
    for name in ("prior_sha256", "target_sha256"):
        checked_hash(value[name], label + " " + name)
    for name in ("prior_entry_sha256", "target_entry_sha256"):
        if value[name] is not None:
            checked_hash(value[name], label + " " + name)
    if value["entry_disposition"] not in REGISTRATION_OWNERSHIP:
        raise RecoveryError("%s ownership is unsupported" % label)
    if value["ownership_origin"] not in REGISTRATION_OWNERSHIP:
        raise RecoveryError("%s ownership origin is unsupported" % label)
    if value["candidate_outcome"] == "candidate":
        _validate_registration_patch(value["forward_patch"], label + " forward patch")
        _validate_registration_patch(value["inverse_patch"], label + " inverse patch")
    elif value["candidate_outcome"] == "unchanged":
        if (value["forward_patch"] is not None or value["inverse_patch"] is not None or
                value["prior_sha256"] != value["target_sha256"]):
            raise RecoveryError("%s unchanged operation is inconsistent" % label)
    else:
        raise RecoveryError("%s refused candidate cannot execute" % label)
    return value


def _validate_registration_extension(value: Any, plan_path: Path,
                                     roots: Dict[str, str]) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("registration extension must be an object")
    exact_keys(
        value,
        ("format", "execution_preview", "quiescent_decision", "operations"),
        "registration extension",
    )
    if exact_int(value["format"], "registration extension format", 1) != REGISTRATION_EXTENSION_FORMAT:
        raise RecoveryError("unsupported registration extension format")
    preview = value["execution_preview"]
    if not isinstance(preview, dict):
        raise RecoveryError("registration execution preview reference is invalid")
    exact_keys(preview, ("path", "sha256"), "registration execution preview")
    if preview["path"] != "registration-preview.json":
        raise RecoveryError("registration execution preview path is not fixed")
    checked_hash(preview["sha256"], "registration execution preview sha256")
    preview_value, preview_data = read_object(
        plan_path.parent / preview["path"], "registration execution preview"
    )
    if sha256_bytes(preview_data) != preview["sha256"]:
        raise RecoveryError("registration execution preview digest mismatch")
    if preview_value.get("registration_execution_format") != REGISTRATION_EXTENSION_FORMAT:
        raise RecoveryError("registration execution preview format is unsupported")
    if preview_value.get("executable") is not False:
        raise RecoveryError("registration execution preview must remain non-executable")
    decision = value["quiescent_decision"]
    if not isinstance(decision, dict):
        raise RecoveryError("quiescent decision must be an object")
    exact_keys(
        decision,
        (
            "plan_sha256", "invocation_id", "goal", "hosts", "files",
            "closed_and_no_competing_writer",
        ),
        "quiescent decision",
    )
    if decision["plan_sha256"] != preview["sha256"]:
        raise RecoveryError("quiescent decision does not bind the registration plan")
    checked_id(decision["invocation_id"], "quiescent invocation_id")
    if decision["goal"] != "target" or decision["closed_and_no_competing_writer"] is not True:
        raise RecoveryError("quiescent decision is not an admitted target assertion")
    if (not isinstance(decision["hosts"], list) or not decision["hosts"] or
            len(decision["hosts"]) != len(set(decision["hosts"])) or
            not all(isinstance(item, str) and item for item in decision["hosts"])):
        raise RecoveryError("quiescent host set is invalid")
    operations = value["operations"]
    if not isinstance(operations, list) or not operations:
        raise RecoveryError("registration extension has no operations")
    parsed = [
        _validate_registration_operation(item, roots, "registration operation %d" % index)
        for index, item in enumerate(operations)
    ]
    ids = [item["operation_id"] for item in parsed]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise RecoveryError("registration operations must be sorted and unique")
    files = [item["source_path"] for item in parsed]
    if decision["files"] != files or len(files) != len(set(files)):
        raise RecoveryError("quiescent file set differs from registration operations")
    if preview_value.get("operations") != parsed:
        raise RecoveryError("registration preview operations differ from the plan")
    value["_execution_preview"] = preview_value
    value["_execution_preview_data"] = preview_data
    return value


def _validate_digest_record(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(value, ("record", "sha256"), label)
    if not isinstance(value["record"], dict):
        raise RecoveryError("%s record must be an object" % label)
    checked_hash(value["sha256"], label + " sha256")
    if sha256_bytes(
        json.dumps(value["record"], sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ) != value["sha256"]:
        raise RecoveryError("%s digest differs" % label)
    return value


def _validate_native_plan_core(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("native plan core must be an object")
    exact_keys(
        value,
        (
            "native_registration_plan_format",
            "executable",
            "operation_id",
            "operation",
            "runtime",
            "source_path",
            "source_scope",
            "source_sha256",
            "prior_state",
            "prior_entry_sha256",
            "prior_complement_sha256",
            "stdio",
            "artifact_receipt",
            "records",
            "required_gates",
            "native_success_activated",
        ),
        "native plan core",
    )
    operation = value["operation"]
    runtime = value["runtime"]
    if (
        value["native_registration_plan_format"] != NATIVE_PLAN_FORMAT
        or value["executable"] is not False
        or value["native_success_activated"] is not False
        or operation not in NATIVE_OPERATIONS
        or runtime not in ("claude", "codex")
        or not operation.startswith(runtime + "_")
    ):
        raise RecoveryError("native plan core is unsupported")
    checked_id(value["operation_id"], "native plan operation_id")
    checked_absolute(value["source_path"], "native plan source_path")
    if value["source_scope"] != (
        "claude_user" if runtime == "claude" else "codex_user"
    ):
        raise RecoveryError("native plan source scope is unsupported")
    checked_hash(value["source_sha256"], "native plan source_sha256")
    checked_hash(
        value["prior_complement_sha256"], "native plan prior complement sha256"
    )
    if value["prior_entry_sha256"] is not None:
        checked_hash(value["prior_entry_sha256"], "native plan prior entry sha256")
    stdio = value["stdio"]
    if not isinstance(stdio, dict):
        raise RecoveryError("native plan stdio must be an object")
    exact_keys(stdio, ("python_executable", "adapter_path"), "native plan stdio")
    for key in stdio:
        checked_absolute(stdio[key], "native plan " + key)
    receipt = value["artifact_receipt"]
    if not isinstance(receipt, dict):
        raise RecoveryError("native plan artifact receipt must be an object")
    exact_keys(
        receipt,
        ("receipt_id", "receipt_sha256", "package_id", "runtime_cohort"),
        "native plan artifact receipt",
    )
    checked_id(receipt["receipt_id"], "native plan artifact receipt_id")
    for name in ("receipt_sha256", "package_id", "runtime_cohort"):
        checked_hash(receipt[name], "native plan artifact " + name)
    records = value["records"]
    if not isinstance(records, dict):
        raise RecoveryError("native plan records must be an object")
    exact_keys(
        records,
        (
            "implementation_identity",
            "shape_policy",
            "qualification_support",
            "qualification_admission",
            "runtime_tuple",
        ),
        "native plan records",
    )
    for name in records:
        if name != "shape_policy":
            _validate_digest_record(records[name], "native plan " + name)
            continue
        shape = records[name]
        if not isinstance(shape, dict):
            raise RecoveryError("native shape policy identity must be an object")
        exact_keys(
            shape,
            ("record", "sha256", "source_sha256"),
            "native plan shape policy",
        )
        if not isinstance(shape["record"], dict):
            raise RecoveryError("native shape policy record must be an object")
        checked_hash(shape["sha256"], "native shape policy record sha256")
        checked_hash(shape["source_sha256"], "native shape policy source sha256")
        if (
            sha256_bytes(
                json.dumps(
                    shape["record"], sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            )
            != shape["sha256"]
            or shape["record"].get("policy_sha256") != shape["source_sha256"]
            or shape["record"].get("qualification_eligible") is not False
        ):
            raise RecoveryError("native shape policy identity differs")
    if value["required_gates"] != [
        "owner-recorded-qualification-admission",
        "exact-current-attempt-binding",
        "fresh-sequence-quiescent-decision",
        "single-c1-writer-lease",
        "complete-process-network-write-observation",
    ]:
        raise RecoveryError("native plan gates differ")
    return value


def _validate_native_execution(value: Any, core: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("native execution preview must be an object")
    exact_keys(
        value,
        (
            "native_registration_execution_format",
            "executable",
            "plan_core_sha256",
            "operation_id",
            "operation",
            "runtime",
            "source_path",
            "source_scope",
            "attempt_family",
            "attempt_binding",
            "execution_admission",
            "semantic_result_identity",
            "copied_recovery_closure",
            "native_success_activated",
        ),
        "native execution preview",
    )
    if (
        value["native_registration_execution_format"] != NATIVE_PLAN_FORMAT
        or value["executable"] is not False
        or value["native_success_activated"] is not False
        or value["copied_recovery_closure"] != "native-v3-three-module-closure"
    ):
        raise RecoveryError("native execution preview is unsupported")
    for key in (
        "operation_id",
        "operation",
        "runtime",
        "source_path",
        "source_scope",
    ):
        if value[key] != core[key]:
            raise RecoveryError("native execution differs from its plan core")
    checked_hash(value["plan_core_sha256"], "native execution plan core sha256")
    _validate_digest_record(value["attempt_family"], "native attempt family")
    _validate_digest_record(value["attempt_binding"], "native attempt binding")
    _validate_digest_record(
        value["execution_admission"], "native execution admission"
    )
    _validate_digest_record(
        value["semantic_result_identity"], "native semantic result identity"
    )
    return value


def _validate_native_extension(value: Any, plan_path: Path,
                               roots: Dict[str, str]) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("native registration extension must be an object")
    exact_keys(
        value,
        ("format", "plan_core", "execution_preview", "quiescent_decision"),
        "native registration extension",
    )
    if exact_int(value["format"], "native registration extension format", 1) != 1:
        raise RecoveryError("unsupported native registration extension format")
    references = (
        ("plan_core", "native-plan-core.json"),
        ("execution_preview", "native-execution-preview.json"),
    )
    loaded = {}
    for name, fixed_path in references:
        reference = value[name]
        if not isinstance(reference, dict):
            raise RecoveryError("native %s reference must be an object" % name)
        exact_keys(reference, ("path", "sha256"), "native " + name)
        if reference["path"] != fixed_path:
            raise RecoveryError("native %s path is not fixed" % name)
        checked_hash(reference["sha256"], "native %s sha256" % name)
        record, data = read_object(plan_path.parent / fixed_path, "native " + name)
        if sha256_bytes(data) != reference["sha256"]:
            raise RecoveryError("native %s digest differs" % name)
        loaded[name] = (record, data)
    core = _validate_native_plan_core(loaded["plan_core"][0])
    if sha256_bytes(loaded["plan_core"][1]) != value["plan_core"]["sha256"]:
        raise RecoveryError("native plan core reference differs")
    execution = _validate_native_execution(loaded["execution_preview"][0], core)
    if execution["plan_core_sha256"] != value["plan_core"]["sha256"]:
        raise RecoveryError("native execution does not bind its plan core")
    decision = value["quiescent_decision"]
    if not isinstance(decision, dict):
        raise RecoveryError("native quiescent decision must be an object")
    exact_keys(
        decision,
        (
            "plan_sha256",
            "invocation_id",
            "goal",
            "hosts",
            "files",
            "closed_and_no_competing_writer",
            "sequence",
        ),
        "native quiescent decision",
    )
    if (
        decision["plan_sha256"] != value["plan_core"]["sha256"]
        or decision["goal"] != "target"
        or decision["closed_and_no_competing_writer"] is not True
        or decision["sequence"] != 0
    ):
        raise RecoveryError("native quiescent decision differs from the plan core")
    checked_id(decision["invocation_id"], "native quiescent invocation_id")
    if decision["files"] != [core["source_path"]]:
        raise RecoveryError("native quiescent file set differs")
    if (
        not isinstance(decision["hosts"], list)
        or decision["hosts"] != [core["runtime"]]
    ):
        raise RecoveryError("native quiescent host set differs")
    if Path(core["source_path"]).parent == Path(roots["state"]):
        raise RecoveryError("native config path cannot be the Council state root")
    value["_core"] = core
    value["_execution"] = execution
    value["_plan_core_data"] = loaded["plan_core"][1]
    value["_execution_data"] = loaded["execution_preview"][1]
    return value


def validate_plan(plan_path: Path, *, pre_intent: bool,
                  require_progress: bool = True,
                  require_executing_tool: bool = True
                  ) -> Tuple[Dict[str, Any], bytes, Dict[str, Any], bytes]:
    plan_path = Path(plan_path).resolve(strict=True)
    plan, plan_data = read_object(plan_path, "prepared plan")
    plan_format = exact_int(plan.get("plan_format"), "plan format", 1)
    plan_keys = (
        "plan_format", "transaction_id", "kind", "roots", "root_identities", "lock_identity",
        "prior_admission", "outcomes", "target_receipt_id", "source_manifest", "proposed_receipt",
        "proposed_prior_receipt", "recovery", "required_operations", "allowed_goals", "units",
        "retained_state", "reader_support",
    )
    if plan_format == REGISTRATION_PLAN_FORMAT:
        plan_keys = plan_keys + ("registration",)
    elif plan_format == NATIVE_PLAN_FORMAT:
        plan_keys = plan_keys + ("native_registration",)
    elif plan_format != PLAN_FORMAT:
        raise RecoveryError("unsupported plan format")
    exact_keys(
        plan,
        plan_keys,
        "plan",
    )
    transaction_id = checked_id(plan["transaction_id"], "transaction_id")
    if plan["kind"] not in KINDS:
        raise RecoveryError("unsupported transaction kind")
    plan["roots"] = validate_roots(plan["roots"])
    canonical_lifecycle = Path(plan["roots"]["state"]) / ".council-lifecycle"
    prepared_lifecycle = Path(plan["roots"]["state"]) / (
        ".council-lifecycle.prepare-" + transaction_id
    )
    actual_lifecycle = plan_path.parent.parent.parent.parent
    if actual_lifecycle not in (canonical_lifecycle, prepared_lifecycle):
        raise RecoveryError("plan is outside its fixed transaction path")
    expected_actual_plan = actual_lifecycle / "v1/transactions" / transaction_id / "plan.json"
    if plan_path != expected_actual_plan:
        raise RecoveryError("plan is outside its fixed transaction path")
    plan["_control_root"] = str(actual_lifecycle)
    plan["_plan_path"] = str(plan_path)
    lifecycle_root = actual_lifecycle
    for path, label in (
        (lifecycle_root, "lifecycle root"),
        (lifecycle_root / "v1", "lifecycle v1 root"),
        (lifecycle_root / "v1/receipts", "receipt root"),
        (lifecycle_root / "v1/recovery", "recovery root"),
        (lifecycle_root / "v1/transactions", "transaction root"),
        (plan_path.parent, "transaction directory"),
    ):
        _require_control_directory(path, label)
    root_identities = plan["root_identities"]
    if not isinstance(root_identities, dict):
        raise RecoveryError("root_identities must be an object")
    exact_keys(
        root_identities,
        ("state", "payload_parent", "opencode", "lifecycle", "v1", "receipts",
         "recovery", "transactions", "transaction"),
        "root_identities",
    )
    for name in root_identities:
        validate_identity(root_identities[name], "root identity %s" % name)
    validate_identity(plan["lock_identity"], "lock_identity")
    plan["prior_admission"] = validate_admission(plan["prior_admission"], plan["roots"])
    prior_committed = plan["prior_admission"]["committed"]
    prior_receipt_value = None
    if prior_committed is not None:
        prior_path = lifecycle_root / "v1/receipts" / (prior_committed["receipt_id"] + ".json")
        prior_receipt, prior_data = read_object(prior_path, "prior receipt")
        validate_receipt_shape(prior_receipt, "prior receipt")
        if sha256_bytes(prior_data) != prior_committed["receipt_sha256"]:
            raise RecoveryError("prior receipt digest mismatch")
        allowed_prior_formats = (
            (RECEIPT_FORMAT, REGISTRATION_RECEIPT_FORMAT, NATIVE_RECEIPT_FORMAT)
            if plan_format == NATIVE_PLAN_FORMAT
            else (RECEIPT_FORMAT, REGISTRATION_RECEIPT_FORMAT, NATIVE_RECEIPT_FORMAT)
        )
        if (prior_receipt.get("receipt_format") not in allowed_prior_formats or
                prior_receipt.get("receipt_id") != prior_committed["receipt_id"] or
                prior_receipt.get("package_id") != prior_committed["package_id"] or
                prior_receipt.get("runtime_cohort") != prior_committed["runtime_cohort"]):
            raise RecoveryError("prior receipt summary mismatch")
        if (
            plan_format != NATIVE_PLAN_FORMAT
            and prior_receipt.get("receipt_format") == NATIVE_RECEIPT_FORMAT
            and not _native_receipt_has_only_absent_entries(prior_receipt)
        ):
            raise RecoveryError(
                "active native registration blocks an artifact/OpenCode transaction"
            )
        _validate_receipt_provenance(Path(plan["roots"]["state"]), prior_receipt)
        prior_receipt_value = prior_receipt
    outcomes = plan["outcomes"]
    if not isinstance(outcomes, dict):
        raise RecoveryError("outcomes must be an object")
    exact_keys(outcomes, ("target", "prior"), "outcomes")
    outcomes["target"] = validate_admission(outcomes["target"], plan["roots"])
    if outcomes["target"]["status"] not in ("committed", "uninstalled"):
        raise RecoveryError("target outcome must be terminal")
    if plan["kind"] == "install":
        if plan["prior_admission"]["status"] != "uninstalled" or outcomes["target"]["status"] != "committed":
            raise RecoveryError("install requires uninstalled prior and committed target outcomes")
    elif plan["kind"] in ("upgrade", "rollback", "registration"):
        if plan["prior_admission"]["status"] != "committed" or outcomes["target"]["status"] != "committed":
            raise RecoveryError("upgrade/rollback requires committed prior and target outcomes")
    elif plan["kind"] == "uninstall":
        if plan["prior_admission"]["status"] != "committed" or outcomes["target"]["status"] != "uninstalled":
            raise RecoveryError("uninstall requires committed prior and uninstalled target outcomes")
    if outcomes["prior"] is not None:
        outcomes["prior"] = validate_admission(outcomes["prior"], plan["roots"])
        if outcomes["prior"]["status"] not in ("committed", "uninstalled"):
            raise RecoveryError("prior outcome must be terminal")
    checked_id(plan["target_receipt_id"], "target_receipt_id")
    source_manifest = plan["source_manifest"]
    if not isinstance(source_manifest, dict):
        raise RecoveryError("source_manifest must be an object")
    exact_keys(source_manifest, ("path", "sha256"), "source_manifest")
    if source_manifest["path"] != "source-manifest.json":
        raise RecoveryError("source manifest path is not fixed")
    checked_hash(source_manifest["sha256"], "source_manifest sha256")
    manifest_path = plan_path.parent / source_manifest["path"]
    manifest_value, manifest_data = read_object(manifest_path, "source manifest")
    if sha256_bytes(manifest_data) != source_manifest["sha256"]:
        raise RecoveryError("source manifest digest mismatch")
    plan["_manifest"] = validate_release_manifest(manifest_value)
    proposed = plan["proposed_receipt"]
    if not isinstance(proposed, dict):
        raise RecoveryError("proposed_receipt must be an object")
    exact_keys(proposed, ("path", "sha256"), "proposed_receipt")
    if proposed["path"] != "receipt.json":
        raise RecoveryError("proposed receipt path is not fixed")
    checked_hash(proposed["sha256"], "proposed receipt sha256")
    prior_proposed = plan["proposed_prior_receipt"]
    if prior_proposed is not None:
        if not isinstance(prior_proposed, dict):
            raise RecoveryError("proposed_prior_receipt must be an object or null")
        exact_keys(prior_proposed, ("path", "sha256"), "proposed_prior_receipt")
        if prior_proposed["path"] != "prior-receipt.json":
            raise RecoveryError("proposed prior receipt path is not fixed")
        checked_hash(prior_proposed["sha256"], "proposed prior receipt sha256")
    recovery = plan["recovery"]
    if not isinstance(recovery, dict):
        raise RecoveryError("recovery must be an object")
    recovery_keys = (
        "format", "tool_path", "tool_sha256", "python_path", "python_version"
    )
    if plan_format == NATIVE_PLAN_FORMAT:
        recovery_keys = recovery_keys + ("native_closure",)
    exact_keys(recovery, recovery_keys, "recovery")
    expected_recovery_format = (
        REGISTRATION_RECOVERY_FORMAT
        if plan_format == REGISTRATION_PLAN_FORMAT
        else NATIVE_RECOVERY_FORMAT
        if plan_format == NATIVE_PLAN_FORMAT
        else RECOVERY_FORMAT
    )
    if exact_int(recovery["format"], "recovery format", 1) != expected_recovery_format:
        raise RecoveryError("unsupported recovery format")
    checked_hash(recovery["tool_sha256"], "recovery tool_sha256")
    canonical_tool = canonical_lifecycle / "v1/recovery" / (recovery["tool_sha256"] + ".py")
    actual_tool = actual_lifecycle / "v1/recovery" / (recovery["tool_sha256"] + ".py")
    if checked_absolute(recovery["tool_path"], "recovery tool_path") != canonical_tool:
        raise RecoveryError("recovery tool path is not fixed by its digest")
    if sha256_file(actual_tool) != recovery["tool_sha256"]:
        raise RecoveryError("the copied recovery tool does not match the plan")
    if require_executing_tool and Path(__file__).resolve(strict=True) != actual_tool:
        raise RecoveryError("the executing recovery tool does not match the plan")
    checked_absolute(recovery["python_path"], "recovery python_path")
    version = recovery["python_version"]
    if (not isinstance(version, list) or len(version) != 3 or
            any(type(item) is not int or item < 0 for item in version) or
            version[0] != 3 or version[1] < 9):
        raise RecoveryError("the recorded Python provenance is incompatible")
    _validate_compatible_python()
    if plan_format == NATIVE_PLAN_FORMAT:
        closure = _validate_native_closure_manifest(
            recovery["native_closure"], "native recovery closure"
        )
        actual_closure = actual_lifecycle / "v1/recovery/native-v3" / closure[
            "implementation_identity_sha256"
        ]
        modules = None
        if require_executing_tool:
            modules = _load_native_recovery_closure(actual_closure, closure)
        else:
            _verified_native_recovery_sources(actual_closure, closure)
        recover_identity = closure["modules"][0]
        if recover_identity["sha256"] != recovery["tool_sha256"]:
            raise RecoveryError("native recovery closure recoverer differs")
        if modules is not None:
            plan["_native_modules"] = modules
        plan["_native_closure_directory"] = str(actual_closure)
    expected_operations = (
        REGISTRATION_REQUIRED_OPERATIONS
        if plan_format == REGISTRATION_PLAN_FORMAT
        else NATIVE_REQUIRED_OPERATIONS
        if plan_format == NATIVE_PLAN_FORMAT
        else REQUIRED_OPERATIONS
    )
    if plan["required_operations"] != list(expected_operations):
        raise RecoveryError("plan requires unsupported or incomplete operations")
    if plan["allowed_goals"] not in (["target"], ["target", "prior"]):
        raise RecoveryError("plan has unsupported recovery goals")
    if outcomes["prior"] is None and plan["allowed_goals"] != ["target"]:
        raise RecoveryError("plan permits prior recovery without a prior outcome")
    if outcomes["prior"] is not None and plan["allowed_goals"] != ["target", "prior"]:
        raise RecoveryError("plan omits its validated prior outcome")
    if not isinstance(plan["units"], list) or len(plan["units"]) != len(UNIT_IDS):
        raise RecoveryError("plan must contain exactly five units")
    plan["units"] = [_validate_unit(unit, index, plan) for index, unit in enumerate(plan["units"])]
    if plan_format == REGISTRATION_PLAN_FORMAT:
        plan["registration"] = _validate_registration_extension(
            plan["registration"], plan_path, plan["roots"]
        )
    elif plan_format == NATIVE_PLAN_FORMAT:
        plan["native_registration"] = _validate_native_extension(
            plan["native_registration"], plan_path, plan["roots"]
        )
        implementation_sha256 = plan["native_registration"]["_core"]["records"][
            "implementation_identity"
        ]["sha256"]
        if implementation_sha256 != recovery["native_closure"][
            "implementation_identity_sha256"
        ]:
            raise RecoveryError("native plan implementation identity differs")
        if pre_intent:
            _validate_native_record_derivation(plan, _native_records(plan))
    if outcomes["target"]["status"] == "uninstalled" and plan["units"][0]["target"]["exists"]:
        raise RecoveryError("uninstalled target cannot retain the payload")
    plan["retained_state"] = validate_retained_state(plan["retained_state"])
    support_reference = plan["reader_support"]
    if not isinstance(support_reference, dict):
        raise RecoveryError("reader_support reference must be an object")
    exact_keys(support_reference, ("path", "sha256"), "reader_support reference")
    if support_reference["path"] != "reader-support.json":
        raise RecoveryError("reader support path is not fixed")
    checked_hash(support_reference["sha256"], "reader support sha256")
    support_value, support_data = read_object(
        plan_path.parent / support_reference["path"], "reader support record"
    )
    if sha256_bytes(support_data) != support_reference["sha256"]:
        raise RecoveryError("reader support digest mismatch")
    plan["_reader_support"] = validate_reader_support(support_value)
    plan["_provenance_data"] = {
        "manifest": manifest_data,
        "reader_support": support_data,
    }
    if plan["_reader_support"]["package_id"] != plan["_manifest"]["package_id"] or plan["_reader_support"]["runtime_cohort"] != plan["_manifest"]["runtime_cohort"]:
        raise RecoveryError("reader evidence differs from source manifest identity")
    _manifest_target_matches(plan)
    receipt_path = plan_path.parent / proposed["path"]
    receipt, receipt_data = read_object(receipt_path, "proposed receipt")
    if sha256_bytes(receipt_data) != proposed["sha256"]:
        raise RecoveryError("proposed receipt digest mismatch")
    validate_receipt(receipt, plan)
    _validate_prior_ownership(plan, prior_receipt_value, receipt)
    target = outcomes["target"]
    expected_summary = {
        "receipt_id": plan["target_receipt_id"],
        "receipt_sha256": proposed["sha256"],
        "package_id": plan["_manifest"]["package_id"],
        "runtime_cohort": plan["_manifest"]["runtime_cohort"],
    }
    if target["committed"] != expected_summary:
        raise RecoveryError("target admission summary differs from proposed receipt")
    plan["_receipt_data"] = {"target": receipt_data, "prior": None}
    if outcomes["prior"] is None:
        if prior_proposed is not None:
            raise RecoveryError("plan has a prior receipt without a prior outcome")
    elif prior_proposed is not None:
        prior_candidate, prior_candidate_data = read_object(
            plan_path.parent / prior_proposed["path"], "proposed prior receipt"
        )
        if sha256_bytes(prior_candidate_data) != prior_proposed["sha256"]:
            raise RecoveryError("proposed prior receipt digest mismatch")
        validate_receipt(prior_candidate, plan, "prior")
        prior_summary = outcomes["prior"]["committed"]
        expected_prior_summary = {
            "receipt_id": prior_candidate["receipt_id"],
            "receipt_sha256": prior_proposed["sha256"],
            "package_id": plan["_manifest"]["package_id"],
            "runtime_cohort": plan["_manifest"]["runtime_cohort"],
        }
        if prior_summary != expected_prior_summary:
            raise RecoveryError("prior admission summary differs from proposed prior receipt")
        plan["_receipt_data"]["prior"] = prior_candidate_data
    elif outcomes["prior"] != plan["prior_admission"] or outcomes["prior"]["committed"] is None:
        raise RecoveryError("prior outcome lacks immutable receipt evidence")
    _root_identity_checks(plan)
    lock_path = Path(plan["roots"]["state"]) / "broker.lock"
    if lock_path_identity(lock_path) != plan["lock_identity"]:
        raise RecoveryError("broker.lock identity changed")
    actual_retained = retained_state_fingerprint(
        Path(plan["roots"]["state"]), actual_lifecycle
    )
    if actual_retained != plan["retained_state"]:
        raise RecoveryError("retained state changed since plan preparation")
    progress = None
    if require_progress:
        progress, _ = read_object(plan_path.parent / "progress.json", "progress")
        _validate_progress(progress, plan, sha256_bytes(plan_data))
        plan["_progress"] = progress
    for unit in plan["units"]:
        for goal in ("target", "prior"):
            source = Path(unit["objects"][goal])
            expected = unit[goal]
            source_present = source.exists() or source.is_symlink()
            if expected["exists"] != source_present or (expected["exists"] and not state_matches(source, expected)):
                raise RecoveryError("%s %s recovery object differs from plan" % (unit["unit_id"], goal))
        if pre_intent:
            if not state_matches(Path(unit["destination"]), unit["initial"]):
                raise RecoveryError("%s changed before intent" % unit["unit_id"])
            for name in ("backup", "stage", "partial", "displaced"):
                if Path(unit["objects"][name]).exists() or Path(unit["objects"][name]).is_symlink():
                    raise RecoveryError("%s pre-intent %s path is occupied" % (unit["unit_id"], name))
    if pre_intent:
        if actual_lifecycle == canonical_lifecycle:
            admission, _ = read_object(canonical_lifecycle / "admission.json", "admission")
            if validate_admission(admission, plan["roots"]) != plan["prior_admission"]:
                raise RecoveryError("admission changed before intent")
        else:
            if canonical_lifecycle.exists() or canonical_lifecycle.is_symlink():
                raise RecoveryError("canonical lifecycle namespace appeared during bootstrap")
            pending, _ = read_object(actual_lifecycle / "admission.json", "prepared admission")
            pending = validate_admission(pending, plan["roots"])
            if (pending["status"] != "recovery_required" or
                    pending["transaction_id"] != transaction_id or
                    pending["committed"] != plan["prior_admission"]["committed"]):
                raise RecoveryError("prepared admission does not bind the bootstrap plan")
        if progress is None or progress["sequence"] != 0 or progress["goal"] != "target" or any(
            unit["phase"] != "pending" for unit in progress["units"]
        ) or (
            plan_format == REGISTRATION_PLAN_FORMAT
            and any(item["phase"] != "pending" for item in progress["registrations"])
        ) or (
            plan_format == NATIVE_PLAN_FORMAT
            and (
                len(progress["native_registrations"][0]["attempts"]) != 1
                or progress["native_registrations"][0]["attempts"][0]["state"]
                != "prepared"
            )
        ):
            raise RecoveryError("initial progress is not pristine")
    return plan, plan_data, receipt, receipt_data


class RecoveryLease:
    def __init__(self, state_root: Path, root_descriptor: int, lock_descriptor: int,
                 root_identity: Dict[str, int], lock_identity: Dict[str, int]):
        self.state_root = state_root
        self.root_descriptor = root_descriptor
        self.lock_descriptor = lock_descriptor
        self.root_identity = root_identity
        self.lock_identity = lock_identity
        self.pid = os.getpid()
        self.closed = False

    def validate(self) -> None:
        if self.closed or self.pid != os.getpid():
            raise RecoveryError("recovery lease is closed or belongs to another process")
        root_details = os.fstat(self.root_descriptor)
        lock_details = os.fstat(self.lock_descriptor)
        if {"device": root_details.st_dev, "inode": root_details.st_ino} != self.root_identity:
            raise RecoveryError("held state-root descriptor changed")
        if {"device": lock_details.st_dev, "inode": lock_details.st_ino} != self.lock_identity:
            raise RecoveryError("held broker.lock descriptor changed")
        if (directory_identity(self.state_root, "state root") != self.root_identity or
                lock_path_identity(self.state_root / "broker.lock") != self.lock_identity):
            raise RecoveryError("state root or broker.lock path was displaced")

    def validate_for_recovery(self, state_root: Path) -> Dict[str, Any]:
        self.validate()
        if Path(state_root).resolve(strict=True) != self.state_root:
            raise RecoveryError("recovery lease belongs to a different state root")
        return {
            "pid": self.pid,
            "state_root": str(self.state_root),
            "root_identity": self.root_identity,
            "lock_identity": self.lock_identity,
            "lock_descriptor": self.lock_descriptor,
        }

    def close(self) -> None:
        if self.closed:
            return
        if self.pid != os.getpid():
            os.close(self.lock_descriptor)
            os.close(self.root_descriptor)
            self.closed = True
            return
        fcntl.flock(self.lock_descriptor, fcntl.LOCK_UN)
        os.close(self.lock_descriptor)
        os.close(self.root_descriptor)
        self.closed = True

    def __enter__(self) -> "RecoveryLease":
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        self.close()


def acquire_recovery_lease(state_root: Path) -> RecoveryLease:
    state_root = Path(state_root).resolve(strict=True)
    if state_root.is_symlink() or not state_root.is_dir():
        raise RecoveryError("state root must resolve to a real directory")
    root_descriptor = os.open(str(state_root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock_descriptor = -1
    try:
        root_details = os.fstat(root_descriptor)
        lock_path = state_root / "broker.lock"
        lock_details = lock_path.lstat()
        if stat.S_ISLNK(lock_details.st_mode) or not stat.S_ISREG(lock_details.st_mode) or lock_details.st_nlink != 1:
            raise RecoveryError("broker.lock must be a single-linked regular file")
        lock_descriptor = os.open(str(lock_path), os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as error:
            raise RecoveryError("Council writer/recovery lease is already held") from error
        lease = RecoveryLease(
            state_root,
            root_descriptor,
            lock_descriptor,
            {"device": root_details.st_dev, "inode": root_details.st_ino},
            {"device": lock_details.st_dev, "inode": lock_details.st_ino},
        )
        lease.validate()
        return lease
    except BaseException:
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        os.close(root_descriptor)
        raise


def _lease_facts(lease_adapter: Any, state_root: Path) -> Dict[str, Any]:
    validator = getattr(lease_adapter, "validate_for_recovery", None)
    if not callable(validator):
        raise RecoveryError("recovery requires a validated in-process lease adapter")
    facts = validator(state_root)
    if not isinstance(facts, dict):
        raise RecoveryError("lease adapter returned invalid facts")
    exact_keys(
        facts,
        ("pid", "state_root", "root_identity", "lock_identity", "lock_descriptor"),
        "lease facts",
    )
    if facts["pid"] != os.getpid() or Path(facts["state_root"]) != state_root:
        raise RecoveryError("lease adapter belongs to another process or state root")
    validate_identity(facts["root_identity"], "lease root_identity")
    validate_identity(facts["lock_identity"], "lease lock_identity")
    descriptor = exact_int(facts["lock_descriptor"], "lease lock_descriptor")
    details = os.fstat(descriptor)
    if not stat.S_ISREG(details.st_mode):
        raise RecoveryError("lease descriptor is not the broker lock")
    descriptor_identity = {"device": details.st_dev, "inode": details.st_ino}
    if descriptor_identity != facts["lock_identity"]:
        raise RecoveryError("lease descriptor identity mismatch")
    if (directory_identity(state_root, "state root") != facts["root_identity"] or
            lock_path_identity(state_root / "broker.lock") != facts["lock_identity"]):
        raise RecoveryError("lease root or lock path was displaced")
    return facts


def _sync_directory(path: Path, failpoint: Failpoint, label: str) -> None:
    _event(failpoint, "before:fsync-directory:" + label)
    descriptor = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _event(failpoint, "after:fsync-directory:" + label)


def _atomic_json(path: Path, value: Any, failpoint: Failpoint, label: str) -> None:
    data = json_bytes(value)
    if len(data) > MAX_METADATA_BYTES:
        raise RecoveryError("%s exceeds the 1 MiB metadata limit" % label)
    temporary = path.with_name(".%s.pending" % path.name)
    if temporary.parent != path.parent:
        raise RecoveryError("metadata temporary path escaped its parent")
    parent_descriptor, parent_identity = _opened_directory(path.parent, label + " parent")
    descriptor = -1
    owned_token = None
    try:
        original_token = _entry_token(parent_descriptor, path.name)
        temporary_token = _entry_token(parent_descriptor, temporary.name)
        if temporary_token is not None:
            temporary_details = os.stat(
                temporary.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if (not stat.S_ISREG(temporary_details.st_mode) or
                    temporary_details.st_nlink != 1):
                raise RecoveryError("owned %s temporary path has an unexpected type" % label)
            os.unlink(temporary.name, dir_fd=parent_descriptor)
            _sync_open_directory(
                parent_descriptor, failpoint, label + ":temporary-cleanup"
            )
        descriptor = os.open(
            temporary.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        owned_token = _stat_token(os.fstat(descriptor))
        _event(failpoint, "before:write:" + label)
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RecoveryError("short metadata write: %s" % label)
            view = view[written:]
        _event(failpoint, "after:write:" + label)
        _event(failpoint, "before:fsync-file:" + label)
        os.fsync(descriptor)
        _event(failpoint, "after:fsync-file:" + label)
        owned_token = _stat_token(os.fstat(descriptor))
        os.close(descriptor)
        descriptor = -1
        _event(failpoint, "before:replace:" + label)
        _require_open_directory(
            path.parent, parent_descriptor, parent_identity, label + " parent"
        )
        if (_entry_token(parent_descriptor, temporary.name) != owned_token or
                _entry_token(parent_descriptor, path.name) != original_token):
            raise RecoveryError("%s changed before metadata replacement" % label)
        os.replace(
            temporary.name, path.name,
            src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor,
        )
        owned_token = None
        _event(failpoint, "after:replace:" + label)
        _sync_open_directory(parent_descriptor, failpoint, label)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if owned_token is not None and _entry_token(parent_descriptor, temporary.name) == owned_token:
            os.unlink(temporary.name, dir_fd=parent_descriptor)
        os.close(parent_descriptor)


def _atomic_bytes(path: Path, data: bytes, failpoint: Failpoint, label: str) -> None:
    if not isinstance(data, bytes) or len(data) > MAX_METADATA_BYTES:
        raise RecoveryError("%s exceeds the 1 MiB byte limit" % label)
    temporary = path.with_name(".%s.pending" % path.name)
    if temporary.parent != path.parent:
        raise RecoveryError("registration temporary path escaped its parent")
    parent_descriptor, parent_identity = _opened_directory(
        path.parent, label + " parent"
    )
    descriptor = -1
    owned_token = None
    try:
        original_token = _entry_token(parent_descriptor, path.name)
        if original_token is None:
            raise RecoveryError("%s target is absent" % label)
        before = os.stat(
            path.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _stat_token(before) != original_token
        ):
            raise RecoveryError(
                "%s target is not a single-linked regular file" % label
            )
        if _entry_token(parent_descriptor, temporary.name) is not None:
            # Reclaim our own leftover temporary the way `_atomic_json` and
            # `_write_immutable` do. A hard kill between O_EXCL creation and
            # os.replace leaves this file behind; refusing it would wedge every
            # later write to this config with no documented repair.
            temporary_details = os.stat(
                temporary.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if (not stat.S_ISREG(temporary_details.st_mode) or
                    temporary_details.st_nlink != 1):
                raise RecoveryError(
                    "owned %s temporary path has an unexpected type: %s"
                    % (label, temporary)
                )
            os.unlink(temporary.name, dir_fd=parent_descriptor)
            _sync_open_directory(
                parent_descriptor, failpoint, label + ":temporary-cleanup"
            )
        descriptor = os.open(
            temporary.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        owned_token = _stat_token(os.fstat(descriptor))
        _event(failpoint, "before:write:" + label)
        os.fchmod(descriptor, stat.S_IMODE(before.st_mode))
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RecoveryError("short byte write: %s" % label)
            view = view[written:]
        _event(failpoint, "after:write:" + label)
        _event(failpoint, "before:fsync-file:" + label)
        os.fsync(descriptor)
        _event(failpoint, "after:fsync-file:" + label)
        owned_token = _stat_token(os.fstat(descriptor))
        os.close(descriptor)
        descriptor = -1
        _event(failpoint, "before:replace:" + label)
        _require_open_directory(
            path.parent, parent_descriptor, parent_identity, label + " parent"
        )
        if (
            _entry_token(parent_descriptor, temporary.name) != owned_token
            or _entry_token(parent_descriptor, path.name) != original_token
        ):
            raise RecoveryError("%s target changed before replace" % label)
        os.replace(
            temporary.name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        owned_token = None
        _event(failpoint, "after:replace:" + label)
        _sync_open_directory(parent_descriptor, failpoint, label)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if (
            owned_token is not None
            and _entry_token(parent_descriptor, temporary.name) == owned_token
        ):
            os.unlink(temporary.name, dir_fd=parent_descriptor)
        os.close(parent_descriptor)


def _write_immutable(path: Path, data: bytes, failpoint: Failpoint, label: str) -> None:
    if not isinstance(data, bytes) or len(data) > MAX_METADATA_BYTES:
        raise RecoveryError("%s exceeds the 1 MiB metadata limit" % label)
    try:
        existing = read_regular(path, label)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if existing != data:
            raise RecoveryError("immutable %s already exists with different bytes" % label)
        _sync_directory(path.parent, failpoint, label + ":existing")
        return
    partial = path.with_name(path.name + ".partial")
    try:
        partial_details = partial.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(partial_details.st_mode) or partial_details.st_nlink != 1:
            raise RecoveryError("immutable %s partial path has an unexpected type" % label)
        partial.unlink()
        _sync_directory(path.parent, failpoint, label + ":partial-cleanup")
    _event(failpoint, "before:write-immutable:" + label)
    descriptor = os.open(str(partial), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RecoveryError("short immutable write: %s" % label)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _event(failpoint, "after:write-immutable:" + label)
    _event(failpoint, "before:replace-immutable:" + label)
    os.replace(partial, path)
    _event(failpoint, "after:replace-immutable:" + label)
    _sync_directory(path.parent, failpoint, label)


def _guard(plan: Dict[str, Any], lease: Any) -> None:
    facts = _lease_facts(lease, Path(plan["roots"]["state"]))
    if facts["root_identity"] != plan["root_identities"]["state"] or facts["lock_identity"] != plan["lock_identity"]:
        raise RecoveryError("validated lease identity differs from the plan")
    _root_identity_checks(plan)
    if retained_state_fingerprint(Path(facts["state_root"])) != plan["retained_state"]:
        raise RecoveryError("retained state changed during recovery")


def _rename(parent: Path, source: Path, destination: Path, plan: Dict[str, Any], lease: Any,
            failpoint: Failpoint, label: str,
            expected_sources: Sequence[Dict[str, Any]]) -> None:
    _guard(plan, lease)
    if source.parent != parent or destination.parent != parent:
        raise RecoveryError("cross-directory rename is not permitted")
    if destination.exists() or destination.is_symlink():
        raise RecoveryError("rename destination is occupied: %s" % destination)
    expected_parent = next(
        (unit["parent_identity"] for unit in plan["units"] if Path(unit["destination"]).parent == parent),
        None,
    )
    if expected_parent is None:
        raise RecoveryError("rename parent is outside the fixed unit set")
    if not any(state_matches(source, expected) for expected in expected_sources):
        raise RecoveryError("rename source differs from its planned state: %s" % source)
    descriptor, opened_identity = _opened_directory(parent, "unit parent")
    try:
        if opened_identity != expected_parent:
            raise RecoveryError("unit parent changed while opening it")
        source_token = _entry_token(descriptor, source.name)
        destination_token = _entry_token(descriptor, destination.name)
        _event(failpoint, "before:rename:" + label)
        _require_open_directory(parent, descriptor, expected_parent, "unit parent")
        if (_entry_token(descriptor, source.name) != source_token or
                _entry_token(descriptor, destination.name) != destination_token or
                destination_token is not None or
                not any(state_matches(source, expected) for expected in expected_sources)):
            raise RecoveryError("rename source or destination changed before mutation")
        os.replace(source.name, destination.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        _event(failpoint, "after:rename:" + label)
        _sync_open_directory(descriptor, failpoint, label)
    finally:
        os.close(descriptor)


def _copy_file(source: Path, destination: Path, expected: Dict[str, Any], failpoint: Failpoint,
               label: str, partial: Optional[Path] = None) -> None:
    partial = partial or destination.with_name(destination.name + ".partial")
    if partial.parent != destination.parent:
        raise RecoveryError("artifact partial path escaped its destination parent")
    source_before = source.lstat()
    if (stat.S_ISLNK(source_before.st_mode) or not stat.S_ISREG(source_before.st_mode) or
            source_before.st_nlink != 1):
        raise RecoveryError("recovery source is not a single-linked regular file")
    source_descriptor = os.open(str(source), os.O_RDONLY | os.O_NOFOLLOW)
    source_token = _stat_token(source_before)
    if _stat_token(os.fstat(source_descriptor)) != source_token:
        os.close(source_descriptor)
        raise RecoveryError("recovery source changed while opening")
    parent_descriptor, parent_identity = _opened_directory(
        destination.parent, label + " destination parent"
    )
    destination_descriptor = -1
    partial_token = None
    try:
        destination_token = _entry_token(parent_descriptor, destination.name)
        if _entry_token(parent_descriptor, partial.name) is not None:
            raise RecoveryError("artifact partial path is occupied")
        destination_descriptor = os.open(
            partial.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            expected["mode"],
            dir_fd=parent_descriptor,
        )
        partial_token = _stat_token(os.fstat(destination_descriptor))
        _event(failpoint, "before:copy-file:" + label)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise RecoveryError("short artifact write: %s" % label)
                view = view[written:]
        os.fchmod(destination_descriptor, expected["mode"])
        os.fsync(destination_descriptor)
        partial_token = _stat_token(os.fstat(destination_descriptor))
        if (digest.hexdigest() != expected["sha256"] or
                _stat_token(os.fstat(source_descriptor)) != source_token or
                _stat_token(source.lstat()) != source_token):
            raise RecoveryError("recovery source changed while copying")
        _event(failpoint, "after:copy-file:" + label)
        os.close(destination_descriptor)
        destination_descriptor = -1
        _event(failpoint, "before:replace-materialized-file:" + label)
        _require_open_directory(
            destination.parent, parent_descriptor, parent_identity,
            label + " destination parent",
        )
        if (_entry_token(parent_descriptor, partial.name) != partial_token or
                _entry_token(parent_descriptor, destination.name) != destination_token or
                _stat_token(source.lstat()) != source_token):
            raise RecoveryError("artifact source or destination changed before replacement")
        os.replace(
            partial.name, destination.name,
            src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor,
        )
        partial_token = None
        _event(failpoint, "after:replace-materialized-file:" + label)
        _sync_open_directory(parent_descriptor, failpoint, label + ":file-created")
    finally:
        os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        os.close(parent_descriptor)


def _partial_tree_is_known(stage: Path, expected: Dict[str, Any]) -> bool:
    try:
        actual = capture_state(stage, "directory")
    except RecoveryError:
        return False
    expected_map = {item["path"]: item for item in expected["artifacts"]}
    partial_paths = {
        str(PurePosixPath(item["path"]).with_name(PurePosixPath(item["path"]).name + ".partial"))
        for item in expected["artifacts"]
        if item["kind"] == "file"
    }
    for item in actual["artifacts"]:
        if item["path"] in partial_paths and item["kind"] == "file":
            continue
        if expected_map.get(item["path"]) != item:
            return False
    return actual["mode"] == expected["mode"]


def _clean_known_partials(stage: Path, expected: Dict[str, Any], failpoint: Failpoint,
                          label: str) -> None:
    stage_descriptor, stage_identity = _opened_directory(stage, label + " stage")
    try:
        _entries, directory_tokens = _snapshot_removal_tree(stage_descriptor, label)
        for item in expected["artifacts"]:
            if item["kind"] != "file":
                continue
            partial = (stage / item["path"]).with_name(
                Path(item["path"]).name + ".partial"
            )
            relative_parent = str(PurePosixPath(item["path"]).parent)
            if relative_parent != "." and relative_parent not in directory_tokens:
                continue
            parent_descriptor = _open_relative_directory(
                stage_descriptor,
                "." if relative_parent == "." else relative_parent,
                directory_tokens,
                label,
            )
            try:
                token = _entry_token(parent_descriptor, partial.name)
                if token is None:
                    continue
                details = os.stat(
                    partial.name, dir_fd=parent_descriptor, follow_symlinks=False
                )
                if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                    raise RecoveryError(
                        "owned partial path is not a regular file: %s" % partial
                    )
                _event(
                    failpoint,
                    "before:unlink-partial:" + label + ":" + item["path"],
                )
                _require_open_directory(
                    stage, stage_descriptor, stage_identity, label + " stage"
                )
                if _entry_token(parent_descriptor, partial.name) != token:
                    raise RecoveryError(
                        "owned partial changed before removal: %s" % partial
                    )
                os.unlink(partial.name, dir_fd=parent_descriptor)
                _event(
                    failpoint,
                    "after:unlink-partial:" + label + ":" + item["path"],
                )
                _sync_open_directory(
                    parent_descriptor, failpoint, label + ":partial-cleanup"
                )
            finally:
                os.close(parent_descriptor)
    finally:
        os.close(stage_descriptor)


def _remove_planned_partial(path: Path, plan: Dict[str, Any], lease: Any,
                            failpoint: Failpoint, label: str) -> None:
    if not (path.exists() or path.is_symlink()):
        return
    _guard(plan, lease)
    parent_descriptor, parent_identity = _opened_directory(
        path.parent, label + " parent"
    )
    try:
        token = _entry_token(parent_descriptor, path.name)
        details = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RecoveryError("planned partial path has unexpected content: %s" % path)
        _event(failpoint, "before:unlink-planned-partial:" + label)
        _require_open_directory(
            path.parent, parent_descriptor, parent_identity, label + " parent"
        )
        if _entry_token(parent_descriptor, path.name) != token:
            raise RecoveryError("planned partial changed before removal: %s" % path)
        os.unlink(path.name, dir_fd=parent_descriptor)
        _event(failpoint, "after:unlink-planned-partial:" + label)
        _sync_open_directory(
            parent_descriptor, failpoint, label + ":planned-partial-cleanup"
        )
    finally:
        os.close(parent_descriptor)


def _materialize(source: Path, stage: Path, expected: Dict[str, Any], plan: Dict[str, Any],
                 lease: Any, failpoint: Failpoint, label: str,
                 partial: Optional[Path] = None) -> None:
    _guard(plan, lease)
    if not state_matches(source, expected):
        raise RecoveryError("recovery source changed: %s" % source)
    if expected["kind"] == "file":
        if stage.exists() or stage.is_symlink():
            if state_matches(stage, expected):
                return
            raise RecoveryError("stage file contains unknown bytes")
        _copy_file(source, stage, expected, failpoint, label, partial)
        return
    if stage.exists() or stage.is_symlink():
        if state_matches(stage, expected):
            return
        _clean_known_partials(stage, expected, failpoint, label)
        if not _partial_tree_is_known(stage, expected):
            raise RecoveryError("stage payload contains unknown content")
    else:
        _event(failpoint, "before:mkdir:" + label)
        stage.mkdir(mode=expected["mode"])
        _event(failpoint, "after:mkdir:" + label)
        _sync_directory(stage.parent, failpoint, label + ":stage-created")
    expected_items = {item["path"]: item for item in expected["artifacts"]}
    directories = sorted(
        (item for item in expected["artifacts"] if item["kind"] == "directory"),
        key=lambda item: (len(PurePosixPath(item["path"]).parts), item["path"]),
    )
    for item in directories:
        path = stage / item["path"]
        if path.exists():
            continue
        _event(failpoint, "before:mkdir:" + label + ":" + item["path"])
        path.mkdir(mode=item["mode"])
        _event(failpoint, "after:mkdir:" + label + ":" + item["path"])
        _sync_directory(path.parent, failpoint, label + ":" + item["path"])
    for item in expected["artifacts"]:
        if item["kind"] != "file":
            continue
        destination = stage / item["path"]
        if destination.exists():
            continue
        source_file = source / item["path"]
        _guard(plan, lease)
        _copy_file(source_file, destination, item, failpoint, label + ":" + item["path"])
    for item in reversed(directories):
        _sync_directory(stage / item["path"], failpoint, label + ":" + item["path"])
    _sync_directory(stage, failpoint, label + ":stage-complete")
    if not state_matches(stage, expected):
        unknown = capture_state(stage, "directory")
        extra = sorted(set(x["path"] for x in unknown["artifacts"]) - set(expected_items))
        raise RecoveryError("materialized payload differs from plan: %s" % extra)


def _classify(path: Path, unit: Dict[str, Any]) -> List[str]:
    labels = []
    for name in ("initial", "prior", "target"):
        if state_matches(path, unit[name]):
            labels.append(name)
    if not labels and not path.exists() and not path.is_symlink():
        labels.append("absent")
    return labels


def _validate_unit_auxiliaries(unit: Dict[str, Any], goal: str) -> None:
    objects = {name: Path(value) for name, value in unit["objects"].items()}
    destination = Path(unit["destination"])
    backup = objects["backup"]
    if backup.exists() or backup.is_symlink():
        if not state_matches(backup, unit["initial"]):
            raise RecoveryError("%s backup differs from initial state" % unit["unit_id"])
    elif (unit["initial"]["exists"] and state_matches(destination, unit[goal])
          and unit["initial"] != unit[goal]):
        raise RecoveryError("%s reached its goal without its required initial backup" % unit["unit_id"])
    displaced = objects["displaced"]
    if displaced.exists() or displaced.is_symlink():
        if not any(state_matches(displaced, unit[name]) for name in ("prior", "target")):
            raise RecoveryError("%s displaced object contains unknown content" % unit["unit_id"])
    stage = objects["stage"]
    if stage.exists() or stage.is_symlink():
        expected = unit[goal]
        if not expected["exists"]:
            desired_known = False
        else:
            desired_known = state_matches(stage, expected) or (
                expected["kind"] == "directory" and _partial_tree_is_known(stage, expected)
            )
        prior_can_discard_target = goal == "prior" and unit["target"]["exists"] and (
            state_matches(stage, unit["target"]) or (
                unit["target"]["kind"] == "directory"
                and _partial_tree_is_known(stage, unit["target"])
            )
        )
        if not desired_known and not prior_can_discard_target:
            raise RecoveryError("%s stage contains unknown content" % unit["unit_id"])
    partial = objects["partial"]
    if partial.exists() or partial.is_symlink():
        details = partial.lstat()
        if (unit["target"]["kind"] != "file" or
                not stat.S_ISREG(details.st_mode) or details.st_nlink != 1):
            raise RecoveryError("%s planned partial contains unknown content" % unit["unit_id"])


def _snapshot_removal_tree(root_descriptor: int, label: str
                           ) -> Tuple[List[Dict[str, Any]], Dict[str, Tuple[int, int, int]]]:
    entries: List[Dict[str, Any]] = []
    root_details = os.fstat(root_descriptor)
    directories: Dict[str, Tuple[int, int, int]] = {
        ".": _stable_directory_token(root_details)
    }

    def visit(descriptor: int, relative_parent: str) -> None:
        with os.scandir(descriptor) as iterator:
            names = sorted(entry.name for entry in iterator)
        for name in names:
            details = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            relative = name if relative_parent == "." else relative_parent + "/" + name
            if stat.S_ISREG(details.st_mode) and details.st_nlink == 1:
                kind = "file"
                token = _stat_token(details)
            elif stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
                kind = "directory"
                token = _stable_directory_token(details)
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    if _stable_directory_token(os.fstat(child)) != token:
                        raise RecoveryError("%s stage changed while enumerating" % label)
                    directories[relative] = token
                    visit(child, relative)
                finally:
                    os.close(child)
            else:
                raise RecoveryError("%s stage contains unsupported content" % label)
            entries.append(
                {"relative": relative, "parent": relative_parent, "name": name,
                 "kind": kind, "token": token}
            )
            if len(entries) > MAX_ARTIFACTS * 2:
                raise RecoveryError("%s stage removal exceeds its bound" % label)

    visit(root_descriptor, ".")
    entries.sort(
        key=lambda item: (len(PurePosixPath(item["relative"]).parts), item["relative"]),
        reverse=True,
    )
    return entries, directories


def _stable_directory_token(details: os.stat_result) -> Tuple[int, int, int]:
    return (details.st_dev, details.st_ino, stat.S_IFMT(details.st_mode))


def _directory_entry_token(descriptor: int, name: str
                           ) -> Optional[Tuple[int, int, int]]:
    try:
        details = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return _stable_directory_token(details)


def _open_relative_directory(root_descriptor: int, relative: str,
                             identities: Dict[str, Tuple[int, int, int]], label: str) -> int:
    descriptor = os.dup(root_descriptor)
    current = "."
    try:
        for component in (() if relative == "." else PurePosixPath(relative).parts):
            expected = identities[current if current != "." else "."]
            details = os.fstat(descriptor)
            if _stable_directory_token(details) != expected:
                raise RecoveryError("%s stage parent changed during removal" % label)
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
            current = component if current == "." else current + "/" + component
            details = os.fstat(descriptor)
            if _stable_directory_token(details) != identities[current]:
                raise RecoveryError("%s stage parent changed during removal" % label)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _remove_owned_stage(stage: Path, expected: Dict[str, Any], plan: Dict[str, Any],
                        lease: Any, failpoint: Failpoint, label: str) -> None:
    _guard(plan, lease)
    parent_descriptor, parent_identity = _opened_directory(
        stage.parent, label + " parent"
    )
    stage_identity = _entry_identity(parent_descriptor, stage.name)
    if expected["kind"] == "file":
        try:
            if not state_matches(stage, expected):
                raise RecoveryError("%s is not the known disposable stage" % label)
            _event(failpoint, "before:unlink-stage:" + label)
            _require_open_directory(
                stage.parent, parent_descriptor, parent_identity, label + " parent"
            )
            if _entry_identity(parent_descriptor, stage.name) != stage_identity:
                raise RecoveryError("%s stage changed before removal" % label)
            os.unlink(stage.name, dir_fd=parent_descriptor)
            _event(failpoint, "after:unlink-stage:" + label)
            _sync_open_directory(parent_descriptor, failpoint, label + ":stage-removed")
            return
        finally:
            os.close(parent_descriptor)
    try:
        if not state_matches(stage, expected) and not _partial_tree_is_known(stage, expected):
            raise RecoveryError("%s is not the known disposable stage" % label)
        stage_descriptor = os.open(
            stage.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        try:
            opened_stage = os.fstat(stage_descriptor)
            if ((opened_stage.st_dev, opened_stage.st_ino, opened_stage.st_mode) !=
                    stage_identity):
                raise RecoveryError("%s stage changed while opening" % label)
            entries, directory_tokens = _snapshot_removal_tree(stage_descriptor, label)
            for entry in entries:
                event = (
                    "before:unlink-stage:" if entry["kind"] == "file"
                    else "before:rmdir-stage:"
                ) + label + ":" + entry["relative"]
                _event(failpoint, event)
                _require_open_directory(
                    stage.parent, parent_descriptor, parent_identity, label + " parent"
                )
                if _entry_identity(parent_descriptor, stage.name) != stage_identity:
                    raise RecoveryError("%s stage changed before bounded removal" % label)
                entry_parent = _open_relative_directory(
                    stage_descriptor, entry["parent"], directory_tokens, label
                )
                try:
                    observed_token = (
                        _entry_token(entry_parent, entry["name"])
                        if entry["kind"] == "file"
                        else _directory_entry_token(entry_parent, entry["name"])
                    )
                    if observed_token != entry["token"]:
                        raise RecoveryError("%s stage changed during bounded removal" % label)
                    if entry["kind"] == "file":
                        os.unlink(entry["name"], dir_fd=entry_parent)
                        after_event = "after:unlink-stage:"
                    else:
                        os.rmdir(entry["name"], dir_fd=entry_parent)
                        after_event = "after:rmdir-stage:"
                    _event(failpoint, after_event + label + ":" + entry["relative"])
                    _sync_open_directory(
                        entry_parent, failpoint, label + ":" + entry["relative"]
                    )
                finally:
                    os.close(entry_parent)
        finally:
            os.close(stage_descriptor)
        _event(failpoint, "before:rmdir-stage:" + label)
        _require_open_directory(
            stage.parent, parent_descriptor, parent_identity, label + " parent"
        )
        if _entry_identity(parent_descriptor, stage.name) != stage_identity:
            raise RecoveryError("%s stage changed before final removal" % label)
        os.rmdir(stage.name, dir_fd=parent_descriptor)
        _event(failpoint, "after:rmdir-stage:" + label)
        _sync_open_directory(parent_descriptor, failpoint, label + ":stage-removed")
    finally:
        os.close(parent_descriptor)


def _ensure_unit(unit: Dict[str, Any], goal: str, plan: Dict[str, Any], lease: Any,
                 failpoint: Failpoint) -> None:
    unit_id = unit["unit_id"]
    desired = unit[goal]
    destination = Path(unit["destination"])
    parent = destination.parent
    objects = {name: Path(value) for name, value in unit["objects"].items()}
    _guard(plan, lease)
    _validate_unit_auxiliaries(unit, goal)
    if desired["kind"] == "file":
        _remove_planned_partial(
            objects["partial"], plan, lease, failpoint,
            unit_id + ":planned-partial",
        )
    stage_is_desired = desired["exists"] and (
        state_matches(objects["stage"], desired) or (
            desired["kind"] == "directory" and _partial_tree_is_known(objects["stage"], desired)
        )
    )
    if (goal == "prior" and (objects["stage"].exists() or objects["stage"].is_symlink())
            and not stage_is_desired):
        _remove_owned_stage(
            objects["stage"], unit["target"], plan, lease, failpoint,
            unit_id + ":discard-target-stage",
        )
    if state_matches(destination, desired):
        if objects["stage"].exists() or objects["stage"].is_symlink():
            raise RecoveryError("%s has both active and staged goal objects" % unit_id)
        return
    labels = _classify(destination, unit)
    if not labels:
        raise RecoveryError("%s destination contains unknown content" % unit_id)
    backup = objects["backup"]
    if (backup.exists() or backup.is_symlink()) and "initial" in labels:
        raise RecoveryError("%s has duplicate active and backed-up initial content" % unit_id)
    if unit["initial"]["exists"] and "initial" in labels and not (backup.exists() or backup.is_symlink()):
        _rename(
            parent, destination, backup, plan, lease, failpoint,
            unit_id + ":preserve-initial", [unit["initial"]],
        )
    elif destination.exists() or destination.is_symlink():
        displaced = objects["displaced"]
        if displaced.exists() or displaced.is_symlink():
            if not any(state_matches(displaced, unit[name]) for name in ("prior", "target")):
                raise RecoveryError("%s displaced object contains unknown content" % unit_id)
            raise RecoveryError("%s has both an active and displaced known object" % unit_id)
        _rename(
            parent, destination, displaced, plan, lease, failpoint,
            unit_id + ":displace-active",
            [unit["initial"], unit["prior"], unit["target"]],
        )
    if desired["exists"]:
        source = objects[goal]
        stage = objects["stage"]
        _materialize(
            source, stage, desired, plan, lease, failpoint, unit_id + ":" + goal,
            objects["partial"] if desired["kind"] == "file" else None,
        )
        _rename(
            parent, stage, destination, plan, lease, failpoint,
            unit_id + ":activate-" + goal, [desired],
        )
    if not state_matches(destination, desired):
        raise RecoveryError("%s did not reach its selected state" % unit_id)


def _progress_path(plan_path: Path) -> Path:
    return plan_path.parent / "progress.json"


def _update_progress(path: Path, progress: Dict[str, Any], failpoint: Failpoint,
                     label: str) -> None:
    progress["sequence"] += 1
    _atomic_json(path, progress, failpoint, label)


def _publish_terminal_receipt(plan: Dict[str, Any], goal: str, state_root: Path,
                              failpoint: Failpoint) -> None:
    outcome = plan["outcomes"][goal]
    summary = outcome["committed"]
    if summary is None:
        raise RecoveryError("terminal outcome lacks a certifying receipt summary")
    receipt_data = plan["_receipt_data"][goal]
    if receipt_data is None:
        _verify_terminal_receipt(state_root, summary)
        return
    receipt = parse_json_bytes(receipt_data, "%s receipt" % goal)
    receipt_id = receipt["receipt_id"]
    manifest_path, support_path = _receipt_provenance_paths(state_root, receipt_id)
    _write_immutable(
        manifest_path, plan["_provenance_data"]["manifest"], failpoint,
        "%s-source-manifest" % goal,
    )
    _write_immutable(
        support_path, plan["_provenance_data"]["reader_support"], failpoint,
        "%s-reader-support" % goal,
    )
    receipt_path = state_root / ".council-lifecycle/v1/receipts" / (receipt_id + ".json")
    _write_immutable(receipt_path, receipt_data, failpoint, "%s-receipt" % goal)
    if sha256_file(receipt_path) != summary["receipt_sha256"]:
        raise RecoveryError("published %s receipt verification failed" % goal)
    _verify_terminal_receipt(state_root, summary)


def _terminal_result(admission: Dict[str, Any], state_root: Path, abort: bool,
                     lease_adapter: Any, failpoint: Failpoint = None) -> Dict[str, Any]:
    if abort:
        raise RecoveryError("a terminal transaction cannot be changed to prior")
    _lease_facts(lease_adapter, state_root)
    summary = admission["committed"]
    if summary is None:
        raise RecoveryError("terminal lifecycle marker has no certifying ownership receipt")
    receipt = _verify_terminal_receipt(state_root, summary)
    if admission["roots"] != receipt["roots"]:
        raise RecoveryError("terminal admission roots differ from the certifying receipt")
    if receipt["outcome"] != admission["status"]:
        raise RecoveryError("terminal receipt outcome differs from admission status")
    _sync_directory(
        state_root / ".council-lifecycle", failpoint, "terminal-admission-reconcile"
    )
    return {"status": admission["status"], "state_root": str(state_root), "verified": True,
            "receipt_id": summary["receipt_id"], "receipt_sha256": summary["receipt_sha256"]}


def _completed_outcome_result(outcome: Dict[str, Any], state_root: Path) -> Dict[str, Any]:
    result = {"status": outcome["status"], "state_root": str(state_root), "verified": True}
    if outcome["committed"] is not None:
        result.update(
            receipt_id=outcome["committed"]["receipt_id"],
            receipt_sha256=outcome["committed"]["receipt_sha256"],
        )
    return result


def _registration_progress_started(progress: Dict[str, Any]) -> bool:
    """Report whether a format-2 transaction has left its prepared state.

    This is the exact negation of the pristine journal `_prepare_transaction`
    requires before intent, so the prepared invocation stays usable for the one
    execution it was admitted for and is replay-rejected from then on.
    """
    return (
        progress["sequence"] != 0
        or progress["goal"] != "target"
        or any(unit["phase"] != "pending" for unit in progress["units"])
        or any(item["phase"] != "pending" for item in progress["registrations"])
    )


def _validate_quiescent_invocation(plan: Dict[str, Any], goal: str,
                                   decision: Any,
                                   progress: Any = None) -> None:
    if plan["plan_format"] not in (
        REGISTRATION_PLAN_FORMAT,
        NATIVE_PLAN_FORMAT,
    ):
        return
    if not isinstance(decision, dict):
        raise RecoveryError("registration recovery requires fresh quiescent admission")
    if plan["plan_format"] == REGISTRATION_PLAN_FORMAT:
        exact_keys(
            decision,
            ("confirmed", "plan_sha256", "invocation_id"),
            "quiescent invocation",
        )
        expected = plan["registration"]["quiescent_decision"]
        if (
            decision["confirmed"] is not True
            or decision["plan_sha256"] != expected["plan_sha256"]
            or goal not in plan["allowed_goals"]
        ):
            raise RecoveryError("quiescent invocation does not bind this plan and goal")
        checked_id(decision["invocation_id"], "quiescent invocation_id")
        if decision["invocation_id"] == expected["invocation_id"] and (
            not isinstance(progress, dict) or _registration_progress_started(progress)
        ):
            raise RecoveryError(
                "registration recovery requires a fresh quiescent invocation"
            )
        return
    exact_keys(
        decision,
        ("confirmed", "plan_sha256", "invocation_id", "sequence", "goal"),
        "native quiescent invocation",
    )
    expected = plan["native_registration"]["quiescent_decision"]
    if (
        decision["confirmed"] is not True
        or decision["plan_sha256"] != expected["plan_sha256"]
        or decision["goal"] != goal
        or goal not in plan["allowed_goals"]
        or not isinstance(progress, dict)
    ):
        raise RecoveryError("native quiescent invocation does not bind this plan")
    checked_id(decision["invocation_id"], "native quiescent invocation_id")
    sequence = exact_int(decision["sequence"], "native quiescent sequence")
    attempt = progress["native_registrations"][0]["attempts"][-1]
    if sequence != attempt["sequence"]:
        raise RecoveryError("native quiescent invocation sequence differs")
    if attempt["state"] != "prepared" and (
        decision["invocation_id"] == attempt["invocation_id"]
    ):
        raise RecoveryError("native recovery requires a fresh quiescent invocation")


def _registration_patch_bytes(data: bytes, patch: Dict[str, Any],
                              expected_sha256: str) -> bytes:
    start = patch["start"]
    end = patch["end"]
    if not 0 <= start <= end <= len(data):
        raise RecoveryError("registration patch bounds differ from current bytes")
    candidate = data[:start] + bytes.fromhex(patch["replacement_hex"]) + data[end:]
    if sha256_bytes(candidate) != expected_sha256:
        raise RecoveryError("registration patch does not produce its intended digest")
    return candidate


def _native_case_evidence(value: Any) -> Tuple[Any, ...]:
    if not isinstance(value, list):
        raise RecoveryError("native case evidence must be a list")
    result = []
    for item in value:
        if not isinstance(item, dict):
            raise RecoveryError("native case evidence must contain objects")
        exact_keys(
            item,
            ("case_id", "case_sha256", "packet_sha256", "evidence_kind"),
            "native case evidence",
        )
        result.append(
            (
                item["case_id"],
                item["case_sha256"],
                item["packet_sha256"],
                item["evidence_kind"],
            )
        )
    return tuple(result)


def _native_records(plan: Dict[str, Any], attempt: Any = None) -> Dict[str, Any]:
    extension = plan["native_registration"]
    core = extension["_core"]
    execution = extension["_execution"]
    execution_admission_reference = (
        attempt["execution_admission"]
        if isinstance(attempt, dict)
        else execution["execution_admission"]
    )
    attempt_binding_reference = (
        attempt["attempt_binding"]
        if isinstance(attempt, dict)
        else execution["attempt_binding"]
    )
    modules = plan["_native_modules"]
    qualification = modules["council_registration_qualification.py"]
    registration = modules["council_registration.py"]
    records = core["records"]
    implementation_value = records["implementation_identity"]["record"]
    formats = implementation_value["formats"]
    sources = implementation_value["source_sha256"]
    implementation = qualification.NativeImplementationIdentity(
        implementation_value["package_id"],
        implementation_value["runtime_cohort"],
        formats["plan"],
        formats["receipt"],
        formats["journal"],
        formats["recovery"],
        sources["council_recover.py"],
        sources["council_registration.py"],
        sources["council_registration_qualification.py"],
        sources["native_supervisor"],
        sources["native_observer"],
        sources["native_observer_policy"],
    )
    if implementation.digest() != records["implementation_identity"]["sha256"]:
        raise RecoveryError("native implementation record digest differs")
    policy_value = records["shape_policy"]["record"]
    policy = qualification.NativeShapePolicy(
        policy_value["format"],
        records["shape_policy"]["source_sha256"],
        tuple(policy_value["policies"]),
        False,
    )
    if policy.digest() != records["shape_policy"]["source_sha256"]:
        raise RecoveryError("native shape policy source digest differs")
    tuple_value = records["runtime_tuple"]["record"]
    runtime_tuple = qualification.RuntimeTuple(**tuple_value)
    if runtime_tuple.digest() != records["runtime_tuple"]["sha256"]:
        raise RecoveryError("native runtime tuple digest differs")
    support_value = dict(records["qualification_support"]["record"])
    support_value["case_evidence"] = _native_case_evidence(
        support_value["case_evidence"]
    )
    support = qualification.QualificationSupportDecision(**support_value)
    if support.digest() != records["qualification_support"]["sha256"]:
        raise RecoveryError("native support decision digest differs")
    admission = qualification.validate_qualification_admission(
        records["qualification_admission"]["record"],
        support,
        implementation,
        policy,
        runtime_tuple,
        core["operation"],
    )
    if admission.digest() != records["qualification_admission"]["sha256"]:
        raise RecoveryError("native qualification admission digest differs")
    execution_admission_value = dict(execution_admission_reference["record"])
    execution_admission_value["write_set"] = tuple(
        execution_admission_value["write_set"]
    )
    execution_admission_value["environment_keys"] = tuple(
        execution_admission_value["environment_keys"]
    )
    execution_admission = qualification.NativeExecutionAdmission(
        **execution_admission_value
    )
    if execution_admission.digest() != execution_admission_reference["sha256"]:
        raise RecoveryError("native execution admission digest differs")
    family_value = dict(execution["attempt_family"]["record"])
    for name in ("argv", "write_set", "environment_keys"):
        family_value[name] = tuple(family_value[name])
    family = qualification.NativeAttemptFamilyIdentity(**family_value)
    if family.digest() != execution["attempt_family"]["sha256"]:
        raise RecoveryError("native attempt family digest differs")
    binding_value = dict(attempt_binding_reference["record"])
    for name in ("argv", "write_set", "environment_keys"):
        binding_value[name] = tuple(binding_value[name])
    binding = qualification.NativeAttemptBinding(**binding_value)
    if binding.digest() != attempt_binding_reference["sha256"]:
        raise RecoveryError("native attempt binding digest differs")
    semantic = qualification.SemanticNativeResultIdentity(
        **execution["semantic_result_identity"]["record"]
    )
    if semantic.digest() != execution["semantic_result_identity"]["sha256"]:
        raise RecoveryError("native semantic result digest differs")
    if (
        binding.operation_id != execution["operation_id"]
        or binding.operation != core["operation"]
        or binding.source_path != core["source_path"]
        or binding.qualification_admission_sha256 != admission.digest()
        or binding.implementation_sha256 != implementation.digest()
        or binding.execution_admission_sha256 != execution_admission.digest()
        or binding.attempt_family_sha256 != family.digest()
        or semantic.attempt_family_sha256 != family.digest()
    ):
        raise RecoveryError("native v3 record closure differs")
    return {
        "registration": registration,
        "qualification": qualification,
        "implementation": implementation,
        "policy": policy,
        "runtime_tuple": runtime_tuple,
        "support": support,
        "qualification_admission": admission,
        "execution_admission": execution_admission,
        "family": family,
        "binding": binding,
        "semantic": semantic,
    }


def _validate_native_record_derivation(
    plan: Dict[str, Any], records: Dict[str, Any]
) -> None:
    binding = records["binding"]
    qualification = records["qualification"]
    registration = records["registration"]
    decision = plan["native_registration"]["quiescent_decision"]
    decision_sha256 = sha256_bytes(
        json.dumps(decision, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if (
        binding.quiescent_decision_sha256 != decision_sha256
        or records["execution_admission"].quiescent_decision_sha256
        != decision_sha256
    ):
        raise RecoveryError("native quiescent decision digest differs")
    data = read_regular(Path(binding.source_path), "native registration config")
    case = qualification.QualificationCase(
        (
            binding.runtime + "-add-absent"
            if binding.operation.endswith("_ensure")
            else binding.runtime + "-remove-present"
        ),
        binding.operation,
        records["runtime_tuple"].version,
        records["runtime_tuple"].os_name,
        records["runtime_tuple"].architecture,
        binding.prior_state,
        registration.ConfigDocument(
            binding.source_path, binding.source_scope, data
        ),
        registration.StdioSpec(
            binding.python_executable, binding.adapter_path
        ),
        binding.neutral_cwd,
        binding.expected_complement_sha256,
        binding.write_set,
    )
    expected_binding = qualification.build_native_attempt_binding(
        binding.operation_id,
        binding.sequence,
        binding.mode,
        case,
        records["execution_admission"],
        records["runtime_tuple"],
        records["qualification_admission"],
        records["support"],
        records["implementation"],
        records["policy"],
        records["family"],
        binding.previous_attempt_terminal_sha256,
    )
    expected_semantic = qualification.build_semantic_native_result_identity(
        expected_binding,
        records["execution_admission"].ownership,
        records["family"],
    )
    if expected_binding != binding or expected_semantic != records["semantic"]:
        raise RecoveryError("native attempt records are not derived from current inputs")


def _native_source_identity(path: Path) -> str:
    details = path.lstat()
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
    ):
        raise RecoveryError("native config must be a single-linked regular file")
    value = {
        "device": details.st_dev,
        "inode": details.st_ino,
        "owner_uid": details.st_uid,
        "mode": stat.S_IMODE(details.st_mode),
    }
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _native_observation(records: Dict[str, Any]) -> Tuple[Any, bytes]:
    binding = records["binding"]
    registration = records["registration"]
    path = Path(binding.source_path)
    data = read_regular(path, "native registration config")
    document = registration.ConfigDocument(
        binding.source_path, binding.source_scope, data
    )
    stdio = registration.StdioSpec(
        binding.python_executable, binding.adapter_path
    )
    if binding.runtime == "claude":
        observation = registration.observe_claude_config(
            document, stdio, scope_inputs_complete=True
        )
    else:
        observation = registration.observe_codex_config(
            document, stdio, layer_inputs_complete=True
        )
    return observation, data


def _native_semantic_classification(
    records: Dict[str, Any], observation: Any, data: bytes
) -> str:
    binding = records["binding"]
    semantic = records["semantic"]
    if (
        observation.state == semantic.intended_state
        and observation.entry_sha256 == semantic.intended_entry_sha256
        and observation.complement_sha256 == semantic.expected_complement_sha256
        and _native_source_identity(Path(binding.source_path))
        == binding.source_identity_sha256
    ):
        return "observed_target"
    if (
        sha256_bytes(data) == binding.source_sha256
        and observation.state == binding.prior_state
        and observation.entry_sha256 == binding.prior_entry_sha256
        and observation.complement_sha256 == binding.prior_complement_sha256
        and _native_source_identity(Path(binding.source_path))
        == binding.source_identity_sha256
    ):
        return "observed_prior"
    return "unknown"


def _native_result_record(
    records: Dict[str, Any], observation: Any, data: bytes, classification: str,
    *, reason: str
) -> Dict[str, Any]:
    binding = records["binding"]
    public_observation = observation.public_dict()
    return {
        "format": "council-native-v3-recovery-observation-v1",
        "operation_id": binding.operation_id,
        "sequence": binding.sequence,
        "attempt_binding_sha256": binding.digest(),
        "classification": classification,
        "reason": reason,
        "post_source_sha256": sha256_bytes(data),
        "post_observation_sha256": sha256_bytes(
            json.dumps(
                public_observation, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ),
        "post_entry_sha256": observation.entry_sha256,
        "post_complement_sha256": observation.complement_sha256,
        "qualification_claimed": False,
    }


def _native_result_reference(value: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "record": value,
        "sha256": sha256_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
    }


def _native_journal_path(plan: Dict[str, Any], operation_id: str,
                         sequence: int) -> Path:
    return Path(plan["_plan_path"]).parent / (
        "native-attempt-%s-%d.json" % (operation_id, sequence)
    )


def _native_runtime_matches(runtime_tuple: Any) -> bool:
    executable = Path(runtime_tuple.executable_path)
    try:
        return (
            executable.resolve(strict=True) == Path(runtime_tuple.executable_realpath)
            and sha256_file(executable) == runtime_tuple.executable_sha256
        )
    except (OSError, RecoveryError):
        return False


def _revalidate_native_inputs(plan: Dict[str, Any], records: Dict[str, Any]) -> None:
    binding = records["binding"]
    execution_admission = records["execution_admission"]
    observation, data = _native_observation(records)
    if (
        sha256_bytes(data) != binding.source_sha256
        or _native_source_identity(Path(binding.source_path))
        != binding.source_identity_sha256
        or observation.state != binding.prior_state
        or observation.entry_sha256 != binding.prior_entry_sha256
        or observation.complement_sha256 != binding.prior_complement_sha256
        or not _native_runtime_matches(records["runtime_tuple"])
        or execution_admission.state_root != plan["roots"]["state"]
        or execution_admission.payload_root != plan["roots"]["payload"]
    ):
        raise RecoveryError("native inputs changed before supervisor release")
    adapter = Path(binding.adapter_path)
    if not adapter.is_file() or adapter.is_symlink():
        raise RecoveryError("native adapter path changed")
    authority_path = Path(plan["roots"]["state"]) / records[
        "qualification_admission"
    ].fixed_relative_path
    details = authority_path.lstat()
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        raise RecoveryError("native qualification authority changed")
    authority, _ = read_object(authority_path, "native qualification authority")
    exact_keys(
        authority,
        (
            "format",
            "runtime_tuple",
            "qualification_support",
            "qualification_admission",
        ),
        "native qualification authority",
    )
    if (
        authority["format"] != "council-native-qualification-authority-v1"
        or authority["runtime_tuple"]
        != plan["native_registration"]["_core"]["records"]["runtime_tuple"][
            "record"
        ]
        or authority["qualification_support"]
        != plan["native_registration"]["_core"]["records"][
            "qualification_support"
        ]["record"]
        or authority["qualification_admission"]
        != records["qualification_admission"].public_dict()
    ):
        raise RecoveryError("native qualification authority differs from plan")


def _native_effects_method(effects: Any, name: str) -> Any:
    method = getattr(effects, name, None) if effects is not None else None
    if not callable(method):
        raise RecoveryError("qualified native supervisor/observer is unavailable")
    return method


def _process_generation(pid: int, pgid: int) -> str:
    result = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "pid=,pgid=,lstart="],
        cwd="/private/tmp",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
        start_new_session=True,
    )
    line = result.stdout.strip()
    fields = line.split(None, 2)
    if result.returncode != 0 or len(fields) != 3:
        raise RecoveryError("native supervisor process generation is unavailable")
    if int(fields[0]) != pid or int(fields[1]) != pgid:
        raise RecoveryError("native supervisor process generation differs")
    return sha256_bytes(line.encode("utf-8"))


def _process_group_members(pgid: int) -> List[Tuple[int, str]]:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid=,lstart="],
        cwd="/private/tmp",
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
        start_new_session=True,
    )
    if result.returncode != 0:
        raise RecoveryError("native process-group observer is unavailable")
    members = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        try:
            pid_value, pgid_value = int(fields[0]), int(fields[1])
        except ValueError:
            continue
        if pgid_value == pgid:
            members.append((pid_value, sha256_bytes(line.strip().encode("utf-8"))))
    return members


def _terminate_process_group(process: Any, pgid: int) -> None:
    """Signal and reap a stuck native supervisor group before unwinding.

    Escalates SIGTERM then SIGKILL and waits for the group to drain, so the
    caller never releases the recovery lease with a live writer behind it.
    """
    if pgid <= 0 or pgid == os.getpgrp():
        raise RecoveryError("native supervisor process group is not a separate session")
    for signal_number in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, signal_number)
        except OSError:
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                continue
            try:
                if not _process_group_members(pgid):
                    return
            except (OSError, subprocess.SubprocessError, RecoveryError):
                return
            time.sleep(0.05)


class _FixedNativeSupervisorEffects:
    """Closed native-v3 supervisor; evidence remains unqualified by default."""

    def __init__(self, plan: Dict[str, Any], records: Dict[str, Any],
                 lease: Any, environment: Optional[Dict[str, str]] = None):
        self.plan = plan
        self.records = records
        self.lease = lease
        self.environment = environment or {
            "HOME": records["execution_admission"].home,
            "LANG": os.environ.get("LANG", ""),
            "LC_ALL": os.environ.get("LC_ALL", ""),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": os.environ.get("TMPDIR", "/private/tmp"),
        }
        actual_environment_sha256 = sha256_bytes(
            json.dumps(
                self.environment, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        )
        if actual_environment_sha256 != records["binding"].environment_sha256:
            raise RecoveryError("native supervisor environment differs")
        self.handles = {}

    def arm_observer(self, binding: Any) -> Dict[str, Any]:
        session = sha256_bytes(
            (binding.digest() + ":" + os.urandom(32).hex()).encode("ascii")
        )
        return {
            "session_sha256": session,
            "implementation_sha256": self.records["implementation"].observer_sha256,
            "policy_sha256": binding.observer_policy_sha256,
            "armed_before_release": True,
            "complete": True,
        }

    def _runtime_directory(self, binding: Any) -> Path:
        return Path(self.plan["_plan_path"]).parent / (
            "native-runtime-%s-%d" % (binding.operation_id, binding.sequence)
        )

    def spawn_blocked(self, argv: Tuple[str, ...], binding: Any,
                      observer: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        directory = self._runtime_directory(binding)
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        request = {
            "format": "council-native-supervisor-request-v1",
            "argv": list(argv),
            "binding_sha256": binding.digest(),
            "operation_id": binding.operation_id,
            "sequence": binding.sequence,
            "plan_path": self.plan["_plan_path"],
            "cwd": binding.neutral_cwd,
            "state_root": self.plan["roots"]["state"],
            "lease_identity": self.plan["lock_identity"],
            "observer_session_sha256": observer["session_sha256"],
            "timeout_seconds": 60,
        }
        request_path = directory / "request.json"
        _write_immutable(request_path, json_bytes(request), None, "native-supervisor-request")
        read_gate, write_gate = os.pipe()
        os.set_inheritable(read_gate, True)
        state_root = Path(self.plan["roots"]["state"])
        lease_facts = _lease_facts(self.lease, state_root)
        # The supervisor only fstat-verifies this descriptor; it never locks it.
        # Passing the lease's own descriptor would share its open file
        # description, so `RecoveryLease.close()` would release the C1 flock for
        # a supervisor that is still running. Hand it an independent description
        # of the same file instead.
        lease_fd = os.open(str(state_root / "broker.lock"), os.O_RDONLY | os.O_NOFOLLOW)
        lease_details = os.fstat(lease_fd)
        if {
            "device": lease_details.st_dev,
            "inode": lease_details.st_ino,
        } != lease_facts["lock_identity"]:
            os.close(lease_fd)
            os.close(read_gate)
            os.close(write_gate)
            raise RecoveryError("broker lock identity changed before the native spawn")
        os.set_inheritable(lease_fd, True)
        try:
            process = subprocess.Popen(
                [
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-B",
                    str(Path(__file__).resolve()),
                    "native-supervisor",
                    "--request",
                    str(request_path),
                    "--gate-fd",
                    str(read_gate),
                    "--lease-fd",
                    str(lease_fd),
                ],
                cwd="/private/tmp",
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                pass_fds=(read_gate, lease_fd),
                start_new_session=True,
            )
        finally:
            os.close(lease_fd)
        os.close(read_gate)
        ready_path = directory / "ready.json"
        deadline = time.monotonic() + 10
        while not ready_path.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                os.close(write_gate)
                raise RecoveryError("native supervisor did not reach its blocked gate")
            time.sleep(0.01)
        if process.poll() is not None and not ready_path.exists():
            os.close(write_gate)
            diagnostic = process.stderr.read(500).decode("utf-8", "replace")
            raise RecoveryError(
                "native supervisor exited before its blocked gate: " + diagnostic
            )
        ready, _ = read_object(ready_path, "native supervisor ready record")
        exact_keys(
            ready,
            (
                "format",
                "pid",
                "pgid",
                "start_generation_sha256",
                "attempt_lock_identity",
                "observer_session_sha256",
            ),
            "native supervisor ready record",
        )
        if ready["format"] != "council-native-supervisor-ready-v1":
            os.close(write_gate)
            raise RecoveryError("native supervisor ready format is unsupported")
        supervisor = {key: ready[key] for key in ready if key != "format"}
        _validate_native_supervisor(supervisor)
        handle = {
            "process": process,
            "gate": write_gate,
            "directory": directory,
            "supervisor": supervisor,
        }
        self.handles[process.pid] = handle
        return handle, supervisor

    def release_and_wait(self, handle: Dict[str, Any], binding: Any) -> Any:
        gate = handle.pop("gate")
        os.write(gate, b"1")
        os.close(gate)
        process = handle["process"]
        try:
            process.wait(timeout=70)
        except subprocess.TimeoutExpired:
            # Terminate and reap before returning. `launch_once` raises on the
            # unconfirmed-absence that follows, and that exception unwinds out of
            # the recovery lease - releasing the C1 lock while a supervisor and
            # its vendor child could still be mutating the config.
            _terminate_process_group(process, handle["supervisor"]["pgid"])
            return self.records["qualification"].LaunchReceipt(
                binding.runtime + ("-add-absent" if binding.operation.endswith("_ensure") else "-remove-present"),
                binding.argv,
                self.records["runtime_tuple"].digest(),
                "timeout",
                "surviving",
                binding.digest(),
                "unobserved",
                binding.observer_policy_sha256,
                None,
                True,
                False,
                b"",
                b"",
            )
        result, _ = read_object(
            handle["directory"] / "result.json", "native supervisor result"
        )
        process.stderr.close()
        exact_keys(
            result,
            (
                "format",
                "returncode",
                "process_state",
                "process_generation_sha256",
                "network_state",
                "network_evidence_sha256",
                "timed_out",
            ),
            "native supervisor result",
        )
        returncode = result["returncode"]
        result_kind = "signal" if returncode is not None and returncode < 0 else "exit"
        return self.records["qualification"].LaunchReceipt(
            binding.runtime + ("-add-absent" if binding.operation.endswith("_ensure") else "-remove-present"),
            binding.argv,
            self.records["runtime_tuple"].digest(),
            result_kind,
            result["process_state"],
            result["process_generation_sha256"],
            result["network_state"],
            result["network_evidence_sha256"],
            returncode,
            result["timed_out"],
            False,
            b"",
            b"",
        )

    def positive_absence(self, supervisor: Dict[str, Any]) -> bool:
        try:
            members = _process_group_members(supervisor["pgid"])
        except (OSError, subprocess.SubprocessError, RecoveryError):
            return False
        if members:
            return False
        binding = self.records["binding"]
        lock_path = self._runtime_directory(binding) / "attempt.lock"
        try:
            descriptor = os.open(str(lock_path), os.O_RDWR | os.O_NOFOLLOW)
        except OSError:
            return False
        try:
            details = os.fstat(descriptor)
            if {
                "device": details.st_dev,
                "inode": details.st_ino,
            } != supervisor["attempt_lock_identity"]:
                return False
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            finally:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            os.close(descriptor)
        return True

    def observe_once(self, binding: Any) -> Any:
        observation, data = _native_observation(self.records)
        document = self.records["registration"].ConfigDocument(
            binding.source_path, binding.source_scope, data
        )
        return self.records["qualification"].ObservationReceipt(
            binding.runtime + ("-add-absent" if binding.operation.endswith("_ensure") else "-remove-present"),
            document,
            self.records["runtime_tuple"],
            observation.complement_sha256,
            binding.write_set,
            False,
        )


def _native_supervisor_main(request_path: Path, gate_fd: int,
                            lease_fd: int) -> int:
    request_path = Path(request_path).resolve(strict=True)
    directory = request_path.parent
    details = directory.lstat()
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISDIR(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_uid != os.getuid()
    ):
        raise RecoveryError("native supervisor directory is unsafe")
    request, _ = read_object(request_path, "native supervisor request")
    exact_keys(
        request,
        (
            "format",
            "argv",
            "binding_sha256",
            "operation_id",
            "sequence",
            "plan_path",
            "cwd",
            "state_root",
            "lease_identity",
            "observer_session_sha256",
            "timeout_seconds",
        ),
        "native supervisor request",
    )
    if request["format"] != "council-native-supervisor-request-v1":
        raise RecoveryError("native supervisor request format is unsupported")
    argv = request["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(item, str) and item for item in argv)
    ):
        raise RecoveryError("native supervisor argv is invalid")
    checked_hash(request["binding_sha256"], "native supervisor binding sha256")
    checked_id(request["operation_id"], "native supervisor operation_id")
    exact_int(request["sequence"], "native supervisor sequence")
    plan_path = checked_absolute(request["plan_path"], "native supervisor plan path")
    checked_absolute(request["cwd"], "native supervisor cwd")
    checked_absolute(request["state_root"], "native supervisor state root")
    validate_identity(request["lease_identity"], "native supervisor lease identity")
    checked_hash(
        request["observer_session_sha256"],
        "native supervisor observer session sha256",
    )
    timeout_seconds = exact_int(
        request["timeout_seconds"], "native supervisor timeout", 1
    )
    if timeout_seconds > 300:
        raise RecoveryError("native supervisor timeout exceeds its bound")
    if directory.parent != plan_path.parent:
        raise RecoveryError("native supervisor directory differs from its plan")
    plan, _plan_data, _receipt, _receipt_data = validate_plan(
        plan_path, pre_intent=False
    )
    if plan["plan_format"] != NATIVE_PLAN_FORMAT:
        raise RecoveryError("native supervisor requires a native-v3 plan")
    supervisor_progress, _ = read_object(
        _progress_path(plan_path), "native supervisor progress"
    )
    _validate_progress(
        supervisor_progress, plan, sha256_file(plan_path)
    )
    supervisor_attempt = supervisor_progress["native_registrations"][0][
        "attempts"
    ][-1]
    records = _native_records(plan, supervisor_attempt)
    binding = records["binding"]
    if (
        request["binding_sha256"] != binding.digest()
        or request["operation_id"] != binding.operation_id
        or request["sequence"] != binding.sequence
        or request["argv"] != list(binding.argv)
        or request["cwd"] != binding.neutral_cwd
        or request["state_root"] != plan["roots"]["state"]
    ):
        raise RecoveryError("native supervisor request differs from its plan")
    lease_details = os.fstat(lease_fd)
    if {
        "device": lease_details.st_dev,
        "inode": lease_details.st_ino,
    } != request["lease_identity"]:
        raise RecoveryError("native supervisor inherited lease differs")
    pid = os.getpid()
    pgid = os.getpgid(pid)
    if pid != pgid:
        raise RecoveryError("native supervisor is not its process-group leader")
    lock_path = directory / "attempt.lock"
    lock_fd = os.open(
        str(lock_path), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        lock_details = os.fstat(lock_fd)
        generation = _process_generation(pid, pgid)
        ready = {
            "format": "council-native-supervisor-ready-v1",
            "pid": pid,
            "pgid": pgid,
            "start_generation_sha256": generation,
            "attempt_lock_identity": {
                "device": lock_details.st_dev,
                "inode": lock_details.st_ino,
            },
            "observer_session_sha256": request["observer_session_sha256"],
        }
        _atomic_json(directory / "ready.json", ready, None, "native-supervisor-ready")
        release = os.read(gate_fd, 1)
        os.close(gate_fd)
        if release != b"1":
            return 0
        vendor = subprocess.Popen(
            argv,
            cwd=request["cwd"],
            env={key: os.environ.get(key, "") for key in (
                "HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"
            )},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        timed_out = False
        try:
            returncode = vendor.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = vendor.wait()
        deadline = time.monotonic() + 10
        process_state = "surviving"
        while time.monotonic() < deadline:
            members = [item for item in _process_group_members(pgid) if item[0] != pid]
            if not members:
                process_state = "terminated"
                break
            time.sleep(0.05)
        result = {
            "format": "council-native-supervisor-result-v1",
            "returncode": returncode,
            "process_state": process_state,
            "process_generation_sha256": generation,
            "network_state": "unobserved",
            "network_evidence_sha256": request["observer_session_sha256"],
            "timed_out": timed_out,
        }
        _atomic_json(directory / "result.json", result, None, "native-supervisor-result")
        return 0
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _execute_native_attempt(
    plan: Dict[str, Any], progress: Dict[str, Any], progress_path: Path,
    records: Dict[str, Any], lease: Any, failpoint: Failpoint,
    effects: Any,
) -> str:
    item = progress["native_registrations"][0]["attempts"][-1]
    binding = records["binding"]
    qualification = records["qualification"]
    if item["state"] != "prepared":
        raise RecoveryError("native attempt sequence is not prepared")
    _revalidate_native_inputs(plan, records)
    _guard(plan, lease)
    arm_observer = _native_effects_method(effects, "arm_observer")
    spawn_blocked = _native_effects_method(effects, "spawn_blocked")
    release_and_wait = _native_effects_method(effects, "release_and_wait")
    positive_absence = _native_effects_method(effects, "positive_absence")
    observe_once = _native_effects_method(effects, "observe_once")

    def journal_before_spawn(journal: Dict[str, Any], digest: str) -> str:
        _guard(plan, lease)
        if item["state"] != "prepared" or item["sequence"] != binding.sequence:
            raise RecoveryError("native journal sequence changed")
        path = _native_journal_path(plan, binding.operation_id, binding.sequence)
        _write_immutable(path, json_bytes(journal), failpoint, "native-attempt-journal")
        if sha256_file(path) != sha256_bytes(json_bytes(journal)):
            raise RecoveryError("native attempt journal verification failed")
        item["journal_sha256"] = digest
        item["state"] = "issued"
        _update_progress(progress_path, progress, failpoint, "native:issued")
        return digest

    def launch_once(argv: Tuple[str, ...], supplied_binding: Any) -> Any:
        _guard(plan, lease)
        if supplied_binding != binding or item["state"] != "issued":
            raise RecoveryError("native launch binding changed")
        observer = arm_observer(binding)
        if not isinstance(observer, dict):
            raise RecoveryError("native observer session is invalid")
        exact_keys(
            observer,
            (
                "session_sha256",
                "implementation_sha256",
                "policy_sha256",
                "armed_before_release",
                "complete",
            ),
            "native observer session",
        )
        if (
            observer["implementation_sha256"]
            != records["implementation"].observer_sha256
            or observer["policy_sha256"] != binding.observer_policy_sha256
            or observer["armed_before_release"] is not True
            or observer["complete"] is not True
        ):
            raise RecoveryError("native observer is not complete and admitted")
        checked_hash(observer["session_sha256"], "native observer session sha256")
        handle, supervisor = spawn_blocked(tuple(argv), binding, dict(observer))
        _validate_native_supervisor(supervisor)
        if supervisor["observer_session_sha256"] != observer["session_sha256"]:
            raise RecoveryError("native supervisor observer session differs")
        item["supervisor"] = supervisor
        item["state"] = "spawn_generation_recorded"
        _update_progress(
            progress_path, progress, failpoint, "native:spawn-generation-recorded"
        )
        _guard(plan, lease)
        _revalidate_native_inputs(plan, records)
        item["state"] = "release_authorized"
        _update_progress(
            progress_path, progress, failpoint, "native:release-authorized"
        )
        launch = release_and_wait(handle, binding)
        if positive_absence(supervisor) is not True:
            raise RecoveryError("native process group termination is unconfirmed")
        if isinstance(launch, qualification.LaunchReceipt):
            return launch
        try:
            launch_value = dict(launch.__dict__)
            launch_value["argv"] = tuple(launch_value["argv"])
            return qualification.LaunchReceipt(**launch_value)
        except (AttributeError, TypeError, ValueError) as error:
            raise RecoveryError("native supervisor returned an invalid receipt") from error

    def copied_observation(supplied_binding: Any) -> Any:
        observed = observe_once(supplied_binding)
        if isinstance(observed, qualification.ObservationReceipt):
            return observed
        try:
            after = records["registration"].ConfigDocument(
                observed.after.path,
                observed.after.scope,
                bytes(observed.after.content),
            )
            runtime_after = qualification.RuntimeTuple(
                **observed.runtime_tuple_after.public_dict()
            )
            return qualification.ObservationReceipt(
                observed.case_id,
                after,
                runtime_after,
                observed.independent_complement_sha256,
                tuple(observed.changed_paths),
                observed.sentinel_started,
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise RecoveryError("native observer returned an invalid receipt") from error

    result = qualification.run_admitted_attempt(
        binding,
        records["semantic"],
        records["family"],
        records["qualification_admission"],
        records["support"],
        records["implementation"],
        records["policy"],
        qualification.QualificationCase(
            (
                binding.runtime + "-add-absent"
                if binding.operation.endswith("_ensure")
                else binding.runtime + "-remove-present"
            ),
            binding.operation,
            records["runtime_tuple"].version,
            records["runtime_tuple"].os_name,
            records["runtime_tuple"].architecture,
            binding.prior_state,
            records["registration"].ConfigDocument(
                binding.source_path,
                binding.source_scope,
                read_regular(Path(binding.source_path), "native registration config"),
            ),
            records["registration"].StdioSpec(
                binding.python_executable, binding.adapter_path
            ),
            binding.neutral_cwd,
            binding.expected_complement_sha256,
            binding.write_set,
        ),
        records["execution_admission"],
        records["runtime_tuple"],
        journal_before_spawn,
        launch_once,
        copied_observation,
    )
    _event(failpoint, "after:native-attempt-result")
    classification = result["classification"]
    item["state"] = classification
    item["result"] = _native_result_reference(result)
    _update_progress(progress_path, progress, failpoint, "native:" + classification)
    if classification != "observed_target":
        raise RecoveryError("native attempt did not reach its admitted target")
    return classification


def _ensure_registration(operation: Dict[str, Any], goal: str,
                         plan: Dict[str, Any], lease: Any,
                         failpoint: Failpoint) -> None:
    path = Path(operation["source_path"])
    data = read_regular(path, "registration config")
    current_sha256 = sha256_bytes(data)
    desired_sha256 = operation[goal + "_sha256"]
    if current_sha256 == desired_sha256:
        return
    other_goal = "prior" if goal == "target" else "target"
    if current_sha256 != operation[other_goal + "_sha256"]:
        # Adopting an unrecognized config would silently certify bytes no plan
        # ever approved, so this stays a refusal. Name the file and all three
        # digests instead, so the operator can see which edit has to be undone.
        raise RecoveryError(
            "registration config is neither prior nor intended: %s; %s observed "
            "%s, expected target %s or prior %s; restore one of those exact "
            "byte sequences, then re-run recovery"
            % (
                operation["operation_id"],
                path,
                current_sha256,
                operation["target_sha256"],
                operation["prior_sha256"],
            )
        )
    patch = (
        operation["forward_patch"] if goal == "target" else operation["inverse_patch"]
    )
    if patch is None:
        raise RecoveryError("registration no-op has unexpected config drift")
    candidate = _registration_patch_bytes(data, patch, desired_sha256)
    _guard(plan, lease)
    _atomic_bytes(
        path,
        candidate,
        failpoint,
        "registration:%s:%s" % (operation["operation_id"], goal),
    )
    _guard(plan, lease)
    if sha256_file(path) != desired_sha256:
        raise RecoveryError("registration config verification failed")


def _native_sequence_decision(
    plan: Dict[str, Any], decision: Dict[str, Any]
) -> Dict[str, Any]:
    initial = plan["native_registration"]["quiescent_decision"]
    return {
        "plan_sha256": initial["plan_sha256"],
        "invocation_id": decision["invocation_id"],
        "sequence": decision["sequence"],
        "goal": decision["goal"],
        "hosts": list(initial["hosts"]),
        "files": list(initial["files"]),
        "closed_and_no_competing_writer": initial[
            "closed_and_no_competing_writer"
        ],
    }


def _append_native_sequence_one(
    plan: Dict[str, Any], progress: Dict[str, Any], progress_path: Path,
    decision: Dict[str, Any], lease: Any, failpoint: Failpoint,
    native_effects: Any,
) -> None:
    operation_progress = progress["native_registrations"][0]
    attempts = operation_progress["attempts"]
    if len(attempts) != 1:
        raise RecoveryError("native attempt family is exhausted")
    prior = attempts[0]
    if prior["state"] != "observed_prior" or prior["result"] is None:
        raise RecoveryError("native sequence one requires terminal observed prior")
    if not isinstance(decision, dict):
        raise RecoveryError("native sequence one requires fresh quiescent admission")
    exact_keys(
        decision,
        ("confirmed", "plan_sha256", "invocation_id", "sequence", "goal"),
        "native sequence-one invocation",
    )
    if (
        decision["confirmed"] is not True
        or decision["plan_sha256"]
        != plan["native_registration"]["quiescent_decision"]["plan_sha256"]
        or decision["sequence"] != 1
        or decision["goal"] != "target"
        or decision["invocation_id"] == prior["invocation_id"]
    ):
        raise RecoveryError("native sequence-one invocation is not fresh and exact")
    checked_id(decision["invocation_id"], "native sequence-one invocation_id")
    records = _native_records(plan, prior)
    observation, data = _native_observation(records)
    if _native_semantic_classification(records, observation, data) != "observed_prior":
        raise RecoveryError("native prior identity changed before sequence one")
    if prior["supervisor"] is not None:
        positive_absence = _native_effects_method(
            native_effects, "positive_absence"
        )
        if positive_absence(prior["supervisor"]) is not True:
            raise RecoveryError("native prior process group termination is unconfirmed")
    _guard(plan, lease)
    _revalidate_native_inputs(plan, records)
    complete_decision = _native_sequence_decision(plan, decision)
    decision_sha256 = sha256_bytes(
        json.dumps(
            complete_decision, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )
    previous_terminal_sha256 = _native_terminal_summary_digest(
        operation_progress["attempt_family"]["sha256"], prior
    )
    qualification = records["qualification"]
    execution_zero = records["execution_admission"]
    execution_one = qualification.NativeExecutionAdmission(
        "native-recovery-" + decision_sha256[:24],
        execution_zero.operation,
        execution_zero.runtime,
        execution_zero.state_root,
        execution_zero.home,
        execution_zero.payload_root,
        execution_zero.config_path,
        True,
        execution_zero.source_identity_sha256,
        execution_zero.ownership,
        execution_zero.neutral_cwd,
        execution_zero.write_set,
        execution_zero.environment_keys,
        execution_zero.environment_sha256,
        execution_zero.observer_policy_sha256,
        decision_sha256,
        execution_zero.owner_authority,
        True,
    )
    binding_zero = records["binding"]
    case = qualification.QualificationCase(
        (
            binding_zero.runtime + "-add-absent"
            if binding_zero.operation.endswith("_ensure")
            else binding_zero.runtime + "-remove-present"
        ),
        binding_zero.operation,
        records["runtime_tuple"].version,
        records["runtime_tuple"].os_name,
        records["runtime_tuple"].architecture,
        binding_zero.prior_state,
        records["registration"].ConfigDocument(
            binding_zero.source_path, binding_zero.source_scope, data
        ),
        records["registration"].StdioSpec(
            binding_zero.python_executable, binding_zero.adapter_path
        ),
        binding_zero.neutral_cwd,
        binding_zero.expected_complement_sha256,
        binding_zero.write_set,
    )
    binding_one = qualification.build_native_attempt_binding(
        binding_zero.operation_id,
        1,
        binding_zero.mode,
        case,
        execution_one,
        records["runtime_tuple"],
        records["qualification_admission"],
        records["support"],
        records["implementation"],
        records["policy"],
        records["family"],
        previous_terminal_sha256,
    )
    sequence = {
        "sequence": 1,
        "invocation_id": decision["invocation_id"],
        "state": "prepared",
        "journal_sha256": None,
        "supervisor": None,
        "result": None,
        "execution_admission": _native_result_reference(
            execution_one.public_dict()
        ),
        "attempt_binding": _native_result_reference(binding_one.public_dict()),
        "previous_attempt_terminal_sha256": previous_terminal_sha256,
    }
    attempts.append(sequence)
    progress["current_attempt_sequence"] = 1
    _update_progress(
        progress_path, progress, failpoint, "native:append-sequence-one"
    )


def check_plan(plan_path: Path) -> Dict[str, Any]:
    plan, plan_data, _receipt, receipt_data = validate_plan(plan_path, pre_intent=True)
    result = {
        "status": "plan-valid",
        "transaction_id": plan["transaction_id"],
        "plan_sha256": sha256_bytes(plan_data),
        "receipt_sha256": sha256_bytes(receipt_data),
        "units": list(UNIT_IDS),
        "allowed_goals": plan["allowed_goals"],
    }
    if plan["plan_format"] == REGISTRATION_PLAN_FORMAT:
        result["registration_plan_sha256"] = plan["registration"][
            "execution_preview"
        ]["sha256"]
        result["registration_operations"] = [
            item["operation_id"] for item in plan["registration"]["operations"]
        ]
    if plan["_receipt_data"]["prior"] is not None:
        result["prior_receipt_sha256"] = sha256_bytes(plan["_receipt_data"]["prior"])
    return result


def _execute_with_lease(state_root: Path, lease_adapter: Any, *, abort: bool = False,
                        failpoint: Failpoint = None,
                        quiescent_decision: Any = None,
                        native_effects: Any = None) -> Dict[str, Any]:
    state_root = Path(state_root).resolve(strict=True)
    facts = _lease_facts(lease_adapter, state_root)
    admission_path = state_root / ".council-lifecycle/admission.json"
    current, _current_data = read_object(admission_path, "admission")
    current = validate_admission(current)
    if current["roots"]["state"] != str(state_root):
        raise RecoveryError("admission state root differs from the requested root")
    if current["status"] != "recovery_required":
        return _terminal_result(current, state_root, abort, lease_adapter, failpoint)
    transaction_id = current["transaction_id"]
    plan_path = state_root / ".council-lifecycle/v1/transactions" / transaction_id / "plan.json"
    plan, plan_data, _receipt, _receipt_data = validate_plan(plan_path, pre_intent=False)
    if plan["transaction_id"] != transaction_id or plan["prior_admission"]["committed"] != current["committed"]:
        raise RecoveryError("pending admission does not bind the prepared plan")
    if current["roots"] != plan["roots"]:
        raise RecoveryError("pending admission roots differ from the prepared plan")
    if plan["root_identities"]["state"] != facts["root_identity"] or plan["lock_identity"] != facts["lock_identity"]:
        raise RecoveryError("held recovery lease differs from the plan")
    progress_path = _progress_path(plan_path)
    progress, _ = read_object(progress_path, "progress")
    progress = _validate_progress(progress, plan, sha256_bytes(plan_data))
    select_prior = False
    if abort:
        if plan["plan_format"] == NATIVE_PLAN_FORMAT:
            raise RecoveryError(
                "native abort requires a separately admitted inverse transaction"
            )
        if "prior" not in plan["allowed_goals"]:
            raise RecoveryError("this transaction has no validated prior outcome")
        if progress["goal"] != "prior":
            # Select the prior goal in memory only. The journal write is deferred
            # until after `_validate_quiescent_invocation`, so a missing or stale
            # confirmation on `--abort` makes no progress write and cannot invert
            # the goal the next recovery reads.
            progress["goal"] = "prior"
            for unit in progress["units"]:
                unit["phase"] = "pending"
            for registration in progress.get("registrations", []):
                registration["phase"] = "pending"
            select_prior = True
    goal = progress["goal"]
    native_operation_progress = (
        progress["native_registrations"][0]
        if plan["plan_format"] == NATIVE_PLAN_FORMAT
        else None
    )
    native_progress = (
        native_operation_progress["attempts"][-1]
        if native_operation_progress is not None
        else None
    )
    native_records = (
        _native_records(plan, native_progress)
        if native_progress is not None
        else None
    )
    if native_records is not None and native_effects is None:
        native_effects = _FixedNativeSupervisorEffects(
            plan, native_records, lease_adapter
        )
    if (
        native_progress is not None
        and isinstance(quiescent_decision, dict)
        and quiescent_decision.get("sequence") == 1
        and native_progress["sequence"] == 0
    ):
        _append_native_sequence_one(
            plan,
            progress,
            progress_path,
            quiescent_decision,
            lease_adapter,
            failpoint,
            native_effects,
        )
        native_progress = native_operation_progress["attempts"][-1]
        native_records = _native_records(plan, native_progress)
        if isinstance(native_effects, _FixedNativeSupervisorEffects):
            native_effects = _FixedNativeSupervisorEffects(
                plan, native_records, lease_adapter
            )
    _validate_quiescent_invocation(plan, goal, quiescent_decision, progress)
    if select_prior:
        _update_progress(progress_path, progress, failpoint, "progress:select-prior")
    registration_operations = (
        plan["registration"]["operations"]
        if plan["plan_format"] == REGISTRATION_PLAN_FORMAT
        else []
    )
    registration_progress = {
        item["operation_id"]: item for item in progress.get("registrations", [])
    }

    def ensure_native_target() -> None:
        if native_records is None:
            return
        if goal != "target":
            raise RecoveryError(
                "native abort requires a separately admitted inverse transaction"
            )
        observation, data = _native_observation(native_records)
        classification = _native_semantic_classification(
            native_records, observation, data
        )
        state = native_progress["state"]
        if classification == "observed_target":
            if state in {
                "spawn_generation_recorded",
                "release_authorized",
            }:
                positive_absence = _native_effects_method(
                    native_effects, "positive_absence"
                )
                if positive_absence(native_progress["supervisor"]) is not True:
                    raise RecoveryError(
                        "native process group termination is unconfirmed"
                    )
            result = _native_result_record(
                native_records,
                observation,
                data,
                classification,
                reason="passive-target-verification",
            )
            native_progress["state"] = "observed_target"
            native_progress["result"] = _native_result_reference(result)
            _update_progress(
                progress_path, progress, failpoint, "native:observed-target"
            )
            return
        if classification == "observed_prior" and state == "prepared":
            _execute_native_attempt(
                plan,
                progress,
                progress_path,
                native_records,
                lease_adapter,
                failpoint,
                native_effects,
            )
            return
        result = _native_result_record(
            native_records,
            observation,
            data,
            classification,
            reason=(
                "new-sequence-required"
                if classification == "observed_prior"
                else "passive-state-unknown"
            ),
        )
        native_progress["state"] = classification
        native_progress["result"] = _native_result_reference(result)
        _update_progress(
            progress_path, progress, failpoint, "native:" + classification
        )
        if classification == "observed_prior":
            raise RecoveryError("native recovery requires a fresh admitted sequence")
        raise RecoveryError("native registration state is unknown")

    if native_records is not None and native_records["semantic"].intended_state == "absent":
        ensure_native_target()
    for operation in registration_operations:
        if operation[goal + "_entry_sha256"] is None:
            _ensure_registration(operation, goal, plan, lease_adapter, failpoint)
            registration_progress[operation["operation_id"]]["phase"] = "complete"
            _update_progress(
                progress_path,
                progress,
                failpoint,
                "progress:registration:" + operation["operation_id"],
            )
    ordered = list(plan["units"] if goal == "target" else reversed(plan["units"]))
    index_by_id = {item["unit_id"]: index for index, item in enumerate(progress["units"])}
    for unit in ordered:
        _ensure_unit(unit, goal, plan, lease_adapter, failpoint)
        progress["units"][index_by_id[unit["unit_id"]]]["phase"] = "complete"
        _update_progress(
            progress_path, progress, failpoint, "progress:" + unit["unit_id"]
        )
    if native_records is not None and native_records["semantic"].intended_state == "matching":
        ensure_native_target()
    for operation in registration_operations:
        if operation[goal + "_entry_sha256"] is not None:
            _ensure_registration(operation, goal, plan, lease_adapter, failpoint)
            registration_progress[operation["operation_id"]]["phase"] = "complete"
            _update_progress(
                progress_path,
                progress,
                failpoint,
                "progress:registration:" + operation["operation_id"],
            )
    for unit in plan["units"]:
        if not state_matches(Path(unit["destination"]), unit[goal]):
            raise RecoveryError("coherent five-unit verification failed")
    for operation in registration_operations:
        if sha256_file(Path(operation["source_path"])) != operation[goal + "_sha256"]:
            raise RecoveryError("coherent registration verification failed")
    if native_records is not None:
        observation, data = _native_observation(native_records)
        if _native_semantic_classification(native_records, observation, data) != "observed_target":
            raise RecoveryError("coherent native registration verification failed")
    _guard(plan, lease_adapter)
    outcome = plan["outcomes"][goal]
    _publish_terminal_receipt(plan, goal, state_root, failpoint)
    _guard(plan, lease_adapter)
    _atomic_json(admission_path, outcome, failpoint, "terminal-admission")
    verified, _ = read_object(admission_path, "terminal admission")
    if validate_admission(verified, plan["roots"]) != outcome:
        raise RecoveryError("terminal admission publication could not be verified")
    return _completed_outcome_result(outcome, state_root)


def recover(state_root: Path, *, abort: bool = False, failpoint: Failpoint = None,
            quiescent_decision: Any = None,
            native_effects: Any = None) -> Dict[str, Any]:
    state_root = Path(state_root).resolve(strict=True)
    with acquire_recovery_lease(state_root) as lease:
        return _execute_with_lease(
            state_root,
            lease,
            abort=abort,
            failpoint=failpoint,
            quiescent_decision=quiescent_decision,
            native_effects=native_effects,
        )


def describe() -> Dict[str, Any]:
    return {
        "interface": "council-lifecycle-recovery",
        "recovery_format": REGISTRATION_RECOVERY_FORMAT,
        "formats": {
            "admission": [1],
            "plan": [1, 2],
            "journal": [1, 2],
            "receipt": [1, 2],
            "recovery": [1, 2],
        },
        "metadata_limit_bytes": MAX_METADATA_BYTES,
        "id_pattern": ID_PATTERN,
        "python_minimum": [3, 9],
        "required_python_flags": ["-I", "-B"],
        "unit_ids": list(UNIT_IDS),
        "required_operations": list(REQUIRED_OPERATIONS),
        "registration_required_operations": list(REGISTRATION_REQUIRED_OPERATIONS),
        "registration_operations": sorted(REGISTRATION_OPERATIONS),
        "native_v3": {
            "formats": {
                "plan": NATIVE_PLAN_FORMAT,
                "journal": NATIVE_JOURNAL_FORMAT,
                "receipt": NATIVE_RECEIPT_FORMAT,
                "recovery": NATIVE_RECOVERY_FORMAT,
            },
            "operations": sorted(NATIVE_OPERATIONS),
            "required_operations": list(NATIVE_REQUIRED_OPERATIONS),
            "attempt_states": sorted(NATIVE_ATTEMPT_STATES),
            "closure_modules": list(NATIVE_RECOVERY_MODULES),
            "attempt_family": "stable-two-sequence-chain",
            "max_attempt_sequences": 2,
            "success_activated": False,
        },
        "goals": ["target", "prior"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("describe")
    check = commands.add_parser("check-plan")
    check.add_argument("plan", type=Path)
    recovery = commands.add_parser("recover")
    recovery.add_argument("--state-root", type=Path, required=True)
    recovery.add_argument("--abort", action="store_true")
    recovery.add_argument("--quiescent-edit", action="store_true")
    recovery.add_argument("--confirm-plan")
    recovery.add_argument("--invocation-id")
    recovery.add_argument("--sequence", type=int)
    supervisor = commands.add_parser("native-supervisor")
    supervisor.add_argument("--request", type=Path, required=True)
    supervisor.add_argument("--gate-fd", type=int, required=True)
    supervisor.add_argument("--lease-fd", type=int, required=True)
    args = parser.parse_args()
    try:
        _validate_compatible_python()
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            raise RecoveryError("recovery CLI requires Python -I -B")
        if args.command == "describe":
            result = describe()
        elif args.command == "check-plan":
            result = check_plan(args.plan)
        elif args.command == "native-supervisor":
            return _native_supervisor_main(
                args.request, args.gate_fd, args.lease_fd
            )
        else:
            decision = None
            if (
                args.quiescent_edit
                or args.confirm_plan
                or args.invocation_id
                or args.sequence is not None
            ):
                if not (
                    args.quiescent_edit and args.confirm_plan and args.invocation_id
                ):
                    raise RecoveryError(
                        "quiescent recovery requires --quiescent-edit, --confirm-plan and --invocation-id"
                    )
                decision = {
                    "confirmed": True,
                    "plan_sha256": args.confirm_plan,
                    "invocation_id": args.invocation_id,
                }
                if args.sequence is not None:
                    decision.update(
                        sequence=args.sequence,
                        goal="prior" if args.abort else "target",
                    )
            result = recover(
                args.state_root,
                abort=args.abort,
                quiescent_decision=decision,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (RecoveryError, OSError, ValueError, KeyError) as error:
        parser.exit(1, "recovery: %s\n" % error)


if __name__ == "__main__":
    sys.exit(main())
