#!/usr/bin/env python3
"""Standalone Council artifact recovery executor (Python 3.9 stdlib only)."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import unicodedata
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


RECOVERY_FORMAT = 1
PLAN_FORMAT = 1
RECEIPT_FORMAT = 1
JOURNAL_FORMAT = 1
ADMISSION_FORMAT = 1
NAMESPACE_VERSION = 1
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
KINDS = {"install", "upgrade", "rollback", "uninstall"}
OWNERSHIP = {"absent", "created", "already_owned", "matching_preexisting_unowned"}
VOLATILE_STATE_NAMES = {"broker.lock", "broker.sock", "broker.log"}


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
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.close(descriptor)


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
    exact_keys(value, ("format", "package_id", "runtime_cohort", "artifacts", "opencode_sources"), "source manifest")
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


def validate_receipt_shape(value: Any, label: str = "receipt") -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("%s must be an object" % label)
    exact_keys(
        value,
        ("receipt_format", "receipt_id", "transaction_id", "outcome", "roots",
         "root_identities", "lock_identity", "package_id", "runtime_cohort",
         "source_manifest_sha256", "prior_receipt", "recovery",
         "reader_support_sha256", "artifacts"),
        label,
    )
    if exact_int(value["receipt_format"], label + " format", 1) != RECEIPT_FORMAT:
        raise RecoveryError("unsupported receipt format")
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
    exact_keys(recovery, ("format", "tool_sha256"), label + " recovery")
    if exact_int(recovery["format"], label + " recovery format", 1) != RECOVERY_FORMAT:
        raise RecoveryError("%s recovery format is unsupported" % label)
    checked_hash(recovery["tool_sha256"], label + " recovery tool_sha256")
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
    return value


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


def _verify_terminal_receipt(state_root: Path, summary: Dict[str, Any]) -> Dict[str, Any]:
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
    if actual_identities != receipt["root_identities"]:
        raise RecoveryError("terminal receipt root identity changed")
    if lock_path_identity(state_root / "broker.lock") != receipt["lock_identity"]:
        raise RecoveryError("terminal receipt broker.lock identity changed")
    manifest, _support = _validate_receipt_provenance(state_root, receipt)
    states = _receipt_unit_states(receipt)
    for unit_id, expected in states.items():
        if not state_matches(_unit_destination(roots, unit_id), expected):
            raise RecoveryError("terminal artifact set is not coherent: %s" % unit_id)
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
    return receipt


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
    if recovery != {"format": RECOVERY_FORMAT, "tool_sha256": plan["recovery"]["tool_sha256"]}:
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
            raise RecoveryError("new plan attempts to adopt a previously unowned artifact")
        if old_ownership != "matching_preexisting_unowned" and new_ownership == "matching_preexisting_unowned":
            raise RecoveryError("new plan drops established artifact ownership")


def _validate_progress(value: Any, plan: Dict[str, Any], plan_digest: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryError("progress must be an object")
    exact_keys(value, ("journal_format", "transaction_id", "plan_sha256", "sequence", "goal", "units"), "progress")
    if (exact_int(value["journal_format"], "journal format", 1) != JOURNAL_FORMAT or
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
    return value


def retained_state_fingerprint(state_root: Path) -> Dict[str, Any]:
    records = []
    for parent, dirs, files in os.walk(state_root, topdown=True, followlinks=False):
        relative_parent = Path(parent).relative_to(state_root)
        if relative_parent == Path("."):
            dirs[:] = sorted(name for name in dirs if name != ".council-lifecycle")
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
    exact_keys(objects, ("target", "prior", "backup", "stage", "displaced"), label + " objects")
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
    lifecycle = roots["state"] / ".council-lifecycle"
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


def validate_plan(plan_path: Path, *, pre_intent: bool,
                  require_progress: bool = True) -> Tuple[Dict[str, Any], bytes, Dict[str, Any], bytes]:
    plan_path = Path(plan_path).resolve(strict=True)
    plan, plan_data = read_object(plan_path, "prepared plan")
    exact_keys(
        plan,
        ("plan_format", "transaction_id", "kind", "roots", "root_identities", "lock_identity",
         "prior_admission", "outcomes", "target_receipt_id", "source_manifest", "proposed_receipt",
         "proposed_prior_receipt", "recovery", "required_operations", "allowed_goals", "units",
         "retained_state", "reader_support"),
        "plan",
    )
    if exact_int(plan["plan_format"], "plan format", 1) != PLAN_FORMAT:
        raise RecoveryError("unsupported plan format")
    transaction_id = checked_id(plan["transaction_id"], "transaction_id")
    if plan["kind"] not in KINDS:
        raise RecoveryError("unsupported transaction kind")
    plan["roots"] = validate_roots(plan["roots"])
    expected_plan_path = (Path(plan["roots"]["state"]) / ".council-lifecycle/v1/transactions" /
                          transaction_id / "plan.json")
    if plan_path != expected_plan_path:
        raise RecoveryError("plan is outside its fixed transaction path")
    lifecycle_root = Path(plan["roots"]["state"]) / ".council-lifecycle"
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
        if (prior_receipt.get("receipt_format") != RECEIPT_FORMAT or
                prior_receipt.get("receipt_id") != prior_committed["receipt_id"] or
                prior_receipt.get("package_id") != prior_committed["package_id"] or
                prior_receipt.get("runtime_cohort") != prior_committed["runtime_cohort"]):
            raise RecoveryError("prior receipt summary mismatch")
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
    elif plan["kind"] in ("upgrade", "rollback"):
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
    exact_keys(recovery, ("format", "tool_path", "tool_sha256", "python_path", "python_version"), "recovery")
    if exact_int(recovery["format"], "recovery format", 1) != RECOVERY_FORMAT:
        raise RecoveryError("unsupported recovery format")
    checked_hash(recovery["tool_sha256"], "recovery tool_sha256")
    expected_tool = Path(plan["roots"]["state"]) / ".council-lifecycle/v1/recovery" / (recovery["tool_sha256"] + ".py")
    if checked_absolute(recovery["tool_path"], "recovery tool_path") != expected_tool:
        raise RecoveryError("recovery tool path is not fixed by its digest")
    if Path(__file__).resolve(strict=True) != expected_tool or sha256_file(expected_tool) != recovery["tool_sha256"]:
        raise RecoveryError("the executing recovery tool does not match the plan")
    if checked_absolute(recovery["python_path"], "recovery python_path") != Path(sys.executable).resolve(strict=True):
        raise RecoveryError("the executing Python does not match the plan")
    version = recovery["python_version"]
    if (not isinstance(version, list) or len(version) != 3 or
            any(type(item) is not int or item < 0 for item in version) or tuple(version) != sys.version_info[:3]):
        raise RecoveryError("the executing Python version does not match the plan")
    if plan["required_operations"] != list(REQUIRED_OPERATIONS):
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
    actual_retained = retained_state_fingerprint(Path(plan["roots"]["state"]))
    if actual_retained != plan["retained_state"]:
        raise RecoveryError("retained state changed since plan preparation")
    progress = None
    if require_progress:
        progress, _ = read_object(plan_path.parent / "progress.json", "progress")
        _validate_progress(progress, plan, sha256_bytes(plan_data))
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
            for name in ("backup", "stage", "displaced"):
                if Path(unit["objects"][name]).exists() or Path(unit["objects"][name]).is_symlink():
                    raise RecoveryError("%s pre-intent %s path is occupied" % (unit["unit_id"], name))
    if pre_intent:
        admission_path = Path(plan["roots"]["state"]) / ".council-lifecycle/admission.json"
        admission, _ = read_object(admission_path, "admission")
        if validate_admission(admission, plan["roots"]) != plan["prior_admission"]:
            raise RecoveryError("admission changed before intent")
        if progress is None or progress["sequence"] != 0 or progress["goal"] != "target" or any(
            unit["phase"] != "pending" for unit in progress["units"]
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
    try:
        temporary_details = temporary.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(temporary_details.st_mode) or temporary_details.st_nlink != 1:
            raise RecoveryError("owned %s temporary path has an unexpected type" % label)
        temporary.unlink()
        _sync_directory(path.parent, failpoint, label + ":temporary-cleanup")
    descriptor = os.open(
        str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
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
        os.close(descriptor)
        descriptor = -1
        _event(failpoint, "before:replace:" + label)
        os.replace(temporary, path)
        _event(failpoint, "after:replace:" + label)
        _sync_directory(path.parent, failpoint, label)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _write_immutable(path: Path, data: bytes, failpoint: Failpoint, label: str) -> None:
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
            failpoint: Failpoint, label: str) -> None:
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
    descriptor = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        opened_identity = {"device": details.st_dev, "inode": details.st_ino}
        if opened_identity != expected_parent or directory_identity(parent, "unit parent") != expected_parent:
            raise RecoveryError("unit parent changed while opening it")
        _event(failpoint, "before:rename:" + label)
        os.replace(source.name, destination.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        _event(failpoint, "after:rename:" + label)
        _event(failpoint, "before:fsync-directory:" + label)
        os.fsync(descriptor)
        _event(failpoint, "after:fsync-directory:" + label)
    finally:
        os.close(descriptor)


def _copy_file(source: Path, destination: Path, expected: Dict[str, Any], failpoint: Failpoint,
               label: str) -> None:
    partial = destination.with_name(destination.name + ".partial")
    try:
        details = partial.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RecoveryError("owned partial path is not a regular file: %s" % partial)
        _event(failpoint, "before:unlink-partial:" + label)
        partial.unlink()
        _event(failpoint, "after:unlink-partial:" + label)
        _sync_directory(partial.parent, failpoint, label + ":partial-cleanup")
    source_descriptor = os.open(str(source), os.O_RDONLY | os.O_NOFOLLOW)
    destination_descriptor = os.open(
        str(partial), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, expected["mode"]
    )
    try:
        _event(failpoint, "before:copy-file:" + label)
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise RecoveryError("short artifact write: %s" % label)
                view = view[written:]
        os.fchmod(destination_descriptor, expected["mode"])
        os.fsync(destination_descriptor)
        _event(failpoint, "after:copy-file:" + label)
    finally:
        os.close(source_descriptor)
        os.close(destination_descriptor)
    _event(failpoint, "before:replace-materialized-file:" + label)
    os.replace(partial, destination)
    _event(failpoint, "after:replace-materialized-file:" + label)
    _sync_directory(destination.parent, failpoint, label + ":file-created")


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
    for item in expected["artifacts"]:
        if item["kind"] != "file":
            continue
        partial = (stage / item["path"]).with_name(Path(item["path"]).name + ".partial")
        try:
            details = partial.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RecoveryError("owned partial path is not a regular file: %s" % partial)
        _event(failpoint, "before:unlink-partial:" + label + ":" + item["path"])
        partial.unlink()
        _event(failpoint, "after:unlink-partial:" + label + ":" + item["path"])
        _sync_directory(partial.parent, failpoint, label + ":partial-cleanup")


def _materialize(source: Path, stage: Path, expected: Dict[str, Any], plan: Dict[str, Any],
                 lease: Any, failpoint: Failpoint, label: str) -> None:
    _guard(plan, lease)
    if not state_matches(source, expected):
        raise RecoveryError("recovery source changed: %s" % source)
    if expected["kind"] == "file":
        if stage.exists() or stage.is_symlink():
            if state_matches(stage, expected):
                return
            raise RecoveryError("stage file contains unknown bytes")
        _copy_file(source, stage, expected, failpoint, label)
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


def _remove_owned_stage(stage: Path, expected: Dict[str, Any], plan: Dict[str, Any],
                        lease: Any, failpoint: Failpoint, label: str) -> None:
    _guard(plan, lease)
    if expected["kind"] == "file":
        if not state_matches(stage, expected):
            raise RecoveryError("%s is not the known disposable stage" % label)
        _event(failpoint, "before:unlink-stage:" + label)
        stage.unlink()
        _event(failpoint, "after:unlink-stage:" + label)
        _sync_directory(stage.parent, failpoint, label + ":stage-removed")
        return
    if not state_matches(stage, expected) and not _partial_tree_is_known(stage, expected):
        raise RecoveryError("%s is not the known disposable stage" % label)
    entries = sorted(
        (path for path in stage.rglob("*")),
        key=lambda path: (len(path.relative_to(stage).parts), str(path)),
        reverse=True,
    )
    for path in entries:
        details = path.lstat()
        relative = str(path.relative_to(stage).as_posix())
        if stat.S_ISREG(details.st_mode) and details.st_nlink == 1:
            _event(failpoint, "before:unlink-stage:" + label + ":" + relative)
            path.unlink()
            _event(failpoint, "after:unlink-stage:" + label + ":" + relative)
        elif stat.S_ISDIR(details.st_mode) and not stat.S_ISLNK(details.st_mode):
            _event(failpoint, "before:rmdir-stage:" + label + ":" + relative)
            path.rmdir()
            _event(failpoint, "after:rmdir-stage:" + label + ":" + relative)
        else:
            raise RecoveryError("%s stage changed during bounded removal" % label)
        _sync_directory(path.parent, failpoint, label + ":" + relative)
    _event(failpoint, "before:rmdir-stage:" + label)
    stage.rmdir()
    _event(failpoint, "after:rmdir-stage:" + label)
    _sync_directory(stage.parent, failpoint, label + ":stage-removed")


def _ensure_unit(unit: Dict[str, Any], goal: str, plan: Dict[str, Any], lease: Any,
                 failpoint: Failpoint) -> None:
    unit_id = unit["unit_id"]
    desired = unit[goal]
    destination = Path(unit["destination"])
    parent = destination.parent
    objects = {name: Path(value) for name, value in unit["objects"].items()}
    _guard(plan, lease)
    _validate_unit_auxiliaries(unit, goal)
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
        _rename(parent, destination, backup, plan, lease, failpoint, unit_id + ":preserve-initial")
    elif destination.exists() or destination.is_symlink():
        displaced = objects["displaced"]
        if displaced.exists() or displaced.is_symlink():
            if not any(state_matches(displaced, unit[name]) for name in ("prior", "target")):
                raise RecoveryError("%s displaced object contains unknown content" % unit_id)
            raise RecoveryError("%s has both an active and displaced known object" % unit_id)
        _rename(parent, destination, displaced, plan, lease, failpoint, unit_id + ":displace-active")
    if desired["exists"]:
        source = objects[goal]
        stage = objects["stage"]
        _materialize(source, stage, desired, plan, lease, failpoint, unit_id + ":" + goal)
        _rename(parent, stage, destination, plan, lease, failpoint, unit_id + ":activate-" + goal)
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
    if plan["_receipt_data"]["prior"] is not None:
        result["prior_receipt_sha256"] = sha256_bytes(plan["_receipt_data"]["prior"])
    return result


def _execute_with_lease(state_root: Path, lease_adapter: Any, *, abort: bool = False,
                        failpoint: Failpoint = None) -> Dict[str, Any]:
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
    if plan["root_identities"]["state"] != facts["root_identity"] or plan["lock_identity"] != facts["lock_identity"]:
        raise RecoveryError("held recovery lease differs from the plan")
    progress_path = _progress_path(plan_path)
    progress, _ = read_object(progress_path, "progress")
    progress = _validate_progress(progress, plan, sha256_bytes(plan_data))
    if abort:
        if "prior" not in plan["allowed_goals"]:
            raise RecoveryError("this transaction has no validated prior outcome")
        if progress["goal"] != "prior":
            progress["goal"] = "prior"
            for unit in progress["units"]:
                unit["phase"] = "pending"
            _update_progress(progress_path, progress, failpoint, "progress:select-prior")
    goal = progress["goal"]
    ordered = list(plan["units"] if goal == "target" else reversed(plan["units"]))
    index_by_id = {item["unit_id"]: index for index, item in enumerate(progress["units"])}
    for unit in ordered:
        _ensure_unit(unit, goal, plan, lease_adapter, failpoint)
        progress["units"][index_by_id[unit["unit_id"]]]["phase"] = "complete"
        _update_progress(progress_path, progress, failpoint, "progress:" + unit["unit_id"])
    for unit in plan["units"]:
        if not state_matches(Path(unit["destination"]), unit[goal]):
            raise RecoveryError("coherent five-unit verification failed")
    _guard(plan, lease_adapter)
    outcome = plan["outcomes"][goal]
    _publish_terminal_receipt(plan, goal, state_root, failpoint)
    _guard(plan, lease_adapter)
    _atomic_json(admission_path, outcome, failpoint, "terminal-admission")
    verified, _ = read_object(admission_path, "terminal admission")
    if validate_admission(verified, plan["roots"]) != outcome:
        raise RecoveryError("terminal admission publication could not be verified")
    return _completed_outcome_result(outcome, state_root)


def recover(state_root: Path, *, abort: bool = False, failpoint: Failpoint = None) -> Dict[str, Any]:
    state_root = Path(state_root).resolve(strict=True)
    with acquire_recovery_lease(state_root) as lease:
        return _execute_with_lease(state_root, lease, abort=abort, failpoint=failpoint)


def describe() -> Dict[str, Any]:
    return {
        "interface": "council-lifecycle-recovery",
        "recovery_format": RECOVERY_FORMAT,
        "formats": {"admission": [1], "plan": [1], "journal": [1], "receipt": [1]},
        "metadata_limit_bytes": MAX_METADATA_BYTES,
        "id_pattern": ID_PATTERN,
        "python_minimum": [3, 9],
        "required_python_flags": ["-I", "-B"],
        "unit_ids": list(UNIT_IDS),
        "required_operations": list(REQUIRED_OPERATIONS),
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
    args = parser.parse_args()
    try:
        if sys.version_info[:2] < (3, 9):
            raise RecoveryError("recovery CLI requires Python 3.9 or newer")
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            raise RecoveryError("recovery CLI requires Python -I -B")
        if args.command == "describe":
            result = describe()
        elif args.command == "check-plan":
            result = check_plan(args.plan)
        else:
            result = recover(args.state_root, abort=args.abort)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (RecoveryError, OSError, ValueError, KeyError) as error:
        parser.exit(1, "recovery: %s\n" % error)


if __name__ == "__main__":
    sys.exit(main())
