#!/usr/bin/env python3
"""Council artifact lifecycle planning, transactions, and recovery handoff."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
import time
import types
from typing import Any, Dict, List, Optional, Tuple


def _load_source_module(name: str, path: Path, expected_sha256: Optional[str] = None,
                        reported_path: Optional[Path] = None) -> types.ModuleType:
    path = Path(path).resolve(strict=True)
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RuntimeError("verified source must be a single-linked regular file")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise RuntimeError("verified source digest mismatch: %s" % name)
    filename = str(reported_path or path)
    module = types.ModuleType(name)
    module.__file__ = filename
    module.__cached__ = None
    module.__package__ = None
    sys.modules[name] = module
    try:
        exec(compile(data, filename, "exec", dont_inherit=True, optimize=sys.flags.optimize),
             module.__dict__)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    module.__source_sha256__ = digest
    return module


SOURCE_ROOT = Path(__file__).resolve().parent
recovery = _load_source_module("council_recover", SOURCE_ROOT / "council_recover.py")
protocol = _load_source_module("council_protocol", SOURCE_ROOT / "council_protocol.py")
admission = _load_source_module("council_admission", SOURCE_ROOT / "council_admission.py")
inspect = _load_source_module("council_inspect", SOURCE_ROOT / "council_inspect.py")


RELEASE_SNAPSHOT_FORMAT = 1
RETAINED_RELEASE_FORMAT = 1
OWNERSHIP_SNAPSHOT_FORMAT = 1
PLANNING_PREVIEW_FORMAT = 1
PREPARATION_RECORD_FORMAT = 1
PLANNING_KINDS = {"install", "upgrade", "rollback", "uninstall"}
RUNTIME_SOURCES = (
    "scripts/council_admission.py", "scripts/council_inspect.py",
    "scripts/council_protocol.py", "scripts/council_protocol.ts",
    "scripts/council.py", "scripts/council_mcp.py", "scripts/council_opencode.py",
    "scripts/opencode_council_plugin.ts", "scripts/opencode_delivery_registry.ts",
    "scripts/tools/council.ts",
)
_STAMP_PATTERN = {
    name: re.compile(
        rb'(?m)^((?:(?:export )?const )?' + name.encode() + rb' = ")[^"]+("\r?)$'
    )
    for name in ("PACKAGE_ID", "RUNTIME_COHORT")
}


class LifecyclePlanningError(recovery.RecoveryError):
    pass


def _real_directory(path: Path, label: str) -> Path:
    resolved = Path(path).resolve(strict=True)
    details = resolved.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise LifecyclePlanningError("%s must resolve to a real directory" % label)
    return resolved


def _payload_path(path: Path) -> Path:
    value = Path(path)
    parent = _real_directory(value.parent, "payload parent")
    resolved = parent / value.name
    if resolved.is_symlink():
        raise LifecyclePlanningError("payload root must not be a symlink")
    return resolved


def _lexical_root(path: Path) -> Path:
    path = Path(path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return Path(os.path.normpath(str(path)))


def _observed_root(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise LifecyclePlanningError("observed root must be absolute")
    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        candidate = current / part
        try:
            details = candidate.lstat()
        except FileNotFoundError:
            return candidate.joinpath(*parts[index + 1:])
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise LifecyclePlanningError("root path has a nonphysical ancestor")
        current = candidate
    return current


def _release_tree_files(release_root: Path) -> Tuple[List[str], List[str]]:
    state = recovery.capture_state(release_root, "directory")
    files = []
    directories = []
    for item in state["artifacts"]:
        if item["mode"] > 0o777:
            raise LifecyclePlanningError("release artifact contains special mode bits: %s" % item["path"])
        if item["kind"] == "file":
            files.append(item["path"])
        else:
            directories.append(item["path"])
    return files, directories


def _expected_directories(files: List[str]) -> List[str]:
    directories = set()
    for name in files:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent
    return sorted(directories)


def _file_fingerprint(details: Any) -> Tuple[int, ...]:
    return (
        details.st_dev, details.st_ino, details.st_mode, details.st_nlink,
        details.st_size, details.st_mtime_ns, details.st_ctime_ns,
    )


def _read_artifact_bytes(path: Path, label: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise LifecyclePlanningError("%s must be a single-linked regular file" % label)
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (_file_fingerprint(before) != _file_fingerprint(opened) or
            _file_fingerprint(opened) != _file_fingerprint(after)):
        raise LifecyclePlanningError("%s changed while reading" % label)
    final = path.lstat()
    if _file_fingerprint(after) != _file_fingerprint(final):
        raise LifecyclePlanningError("%s changed while reading" % label)
    return b"".join(chunks)


def _identity_hash(hashes: Dict[str, str]) -> str:
    return recovery.sha256_bytes(
        json.dumps(sorted(hashes.items()), separators=(",", ":")).encode("utf-8")
    )


def _derived_release_identity(release_root: Path, manifest: Dict[str, Any],
                              artifacts: List[Dict[str, Any]]) -> Tuple[str, str]:
    if manifest["runtime_sources"] != list(RUNTIME_SOURCES):
        raise LifecyclePlanningError("release runtime source inventory is unsupported")
    payload_hashes = {
        item["release_path"].removeprefix("payload/"): item["sha256"]
        for item in artifacts if item["release_path"].startswith("payload/")
    }
    normalized = {}
    embedded = {"PACKAGE_ID": set(), "RUNTIME_COHORT": set()}
    for name in RUNTIME_SOURCES:
        data = _read_artifact_bytes(release_root / "payload" / name, "runtime source")
        for field, pattern in _STAMP_PATTERN.items():
            matches = pattern.findall(data)
            if len(matches) != 1:
                raise LifecyclePlanningError("runtime source has missing or duplicate stamps")
            match = pattern.search(data)
            try:
                value = data[match.start(0):match.end(0)].split(b'"')[1].decode("ascii")
            except UnicodeError as error:
                raise LifecyclePlanningError("runtime source stamp is not ASCII") from error
            if re.fullmatch(recovery.HASH_PATTERN, value) is None:
                raise LifecyclePlanningError("runtime source has an invalid embedded stamp")
            embedded[field].add(value)
            data = pattern.sub(rb'\1unstamped\2', data)
        normalized[name] = recovery.sha256_bytes(data)
        payload_hashes[name] = normalized[name]
    package_id = _identity_hash(payload_hashes)
    runtime_cohort = _identity_hash(normalized)
    if embedded["PACKAGE_ID"] != {package_id} or embedded["RUNTIME_COHORT"] != {runtime_cohort}:
        raise LifecyclePlanningError("runtime embedded stamps differ from derived release identity")
    if manifest["package_id"] != package_id or manifest["runtime_cohort"] != runtime_cohort:
        raise LifecyclePlanningError("manifest identity differs from validated release bytes")
    return package_id, runtime_cohort


def validate_release(release_root: Path) -> Dict[str, Any]:
    """Validate an already generated release without generating or changing it."""
    release_root = _real_directory(release_root, "release root")
    manifest_path = release_root / "release_manifest.json"
    manifest, manifest_data = recovery.read_object(manifest_path, "release manifest")
    manifest = recovery.validate_release_manifest(manifest)
    expected_files = sorted(["release_manifest.json", *manifest["artifacts"]])
    actual_files, actual_directories = _release_tree_files(release_root)
    if actual_files != expected_files:
        missing = sorted(set(expected_files) - set(actual_files))
        extra = sorted(set(actual_files) - set(expected_files))
        raise LifecyclePlanningError(
            "release artifact closure differs from manifest; missing=%s extra=%s"
            % (missing, extra)
        )
    expected_directories = _expected_directories(expected_files)
    if actual_directories != expected_directories:
        raise LifecyclePlanningError("release contains missing or extra directories")
    artifacts = []
    external_by_manifest = {
        value: unit_id for unit_id, value in recovery.EXTERNAL_MANIFEST_PATHS.items()
    }
    for release_path, expected_hash in manifest["artifacts"].items():
        path = release_root / release_path
        actual_hash = recovery.sha256_file(path)
        if actual_hash != expected_hash:
            raise LifecyclePlanningError("release artifact hash mismatch: %s" % release_path)
        if release_path.startswith("payload/"):
            unit_id = "payload"
            destination_relative = release_path[len("payload/"):]
        else:
            unit_id = external_by_manifest.get(release_path)
            if unit_id is None:
                raise LifecyclePlanningError("release contains an unsupported external artifact")
            destination_relative = "."
        artifacts.append(
            {
                "release_path": release_path,
                "sha256": actual_hash,
                "unit_id": unit_id,
                "destination_relative": destination_relative,
                "intended_mode": 0o644,
            }
        )
    package_id, runtime_cohort = _derived_release_identity(
        release_root, manifest, artifacts
    )
    for destination, source_name in manifest["opencode_sources"].items():
        external = release_root / "opencode" / destination
        payload = release_root / "payload" / source_name
        if recovery.sha256_file(external) != recovery.sha256_file(payload):
            raise LifecyclePlanningError("OpenCode artifact differs from its payload source: %s" % destination)
    if recovery.read_regular(manifest_path, "release manifest") != manifest_data:
        raise LifecyclePlanningError("release manifest changed during validation")
    return {
        "release_snapshot_format": RELEASE_SNAPSHOT_FORMAT,
        "root": str(release_root),
        "manifest_path": str(manifest_path),
        "manifest_sha256": recovery.sha256_bytes(manifest_data),
        "package_id": package_id,
        "runtime_cohort": runtime_cohort,
        "runtime_sources": manifest["runtime_sources"],
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def inspect_ownership(state_root: Path, payload_root: Path,
                      opencode_root: Path) -> Dict[str, Any]:
    """Capture current artifact/receipt facts without acquiring a lease or writing."""
    state_input = _lexical_root(state_root)
    payload_input = _lexical_root(payload_root)
    opencode_input = _lexical_root(opencode_root)
    namespace = state_input / ".council-lifecycle"
    if not namespace.exists() and not namespace.is_symlink():
        state_observed = _observed_root(state_input)
        payload_parent = _observed_root(payload_input.parent)
        opencode_observed = _observed_root(opencode_input)
        roots = recovery.validate_roots(
            {"state": str(state_observed), "payload": str(payload_parent / payload_input.name),
             "opencode": str(opencode_observed)}
        )
        terminal = {
            "status": "legacy_unmanaged", "certified": False,
            "reason": "lifecycle namespace is absent", "roots": roots,
            "summary": None, "receipt": None, "payload_cache": [],
        }
    else:
        state_root = _real_directory(state_input, "state root")
        payload_root = _payload_path(payload_input)
        opencode_root = _real_directory(opencode_input, "OpenCode root")
        terminal = recovery.inspect_terminal_ownership(
            state_root, payload_root, opencode_root
        )
    roots = terminal["roots"]
    units = []
    for unit_id in recovery.UNIT_IDS:
        kind = "directory" if unit_id == "payload" else "file"
        destination = recovery._unit_destination(roots, unit_id)
        observed_parent = _observed_root(destination.parent)
        if observed_parent != destination.parent:
            raise LifecyclePlanningError("fixed unit parent changed during inspection")
        units.append(
            {
                "unit_id": unit_id,
                "destination": str(destination),
                "kind": kind,
                "state": recovery.capture_state(destination, kind),
            }
        )
    return {
        "ownership_snapshot_format": OWNERSHIP_SNAPSHOT_FORMAT,
        "roots": roots,
        "management": {
            "status": terminal["status"],
            "certified": terminal["certified"],
            "reason": terminal["reason"],
            "summary": terminal["summary"],
        },
        "receipt": terminal["receipt"],
        "payload_cache": terminal["payload_cache"],
        "units": units,
    }


def _pending_status(state_root: Path, payload_root: Path,
                    opencode_root: Path) -> Optional[Dict[str, Any]]:
    """Load the digest-bound copied recoverer only when canonical intent is pending."""
    state_input = _lexical_root(state_root)
    lifecycle_root = state_input / ".council-lifecycle"
    if not lifecycle_root.exists() and not lifecycle_root.is_symlink():
        return None
    state_root = _real_directory(state_input, "state root")
    payload_root = _payload_path(_lexical_root(payload_root))
    opencode_root = _real_directory(_lexical_root(opencode_root), "OpenCode root")
    roots = recovery.validate_roots(
        {"state": str(state_root), "payload": str(payload_root), "opencode": str(opencode_root)}
    )
    admission_value, _admission_data = recovery.read_object(
        lifecycle_root / "admission.json", "admission"
    )
    admission_value = recovery.validate_admission(admission_value, roots)
    if admission_value["status"] != "recovery_required":
        return None
    return recovery.inspect_pending_status(state_root, payload_root, opencode_root)


def _target_states(release: Dict[str, Any], roots: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    payload_files = [
        item for item in release["artifacts"] if item["unit_id"] == "payload"
    ]
    directory_paths = set()
    for item in payload_files:
        parent = PurePosixPath(item["destination_relative"]).parent
        while str(parent) != ".":
            directory_paths.add(str(parent))
            parent = parent.parent
    payload_artifacts = [
        {"path": name, "kind": "directory", "sha256": None, "mode": 0o700}
        for name in sorted(directory_paths)
    ]
    payload_artifacts.extend(
        {
            "path": item["destination_relative"],
            "kind": "file",
            "sha256": item["sha256"],
            "mode": 0o644,
        }
        for item in payload_files
    )
    payload_artifacts.sort(key=lambda item: item["path"])
    states = {
        "payload": {
            "exists": True,
            "kind": "directory",
            "sha256": recovery._inventory_digest(payload_artifacts),
            "mode": 0o700,
            "artifacts": payload_artifacts,
        }
    }
    by_unit = {item["unit_id"]: item for item in release["artifacts"] if item["unit_id"] != "payload"}
    for unit_id in recovery.UNIT_IDS[1:]:
        item = by_unit[unit_id]
        states[unit_id] = {
            "exists": True,
            "kind": "file",
            "sha256": item["sha256"],
            "mode": 0o644,
            "artifacts": [],
        }
    return states


def _validate_release_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise LifecyclePlanningError("release snapshot must be an object")
    recovery.exact_keys(
        snapshot,
        ("release_snapshot_format", "root", "manifest_path", "manifest_sha256", "package_id",
         "runtime_cohort", "runtime_sources", "artifact_count", "artifacts"),
        "release snapshot",
    )
    if recovery.exact_int(snapshot["release_snapshot_format"], "release snapshot format", 1) != RELEASE_SNAPSHOT_FORMAT:
        raise LifecyclePlanningError("unsupported release snapshot")
    observed = validate_release(Path(snapshot["root"]))
    if observed != snapshot:
        raise LifecyclePlanningError("release changed after validation")
    return snapshot


def retained_release(state_root: Path, receipt_id: str) -> Dict[str, Any]:
    """Validate one retained committed receipt as a rollback source without writing."""
    receipt_id = recovery.checked_id(receipt_id, "rollback receipt_id")
    state_root = _real_directory(state_root, "state root")
    lifecycle = state_root / ".council-lifecycle"
    admission_value, _ = recovery.read_object(lifecycle / "admission.json", "admission")
    admission_value = recovery.validate_admission(admission_value)
    if admission_value["status"] != "committed":
        raise LifecyclePlanningError("rollback requires a committed current installation")
    reference = admission_value["committed"]
    seen = set()
    receipt = receipt_data = None
    while reference is not None and reference["receipt_id"] not in seen:
        seen.add(reference["receipt_id"])
        if len(seen) > recovery.MAX_ARTIFACTS:
            raise LifecyclePlanningError("rollback receipt history exceeds its bound")
        path = lifecycle / "v1/receipts" / (reference["receipt_id"] + ".json")
        candidate, candidate_data = recovery.read_object(path, "receipt history")
        candidate = recovery.validate_receipt_shape(candidate, "receipt history")
        if (candidate["receipt_id"] != reference["receipt_id"] or
                recovery.sha256_bytes(candidate_data) != reference["receipt_sha256"]):
            raise LifecyclePlanningError("rollback receipt history binding is invalid")
        if candidate["receipt_id"] == receipt_id:
            receipt, receipt_data = candidate, candidate_data
            break
        reference = candidate["prior_receipt"]
    if receipt is None or receipt_data is None:
        raise LifecyclePlanningError("rollback receipt is not in current managed history")
    if receipt["outcome"] != "committed":
        raise LifecyclePlanningError("rollback source must be a committed receipt")
    roots = recovery.validate_roots(receipt["roots"])
    if roots["state"] != str(state_root):
        raise LifecyclePlanningError("rollback receipt belongs to another state root")
    expected_identities = {
        "state": recovery.directory_identity(state_root, "state root"),
        "payload_parent": recovery.directory_identity(
            Path(roots["payload"]).parent, "payload parent"
        ),
        "opencode": recovery.directory_identity(Path(roots["opencode"]), "OpenCode root"),
    }
    if expected_identities != receipt["root_identities"]:
        raise LifecyclePlanningError("rollback receipt root identity changed")
    if recovery.lock_path_identity(state_root / "broker.lock") != receipt["lock_identity"]:
        raise LifecyclePlanningError("rollback receipt broker.lock identity changed")
    manifest, support = recovery._validate_receipt_provenance(state_root, receipt)
    manifest_path, support_path = recovery._receipt_provenance_paths(state_root, receipt_id)
    unit_states = recovery._receipt_unit_states(receipt)
    transaction_id = receipt["transaction_id"]
    unit_sources = {}
    for unit_id in recovery.UNIT_IDS:
        destination = recovery._unit_destination(roots, unit_id)
        source_path = Path(
            recovery._unit_objects(destination, transaction_id, unit_id)["target"]
        )
        if not recovery.state_matches(source_path, unit_states[unit_id]):
            raise LifecyclePlanningError(
                "rollback source object is unavailable or differs: %s" % unit_id
            )
        unit_sources[unit_id] = str(source_path)
    artifacts = _retained_release_artifacts(manifest, unit_sources)
    tool_path = lifecycle / "v1/recovery" / (
        receipt["recovery"]["tool_sha256"] + ".py"
    )
    return {
        "retained_release_format": RETAINED_RELEASE_FORMAT,
        "state_root": str(state_root), "receipt_id": receipt_id,
        "receipt_sha256": recovery.sha256_bytes(receipt_data),
        "manifest_path": str(manifest_path),
        "manifest_sha256": receipt["source_manifest_sha256"],
        "support_path": str(support_path),
        "support_sha256": receipt["reader_support_sha256"],
        "tool_path": str(tool_path), "tool_sha256": receipt["recovery"]["tool_sha256"],
        "package_id": manifest["package_id"], "runtime_cohort": manifest["runtime_cohort"],
        "runtime_sources": manifest["runtime_sources"],
        "artifact_count": len(artifacts), "artifacts": artifacts,
        "unit_sources": unit_sources, "reader_support": support,
    }


def _retained_release_artifacts(manifest: Dict[str, Any],
                                unit_sources: Dict[str, str]) -> List[Dict[str, Any]]:
    external_by_manifest = {
        value: unit_id for unit_id, value in recovery.EXTERNAL_MANIFEST_PATHS.items()
    }
    artifacts = []
    for release_path, digest in manifest["artifacts"].items():
        if release_path.startswith("payload/"):
            unit_id = "payload"
            destination_relative = release_path[len("payload/"):]
            source_path = Path(unit_sources[unit_id]) / destination_relative
        else:
            unit_id = external_by_manifest.get(release_path)
            if unit_id is None:
                raise LifecyclePlanningError("rollback manifest has an unsupported artifact")
            destination_relative = "."
            source_path = Path(unit_sources[unit_id])
        if recovery.sha256_file(source_path) != digest:
            raise LifecyclePlanningError("rollback source artifact differs from manifest")
        artifacts.append({
            "release_path": release_path, "sha256": digest, "unit_id": unit_id,
            "destination_relative": destination_relative, "intended_mode": 0o644,
        })
    return artifacts


def _validate_retained_release(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise LifecyclePlanningError("retained release snapshot must be an object")
    recovery.exact_keys(
        snapshot,
        ("retained_release_format", "state_root", "receipt_id", "receipt_sha256",
         "manifest_path", "manifest_sha256", "support_path", "support_sha256",
         "tool_path", "tool_sha256", "package_id", "runtime_cohort",
         "runtime_sources", "artifact_count", "artifacts", "unit_sources",
         "reader_support"),
        "retained release snapshot",
    )
    if (recovery.exact_int(snapshot["retained_release_format"],
                           "retained release format", 1) != RETAINED_RELEASE_FORMAT):
        raise LifecyclePlanningError("unsupported retained release snapshot")
    observed = retained_release(Path(snapshot["state_root"]), snapshot["receipt_id"])
    if observed != snapshot:
        raise LifecyclePlanningError("retained rollback source changed after validation")
    return snapshot


def _validated_release_source(kind: str,
                              value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if kind == "rollback":
        return _validate_retained_release(value)
    return _validate_release_snapshot(value)


def _validate_ownership_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise LifecyclePlanningError("ownership snapshot must be an object")
    recovery.exact_keys(
        snapshot,
        ("ownership_snapshot_format", "roots", "management", "receipt", "payload_cache", "units"),
        "ownership snapshot",
    )
    if recovery.exact_int(snapshot["ownership_snapshot_format"], "ownership snapshot format", 1) != OWNERSHIP_SNAPSHOT_FORMAT:
        raise LifecyclePlanningError("unsupported ownership snapshot")
    roots = snapshot["roots"]
    observed = inspect_ownership(
        Path(roots["state"]), Path(roots["payload"]), Path(roots["opencode"])
    )
    if observed != snapshot:
        raise LifecyclePlanningError("ownership inputs changed after inspection")
    return snapshot


def _state_entries(state_value: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result = {".": recovery._leaf_state(state_value, ".")}
    for item in state_value["artifacts"]:
        result[item["path"]] = recovery._leaf_state(state_value, item["path"])
    return result


def _artifact_destination(unit: Dict[str, Any], relative: str) -> str:
    destination = Path(unit["destination"])
    return str(destination if relative == "." else destination / relative)


def _contains_git_stop(state_value: Dict[str, Any]) -> bool:
    return any(PurePosixPath(item["path"]).parts[0] == ".git" for item in state_value["artifacts"])


def _record_blocker(blockers: List[Dict[str, str]], code: str, unit_id: str,
                    path: str, reason: str) -> None:
    blockers.append({"code": code, "unit_id": unit_id, "path": path, "reason": reason})


def plan_ownership(kind: str, release_snapshot: Optional[Dict[str, Any]],
                   ownership_snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deterministic non-executable ownership preview; never stages or writes."""
    if kind not in PLANNING_KINDS:
        raise LifecyclePlanningError("unsupported planning kind")
    ownership = _validate_ownership_snapshot(ownership_snapshot)
    release = None
    if kind == "uninstall":
        if release_snapshot is not None:
            raise LifecyclePlanningError("uninstall planning does not accept a release")
    elif release_snapshot is None:
        raise LifecyclePlanningError("install/upgrade/rollback planning requires a release")
    else:
        release = _validated_release_source(kind, release_snapshot)
    management = ownership["management"]
    blockers: List[Dict[str, str]] = []
    if kind == "install":
        if management["status"] not in ("legacy_unmanaged", "uninstalled"):
            _record_blocker(blockers, "managed_installation_present", "payload", ".",
                            "install requires unmanaged or uninstalled current state")
        elif management["status"] == "uninstalled" and not management["certified"]:
            _record_blocker(blockers, "uncertified_lifecycle_marker", "payload", ".",
                            "uninstalled lifecycle metadata requires a certifying receipt")
    elif management["status"] != "committed" or not management["certified"]:
        _record_blocker(blockers, "certified_installation_required", "payload", ".",
                        "%s requires a receipt-certified committed installation" % kind)
    roots = ownership["roots"]
    current_units = {item["unit_id"]: item for item in ownership["units"]}
    if _contains_git_stop(current_units["payload"]["state"]):
        _record_blocker(blockers, "source_clone", "payload", ".git",
                        "payload contains a .git ownership stop")
    if release is None:
        target_states = {
            unit_id: recovery.absent_state("directory" if unit_id == "payload" else "file")
            for unit_id in recovery.UNIT_IDS
        }
    else:
        target_states = _target_states(release, roots)
    prior_receipt = ownership["receipt"]
    prior_records = {}
    if prior_receipt is not None:
        prior_records = {
            (item["unit_id"], item["path"]): item
            for item in prior_receipt["artifacts"]
            if item["intended"]["exists"]
        }
    unit_previews = []
    artifact_previews = []
    for unit_id in recovery.UNIT_IDS:
        current_unit = current_units[unit_id]
        initial_state = current_unit["state"]
        target_state = target_states[unit_id]
        initial_entries = _state_entries(initial_state)
        target_entries = _state_entries(target_state)
        keys = sorted(set(initial_entries) | set(target_entries) |
                      {path for old_unit, path in prior_records if old_unit == unit_id})
        for relative in keys:
            prior = initial_entries.get(
                relative, {"exists": False, "sha256": None, "mode": None, "kind": None}
            )
            intended = target_entries.get(
                relative, {"exists": False, "sha256": None, "mode": None, "kind": None}
            )
            old = prior_records.get((unit_id, relative))
            if old is not None and old["ownership"] == "matching_preexisting_unowned":
                if intended["exists"] and intended["sha256"] == old["intended"]["sha256"]:
                    intended = old["intended"]
                    disposition = "matching_preexisting_unowned"
                elif kind == "uninstall":
                    intended = old["intended"]
                    disposition = "matching_preexisting_unowned"
                else:
                    disposition = "unresolved"
                    _record_blocker(
                        blockers, "unowned_change_requires_adoption", unit_id, relative,
                        "release would change or remove a matching pre-existing unowned artifact",
                    )
            elif management["status"] == "legacy_unmanaged" and prior["exists"]:
                if (unit_id != "payload" and intended["exists"] and prior["kind"] == "file"
                        and prior["sha256"] == intended["sha256"] and prior["mode"] == 0o644):
                    disposition = "matching_preexisting_unowned"
                    intended = prior
                else:
                    disposition = "unresolved"
                    _record_blocker(
                        blockers,
                        "unowned_payload" if unit_id == "payload" else "unowned_collision",
                        unit_id, relative,
                        "unmanaged existing content cannot be changed or claimed",
                    )
            elif prior["exists"]:
                disposition = "already_owned"
            elif intended["exists"]:
                disposition = "created"
            else:
                disposition = "absent"
            artifact_previews.append(
                {
                    "unit_id": unit_id,
                    "path": relative,
                    "destination": _artifact_destination(current_unit, relative),
                    "prior": prior,
                    "intended": intended,
                    "ownership": disposition,
                    "local_change": "none" if disposition != "unresolved" else "blocked",
                }
            )
        if unit_id != "payload":
            root_record = next(
                item for item in artifact_previews
                if item["unit_id"] == unit_id and item["path"] == "."
            )
            if root_record["ownership"] == "matching_preexisting_unowned":
                target_state = {
                    "exists": True, "kind": "file",
                    "sha256": root_record["intended"]["sha256"],
                    "mode": root_record["intended"]["mode"], "artifacts": [],
                }
                target_states[unit_id] = target_state
        unit_previews.append(
            {
                "unit_id": unit_id,
                "destination": current_unit["destination"],
                "kind": current_unit["kind"],
                "initial": initial_state,
                "target": target_state,
            }
        )
    blockers.sort(key=lambda item: (item["code"], item["unit_id"], item["path"], item["reason"]))
    required_gates = {
        "authentic-reader-support",
        "c1-terminal-admission-integration",
        "external-recovery-check-plan",
        "under-lease-liveness-and-ownership-revalidation",
    }
    if management["status"] == "legacy_unmanaged":
        required_gates.add("user-maintenance-window-for-first-adoption")
    if kind == "rollback":
        required_gates.add("supported-managed-rollback-target")
    return {
        "planning_preview_format": PLANNING_PREVIEW_FORMAT,
        "executable": False,
        "non_executable_reason": (
            "C1 admission/liveness, authentic reader evidence, recovery staging and the held-lease "
            "handshake are deliberately absent from this planning slice"
        ),
        "kind": kind,
        "roots": roots,
        "release": None if release is None else {
            "root": release.get("root", release["manifest_path"]),
            "manifest_sha256": release["manifest_sha256"],
            "package_id": release["package_id"],
            "runtime_cohort": release["runtime_cohort"],
            "artifact_count": release["artifact_count"],
        },
        "current": management,
        "eligible_for_integration": not blockers,
        "blockers": blockers,
        "required_gates": sorted(required_gates),
        "payload_cache_backup": ownership["payload_cache"],
        "units": unit_previews,
        "artifacts": artifact_previews,
    }


def canonical_preview_bytes(preview: Dict[str, Any]) -> bytes:
    recovery.exact_keys(
        preview,
        ("planning_preview_format", "executable", "non_executable_reason", "kind", "roots",
         "release", "current", "eligible_for_integration", "blockers", "required_gates",
         "payload_cache_backup", "units", "artifacts"),
        "planning preview",
    )
    if (recovery.exact_int(preview["planning_preview_format"], "planning preview format", 1)
            != PLANNING_PREVIEW_FORMAT or preview["executable"] is not False):
        raise LifecyclePlanningError("planning preview must remain explicitly non-executable")
    forbidden = {"transaction_id", "plan_format", "proposed_receipt", "proposed_prior_receipt",
                 "recovery_required", "intent"}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if forbidden.intersection(value):
                raise LifecyclePlanningError("planning preview contains executable transaction fields")
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(preview)
    return recovery.json_bytes(preview)


def _mkdir(path: Path) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        recovery._sync_directory(path, None, "prepared-directory")
        recovery._sync_directory(path.parent, None, "prepared-directory-parent")
        return
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise LifecyclePlanningError("prepared path is not a real directory: %s" % path)


def _prepared_file_state(data: bytes, mode: int = 0o600) -> Dict[str, Any]:
    return {
        "exists": True,
        "kind": "file",
        "sha256": recovery.sha256_bytes(data),
        "mode": mode,
        "artifacts": [],
    }


def _preparation_root(state_root: Path) -> Path:
    return state_root / recovery.PREPARATION_ROOT_NAME


def _validate_preparation_record(value: Any, state_root: Path) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise LifecyclePlanningError("preparation ownership record must be an object")
    recovery.exact_keys(
        value,
        ("format", "transaction_id", "roots", "root_identities", "bootstrap",
         "control_root", "claims"),
        "preparation ownership record",
    )
    if recovery.exact_int(value["format"], "preparation record format", 1) != 1:
        raise LifecyclePlanningError("unsupported preparation ownership record")
    transaction_id = recovery.checked_id(
        value["transaction_id"], "preparation transaction_id"
    )
    roots = recovery.validate_roots(value["roots"])
    if roots["state"] != str(state_root):
        raise LifecyclePlanningError("preparation record belongs to another state root")
    identities = value["root_identities"]
    if not isinstance(identities, dict):
        raise LifecyclePlanningError("preparation root identities must be an object")
    recovery.exact_keys(
        identities, ("state", "payload_parent", "opencode"),
        "preparation root identities",
    )
    for name in identities:
        recovery.validate_identity(identities[name], "preparation %s identity" % name)
    if type(value["bootstrap"]) is not bool:
        raise LifecyclePlanningError("preparation bootstrap must be boolean")
    canonical = state_root / ".council-lifecycle"
    prepared = state_root / (".council-lifecycle.prepare-" + transaction_id)
    control = recovery.checked_absolute(value["control_root"], "preparation control root")
    expected_control = prepared if value["bootstrap"] else canonical
    if control != expected_control:
        raise LifecyclePlanningError("preparation control root is not fixed")
    allowed_objects = set()
    for unit_id in recovery.UNIT_IDS:
        destination = recovery._unit_destination(roots, unit_id)
        objects = recovery._unit_objects(destination, transaction_id, unit_id)
        allowed_objects.update(Path(objects[name]) for name in ("target", "prior"))
    claims = value["claims"]
    if not isinstance(claims, list) or len(claims) > recovery.MAX_ARTIFACTS * 2:
        raise LifecyclePlanningError("preparation claims are not bounded")
    seen = set()
    for index, claim in enumerate(claims):
        label = "preparation claim %d" % index
        if not isinstance(claim, dict):
            raise LifecyclePlanningError("%s must be an object" % label)
        recovery.exact_keys(claim, ("path", "parent_identity", "expected"), label)
        path = recovery.checked_absolute(claim["path"], label + " path")
        if path in seen:
            raise LifecyclePlanningError("duplicate preparation claim")
        seen.add(path)
        parent_identity = recovery.validate_identity(
            claim["parent_identity"], label + " parent identity"
        )
        if parent_identity != claim["parent_identity"]:
            raise LifecyclePlanningError("preparation parent identity is not canonical")
        expected = claim["expected"]
        if expected is not None:
            kind = expected.get("kind") if isinstance(expected, dict) else None
            recovery.validate_state(expected, label + " expected", kind)
        inside_control = path == control or control in path.parents
        if not inside_control and path not in allowed_objects:
            raise LifecyclePlanningError("preparation claim escapes the fixed namespace")
    return value


def _remove_prepared_tree(path: Path, expected: Dict[str, Any], counter: List[int]) -> None:
    allowed = {item["path"]: item for item in expected["artifacts"]}
    actual = []
    for child in path.rglob("*"):
        relative = str(child.relative_to(path).as_posix())
        item = allowed.get(relative)
        details = child.lstat()
        if item is None or stat.S_ISLNK(details.st_mode):
            raise LifecyclePlanningError("prepared cleanup encountered unexpected content")
        if item["kind"] == "file":
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise LifecyclePlanningError("prepared cleanup encountered a changed file")
            observed = {
                "path": relative, "kind": "file",
                "sha256": recovery.sha256_file(child),
                "mode": stat.S_IMODE(details.st_mode),
            }
            if observed != item:
                raise LifecyclePlanningError("prepared cleanup encountered changed file bytes")
        elif not stat.S_ISDIR(details.st_mode):
            raise LifecyclePlanningError("prepared cleanup encountered a changed directory")
        elif item != {
            "path": relative, "kind": "directory", "sha256": None,
            "mode": stat.S_IMODE(details.st_mode),
        }:
            raise LifecyclePlanningError("prepared cleanup encountered changed directory metadata")
        actual.append(child)
        counter[0] += 1
        if counter[0] > recovery.MAX_ARTIFACTS * 2:
            raise LifecyclePlanningError("prepared cleanup exceeds its bound")
    for child in sorted(
        actual, key=lambda item: (len(item.relative_to(path).parts), str(item)),
        reverse=True,
    ):
        if child.is_dir():
            child.rmdir()
        else:
            child.unlink()
        recovery._sync_directory(child.parent, None, "pre-intent-cleanup")


def _remove_prepared_path(path: Path, expected: Optional[Dict[str, Any]],
                          counter: List[int]) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return
    counter[0] += 1
    if counter[0] > recovery.MAX_ARTIFACTS * 2:
        raise LifecyclePlanningError("prepared cleanup exceeds its bound")
    if stat.S_ISLNK(details.st_mode):
        raise LifecyclePlanningError("prepared cleanup encountered a symlink")
    if expected is not None and expected["kind"] == "file":
        if not stat.S_ISREG(details.st_mode):
            raise LifecyclePlanningError("prepared cleanup encountered a changed file")
        if details.st_nlink != 1:
            raise LifecyclePlanningError("prepared cleanup encountered a hard link")
        if not recovery.state_matches(path, expected):
            raise LifecyclePlanningError("prepared cleanup encountered changed file bytes")
        path.unlink()
        recovery._sync_directory(path.parent, None, "pre-intent-cleanup")
        return
    if not stat.S_ISDIR(details.st_mode):
        raise LifecyclePlanningError("prepared cleanup encountered unsupported content")
    if expected is not None:
        if expected["kind"] != "directory":
            raise LifecyclePlanningError("prepared cleanup kind differs")
        if stat.S_IMODE(details.st_mode) != expected["mode"]:
            raise LifecyclePlanningError("prepared cleanup directory mode differs")
        _remove_prepared_tree(path, expected, counter)
    else:
        with os.scandir(path) as entries:
            if next(entries, None) is not None:
                raise LifecyclePlanningError(
                    "prepared cleanup directory contains unexpected content"
                )
    path.rmdir()
    recovery._sync_directory(path.parent, None, "pre-intent-cleanup")


class _PreparationGuard:
    def __init__(self, lease: Any, transaction_id: str, roots: Dict[str, str],
                 bootstrap: bool, control_root: Path, failpoint: Any = None):
        self.lease = lease
        self.failpoint = failpoint
        self.active = True
        self.state_root = Path(roots["state"])
        self.record_root = _preparation_root(self.state_root)
        _mkdir(self.record_root)
        record_root_details = self.record_root.lstat()
        if (stat.S_ISLNK(record_root_details.st_mode) or
                not stat.S_ISDIR(record_root_details.st_mode) or
                stat.S_IMODE(record_root_details.st_mode) != 0o700):
            raise LifecyclePlanningError("preparation record root is not a private directory")
        self.record_path = self.record_root / (transaction_id + ".json")
        if self.record_path.exists() or self.record_path.is_symlink():
            raise LifecyclePlanningError("preparation transaction identifier is already present")
        self.record = {
            "format": PREPARATION_RECORD_FORMAT,
            "transaction_id": transaction_id,
            "roots": roots,
            "root_identities": {
                "state": recovery.physical_identity(self.state_root),
                "payload_parent": recovery.physical_identity(Path(roots["payload"]).parent),
                "opencode": recovery.physical_identity(Path(roots["opencode"])),
            },
            "bootstrap": bootstrap,
            "control_root": str(control_root),
            "claims": [],
        }
        _validate_preparation_record(self.record, self.state_root)
        recovery._atomic_json(
            self.record_path, self.record, self.failpoint, "preparation-record"
        )

    @property
    def claims(self) -> List[Tuple[Path, Dict[str, int], Optional[Dict[str, Any]]]]:
        return [
            (Path(item["path"]), item["parent_identity"], item["expected"])
            for item in self.record["claims"]
        ]

    def claim_absent(self, path: Path,
                     expected: Optional[Dict[str, Any]] = None) -> None:
        self.lease.validate()
        if path.exists() or path.is_symlink():
            raise LifecyclePlanningError("prepared path was occupied before creation")
        claim = {
            "path": str(path),
            "parent_identity": recovery.physical_identity(path.parent),
            "expected": expected,
        }
        self.record["claims"].append(claim)
        _validate_preparation_record(self.record, self.state_root)
        recovery._atomic_json(
            self.record_path, self.record, self.failpoint, "preparation-record"
        )

    def _retire_record(self) -> None:
        expected = recovery.json_bytes(self.record)
        actual = recovery.read_regular(self.record_path, "preparation ownership record")
        if actual != expected:
            raise LifecyclePlanningError("preparation ownership record changed")
        self.record_path.unlink()
        recovery._sync_directory(self.record_root, self.failpoint, "preparation-record-retired")

    def cleanup(self) -> None:
        if not self.active:
            return
        self.lease.validate()
        counter = [0]
        for path, parent_identity, expected in reversed(self.claims):
            if not (path.exists() or path.is_symlink()):
                continue
            if recovery.physical_identity(path.parent) != parent_identity:
                raise LifecyclePlanningError("prepared cleanup parent identity changed")
            _remove_prepared_path(path, expected, counter)
        self._retire_record()
        self.active = False

    def preserve(self) -> None:
        if not self.active:
            return
        self.lease.validate()
        self._retire_record()
        self.active = False

    @classmethod
    def from_record(cls, lease: Any, record_path: Path,
                    record: Dict[str, Any]) -> "_PreparationGuard":
        guard = object.__new__(cls)
        guard.lease = lease
        guard.failpoint = None
        guard.active = True
        guard.state_root = Path(record["roots"]["state"])
        guard.record_root = record_path.parent
        guard.record_path = record_path
        guard.record = record
        return guard


def _remove_stale_preparation_pending(path: Path, canonical: Optional[Dict[str, Any]],
                                      state_root: Path) -> None:
    value, _data = recovery.read_object(path, "preparation record pending replacement")
    value = _validate_preparation_record(value, state_root)
    if canonical is not None:
        if (value["transaction_id"] != canonical["transaction_id"] or
                value["claims"][:len(canonical["claims"])] != canonical["claims"] or
                len(value["claims"]) != len(canonical["claims"]) + 1):
            raise LifecyclePlanningError("preparation pending record is not the next claim")
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise LifecyclePlanningError("preparation pending record changed")
    path.unlink()
    recovery._sync_directory(path.parent, None, "preparation-pending-retired")


def _reconcile_preparations(state_root: Path, lease: Any) -> None:
    root = _preparation_root(state_root)
    if not root.exists() and not root.is_symlink():
        return
    details = root.lstat()
    if (stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode) or
            stat.S_IMODE(details.st_mode) != 0o700):
        raise LifecyclePlanningError("preparation record root is not a private directory")
    entries = sorted(root.iterdir(), key=lambda item: item.name)
    if len(entries) > recovery.MAX_ARTIFACTS:
        raise LifecyclePlanningError("preparation record inventory exceeds its bound")
    canonical_paths = {
        item.name: item for item in entries
        if item.name.endswith(".json") and not item.name.startswith(".")
    }
    pending_paths = {
        item.name[1:-len(".pending")]: item for item in entries
        if item.name.startswith(".") and item.name.endswith(".json.pending")
    }
    known = set(canonical_paths.values()) | set(pending_paths.values())
    if set(entries) != known:
        raise LifecyclePlanningError("preparation record root contains unknown content")
    for name in sorted(set(canonical_paths) | set(pending_paths)):
        record_path = canonical_paths.get(name)
        record = None
        if record_path is not None:
            record, _data = recovery.read_object(record_path, "preparation ownership record")
            record = _validate_preparation_record(record, state_root)
        pending_path = pending_paths.get(name)
        if pending_path is not None:
            _remove_stale_preparation_pending(pending_path, record, state_root)
        if record is None:
            continue
        identities = {
            "state": recovery.physical_identity(state_root),
            "payload_parent": recovery.physical_identity(Path(record["roots"]["payload"]).parent),
            "opencode": recovery.physical_identity(Path(record["roots"]["opencode"])),
        }
        if identities != record["root_identities"]:
            raise LifecyclePlanningError("preparation record root identity changed")
        canonical = state_root / ".council-lifecycle"
        intent_matches = False
        if canonical.exists() and not canonical.is_symlink():
            try:
                admission_value, _ = recovery.read_object(
                    canonical / "admission.json", "admission"
                )
                admission_value = recovery.validate_admission(
                    admission_value, record["roots"]
                )
            except (OSError, ValueError, UnicodeError):
                admission_value = None
            if (admission_value is not None and
                    admission_value["status"] == "recovery_required"):
                if admission_value["transaction_id"] != record["transaction_id"]:
                    raise LifecyclePlanningError(
                        "another recovery transaction blocks preparation reconciliation"
                    )
                intent_matches = True
            elif admission_value is not None and admission_value["committed"] is not None:
                try:
                    receipt = recovery._verify_terminal_receipt(
                        state_root, admission_value["committed"]
                    )
                except (OSError, ValueError, UnicodeError):
                    receipt = None
                if receipt is not None and receipt["transaction_id"] == record["transaction_id"]:
                    intent_matches = True
        guard = _PreparationGuard.from_record(lease, record_path, record)
        if intent_matches:
            guard.preserve()
        else:
            guard.cleanup()


class _PreparedBundle(dict):
    pass


def _cleanup_preintent_bundle(bundle: _PreparedBundle) -> None:
    guard = bundle.preparation_guard
    canonical = Path(bundle["canonical_root"])
    if bundle["bootstrap"]:
        if canonical.exists() or canonical.is_symlink():
            guard.preserve()
    else:
        try:
            current, _ = recovery.read_object(canonical / "admission.json", "admission")
            current = recovery.validate_admission(current)
        except (OSError, ValueError, UnicodeError):
            guard.preserve()
        else:
            if current == bundle["pending_admission"] or current["transaction_id"] is not None:
                guard.preserve()
    guard.cleanup()


def _copy_file(source: Path, destination: Path, expected_sha256: str,
               mode: int = 0o644) -> None:
    before = source.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise LifecyclePlanningError("staged source must be a single-linked regular file")
    source_descriptor = os.open(str(source), os.O_RDONLY | os.O_NOFOLLOW)
    destination_descriptor = -1
    destination_identity = None
    complete = False
    try:
        destination_descriptor = os.open(
            str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode
        )
        destination_details = os.fstat(destination_descriptor)
        destination_identity = (destination_details.st_dev, destination_details.st_ino)
        opened = os.fstat(source_descriptor)
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
                    raise LifecyclePlanningError("short artifact staging write")
                view = view[written:]
        after = os.fstat(source_descriptor)
        if (_file_fingerprint(before) != _file_fingerprint(opened) or
                _file_fingerprint(opened) != _file_fingerprint(after) or
                _file_fingerprint(after) != _file_fingerprint(source.lstat()) or
                digest.hexdigest() != expected_sha256):
            raise LifecyclePlanningError("staged source changed or differs from its digest")
        os.fchmod(destination_descriptor, mode)
        os.fsync(destination_descriptor)
        complete = True
    finally:
        os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if not complete and destination_identity is not None:
            try:
                current = destination.lstat()
            except FileNotFoundError:
                current = None
            if (current is not None and
                    (current.st_dev, current.st_ino) == destination_identity):
                destination.unlink()
                recovery._sync_directory(
                    destination.parent, None, "failed-staged-artifact-cleanup"
                )
    recovery._sync_directory(destination.parent, None, "staged-artifact")


def _copy_state(source: Path, destination: Path, expected: Dict[str, Any]) -> None:
    if not expected["exists"]:
        return
    if expected["kind"] == "file":
        _copy_file(source, destination, expected["sha256"], expected["mode"])
    else:
        _mkdir(destination)
        destination.chmod(expected["mode"])
        for item in expected["artifacts"]:
            path = destination / item["path"]
            if item["kind"] == "directory":
                _mkdir(path)
                path.chmod(item["mode"])
            else:
                _copy_file(source / item["path"], path, item["sha256"], item["mode"])
    if not recovery.state_matches(destination, expected):
        raise LifecyclePlanningError("staged recovery object differs from planned state")


def _control_bytes(value: Any, label: str) -> bytes:
    data = value if isinstance(value, bytes) else recovery.json_bytes(value)
    if len(data) > recovery.MAX_METADATA_BYTES:
        raise LifecyclePlanningError("%s exceeds the 1 MiB metadata limit" % label)
    return data


def _release_artifact_map(release: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    return {
        (item["unit_id"], item["destination_relative"]): item
        for item in release["artifacts"]
    }


def reader_support_record(release: Dict[str, Any]) -> Dict[str, Any]:
    release = _validate_release_snapshot(release)
    artifacts = {item["release_path"]: item["sha256"] for item in release["artifacts"]}
    policy_name = "payload/scripts/fixtures/lifecycle/reader-support-v1.json"
    policy, policy_data = recovery.read_object(
        Path(release["root"]) / policy_name, "reader support policy"
    )
    recovery.exact_keys(
        policy, ("format", "features", "formats", "required_tests", "results"),
        "reader support policy",
    )
    if recovery.exact_int(policy["format"], "reader support policy format", 1) != 1:
        raise LifecyclePlanningError("unsupported reader support policy")
    required_tests = [
        "scripts/test_admission.py", "scripts/test_lifecycle.py",
        "scripts/test_lifecycle_recovery.py", "scripts/test_predecessors.py",
    ]
    if policy["required_tests"] != required_tests or any(
        "payload/" + name not in artifacts for name in required_tests
    ):
        raise LifecyclePlanningError("reader support policy lacks its exact test closure")
    results = policy["results"]
    if not isinstance(results, dict):
        raise LifecyclePlanningError("reader support results must be an object")
    recovery.exact_keys(
        results, ("state_reader", "managed_writer_admission", "external_recoverer"),
        "reader support results",
    )
    if any(value != "pass" for value in results.values()):
        raise LifecyclePlanningError("reader support policy is not qualified")
    reader_names = ["payload/" + name for name in release["runtime_sources"]]
    closure_names = sorted(set(reader_names + [
        "payload/scripts/council_recover.py",
        "payload/scripts/council_lifecycle.py",
        policy_name,
    ]))
    if any(name not in artifacts for name in closure_names):
        raise LifecyclePlanningError("release lacks the lifecycle reader/import closure")

    def identity(names: List[str]) -> str:
        return hashlib.sha256(
            json.dumps([[name, artifacts[name]] for name in names], separators=(",", ":")).encode()
        ).hexdigest()

    corpus_names = [
        "payload/scripts/fixtures/predecessors/corpus.json",
        "payload/scripts/fixtures/predecessors/corpus.sha256",
        "payload/scripts/fixtures/predecessors/readers.json",
        "payload/scripts/fixtures/predecessors/support.json",
        "payload/scripts/fixtures/predecessors/c2-current/LICENSE",
        "payload/scripts/fixtures/predecessors/c2-current/NOTICE",
        "payload/scripts/fixtures/predecessors/c2-current/reader.json",
        "payload/scripts/fixtures/predecessors/c2-current/scripts/council.py",
        "payload/scripts/fixtures/predecessors/c2-current/scripts/council_admission.py",
        "payload/scripts/fixtures/predecessors/c2-current/scripts/council_inspect.py",
        "payload/scripts/fixtures/predecessors/c2-current/scripts/council_protocol.py",
    ]
    if any(name not in artifacts for name in corpus_names):
        raise LifecyclePlanningError("release lacks predecessor corpus evidence")
    if recovery.sha256_bytes(policy_data) != artifacts[policy_name]:
        raise LifecyclePlanningError("reader support policy changed during validation")
    record = {
        "source_sha256": identity(reader_names),
        "package_id": release["package_id"],
        "runtime_cohort": release["runtime_cohort"],
        "import_closure_sha256": identity(closure_names),
        "fixture_corpus_sha256": identity(corpus_names),
        "features": policy["features"],
        "state_reader": results["state_reader"],
        "managed_writer_admission": results["managed_writer_admission"],
        "external_recoverer": results["external_recoverer"],
        "formats": policy["formats"],
    }
    return recovery.validate_reader_support(record)


def _current_provenance(preview: Dict[str, Any]) -> Tuple[Dict[str, Any], bytes,
                                                          Dict[str, Any], bytes]:
    summary = preview["current"]["summary"]
    if summary is None:
        raise LifecyclePlanningError("current lifecycle state has no receipt provenance")
    state_root = Path(preview["roots"]["state"])
    receipt = recovery._verify_terminal_receipt(state_root, summary)
    manifest_path, support_path = recovery._receipt_provenance_paths(
        state_root, summary["receipt_id"]
    )
    manifest, manifest_data = recovery.read_object(manifest_path, "current source manifest")
    support, support_data = recovery.read_object(support_path, "current reader support")
    manifest = recovery.validate_release_manifest(manifest)
    support = recovery.validate_reader_support(support)
    if (recovery.sha256_bytes(manifest_data) != receipt["source_manifest_sha256"] or
            recovery.sha256_bytes(support_data) != receipt["reader_support_sha256"] or
            manifest["package_id"] != summary["package_id"] or
            manifest["runtime_cohort"] != summary["runtime_cohort"] or
            support["package_id"] != summary["package_id"] or
            support["runtime_cohort"] != summary["runtime_cohort"]):
        raise LifecyclePlanningError("current provenance differs from receipt")
    return manifest, manifest_data, support, support_data


def _admission(status: str, roots: Dict[str, str], summary: Optional[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "format": 1, "namespace_version": 1, "roots": roots, "status": status,
        "transaction_id": None, "committed": summary,
    }


def _receipt_from_preview(preview: Dict[str, Any], transaction_id: str, receipt_id: str,
                          outcome: str, roots: Dict[str, str], root_identities: Dict[str, Any],
                          lock_identity: Dict[str, Any], manifest_sha256: str,
                          tool_sha256: str, support_sha256: str,
                          artifacts: List[Dict[str, Any]], prior_summary: Optional[Dict[str, Any]],
                          package_id: str, runtime_cohort: str) -> Dict[str, Any]:
    return {
        "receipt_format": 1,
        "receipt_id": receipt_id,
        "transaction_id": transaction_id,
        "outcome": outcome,
        "roots": roots,
        "root_identities": root_identities,
        "lock_identity": lock_identity,
        "package_id": package_id,
        "runtime_cohort": runtime_cohort,
        "source_manifest_sha256": manifest_sha256,
        "prior_receipt": None if prior_summary is None else {
            "receipt_id": prior_summary["receipt_id"],
            "receipt_sha256": prior_summary["receipt_sha256"],
        },
        "recovery": {"format": 1, "tool_sha256": tool_sha256},
        "reader_support_sha256": support_sha256,
        "artifacts": artifacts,
    }


def prepare_transaction(preview: Dict[str, Any], release_snapshot: Optional[Dict[str, Any]],
                        lease: Any, *, transaction_id: Optional[str] = None,
                        failpoint: Any = None) -> Dict[str, Any]:
    guards: List[_PreparationGuard] = []
    try:
        return _prepare_transaction(
            preview, release_snapshot, lease, transaction_id=transaction_id,
            preparation_guards=guards, failpoint=failpoint,
        )
    except BaseException:
        if guards:
            guards[0].cleanup()
        raise


def _prepare_transaction(preview: Dict[str, Any], release_snapshot: Optional[Dict[str, Any]],
                         lease: Any, *, transaction_id: Optional[str],
                         preparation_guards: List[_PreparationGuard],
                         failpoint: Any) -> Dict[str, Any]:
    """Prepare durable recovery inputs under an already-held C1 lease; no intent is published."""
    if preview["executable"] is not False or not preview["eligible_for_integration"]:
        raise LifecyclePlanningError("only an eligible non-executable preview can be prepared")
    if preview["kind"] == "uninstall":
        if release_snapshot is not None or preview["release"] is not None:
            raise LifecyclePlanningError("uninstall preparation does not accept a release")
        manifest, manifest_data, support, support_data = _current_provenance(preview)
        source = None
    else:
        if release_snapshot is None:
            raise LifecyclePlanningError("transaction preparation requires a release")
        source = _validated_release_source(preview["kind"], release_snapshot)
        if (preview["release"] is None or
                preview["release"]["manifest_sha256"] != source["manifest_sha256"]):
            raise LifecyclePlanningError("preview and release differ")
        manifest, manifest_data = recovery.read_object(
            Path(source["manifest_path"]), "release manifest"
        )
        manifest = recovery.validate_release_manifest(manifest)
        if "retained_release_format" in source:
            support, support_data = recovery.read_object(
                Path(source["support_path"]), "retained reader support"
            )
            support = recovery.validate_reader_support(support)
            if (recovery.sha256_bytes(manifest_data) != source["manifest_sha256"] or
                    recovery.sha256_bytes(support_data) != source["support_sha256"]):
                raise LifecyclePlanningError("retained release provenance changed")
        else:
            support = reader_support_record(source)
            support_data = recovery.json_bytes(support)
    transaction_id = transaction_id or ("txn-" + secrets.token_hex(16))
    recovery.checked_id(transaction_id, "transaction_id")
    roots = preview["roots"]
    state_root = Path(roots["state"])
    lease.validate(state_root)
    canonical = state_root / ".council-lifecycle"
    bootstrap = not canonical.exists() and not canonical.is_symlink()
    control = state_root / (".council-lifecycle.prepare-" + transaction_id) if bootstrap else canonical
    if control.exists() or control.is_symlink():
        if bootstrap:
            raise LifecyclePlanningError("prepared lifecycle namespace already exists")
    transaction = control / "v1/transactions" / transaction_id
    if transaction.exists() or transaction.is_symlink():
        raise LifecyclePlanningError("transaction identifier is already present")
    preparation_guard = _PreparationGuard(
        lease, transaction_id, roots, bootstrap, control, failpoint
    )
    preparation_guards.append(preparation_guard)
    for path in (
        control, control / "v1", control / "v1/receipts", control / "v1/recovery",
        control / "v1/transactions", transaction,
    ):
        if not (path.exists() or path.is_symlink()):
            preparation_guard.claim_absent(path)
        _mkdir(path)
        recovery._event(failpoint, "after:prepare-directory:" + str(path))
    manifest_path = transaction / "source-manifest.json"
    support_path = transaction / "reader-support.json"
    support_sha256 = recovery.sha256_bytes(support_data)
    if source is None:
        tool_source = Path(roots["payload"]) / "scripts/council_recover.py"
    elif "retained_release_format" in source:
        tool_source = Path(source["tool_path"])
    else:
        tool_source = Path(source["root"]) / "payload/scripts/council_recover.py"
    expected_tool = manifest["artifacts"].get("payload/scripts/council_recover.py")
    if expected_tool is None or recovery.sha256_file(tool_source) != expected_tool:
        raise LifecyclePlanningError("source recovery tool differs from its manifest")
    tool_sha256 = recovery.sha256_file(tool_source)
    actual_tool = control / "v1/recovery" / (tool_sha256 + ".py")
    tool_exists = actual_tool.exists() or actual_tool.is_symlink()
    if tool_exists:
        if (actual_tool.is_symlink() or recovery.sha256_file(actual_tool) != tool_sha256 or
                stat.S_IMODE(actual_tool.stat().st_mode) != 0o600):
            raise LifecyclePlanningError("retained recovery tool differs from source")
    canonical_tool = canonical / "v1/recovery" / (tool_sha256 + ".py")
    unit_map = {item["unit_id"]: item for item in preview["units"]}
    release_map = {} if source is None else _release_artifact_map(source)
    units = []
    copy_jobs = []
    for unit_id in recovery.UNIT_IDS:
        unit = unit_map[unit_id]
        destination = Path(unit["destination"])
        initial = unit["initial"]
        prior = initial
        if unit_id == "payload" and initial["exists"]:
            prior, _cache = recovery._payload_without_known_caches(initial)
        target = unit["target"]
        objects = recovery._unit_objects(destination, transaction_id, unit_id)
        prior_path = Path(objects["prior"])
        target_path = Path(objects["target"])
        if prior["exists"]:
            copy_jobs.append((destination, prior_path, prior))
        if target["exists"]:
            if source is not None and "retained_release_format" in source:
                target_source = Path(source["unit_sources"][unit_id])
            elif unit_id == "payload":
                target_source = Path(source["root"]) / "payload"
            else:
                release_item = release_map.get((unit_id, "."))
                target_source = (
                    Path(source["root"]) / release_item["release_path"]
                    if release_item is not None and release_item["sha256"] == target["sha256"]
                    else destination
                )
            copy_jobs.append((target_source, target_path, target))
        units.append({
            "unit_id": unit_id, "destination": str(destination),
            "parent_identity": recovery.physical_identity(destination.parent),
            "initial": initial, "prior": prior, "target": target, "objects": objects,
        })
    receipt_root_identities = {
        "state": recovery.physical_identity(state_root),
        "payload_parent": recovery.physical_identity(Path(roots["payload"]).parent),
        "opencode": recovery.physical_identity(Path(roots["opencode"])),
    }
    lock_identity = recovery.lock_path_identity(state_root / "broker.lock")
    prior_summary = preview["current"]["summary"]
    receipt_id = "receipt-" + transaction_id.removeprefix("txn-")
    target_receipt = _receipt_from_preview(
        preview, transaction_id, receipt_id,
        "uninstalled" if preview["kind"] == "uninstall" else "committed",
        roots, receipt_root_identities, lock_identity, recovery.sha256_bytes(manifest_data),
        tool_sha256, support_sha256, preview["artifacts"], prior_summary,
        manifest["package_id"], manifest["runtime_cohort"],
    )
    target_receipt_path = transaction / "receipt.json"
    target_receipt_data = recovery.json_bytes(target_receipt)
    target_summary = {
        "receipt_id": receipt_id,
        "receipt_sha256": recovery.sha256_bytes(target_receipt_data),
        "package_id": manifest["package_id"],
        "runtime_cohort": manifest["runtime_cohort"],
    }
    target_outcome = _admission(
        "uninstalled" if preview["kind"] == "uninstall" else "committed",
        roots, target_summary,
    )
    prior_outcome = _admission(preview["current"]["status"], roots, prior_summary)
    proposed_prior = None
    prior_receipt_data = None
    if prior_summary is None:
        prior_id = receipt_id + "-prior"
        preview_artifacts = {
            (artifact["unit_id"], artifact["path"]): artifact
            for artifact in preview["artifacts"]
        }
        planned_units = {unit["unit_id"]: unit for unit in units}
        prior_artifacts = []
        for unit_id, relative in recovery._receipt_artifact_keys(units, "prior"):
            unit = planned_units[unit_id]
            initial = recovery._leaf_state(unit["initial"], relative)
            intended = recovery._leaf_state(unit["prior"], relative)
            preview_artifact = preview_artifacts.get((unit_id, relative))
            ownership = (
                "matching_preexisting_unowned"
                if preview_artifact is not None and
                preview_artifact["ownership"] == "matching_preexisting_unowned"
                else "absent"
            )
            prior_artifacts.append({
                "unit_id": unit_id, "path": relative,
                "destination": str(Path(unit["destination"]) if relative == "."
                                   else Path(unit["destination"]) / relative),
                "prior": initial, "intended": intended,
                "ownership": ownership, "local_change": "none",
            })
        prior_receipt = _receipt_from_preview(
            preview, transaction_id, prior_id, "uninstalled", roots,
            receipt_root_identities, lock_identity, recovery.sha256_bytes(manifest_data), tool_sha256,
            support_sha256, prior_artifacts, None,
            manifest["package_id"], manifest["runtime_cohort"],
        )
        prior_path = transaction / "prior-receipt.json"
        prior_receipt_data = recovery.json_bytes(prior_receipt)
        proposed_prior = {
            "path": "prior-receipt.json",
            "sha256": recovery.sha256_bytes(prior_receipt_data),
        }
        prior_summary = {
            "receipt_id": prior_id, "receipt_sha256": proposed_prior["sha256"],
            "package_id": manifest["package_id"], "runtime_cohort": manifest["runtime_cohort"],
        }
        prior_outcome = _admission("uninstalled", roots, prior_summary)
    root_identities = {
        "state": recovery.physical_identity(state_root),
        "payload_parent": recovery.physical_identity(Path(roots["payload"]).parent),
        "opencode": recovery.physical_identity(Path(roots["opencode"])),
        "lifecycle": recovery.physical_identity(control),
        "v1": recovery.physical_identity(control / "v1"),
        "receipts": recovery.physical_identity(control / "v1/receipts"),
        "recovery": recovery.physical_identity(control / "v1/recovery"),
        "transactions": recovery.physical_identity(control / "v1/transactions"),
        "transaction": recovery.physical_identity(transaction),
    }
    prior_admission = _admission(
        "uninstalled" if preview["current"]["status"] == "legacy_unmanaged"
        else preview["current"]["status"],
        roots, preview["current"]["summary"],
    )
    plan = {
        "plan_format": 1, "transaction_id": transaction_id, "kind": preview["kind"],
        "roots": roots, "root_identities": root_identities, "lock_identity": lock_identity,
        "prior_admission": prior_admission, "outcomes": {"target": target_outcome, "prior": prior_outcome},
        "target_receipt_id": receipt_id,
        "source_manifest": {"path": "source-manifest.json",
                            "sha256": recovery.sha256_bytes(manifest_data)},
        "proposed_receipt": {"path": "receipt.json", "sha256": target_summary["receipt_sha256"]},
        "proposed_prior_receipt": proposed_prior,
        "recovery": {"format": 1, "tool_path": str(canonical_tool), "tool_sha256": tool_sha256,
                     "python_path": str(Path(sys.executable).resolve()),
                     "python_version": list(sys.version_info[:3])},
        "required_operations": list(recovery.REQUIRED_OPERATIONS),
        "allowed_goals": ["target", "prior"], "units": units,
        "retained_state": recovery.retained_state_fingerprint(state_root, control),
        "reader_support": {"path": "reader-support.json", "sha256": support_sha256},
    }
    plan_path = transaction / "plan.json"
    plan_data = recovery.json_bytes(plan)
    progress = {
        "journal_format": 1, "transaction_id": transaction_id,
        "plan_sha256": recovery.sha256_bytes(plan_data), "sequence": 0, "goal": "target",
        "units": [{"unit_id": unit_id, "phase": "pending"} for unit_id in recovery.UNIT_IDS],
    }
    pending = _admission("recovery_required", roots, preview["current"]["summary"])
    pending["transaction_id"] = transaction_id
    for value, label in (
        (manifest_data, "source manifest"),
        (support_data, "reader support"),
        (target_receipt_data, "target receipt"),
        (plan_data, "prepared plan"),
        (progress, "progress journal"),
        (pending, "pending admission"),
    ):
        _control_bytes(value, label)
    if prior_receipt_data is not None:
        _control_bytes(prior_receipt_data, "prior receipt")
    immutable_values = [
        (manifest_path, manifest_data),
        (support_path, support_data),
        (target_receipt_path, target_receipt_data),
        (plan_path, plan_data),
    ]
    if prior_receipt_data is not None:
        immutable_values.append((transaction / "prior-receipt.json", prior_receipt_data))
    for path, data in immutable_values:
        expected_file = _prepared_file_state(data)
        preparation_guard.claim_absent(path, expected_file)
        preparation_guard.claim_absent(
            path.with_name(path.name + ".partial"), expected_file
        )
    progress_path = transaction / "progress.json"
    progress_data = recovery.json_bytes(progress)
    progress_expected = _prepared_file_state(progress_data)
    preparation_guard.claim_absent(progress_path, progress_expected)
    preparation_guard.claim_absent(
        progress_path.with_name(".%s.pending" % progress_path.name),
        progress_expected,
    )
    if bootstrap:
        admission_path = control / "admission.json"
        pending_data = recovery.json_bytes(pending)
        pending_expected = _prepared_file_state(pending_data)
        preparation_guard.claim_absent(admission_path, pending_expected)
        preparation_guard.claim_absent(
            admission_path.with_name(".%s.pending" % admission_path.name),
            pending_expected,
        )
    recovery._write_immutable(manifest_path, manifest_data, None, "source-manifest")
    recovery._write_immutable(support_path, support_data, None, "reader-support")
    if not tool_exists:
        preparation_guard.claim_absent(
            actual_tool,
            {
                "exists": True, "kind": "file", "sha256": tool_sha256,
                "mode": 0o600, "artifacts": [],
            },
        )
        _copy_file(tool_source, actual_tool, tool_sha256, 0o600)
        recovery._event(failpoint, "after:prepare-recoverer-copy")
    loaded = _load_source_module(
        "_council_pinned_recover_" + transaction_id.replace("-", "_"), actual_tool,
        tool_sha256, canonical_tool,
    )
    for copy_source, copy_destination, copy_expected in copy_jobs:
        preparation_guard.claim_absent(copy_destination, copy_expected)
        _copy_state(copy_source, copy_destination, copy_expected)
        recovery._event(failpoint, "after:prepare-artifact-copy:" + str(copy_destination))
    recovery._write_immutable(
        target_receipt_path, target_receipt_data, None, "target-receipt"
    )
    if prior_receipt_data is not None:
        recovery._write_immutable(
            transaction / "prior-receipt.json", prior_receipt_data, None,
            "prior-receipt",
        )
    recovery._write_immutable(plan_path, plan_data, None, "plan")
    recovery._atomic_json(progress_path, progress, None, "progress")
    if bootstrap:
        recovery._atomic_json(control / "admission.json", pending, None, "prepared-admission")
    bundle = _PreparedBundle({
        "transaction_id": transaction_id, "kind": preview["kind"], "bootstrap": bootstrap,
        "control_root": str(control), "canonical_root": str(canonical),
        "plan": str(plan_path), "tool": str(actual_tool), "canonical_tool": str(canonical_tool),
        "pending_admission": pending, "loaded_recoverer": loaded,
        "preview_bytes": canonical_preview_bytes(preview),
        "release_snapshot": source,
        "recovery_command": [str(Path(sys.executable).resolve()), "-I", "-B", str(canonical_tool),
                             "recover", "--state-root", str(state_root)],
    })
    bundle.preparation_guard = preparation_guard
    return bundle


class C1LeaseAdapter:
    def __init__(self, lease: Any):
        self.lease = lease
        self._operation = None

    def __enter__(self) -> "C1LeaseAdapter":
        self._operation = self.lease.operation()
        self._operation.__enter__()
        self.lease.validate()
        return self

    def validate_for_recovery(self, state_root: Path) -> Dict[str, Any]:
        if self._operation is None:
            raise LifecyclePlanningError("C1 lease adapter is not active")
        self.lease.validate(state_root)
        return {
            "pid": self.lease.pid, "state_root": str(self.lease.root),
            "root_identity": {"device": self.lease.root_identity[0], "inode": self.lease.root_identity[1]},
            "lock_identity": {"device": self.lease.lock_identity[0], "inode": self.lease.lock_identity[1]},
            "lock_descriptor": self.lease.fd,
        }

    def __exit__(self, kind: Any, value: Any, traceback: Any) -> None:
        operation, self._operation = self._operation, None
        operation.__exit__(kind, value, traceback)


def run_handshake(bundle: Dict[str, Any]) -> None:
    environment = {key: os.environ[key] for key in ("LANG", "LC_ALL", "TMPDIR") if key in os.environ}
    environment.update(PATH="/usr/bin:/bin:/usr/sbin:/sbin", PYTHONDONTWRITEBYTECODE="1")
    tool = bundle["tool"]
    for arguments in (("describe",), ("check-plan", bundle["plan"])):
        result = subprocess.run(
            [str(Path(sys.executable).resolve()), "-I", "-B", tool, *arguments],
            cwd="/private/tmp", env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60,
        )
        if result.returncode:
            raise LifecyclePlanningError("external recovery handshake failed: " + result.stderr[-500:])
        value = json.loads(result.stdout)
        if arguments[0] == "describe" and value != recovery.describe():
            raise LifecyclePlanningError("external recovery description mismatch")
        if arguments[0] == "check-plan" and value.get("status") != "plan-valid":
            raise LifecyclePlanningError("external recovery plan check failed")


def publish_and_execute(bundle: Dict[str, Any], lease: Any, c1_inspect: Any,
                        registration_snapshot: Any, *, now: Optional[float] = None,
                        probe: Optional[Any] = None) -> Dict[str, Any]:
    try:
        return _publish_and_execute(
            bundle, lease, c1_inspect, registration_snapshot, now=now, probe=probe
        )
    except BaseException:
        _cleanup_preintent_bundle(bundle)
        raise


def _publish_and_execute(bundle: Dict[str, Any], lease: Any, c1_inspect: Any,
                         registration_snapshot: Any, *, now: Optional[float],
                         probe: Optional[Any]) -> Dict[str, Any]:
    """Revalidate under C1 exclusion, publish intent, and execute the prepared plan."""
    state_root = lease.root
    canonical = Path(bundle["canonical_root"])
    control = Path(bundle["control_root"])
    now = time.time() if now is None else now
    with C1LeaseAdapter(lease) as adapter:
        run_handshake(bundle)
        arguments = (registration_snapshot, lease, now)
        revalidated = (
            c1_inspect.revalidate_under_lease(*arguments, probe=probe)
            if probe is not None else c1_inspect.revalidate_under_lease(*arguments)
        )
        if not revalidated.get("valid") or revalidated.get("blocked"):
            raise LifecyclePlanningError(
                "registration/liveness revalidation blocked lifecycle intent"
            )
        roots = bundle["pending_admission"]["roots"]
        ownership = inspect_ownership(
            Path(roots["state"]), Path(roots["payload"]), Path(roots["opencode"])
        )
        refreshed = plan_ownership(
            bundle["kind"], bundle["release_snapshot"], ownership
        )
        if canonical_preview_bytes(refreshed) != bundle["preview_bytes"]:
            raise LifecyclePlanningError("ownership/release inputs changed before intent")
        if bundle["bootstrap"]:
            if canonical.exists() or canonical.is_symlink():
                raise LifecyclePlanningError("canonical lifecycle namespace appeared before intent")
            os.replace(control, canonical)
            recovery._sync_directory(state_root, None, "bootstrap-intent")
        else:
            recovery._atomic_json(
                canonical / "admission.json", bundle["pending_admission"], None,
                "intent-admission",
            )
        bundle.preparation_guard.preserve()
        if (recovery.sha256_file(Path(bundle["canonical_tool"])) !=
                bundle["loaded_recoverer"].__source_sha256__):
            raise LifecyclePlanningError("canonical recoverer changed after intent publication")
        return bundle["loaded_recoverer"]._execute_with_lease(state_root, adapter)


def status(state_root: Path, payload_root: Path, opencode_root: Path) -> Dict[str, Any]:
    pending = _pending_status(state_root, payload_root, opencode_root)
    if pending is not None:
        return pending
    ownership = inspect_ownership(state_root, payload_root, opencode_root)
    return {
        "status_format": 1,
        "roots": ownership["roots"],
        "management": ownership["management"],
        "payload_cache_count": len(ownership["payload_cache"]),
        "units": [
            {"unit_id": unit["unit_id"], "exists": unit["state"]["exists"],
             "sha256": unit["state"]["sha256"]}
            for unit in ownership["units"]
        ],
    }


def _create_fixed_directory(path: Path) -> None:
    if _observed_root(path) != path:
        raise LifecyclePlanningError("installation root changed during observation")
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for item in reversed(missing):
        _mkdir(item)


def execute_operation(kind: str, release_root: Optional[Path], state_root: Path,
                      payload_root: Path, opencode_root: Path, *,
                      maintenance_window_confirmed: bool = False,
                      receipt_id: Optional[str] = None,
                      transaction_id: Optional[str] = None,
                      now: Optional[float] = None,
                      probe: Optional[Any] = None,
                      recovery_command_sink: Optional[Any] = None,
                      _preparation_failpoint: Optional[Any] = None) -> Dict[str, Any]:
    """Execute one normal artifact transaction through the shared C1 lease."""
    state_input = _lexical_root(state_root)
    payload_input = _lexical_root(payload_root)
    opencode_input = _lexical_root(opencode_root)
    if kind == "rollback":
        if release_root is not None or receipt_id is None:
            raise LifecyclePlanningError("rollback requires exactly one retained receipt ID")
        release = retained_release(state_input, receipt_id)
    else:
        if receipt_id is not None:
            raise LifecyclePlanningError("receipt selection is supported only for rollback")
        release = None if release_root is None else validate_release(release_root)
    if kind == "uninstall" and release is not None:
        raise LifecyclePlanningError("uninstall does not accept a release")
    if kind != "uninstall" and release is None:
        raise LifecyclePlanningError("install and upgrade require a generated release")
    preflight = plan_ownership(
        kind, release, inspect_ownership(state_input, payload_input, opencode_input)
    )
    if not preflight["eligible_for_integration"]:
        raise LifecyclePlanningError("lifecycle preflight has ownership blockers")
    if (preflight["current"]["status"] == "legacy_unmanaged" and
            not maintenance_window_confirmed):
        raise LifecyclePlanningError(
            "first adoption requires an explicit maintenance-window decision"
        )
    state_input = Path(preflight["roots"]["state"])
    payload_input = Path(preflight["roots"]["payload"])
    opencode_input = Path(preflight["roots"]["opencode"])
    with admission.acquire_writer_lease(state_input) as lease:
        with lease.operation():
            _create_fixed_directory(payload_input.parent)
            _create_fixed_directory(opencode_input)
            _create_fixed_directory(opencode_input / "tools")
            _reconcile_preparations(state_input, lease)
            current = inspect_ownership(state_input, payload_input, opencode_input)
            preview = plan_ownership(kind, release, current)
            if not preview["eligible_for_integration"]:
                raise LifecyclePlanningError(
                    "lifecycle inputs changed or are blocked after exclusion"
                )
            snapshot = inspect.snapshot_registrations(state_input)
            report = inspect.registration_report(
                snapshot, time.time() if now is None else now,
                inspect.probe_process if probe is None else probe,
            )
            if report["blocked"]:
                raise LifecyclePlanningError(
                    "live, unknown, duplicate, or incompatible registrations block maintenance"
                )
            bundle = prepare_transaction(
                preview, release, lease, transaction_id=transaction_id,
                failpoint=_preparation_failpoint,
            )
            try:
                if recovery_command_sink is not None:
                    recovery_command_sink(list(bundle["recovery_command"]))
                result = publish_and_execute(
                    bundle, lease, inspect, snapshot, now=now, probe=probe
                )
            except BaseException:
                _cleanup_preintent_bundle(bundle)
                raise
    result["recovery_command"] = bundle["recovery_command"]
    return result


def _production_roots() -> Tuple[Path, Path, Path]:
    home = Path.home().resolve(strict=True)
    return (
        home / ".claude/peer-consults",
        home / ".claude/skills/council",
        home / ".config/opencode",
    )


def _release_argument(value: Optional[Path]) -> Path:
    if value is not None:
        return value
    candidate = SOURCE_ROOT.parent.parent
    if (candidate / "release_manifest.json").is_file() and (
        candidate / "payload/scripts/council_lifecycle.py"
    ).is_file():
        return candidate
    raise LifecyclePlanningError(
        "a generated release directory is required; use --release"
    )


def _plan_command(kind: str, release_value: Optional[Path], receipt_id: Optional[str],
                  roots: Tuple[Path, Path, Path]) -> Dict[str, Any]:
    state_root, payload_root, opencode_root = roots
    if kind == "rollback":
        if receipt_id is None or release_value is not None:
            raise LifecyclePlanningError("rollback planning requires exactly one receipt ID")
        release = retained_release(state_root, receipt_id)
    elif kind == "uninstall":
        if release_value is not None or receipt_id is not None:
            raise LifecyclePlanningError("uninstall planning accepts no release or receipt")
        release = None
    else:
        if receipt_id is not None:
            raise LifecyclePlanningError("receipt selection is supported only for rollback")
        release = validate_release(_release_argument(release_value))
    return plan_ownership(
        kind, release, inspect_ownership(state_root, payload_root, opencode_root)
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="inspect lifecycle state without writing")
    plan = commands.add_parser("plan", help="emit a non-executable ownership preview")
    plan_actions = plan.add_subparsers(dest="kind", required=True)
    for kind in ("install", "upgrade"):
        action = plan_actions.add_parser(kind)
        action.add_argument("--release", type=Path)
    rollback_plan = plan_actions.add_parser("rollback")
    rollback_plan.add_argument("--receipt", required=True)
    plan_actions.add_parser("uninstall")
    install = commands.add_parser("install", help="adopt an eligible generated release")
    install.add_argument("--release", type=Path)
    install.add_argument("--maintenance-window-confirmed", action="store_true")
    upgrade = commands.add_parser("upgrade", help="replace a managed artifact set")
    upgrade.add_argument("--release", type=Path)
    rollback = commands.add_parser("rollback", help="restore an exact retained receipt")
    rollback.add_argument("--receipt", required=True)
    commands.add_parser("uninstall", help="remove only receipt-owned code artifacts")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if sys.platform != "darwin":
            raise LifecyclePlanningError("Council lifecycle commands require macOS")
        roots = _production_roots()
        if args.command == "status":
            result = status(*roots)
        elif args.command == "plan":
            result = _plan_command(
                args.kind, getattr(args, "release", None),
                getattr(args, "receipt", None), roots,
            )
        else:
            release_root = (
                _release_argument(getattr(args, "release", None))
                if args.command in ("install", "upgrade") else None
            )

            def announce(command: List[str]) -> None:
                sys.stderr.write(
                    "recovery-command: " +
                    json.dumps(command, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
                sys.stderr.flush()

            result = execute_operation(
                args.command, release_root, *roots,
                maintenance_window_confirmed=getattr(
                    args, "maintenance_window_confirmed", False
                ),
                receipt_id=getattr(args, "receipt", None),
                recovery_command_sink=announce,
            )
        sys.stdout.buffer.write(recovery.json_bytes(result))
        return 0
    except (LifecyclePlanningError, recovery.RecoveryError, OSError,
            subprocess.SubprocessError, ValueError) as error:
        parser.exit(2, "lifecycle: %s\n" % error)


if __name__ == "__main__":
    main()
