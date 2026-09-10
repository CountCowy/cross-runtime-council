#!/usr/bin/env python3
"""Council artifact lifecycle planning, transactions, and recovery handoff."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
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
PLANNING_KINDS = {"install", "upgrade", "rollback", "uninstall"}


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
    if path.exists():
        if path.is_symlink():
            raise LifecyclePlanningError("root path must not be a symlink")
        return path.resolve(strict=True)
    missing = [path.name]
    ancestor = path.parent
    while not ancestor.exists():
        if ancestor == ancestor.parent:
            break
        missing.append(ancestor.name)
        ancestor = ancestor.parent
    if not ancestor.is_dir():
        raise LifecyclePlanningError("absent root has no physical directory ancestor")
    return ancestor.resolve(strict=True).joinpath(*reversed(missing))


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
        "package_id": manifest["package_id"],
        "runtime_cohort": manifest["runtime_cohort"],
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


def _copy_file(source: Path, destination: Path, mode: int = 0o644) -> None:
    data = recovery.read_regular(source, "release/staged artifact")
    descriptor = os.open(
        str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise LifecyclePlanningError("short artifact staging write")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    recovery._sync_directory(destination.parent, None, "staged-artifact")


def _copy_state(source: Path, destination: Path, expected: Dict[str, Any]) -> None:
    if not expected["exists"]:
        return
    if expected["kind"] == "file":
        _copy_file(source, destination, expected["mode"])
    else:
        _mkdir(destination)
        destination.chmod(expected["mode"])
        for item in expected["artifacts"]:
            path = destination / item["path"]
            if item["kind"] == "directory":
                _mkdir(path)
                path.chmod(item["mode"])
            else:
                _copy_file(source / item["path"], path, item["mode"])
    if not recovery.state_matches(destination, expected):
        raise LifecyclePlanningError("staged recovery object differs from planned state")


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
                        lease: Any, *, transaction_id: Optional[str] = None) -> Dict[str, Any]:
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
    for path in (
        control, control / "v1", control / "v1/receipts", control / "v1/recovery",
        control / "v1/transactions", transaction,
    ):
        _mkdir(path)
    manifest_path = transaction / "source-manifest.json"
    recovery._write_immutable(manifest_path, manifest_data, None, "source-manifest")
    support_path = transaction / "reader-support.json"
    recovery._write_immutable(support_path, support_data, None, "reader-support")
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
    if actual_tool.exists() or actual_tool.is_symlink():
        if (actual_tool.is_symlink() or recovery.sha256_file(actual_tool) != tool_sha256 or
                stat.S_IMODE(actual_tool.stat().st_mode) != 0o600):
            raise LifecyclePlanningError("retained recovery tool differs from source")
    else:
        _copy_file(tool_source, actual_tool, 0o600)
    canonical_tool = canonical / "v1/recovery" / (tool_sha256 + ".py")
    loaded = _load_source_module(
        "_council_pinned_recover_" + transaction_id.replace("-", "_"), actual_tool,
        tool_sha256, canonical_tool,
    )
    unit_map = {item["unit_id"]: item for item in preview["units"]}
    release_map = {} if source is None else _release_artifact_map(source)
    units = []
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
            _copy_state(destination, prior_path, prior)
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
            _copy_state(target_source, target_path, target)
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
        tool_sha256, recovery.sha256_file(support_path), preview["artifacts"], prior_summary,
        manifest["package_id"], manifest["runtime_cohort"],
    )
    target_receipt_path = transaction / "receipt.json"
    recovery._write_immutable(target_receipt_path, recovery.json_bytes(target_receipt), None,
                              "target-receipt")
    target_summary = {
        "receipt_id": receipt_id,
        "receipt_sha256": recovery.sha256_file(target_receipt_path),
        "package_id": manifest["package_id"],
        "runtime_cohort": manifest["runtime_cohort"],
    }
    target_outcome = _admission(
        "uninstalled" if preview["kind"] == "uninstall" else "committed",
        roots, target_summary,
    )
    prior_outcome = _admission(preview["current"]["status"], roots, prior_summary)
    proposed_prior = None
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
            recovery.sha256_file(support_path), prior_artifacts, None,
            manifest["package_id"], manifest["runtime_cohort"],
        )
        prior_path = transaction / "prior-receipt.json"
        recovery._write_immutable(prior_path, recovery.json_bytes(prior_receipt), None,
                                  "prior-receipt")
        proposed_prior = {"path": "prior-receipt.json", "sha256": recovery.sha256_file(prior_path)}
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
        "reader_support": {"path": "reader-support.json", "sha256": recovery.sha256_file(support_path)},
    }
    plan_path = transaction / "plan.json"
    recovery._write_immutable(plan_path, recovery.json_bytes(plan), None, "plan")
    progress = {
        "journal_format": 1, "transaction_id": transaction_id,
        "plan_sha256": recovery.sha256_file(plan_path), "sequence": 0, "goal": "target",
        "units": [{"unit_id": unit_id, "phase": "pending"} for unit_id in recovery.UNIT_IDS],
    }
    recovery._atomic_json(transaction / "progress.json", progress, None, "progress")
    pending = _admission("recovery_required", roots, preview["current"]["summary"])
    pending["transaction_id"] = transaction_id
    if bootstrap:
        recovery._atomic_json(control / "admission.json", pending, None, "prepared-admission")
    return {
        "transaction_id": transaction_id, "kind": preview["kind"], "bootstrap": bootstrap,
        "control_root": str(control), "canonical_root": str(canonical),
        "plan": str(plan_path), "tool": str(actual_tool), "canonical_tool": str(canonical_tool),
        "pending_admission": pending, "loaded_recoverer": loaded,
        "preview_bytes": canonical_preview_bytes(preview),
        "release_snapshot": source,
        "recovery_command": [str(Path(sys.executable).resolve()), "-I", "-B", str(canonical_tool),
                             "recover", "--state-root", str(state_root)],
    }


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
        if (recovery.sha256_file(Path(bundle["canonical_tool"])) !=
                bundle["loaded_recoverer"].__source_sha256__):
            raise LifecyclePlanningError("canonical recoverer changed after intent publication")
        return bundle["loaded_recoverer"]._execute_with_lease(state_root, adapter)


def status(state_root: Path, payload_root: Path, opencode_root: Path) -> Dict[str, Any]:
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
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir() or current.resolve(strict=True) != current:
        raise LifecyclePlanningError("installation root has an unsafe existing ancestor")
    for item in reversed(missing):
        _mkdir(item)


def execute_operation(kind: str, release_root: Optional[Path], state_root: Path,
                      payload_root: Path, opencode_root: Path, *,
                      maintenance_window_confirmed: bool = False,
                      receipt_id: Optional[str] = None,
                      transaction_id: Optional[str] = None,
                      now: Optional[float] = None,
                      probe: Optional[Any] = None,
                      recovery_command_sink: Optional[Any] = None) -> Dict[str, Any]:
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
                preview, release, lease, transaction_id=transaction_id
            )
            if recovery_command_sink is not None:
                recovery_command_sink(list(bundle["recovery_command"]))
            result = publish_and_execute(
                bundle, lease, inspect, snapshot, now=now, probe=probe
            )
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
