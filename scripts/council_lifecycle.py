#!/usr/bin/env python3
"""Read-only Council release validation and ownership planning."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import stat
from typing import Any, Dict, List, Optional, Tuple

import council_recover as recovery


RELEASE_SNAPSHOT_FORMAT = 1
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
    state_root = _real_directory(state_root, "state root")
    payload_root = _payload_path(payload_root)
    opencode_root = _real_directory(opencode_root, "OpenCode root")
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
        release = _validate_release_snapshot(release_snapshot)
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
            "root": release["root"],
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
