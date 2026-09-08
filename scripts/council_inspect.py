#!/usr/bin/env python3
"""Offline Council artifact/liveness inspection: no broker, transport or repair."""

import argparse
import errno
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Optional

sys.dont_write_bytecode = True
# ruff: noqa: E402 -- custom imports must follow bytecode-write suppression.
import council_admission as admission
import council_protocol as protocol

PACKAGE_ID = "003cbb6ce7f17cf151a8080a7779620e64e977994490bcc0db6fac6b46f296ca"
RUNTIME_COHORT = "d2a7edbc35ad87c89677773c90d815182afe3e4f31f5ce44c28e102b82a433df"
if (
    RUNTIME_COHORT != admission.RUNTIME_COHORT
    or RUNTIME_COHORT != protocol.RUNTIME_COHORT
):
    raise RuntimeError(
        "Council inspector/helper cohort mismatch; refresh the complete runtime set"
    )

MAX_FILES = 10000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
FAMILIES = ("dialogues", "outbox", "registrations", "tombstones")
CONFIGS = ("router.json", "retention.json", "opencode-runtime.json")
EXPECTED_RUNTIME_SOURCES = {
    "scripts/council_admission.py",
    "scripts/council_inspect.py",
    "scripts/council_protocol.py",
    "scripts/council_protocol.ts",
    "scripts/council.py",
    "scripts/council_mcp.py",
    "scripts/council_opencode.py",
    "scripts/opencode_council_plugin.ts",
    "scripts/opencode_delivery_registry.ts",
    "scripts/tools/council.ts",
}


@dataclass(frozen=True)
class ProcessEvidence:
    status: str  # absent, present, unknown
    generation: Optional[tuple] = None  # (explicit encoding, exact value)


def probe_process(pid):
    """Signal zero only. Presence alone cannot identify a process generation.

    No precision/ABI upgrade is inferred from legacy ps-derived timestamps.
    A same-encoder coarse match is conservatively live; a mismatch is unknown.
    At most one bounded ps invocation is made per distinct present holder PID.
    """
    try:
        os.kill(pid, 0)
    except OSError as error:
        return ProcessEvidence("absent" if error.errno == errno.ESRCH else "unknown")
    try:
        result = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "lstart="],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
            env={**os.environ, "LC_ALL": "C"},
        )
        epoch = int(
            time.mktime(time.strptime(result.stdout.strip(), "%a %b %d %H:%M:%S %Y"))
        )
        return ProcessEvidence("present", ("legacy-ps-lstart-seconds", epoch))
    except (OSError, subprocess.SubprocessError, ValueError, OverflowError):
        return ProcessEvidence("unknown")


@dataclass(frozen=True, repr=False)
class RegistrationSnapshot:
    root: Path
    root_identity: Any
    directory_identity: Any
    records: tuple  # private: name, fingerprint, digest, parsed route, error
    error: Optional[str] = None


def _directory_names(path):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise admission.AdmissionError("nonphysical artifact directory")
    with os.scandir(path) as entries:
        names = []
        for entry in entries:
            names.append(entry.name)
            if len(names) > MAX_FILES:
                raise admission.AdmissionError("artifact inventory exceeds bound")
    return sorted(names)


def snapshot_registrations(state_root):
    root = Path(state_root).expanduser().resolve()
    directory = root / "registrations"
    records = []
    root_id = dir_id = None
    total = 0
    try:
        try:
            root_id = admission.identity(root.stat())
        except FileNotFoundError:
            return RegistrationSnapshot(root, None, None, ())
        try:
            dir_id = admission.identity(directory.lstat())
        except FileNotFoundError:
            return RegistrationSnapshot(root, root_id, None, ())
        names = _directory_names(directory)
        for name in names:  # include malformed, temporary and non-json entries
            path = directory / name
            route = None
            fingerprint = digest = error = None
            try:
                data, fingerprint = admission.read_regular(
                    path, min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total)
                )
                total += len(data)
                if total >= MAX_TOTAL_BYTES:
                    return RegistrationSnapshot(
                        root,
                        root_id,
                        dir_id,
                        tuple(records),
                        "registration_bytes_exceed_bound",
                    )
                digest = hashlib.sha256(data).hexdigest()
                route = json.loads(data, object_pairs_hook=admission.no_duplicates)
                if not isinstance(route, dict) or not name.endswith(".json"):
                    raise ValueError("invalid route")
            except (OSError, ValueError, UnicodeError):
                error = "malformed_registration"
            records.append((name, fingerprint, digest, route, error))
        if names != _directory_names(directory) or dir_id != admission.identity(
            directory.stat()
        ):
            raise admission.AdmissionError("registration inventory changed")
        return RegistrationSnapshot(root, root_id, dir_id, tuple(records))
    except (OSError, ValueError):
        return RegistrationSnapshot(
            root, root_id, dir_id, tuple(records), "registration_inventory_unavailable"
        )


def classify_registration(record, now, probe=probe_process):
    """Pure liveness classification; malformed compatibility stays separate."""
    route = record[3]
    if not isinstance(route, dict):
        return "unknown"
    expiry = route.get("lease_expires_epoch")
    if not admission.finite_number(now) or not admission.finite_number(expiry):
        return "unknown"
    if expiry <= now:
        return "expired"
    # Legacy Codex has no holder identity; never invent one from unrelated data.
    if route.get("runtime") not in ("claude", "opencode"):
        return "unknown"
    pid = route.get("relay_pid")
    if type(pid) is not int or pid <= 1:
        return "unknown"
    try:
        evidence = probe(pid)
    except Exception:
        return "unknown"
    if not isinstance(evidence, ProcessEvidence):
        return "unknown"
    if evidence.status == "absent":
        return "dead"
    expected = route.get("relay_process_start_epoch")
    if (
        evidence.status == "present"
        and type(expected) is int
        and evidence.generation == ("legacy-ps-lstart-seconds", expected)
    ):
        return "live"
    # Legacy timestamps have no declared precision/timezone; a mismatch cannot
    # prove original-generation death. Only positive PID absence does so.
    return "unknown"


def _route_compatible(record):
    name, _, _, route, error = record
    if error or not isinstance(route, dict):
        return False
    if (
        route.get("runtime") not in ("codex", "claude", "opencode")
        or name != str(route.get("participant")) + ".json"
        or not all(
            isinstance(route.get(key), str) and route[key]
            for key in ("participant", "label", "project", "bound_at")
        )
        or not isinstance(route.get("capability_hash"), str)
        or not admission.HASH_PATTERN.fullmatch(route["capability_hash"])
        or type(route.get("lease_minutes")) is not int
        or not 1 <= route["lease_minutes"] <= protocol.MAX_LEASE_MINUTES
        or not admission.finite_number(route.get("lease_expires_epoch"))
    ):
        return False
    for key in ("participant", "binding_generation"):
        if route.get(key) is not None and (
            not isinstance(route[key], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", route[key])
        ):
            return False
    generation = route.get("binding_generation")
    cohort = route.get("runtime_cohort")
    if generation is not None and (not isinstance(generation, str) or not generation):
        return False
    # A historical cohort remains readable tombstone data. It is not route
    # admission; only the authenticated broker rebind can establish that.
    if cohort is not None and (
        not isinstance(cohort, str) or not admission.HASH_PATTERN.fullmatch(cohort)
    ):
        return False
    if route["runtime"] == "codex":
        return isinstance(route.get("target_thread_id"), str) and bool(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", route["target_thread_id"])
        )
    return (
        route.get("transport")
        == (
            "claude_mcp_child_relay"
            if route["runtime"] == "claude"
            else "opencode_plugin_relay"
        )
        and isinstance(route.get("relay_path"), str)
        and Path(route["relay_path"]).is_absolute()
        and type(route.get("relay_pid")) is int
        and route["relay_pid"] > 1
        and type(route.get("relay_process_start_epoch")) is int
        and isinstance(
            route.get(
                "relay_owner_hash"
                if route["runtime"] == "claude"
                else "target_session_id"
            ),
            str,
        )
    )


def registration_report(snapshot, now, probe=probe_process):
    cache = {}
    deadline = time.monotonic() + 10

    def cached(pid):
        if pid not in cache:
            cache[pid] = (
                probe(pid)
                if time.monotonic() < deadline
                else ProcessEvidence("unknown")
            )
        return cache[pid]

    counts = dict.fromkeys(("expired", "dead", "live", "unknown"), 0)
    incompatible = 0
    restored_unready = 0
    exact_routes = set()
    duplicate_routes = 0
    for record in snapshot.records:
        classification = classify_registration(record, now, cached)
        counts[classification] += 1
        incompatible += not _route_compatible(record)
        route = record[3]
        if isinstance(route, dict) and classification != "expired":
            exact = (
                route.get("target_thread_id")
                or route.get("target_session_id")
                or route.get("relay_owner_hash")
            )
            if isinstance(exact, str):
                duplicate_routes += exact in exact_routes
                exact_routes.add(exact)
        if isinstance(route, dict) and (
            route.get("runtime") in ("claude", "opencode")
            or route.get("runtime_cohort") != RUNTIME_COHORT
        ):
            restored_unready += 1
    return {
        "counts": counts,
        "inventory_error": snapshot.error,
        "incompatible_count": incompatible,
        "duplicate_route_count": duplicate_routes,
        "observed_restore_unready_count": restored_unready,
        "blocked": bool(
            snapshot.error
            or incompatible
            or duplicate_routes
            or counts["live"]
            or counts["unknown"]
        ),
        "authenticated_readiness": "unobserved",
    }


def revalidate_under_lease(snapshot, lease, now, probe=probe_process):
    if not isinstance(lease, admission.WriterLease):
        raise admission.AdmissionError("an acquired WriterLease is required")
    with lease.operation():
        lease.validate(snapshot.root)
        fresh = snapshot_registrations(snapshot.root)
        if snapshot != fresh or fresh.error:
            return {
                "valid": False,
                "blocked": True,
                "reason": "registration_snapshot_changed",
            }
        result = registration_report(fresh, now, probe)
        # Probes can take time. The result binds the same complete registry and
        # root/descriptor generation at its end, not only before probing.
        after = snapshot_registrations(snapshot.root)
        lease.validate(snapshot.root)
        if fresh != after or after.error:
            return {
                "valid": False,
                "blocked": True,
                "reason": "registration_snapshot_changed",
            }
        result.update(valid=not result["blocked"], reason="registration_revalidated")
        return result


def inspect_state(
    state_root, now=None, probe=probe_process, *, payload_root=None, opencode_root=None
):
    root = Path(state_root).expanduser().resolve()
    now = time.time() if now is None else now
    snapshot = snapshot_registrations(root)
    report = {
        "root_exists": root.exists(),
        "registrations": registration_report(snapshot, now, probe),
        "admission": admission.inspect_admission(root, payload_root, opencode_root),
        "artifacts": {
            "count": 0,
            "bytes": 0,
            "malformed_count": 0,
            "unsupported_schema_count": 0,
            "torn_audit_count": 0,
        },
        "restoration": "unobserved",
        "reader_support": "requires_exact_predecessor_tuple",
    }
    artifacts = report["artifacts"]
    if not root.exists():
        return report
    try:
        visited = 0
        queue = [
            root / name for name in FAMILIES + CONFIGS if os.path.lexists(root / name)
        ]
        while queue:
            path = queue.pop()
            visited += 1
            if visited > MAX_FILES:
                raise admission.AdmissionError("artifact inventory exceeds bound")
            details = path.lstat()
            if stat.S_ISDIR(details.st_mode):
                queue.extend(path / name for name in _directory_names(path))
                if len(queue) + artifacts["count"] > MAX_FILES:
                    raise admission.AdmissionError("artifact inventory exceeds bound")
                continue
            artifacts["count"] += 1
            try:
                if artifacts["bytes"] >= MAX_TOTAL_BYTES:
                    artifacts["inventory_error"] = True
                    break
                data, _ = admission.read_regular(
                    path, min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - artifacts["bytes"])
                )
                artifacts["bytes"] += len(data)
                if artifacts["bytes"] > MAX_TOTAL_BYTES:
                    raise admission.AdmissionError("artifact bytes exceed bound")
                if path.name == "audit.jsonl":
                    if data and not data.endswith(b"\n"):
                        artifacts["torn_audit_count"] += 1
                    values = [
                        json.loads(line, object_pairs_hook=admission.no_duplicates)
                        for line in data.splitlines()
                        if line
                    ]
                else:
                    values = [
                        json.loads(data, object_pairs_hook=admission.no_duplicates)
                    ]
                for value in values:
                    if not isinstance(value, dict):
                        raise ValueError("artifact object required")
                    for key, expected in (
                        ("schema_version", protocol.SCHEMA_VERSION),
                        ("dialogue_schema_version", protocol.DIALOGUE_SCHEMA_VERSION),
                    ):
                        schema = value.get(key)
                        if schema is not None and (
                            type(schema) is not int or schema != expected
                        ):
                            artifacts["unsupported_schema_count"] += 1
            except (OSError, ValueError, UnicodeError):
                artifacts["malformed_count"] += 1
    except (OSError, ValueError):
        artifacts["inventory_error"] = True
    return report


def inspect_artifacts(payload_root, opencode_root):
    payload = Path(payload_root).expanduser().resolve()
    opencode = Path(opencode_root).expanduser().resolve()
    result = {
        "provenance": "unavailable",
        "verified_count": 0,
        "mismatch_count": 0,
        "artifact_cohort_compatible": False,
    }
    try:
        manifest = admission.read_object(payload / "release_manifest.json")
        if (
            type(manifest.get("format")) is not int
            or manifest["format"] != 1
            or not isinstance(manifest.get("artifacts"), dict)
            or not manifest["artifacts"]
            or len(manifest["artifacts"]) > MAX_FILES
            or not isinstance(manifest.get("runtime_sources"), list)
            or any(not isinstance(name, str) for name in manifest["runtime_sources"])
            or set(manifest["runtime_sources"]) != EXPECTED_RUNTIME_SOURCES
            or len(manifest["runtime_sources"]) != len(EXPECTED_RUNTIME_SOURCES)
        ):
            raise ValueError("invalid release manifest")
        for key in ("package_id", "runtime_cohort"):
            if not isinstance(
                manifest.get(key), str
            ) or not admission.HASH_PATTERN.fullmatch(manifest[key]):
                raise ValueError("invalid release identity")
        external = {
            "council-plugin.ts",
            "council_protocol.ts",
            "opencode_delivery_registry.ts",
            "tools/council.ts",
        }
        if {
            name.removeprefix("opencode/")
            for name in manifest["artifacts"]
            if name.startswith("opencode/")
        } != external:
            raise ValueError("incomplete external artifact coverage")
        if any(
            "payload/" + name not in manifest["artifacts"]
            for name in manifest["runtime_sources"]
        ):
            raise ValueError("incomplete runtime artifact coverage")
        remaining_bytes = MAX_TOTAL_BYTES
        for name, expected in manifest["artifacts"].items():
            parts = Path(name).parts
            if (
                not parts
                or parts[0] not in ("payload", "opencode")
                or len(parts) < 2
                or any(part in (".", "..") for part in parts)
                or str(Path(name)) != name
                or not isinstance(expected, str)
                or not admission.HASH_PATTERN.fullmatch(expected)
            ):
                raise ValueError("invalid artifact name or digest")
            path = (payload if parts[0] == "payload" else opencode).joinpath(*parts[1:])
            try:
                if remaining_bytes <= 0:
                    raise ValueError("artifact byte budget exceeded")
                data, _ = admission.read_regular(
                    path, min(MAX_FILE_BYTES, remaining_bytes)
                )
                remaining_bytes -= len(data)
                if hashlib.sha256(data).hexdigest() == expected:
                    result["verified_count"] += 1
                else:
                    result["mismatch_count"] += 1
            except (OSError, ValueError):
                result["mismatch_count"] += 1
        result.update(
            provenance="manifest_observed",
            package_id=manifest["package_id"],
            runtime_cohort=manifest["runtime_cohort"],
            artifact_cohort_compatible=not result["mismatch_count"]
            and manifest["runtime_cohort"] == RUNTIME_COHORT,
        )
    except (OSError, ValueError, TypeError, UnicodeError):
        result["error"] = "missing_or_invalid_release_manifest"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--state-root", type=Path, default=Path.home() / ".claude/peer-consults"
    )
    parser.add_argument(
        "--payload-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--opencode-root", type=Path, default=Path.home() / ".config/opencode"
    )
    args = parser.parse_args()
    result = inspect_state(
        args.state_root,
        payload_root=args.payload_root,
        opencode_root=args.opencode_root,
    )
    result["release_artifacts"] = inspect_artifacts(
        args.payload_root, args.opencode_root
    )
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
