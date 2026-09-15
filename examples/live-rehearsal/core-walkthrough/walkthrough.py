#!/usr/bin/env python3
"""Run the file-only rehearsal CLI through a synthetic, proof-ineligible cycle."""

import argparse
import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
RUNNER = REPOSITORY / "scripts" / "council_rehearsal.py"
RECORD_FIXTURE = (
    REPOSITORY
    / "scripts"
    / "fixtures"
    / "live_rehearsal"
    / "named-g1-pass.fixture.json"
)
SCENARIO = HERE / "scenario.json"
SUPPORT = HERE / "support.txt"
CHECKPOINT_TIMES = {
    3: "2026-09-08T19:56:00Z",
    4: "2026-09-08T19:57:00Z",
    5: "2026-09-08T20:00:00Z",
    6: "2026-09-08T20:10:00Z",
    7: "2026-09-08T20:11:00Z",
    8: "2026-09-08T20:12:00Z",
    9: "2026-09-08T20:13:00Z",
}


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, value):
    encoded = (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_ref(node, old, new):
    if isinstance(node, dict):
        return {key: replace_ref(value, old, new) for key, value in node.items()}
    if isinstance(node, list):
        return [replace_ref(value, old, new) for value in node]
    return new if node == old else node


def run_cli(command, *arguments, expected=0):
    completed = subprocess.run(
        [sys.executable, str(RUNNER), command, *map(str, arguments)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        payload = json.loads(completed.stdout)
    except ValueError as error:
        raise RuntimeError("%s did not return JSON" % command) from error
    if completed.returncode != expected:
        raise RuntimeError(
            "%s exited %d instead of %d: %s"
            % (command, completed.returncode, expected, payload)
        )
    return payload


def checkpoint(inputs, run_root, sequence, transition, previous, case_id=None, details=None):
    value = {
        "format": "rehearsal-checkpoint/v1",
        "checkpoint_id": "walkthrough-%02d-%s" % (sequence, transition),
        "transition": transition,
        "expected_previous_digest": previous,
        "at_utc": CHECKPOINT_TIMES[sequence],
        "actor_ref": "maintainer-one",
        "case_id": case_id,
        "evidence_refs": [],
        "details": details or {},
    }
    path = inputs / ("%02d-%s.json" % (sequence, transition))
    write_json(path, value)
    payload = run_cli("checkpoint", "--run", run_root, "--input", path)
    return payload["checkpoint"]["state"]["previous_checkpoint_digest"]


def prepare_unattempted(record):
    prepared = copy.deepcopy(record)
    prepared["record_kind"] = "run"
    prepared["completed_utc"] = None
    prepared["overall_result"] = "unobserved"
    gate = prepared["gates"][0]
    case = gate["cases"][0]
    gate.update(result="unobserved", rationale="aggregate:unobserved")
    case.update(result="unobserved", rationale="case-not-attempted")
    case["observed"]["common"].update(
        attempted=False,
        actual_start_utc=None,
        intervention_utc=None,
        recovery_utc=None,
        actual_end_utc=None,
        coverage_result="unobserved",
        coverage_limitation="Synthetic attempt has not started.",
        deadline_met=False,
    )
    case["observer"].update(
        completeness_result="unobserved",
        limitations=["Synthetic attempt has not started."],
    )
    case["controls"][0].update(
        observed=None,
        result="unobserved",
        evidence_refs=[],
        rationale="control-not-observed",
    )
    return prepared


def validate_workspace(workspace):
    if not workspace.is_absolute():
        raise ValueError("--workspace must be absolute")
    info = workspace.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("--workspace must name an existing regular directory")
    for name in ("run", "export", "inputs", "walkthrough-result.json"):
        if (workspace / name).exists() or (workspace / name).is_symlink():
            raise ValueError("--workspace must not already contain %s" % name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="absolute existing directory that will retain the synthetic run and export",
    )
    args = parser.parse_args(argv)
    workspace = args.workspace
    validate_workspace(workspace)
    inputs = workspace / "inputs"
    inputs.mkdir(mode=0o700)
    os.chmod(inputs, 0o700)
    run_root = workspace / "run"
    export_root = workspace / "export"

    scenario = read_json(SCENARIO)
    expected_scenario_keys = {
        "format",
        "context_kind",
        "run_id",
        "source_commit",
        "source_tree",
        "support_identity",
        "collected_utc",
        "cleanup_utc",
    }
    if set(scenario) != expected_scenario_keys:
        raise ValueError("scenario.json has unexpected fields")
    if scenario["format"] != "rehearsal-core-walkthrough/v1":
        raise ValueError("unsupported walkthrough scenario")
    if scenario["context_kind"] != "fixture":
        raise ValueError("walkthrough must remain fixture-only")

    record = read_json(RECORD_FIXTURE)
    record["record_kind"] = "template"
    record["overall_result"] = "unobserved"
    record["tested_tuple"]["source_commit"] = scenario["source_commit"]
    record["tested_tuple"]["source_tree"] = scenario["source_tree"]
    plan = {
        "format": "rehearsal-plan/v1",
        "context_kind": "fixture",
        "run_id": scenario["run_id"],
        "record": record,
    }
    plan_path = inputs / "00-plan.json"
    write_json(plan_path, plan)
    run_cli("init", "--private-root", run_root, "--plan", plan_path)

    import_spec = {
        "format": "rehearsal-import/v1",
        "collected_utc": scenario["collected_utc"],
        "items": [
            {
                "source": str(SUPPORT),
                "source_identity": scenario["support_identity"],
                "classification": "private_capture",
                "content_kind": "support_record",
                "transformations": ["none"],
                "qualification_refs": [],
                "selection_scope": "test_dialogue",
                "reviewed_safe": True,
            }
        ],
    }
    import_path = inputs / "01-import.json"
    write_json(import_path, import_spec)
    imported_payload = run_cli(
        "import-evidence", "--run", run_root, "--input", import_path
    )
    imported = imported_payload["imported"][0]
    record = replace_ref(record, "ev-a", imported["ref"])
    record["evidence"] = [imported]
    write_json(run_root / "record.json", record)

    freeze_input = {
        "format": "rehearsal-checkpoint/v1",
        "checkpoint_id": "walkthrough-02-freeze-plan",
        "transition": "freeze_plan",
        "expected_previous_digest": None,
        "at_utc": "2026-09-08T19:55:00Z",
        "actor_ref": "maintainer-one",
        "case_id": None,
        "evidence_refs": [],
        "details": {},
    }
    freeze_path = inputs / "02-freeze-plan.json"
    write_json(freeze_path, freeze_input)
    preview = run_cli(
        "checkpoint",
        "--run",
        run_root,
        "--input",
        freeze_path,
        "--preview",
    )
    if preview["checkpoint"]["state"]["state"] != "plan_frozen":
        raise RuntimeError("freeze preview did not reach plan_frozen")
    frozen = run_cli(
        "checkpoint", "--run", run_root, "--input", freeze_path
    )
    previous = frozen["checkpoint"]["state"]["previous_checkpoint_digest"]
    previous = checkpoint(inputs, run_root, 3, "record_authorization", previous)
    previous = checkpoint(
        inputs,
        run_root,
        4,
        "arm_case",
        previous,
        case_id="case-g1",
        details={"intervention_action": "observe-wake"},
    )

    passing_record = copy.deepcopy(record)
    passing_record["record_kind"] = "run"
    passing_record["overall_result"] = "pass"
    write_json(run_root / "record.json", prepare_unattempted(record))
    previous = checkpoint(
        inputs, run_root, 5, "begin_case", previous, case_id="case-g1"
    )
    write_json(run_root / "record.json", passing_record)
    previous = checkpoint(
        inputs, run_root, 6, "seal_case", previous, case_id="case-g1"
    )
    previous = checkpoint(inputs, run_root, 7, "ready_assessment", previous)

    validation = run_cli("validate", "--run", run_root)
    assessment = run_cli("assess", "--run", run_root)
    exported = run_cli(
        "export",
        "--run",
        run_root,
        "--destination",
        export_root,
        "--fixture-artifacts",
    )
    if exported.get("proof_eligible") is not False:
        raise RuntimeError("fixture export was not marked proof-ineligible")
    manifest_bytes = (export_root / "export-manifest.json").read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    previous = checkpoint(
        inputs,
        run_root,
        8,
        "verify_export",
        previous,
        details={
            "destination": str(export_root),
            "manifest_sha256": manifest_sha256,
        },
    )

    passing_record["cleanup"]["exports_verified_utc"] = scenario["cleanup_utc"]
    passing_record["cleanup"]["dialogue_deletion"] = {
        "result": "skipped",
        "evidence_refs": [],
    }
    passing_record["cleanup"]["detached_capture_deletion"] = {
        "result": "skipped",
        "evidence_refs": [],
    }
    write_json(run_root / "record.json", passing_record)
    checkpoint(
        inputs,
        run_root,
        9,
        "record_cleanup",
        previous,
        details={
            "terminal_handling_result": "skipped",
            "participants_unbound_result": "skipped",
            "adapters_closed_result": "skipped",
            "dialogue_result": "skipped",
            "detached_capture_result": "skipped",
            "retained_evidence_result": "pass",
        },
    )
    final_validation = run_cli("validate", "--run", run_root)
    manifest = read_json(export_root / "export-manifest.json")
    summary = read_json(export_root / "summary.json")
    if (
        manifest.get("format") != "rehearsal-fixture-export/v1"
        or manifest.get("proof_eligible") is not False
    ):
        raise RuntimeError("fixture manifest markers changed")
    if summary.get("proof_eligible") is not False or summary.get("context_kind") != "fixture":
        raise RuntimeError("fixture summary markers changed")
    result = {
        "format": "rehearsal-core-walkthrough-result/v1",
        "context_kind": "fixture",
        "proof_eligible": False,
        "calculated_result": assessment["result"],
        "record_valid": final_validation["record_valid"],
        "runner_state": final_validation["runner_state"],
        "evidence_items_verified": validation["evidence_items_verified"],
        "export_format": manifest["format"],
        "live_actions_performed": [],
        "workspace_retained": str(workspace),
    }
    write_json(workspace / "walkthrough-result.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
