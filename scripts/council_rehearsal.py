#!/usr/bin/env python3
"""Assisted, file-only runner for the council live-rehearsal contract.

The runner validates prepared records and evidence, records operator checkpoints,
and computes conservative verdicts.  It never contacts a broker or participant,
starts a process, opens a socket, inspects an installed runtime, or performs a
host intervention.  Every mutable root is supplied explicitly by the maintainer.
"""

import argparse
import copy
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from rehearsal_evidence import (
    CLASSIFICATIONS,
    EvidenceError,
    MAX_EVIDENCE_ITEMS,
    RESULTS,
    assert_no_private_markers,
    assess_arrival_count,
    atomic_write_private,
    canonical_json_bytes,
    empty_private_index,
    import_evidence,
    is_nonnegative_int,
    load_private_index,
    normalized_arrivals,
    read_imported_json,
    require_bool,
    require_keys,
    require_list,
    require_nonnegative_int,
    require_ref,
    require_sha256,
    require_string,
    require_unique,
    require_utc,
    sha256_bytes,
    strict_load_json,
    validate_import_spec,
    verify_evidence,
    write_new_private,
)


CONTRACT = "council-live-rehearsal/v1"
PLAN_FORMAT = "rehearsal-plan/v1"
STATE_FORMAT = "rehearsal-runner-state/v1"
CHECKPOINT_FORMAT = "rehearsal-checkpoint/v1"
EXPORT_FORMAT = "rehearsal-export/v1"
FIXTURE_EXPORT_FORMAT = "rehearsal-fixture-export/v1"
GATE_IDS = ("G1", "G2", "G3", "G4", "G5")
PRECEDENCE = {"pass": 0, "skipped": 1, "unobserved": 2, "fail": 3}
MAX_CASES = 512
MAX_CONTROLS_PER_CASE = 128
MAX_HOSTS = 64
MAX_SEATS = 256
MAX_LIMITATIONS = 1024
MAX_REF_LIST = 4096
MAX_OBSERVATION_COUNT = 2**31 - 1
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class RehearsalError(ValueError):
    """A structural, state, or policy refusal safe for public diagnostics."""

    def __init__(self, code, field=""):
        self.code = code
        self.field = field
        message = code if not field else "%s at %s" % (code, field)
        super().__init__(message)


def _convert_error(error):
    if isinstance(error, RehearsalError):
        return error
    if isinstance(error, EvidenceError):
        return RehearsalError(error.code, error.field)
    return RehearsalError("operation-failed")


def _result(value, field):
    if value not in RESULTS:
        raise RehearsalError("unknown-result", field)
    return value


def _count(value, field):
    require_nonnegative_int(value, field)
    if value > MAX_OBSERVATION_COUNT:
        raise RehearsalError("count-too-large", field)
    return value


def _object_id(value, field):
    if not isinstance(value, str) or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
        raise RehearsalError("invalid-source-object-id", field)
    return value


def _optional_utc(value, field):
    if value is None:
        return None
    return require_utc(value, field)


def _refs(values, field, nonempty=False):
    values = require_list(values, field, MAX_REF_LIST, nonempty=nonempty)
    for position, value in enumerate(values):
        require_ref(value, "%s[%d]" % (field, position))
    require_unique(values, field)
    return values


def _strings(values, field, nonempty=False, limit=2048):
    values = require_list(values, field, MAX_LIMITATIONS, nonempty=nonempty)
    for position, value in enumerate(values):
        require_string(value, "%s[%d]" % (field, position), limit=limit)
    return values


def _preflight_result(value, field):
    require_keys(value, ("result", "evidence_refs", "limitation"), field=field)
    _result(value["result"], field + ".result")
    _refs(value["evidence_refs"], field + ".evidence_refs")
    if value["limitation"] is not None:
        require_string(value["limitation"], field + ".limitation", limit=2048)
    if value["result"] == "unobserved" and not value["limitation"]:
        raise RehearsalError("limitation-required", field + ".limitation")
    if value["result"] in {"pass", "fail"} and not value["evidence_refs"]:
        raise RehearsalError("evidence-required", field + ".evidence_refs")


def _validate_claim(claim):
    require_keys(claim, ("kind", "required_gates", "description"), field="claim")
    if claim["kind"] not in {"full_matrix", "named_gates"}:
        raise RehearsalError("unknown-claim-kind", "claim.kind")
    required = require_list(
        claim["required_gates"], "claim.required_gates", len(GATE_IDS), nonempty=True
    )
    for position, gate in enumerate(required):
        require_string(gate, "claim.required_gates[%d]" % position, limit=2)
    require_unique(required, "claim.required_gates")
    if any(gate not in GATE_IDS for gate in required):
        raise RehearsalError("unknown-gate", "claim.required_gates")
    if claim["kind"] == "full_matrix" and set(required) != set(GATE_IDS):
        raise RehearsalError("full-matrix-requires-g1-g5", "claim.required_gates")
    require_string(claim["description"], "claim.description", limit=2048)


def _validate_authorization(value):
    require_keys(
        value,
        ("user_ref", "scope_ref", "allowed_interventions"),
        field="authorization",
    )
    require_ref(value["user_ref"], "authorization.user_ref")
    require_ref(value["scope_ref"], "authorization.scope_ref")
    interventions = require_list(
        value["allowed_interventions"], "authorization.allowed_interventions", MAX_CASES
    )
    seen = []
    for position, intervention in enumerate(interventions):
        field = "authorization.allowed_interventions[%d]" % position
        require_keys(intervention, ("action", "actor_ref", "case_ids"), field=field)
        require_ref(intervention["action"], field + ".action")
        require_ref(intervention["actor_ref"], field + ".actor_ref")
        _refs(intervention["case_ids"], field + ".case_ids", nonempty=True)
        seen.extend((intervention["action"], case_id) for case_id in intervention["case_ids"])
    require_unique(seen, "authorization.allowed_interventions.action_case")


def _validate_isolation(value):
    require_keys(
        value,
        (
            "kind",
            "account_ref",
            "host_inventory_ref",
            "shared_service_refs",
            "evidence_refs",
        ),
        field="isolation",
    )
    if value["kind"] not in {"dedicated_account", "production_smoke"}:
        raise RehearsalError("unknown-isolation-kind", "isolation.kind")
    require_ref(value["account_ref"], "isolation.account_ref")
    require_ref(value["host_inventory_ref"], "isolation.host_inventory_ref")
    _refs(value["shared_service_refs"], "isolation.shared_service_refs")
    _refs(value["evidence_refs"], "isolation.evidence_refs", nonempty=True)


def _nullable_string(value, field, limit=512):
    if value is not None:
        require_string(value, field, limit=limit)


def _validate_tested_tuple(value):
    require_keys(
        value,
        (
            "source_commit",
            "source_tree",
            "dirty",
            "captured_diff_ref",
            "release_manifest_sha256",
            "package_id",
            "runtime_cohort",
            "artifact_identity_evidence_refs",
            "os",
            "python",
            "hosts",
            "private_roster_ref",
        ),
        field="tested_tuple",
    )
    for key in ("source_commit", "source_tree"):
        _object_id(value[key], "tested_tuple." + key)
    require_sha256(
        value["release_manifest_sha256"],
        "tested_tuple.release_manifest_sha256",
    )
    require_bool(value["dirty"], "tested_tuple.dirty")
    if value["captured_diff_ref"] is not None:
        require_ref(value["captured_diff_ref"], "tested_tuple.captured_diff_ref")
    if value["dirty"] and value["captured_diff_ref"] is None:
        raise RehearsalError("dirty-source-requires-captured-diff", "tested_tuple")
    require_ref(value["package_id"], "tested_tuple.package_id")
    require_ref(value["runtime_cohort"], "tested_tuple.runtime_cohort")
    _refs(
        value["artifact_identity_evidence_refs"],
        "tested_tuple.artifact_identity_evidence_refs",
        nonempty=True,
    )
    os_value = require_keys(
        value["os"], ("version", "build", "architecture"), field="tested_tuple.os"
    )
    for key in ("version", "build", "architecture"):
        _nullable_string(os_value[key], "tested_tuple.os." + key, limit=128)
    python_value = require_keys(
        value["python"], ("version", "configuration_ref"), field="tested_tuple.python"
    )
    _nullable_string(python_value["version"], "tested_tuple.python.version", limit=128)
    if python_value["configuration_ref"] is not None:
        require_ref(python_value["configuration_ref"], "tested_tuple.python.configuration_ref")
    hosts = require_list(value["hosts"], "tested_tuple.hosts", MAX_HOSTS, nonempty=True)
    host_refs = []
    seat_refs = []
    for position, host in enumerate(hosts):
        field = "tested_tuple.hosts[%d]" % position
        require_keys(
            host,
            (
                "host_ref",
                "runtime",
                "version",
                "build",
                "transport",
                "sdk_version",
                "executable_pin_ref",
                "seat_refs",
                "identity_evidence_refs",
            ),
            field=field,
        )
        host_refs.append(require_ref(host["host_ref"], field + ".host_ref"))
        require_ref(host["runtime"], field + ".runtime")
        for key in ("version", "build", "transport", "sdk_version"):
            _nullable_string(host[key], field + "." + key, limit=128)
        if host["executable_pin_ref"] is not None:
            require_ref(host["executable_pin_ref"], field + ".executable_pin_ref")
        seats = _refs(host["seat_refs"], field + ".seat_refs", nonempty=True)
        seat_refs.extend(seats)
        _refs(host["identity_evidence_refs"], field + ".identity_evidence_refs", nonempty=True)
    require_unique(host_refs, "tested_tuple.hosts.host_ref")
    require_unique(seat_refs, "tested_tuple.hosts.seat_refs")
    if len(seat_refs) > MAX_SEATS:
        raise RehearsalError("too-many-seats", "tested_tuple.hosts.seat_refs")
    require_ref(value["private_roster_ref"], "tested_tuple.private_roster_ref")
    return set(seat_refs)


def _validate_preflight(value, seats):
    require_keys(
        value,
        (
            "installed_compatibility",
            "loaded_component_identities",
            "exact_seat_readiness",
            "aggregate_restoration_health",
        ),
        field="preflight",
    )
    _preflight_result(value["installed_compatibility"], "preflight.installed_compatibility")
    _preflight_result(
        value["loaded_component_identities"], "preflight.loaded_component_identities"
    )
    readiness = require_list(
        value["exact_seat_readiness"], "preflight.exact_seat_readiness", MAX_SEATS
    )
    readiness_seats = []
    for position, item in enumerate(readiness):
        field = "preflight.exact_seat_readiness[%d]" % position
        require_keys(item, ("seat_ref", "result", "evidence_refs", "limitation"), field=field)
        seat = require_ref(item["seat_ref"], field + ".seat_ref")
        if seat not in seats:
            raise RehearsalError("unknown-seat", field + ".seat_ref")
        readiness_seats.append(seat)
        _result(item["result"], field + ".result")
        _refs(item["evidence_refs"], field + ".evidence_refs")
        if item["limitation"] is not None:
            require_string(item["limitation"], field + ".limitation", limit=2048)
        if item["result"] == "unobserved" and not item["limitation"]:
            raise RehearsalError("limitation-required", field + ".limitation")
        if item["result"] in {"pass", "fail"} and not item["evidence_refs"]:
            raise RehearsalError("evidence-required", field + ".evidence_refs")
    require_unique(readiness_seats, "preflight.exact_seat_readiness.seat_ref")
    if set(readiness_seats) != seats:
        raise RehearsalError("seat-readiness-inventory-mismatch", "preflight.exact_seat_readiness")
    _preflight_result(
        value["aggregate_restoration_health"],
        "preflight.aggregate_restoration_health",
    )


def _validate_declared_plan(value, seats):
    require_keys(
        value,
        (
            "frozen_utc",
            "required_cases",
            "expected_counts_ref",
            "windows_and_timers_ref",
            "control_plan_ref",
        ),
        field="declared_plan",
    )
    require_utc(value["frozen_utc"], "declared_plan.frozen_utc")
    required = require_list(
        value["required_cases"], "declared_plan.required_cases", MAX_CASES, nonempty=True
    )
    identities = []
    for position, item in enumerate(required):
        field = "declared_plan.required_cases[%d]" % position
        require_keys(item, ("gate_id", "case_id", "seat_refs"), field=field)
        if item["gate_id"] not in GATE_IDS:
            raise RehearsalError("unknown-gate", field + ".gate_id")
        require_ref(item["case_id"], field + ".case_id")
        target_seats = _refs(item["seat_refs"], field + ".seat_refs", nonempty=True)
        if not set(target_seats).issubset(seats):
            raise RehearsalError("unknown-seat", field + ".seat_refs")
        identities.append((item["gate_id"], item["case_id"]))
    require_unique(identities, "declared_plan.required_cases")
    for key in ("expected_counts_ref", "windows_and_timers_ref", "control_plan_ref"):
        require_ref(value[key], "declared_plan." + key)
    return {(item["gate_id"], item["case_id"]): item for item in required}


def _validate_targets(value, field, seats):
    require_keys(
        value,
        (
            "dialogue_ref",
            "envelope_ref",
            "seat_refs",
            "session_refs",
            "broker_generation_refs",
            "relay_generation_refs",
        ),
        field=field,
    )
    require_ref(value["dialogue_ref"], field + ".dialogue_ref")
    require_ref(value["envelope_ref"], field + ".envelope_ref")
    target_seats = _refs(value["seat_refs"], field + ".seat_refs", nonempty=True)
    if not set(target_seats).issubset(seats):
        raise RehearsalError("unknown-seat", field + ".seat_refs")
    _refs(value["session_refs"], field + ".session_refs", nonempty=True)
    _refs(value["broker_generation_refs"], field + ".broker_generation_refs")
    _refs(value["relay_generation_refs"], field + ".relay_generation_refs")


def _validate_window(value, field):
    require_keys(
        value,
        (
            "planned_start_utc",
            "deadline_utc",
            "quiet_until_utc",
            "retry_eligibility_utc",
            "delivery_allowance_end_utc",
            "timer_config_ref",
        ),
        field=field,
    )
    start = require_utc(value["planned_start_utc"], field + ".planned_start_utc")
    deadline = require_utc(value["deadline_utc"], field + ".deadline_utc")
    quiet = require_utc(value["quiet_until_utc"], field + ".quiet_until_utc")
    retry = require_utc(value["retry_eligibility_utc"], field + ".retry_eligibility_utc")
    allowance = require_utc(
        value["delivery_allowance_end_utc"], field + ".delivery_allowance_end_utc"
    )
    if not (start <= retry <= allowance <= deadline <= quiet):
        raise RehearsalError("invalid-time-order", field)
    require_ref(value["timer_config_ref"], field + ".timer_config_ref")


def _validate_interventions(values, field):
    values = require_list(values, field, 64)
    for position, item in enumerate(values):
        item_field = "%s[%d]" % (field, position)
        require_keys(
            item,
            ("actor_ref", "action", "at_utc", "boundary_ref", "evidence_refs"),
            field=item_field,
        )
        require_ref(item["actor_ref"], item_field + ".actor_ref")
        require_ref(item["action"], item_field + ".action")
        require_utc(item["at_utc"], item_field + ".at_utc")
        require_ref(item["boundary_ref"], item_field + ".boundary_ref")
        _refs(item["evidence_refs"], item_field + ".evidence_refs", nonempty=True)


def _validate_control(control, field):
    require_keys(
        control,
        (
            "control_id",
            "actor_ref",
            "kind",
            "expected",
            "observed",
            "result",
            "evidence_refs",
            "rationale",
        ),
        field=field,
    )
    require_ref(control["control_id"], field + ".control_id")
    require_ref(control["actor_ref"], field + ".actor_ref")
    if control["kind"] not in {"observer_fixture", "isolated_live"}:
        raise RehearsalError("unknown-control-kind", field + ".kind")
    expected = require_keys(control["expected"], ("outcome",), field=field + ".expected")
    require_ref(expected["outcome"], field + ".expected.outcome")
    if control["observed"] is not None:
        observed = require_keys(control["observed"], ("outcome",), field=field + ".observed")
        require_ref(observed["outcome"], field + ".observed.outcome")
    _result(control["result"], field + ".result")
    _refs(control["evidence_refs"], field + ".evidence_refs")
    require_string(control["rationale"], field + ".rationale", limit=2048)
    computed, reason = evaluate_control(control)
    if control["result"] != computed or control["rationale"] != reason:
        raise RehearsalError("stored-control-result-inconsistent", field)


def _validate_observation_common(value, field):
    require_keys(
        value,
        (
            "attempted",
            "preconditions_result",
            "harness_result",
            "actual_start_utc",
            "intervention_utc",
            "recovery_utc",
            "actual_end_utc",
            "coverage_result",
            "coverage_limitation",
            "deadline_met",
        ),
        field=field,
    )
    require_bool(value["attempted"], field + ".attempted")
    _result(value["preconditions_result"], field + ".preconditions_result")
    _result(value["harness_result"], field + ".harness_result")
    start = _optional_utc(value["actual_start_utc"], field + ".actual_start_utc")
    intervention = _optional_utc(value["intervention_utc"], field + ".intervention_utc")
    recovery = _optional_utc(value["recovery_utc"], field + ".recovery_utc")
    end = _optional_utc(value["actual_end_utc"], field + ".actual_end_utc")
    ordered = [item for item in (start, intervention, recovery, end) if item is not None]
    if ordered != sorted(ordered):
        raise RehearsalError("invalid-time-order", field)
    _result(value["coverage_result"], field + ".coverage_result")
    if value["coverage_limitation"] is not None:
        require_string(value["coverage_limitation"], field + ".coverage_limitation", limit=2048)
    if value["coverage_result"] != "pass" and not value["coverage_limitation"]:
        raise RehearsalError("limitation-required", field + ".coverage_limitation")
    require_bool(value["deadline_met"], field + ".deadline_met")


def _gate_expectation_keys(gate_id):
    return {
        "G1": (
            "seat_ref",
            "session_ref",
            "envelope_ref",
            "binding_generation_ref",
            "router_cadence_seconds",
        ),
        "G2": (
            "dialogue_ref",
            "phase_ref",
            "old_generation_ref",
            "new_generation_ref",
            "required_seat_refs",
            "missing_seat_ref",
        ),
        "G3": (
            "variant",
            "seat_ref",
            "session_ref",
            "generation_ref",
            "expected_count",
            "count_unit",
        ),
        "G4": (
            "boundary_kind",
            "recovery_variant",
            "request_ref",
            "logical_response_ref",
        ),
        "G5": ("final_sha256", "final_bytes", "required_seat_refs"),
    }[gate_id]


def _validate_expectation(gate_id, value, field):
    format_value = "%s-expectation/v1" % gate_id.lower()
    require_keys(value, ("format", "chain"), field=field)
    if value["format"] != format_value:
        raise RehearsalError("unsupported-format", field + ".format")
    keys = _gate_expectation_keys(gate_id)
    chain = require_keys(value["chain"], keys, field=field + ".chain")
    if gate_id == "G1":
        for key in keys[:-1]:
            require_ref(chain[key], field + ".chain." + key)
        _count(chain["router_cadence_seconds"], field + ".chain.router_cadence_seconds")
    elif gate_id == "G2":
        for key in ("dialogue_ref", "phase_ref", "old_generation_ref", "new_generation_ref", "missing_seat_ref"):
            require_ref(chain[key], field + ".chain." + key)
        _refs(chain["required_seat_refs"], field + ".chain.required_seat_refs", nonempty=True)
        if chain["old_generation_ref"] == chain["new_generation_ref"]:
            raise RehearsalError("generation-must-change", field + ".chain")
    elif gate_id == "G3":
        if chain["variant"] not in {"surviving_relay", "replacement_session"}:
            raise RehearsalError("unknown-variant", field + ".chain.variant")
        for key in ("seat_ref", "session_ref", "generation_ref"):
            require_ref(chain[key], field + ".chain." + key)
        _count(chain["expected_count"], field + ".chain.expected_count")
        if chain["count_unit"] != "native_arrival":
            raise RehearsalError("unknown-count-unit", field + ".chain.count_unit")
    elif gate_id == "G4":
        if chain["boundary_kind"] not in {"lost_submit_rpc_reply", "missing_handling_ack"}:
            raise RehearsalError("unknown-boundary-kind", field + ".chain.boundary_kind")
        if chain["recovery_variant"] not in {"authenticated_operation", "broker_restart"}:
            raise RehearsalError("unknown-recovery-variant", field + ".chain.recovery_variant")
        require_ref(chain["request_ref"], field + ".chain.request_ref")
        require_ref(chain["logical_response_ref"], field + ".chain.logical_response_ref")
    else:
        require_sha256(chain["final_sha256"], field + ".chain.final_sha256")
        _count(chain["final_bytes"], field + ".chain.final_bytes")
        _refs(chain["required_seat_refs"], field + ".chain.required_seat_refs", nonempty=True)


def _observation_chain_keys(gate_id):
    return {
        "G1": (
            "notification_sent",
            "wake_received",
            "claim_succeeded",
            "task_match",
            "envelope_match",
            "manual_steering",
        ),
        "G2": (
            "generations_distinct",
            "same_dialogue_phase",
            "roster_unchanged",
            "accepted_responses_retained",
            "withheld_pending",
            "premature_advance",
            "premature_disclosure",
            "missing_response_submitted",
            "advance_count",
            "participant_request_emitted",
            "surviving_relays_available",
            "rebind_authenticated",
            "restore_errors_accounted",
        ),
        "G3": (
            "collector_result_ref",
            "collector_qualification_ref",
            "recovery_delivery_attempted",
            "fresh_control_passed",
        ),
        "G4": (
            "request_claimed_delivered",
            "durable_response_evidenced",
            "interruption_boundary_evidenced",
            "submit_attempt_evidenced",
            "response_identity_matches",
            "accepted_logical_responses",
            "raw_retry_attempts",
            "forward_transitions",
            "reconciled",
            "later_ack_duplicate_safe",
        ),
        "G5": ("canonical_source_ref", "seat_results"),
    }[gate_id]


def _validate_observation(gate_id, value, field):
    require_keys(value, ("format", "common", "chain"), field=field)
    if value["format"] != "%s-observation/v1" % gate_id.lower():
        raise RehearsalError("unsupported-format", field + ".format")
    _validate_observation_common(value["common"], field + ".common")
    chain = require_keys(
        value["chain"], _observation_chain_keys(gate_id), field=field + ".chain"
    )
    if gate_id == "G1":
        for key in _observation_chain_keys(gate_id):
            require_bool(chain[key], field + ".chain." + key)
    elif gate_id == "G2":
        for key in _observation_chain_keys(gate_id):
            if key == "advance_count":
                _count(chain[key], field + ".chain.advance_count")
            else:
                require_bool(chain[key], field + ".chain." + key)
    elif gate_id == "G3":
        require_ref(chain["collector_result_ref"], field + ".chain.collector_result_ref")
        require_ref(
            chain["collector_qualification_ref"],
            field + ".chain.collector_qualification_ref",
        )
        require_bool(
            chain["recovery_delivery_attempted"],
            field + ".chain.recovery_delivery_attempted",
        )
        require_bool(chain["fresh_control_passed"], field + ".chain.fresh_control_passed")
    elif gate_id == "G4":
        for key in (
            "request_claimed_delivered",
            "durable_response_evidenced",
            "interruption_boundary_evidenced",
            "submit_attempt_evidenced",
            "response_identity_matches",
            "reconciled",
            "later_ack_duplicate_safe",
        ):
            require_bool(chain[key], field + ".chain." + key)
        for key in ("accepted_logical_responses", "raw_retry_attempts", "forward_transitions"):
            _count(chain[key], field + ".chain." + key)
    else:
        require_ref(chain["canonical_source_ref"], field + ".chain.canonical_source_ref")
        seats = require_list(chain["seat_results"], field + ".chain.seat_results", MAX_SEATS)
        seat_refs = []
        for position, seat in enumerate(seats):
            seat_field = "%s.chain.seat_results[%d]" % (field, position)
            require_keys(
                seat,
                (
                    "seat_ref",
                    "receipt",
                    "digest",
                    "bytes",
                    "verified",
                    "handled",
                    "acknowledged",
                    "ack_after_handling",
                    "evidence_refs",
                ),
                field=seat_field,
            )
            seat_refs.append(require_ref(seat["seat_ref"], seat_field + ".seat_ref"))
            for key in ("receipt", "verified", "handled", "acknowledged", "ack_after_handling"):
                require_bool(seat[key], seat_field + "." + key)
            require_sha256(seat["digest"], seat_field + ".digest")
            _count(seat["bytes"], seat_field + ".bytes")
            _refs(seat["evidence_refs"], seat_field + ".evidence_refs", nonempty=True)
        require_unique(seat_refs, field + ".chain.seat_results.seat_ref")


def _validate_observer(value, field):
    require_keys(
        value,
        (
            "contract_ref",
            "validation_evidence_refs",
            "completeness_result",
            "limitations",
        ),
        field=field,
    )
    require_ref(value["contract_ref"], field + ".contract_ref")
    _refs(value["validation_evidence_refs"], field + ".validation_evidence_refs")
    _result(value["completeness_result"], field + ".completeness_result")
    _strings(value["limitations"], field + ".limitations")
    if value["completeness_result"] != "pass" and not value["limitations"]:
        raise RehearsalError("limitation-required", field + ".limitations")
    if value["completeness_result"] == "pass" and not value[
        "validation_evidence_refs"
    ]:
        raise RehearsalError("evidence-required", field + ".validation_evidence_refs")


def _validate_case(case, gate_id, field, seats):
    require_keys(
        case,
        (
            "case_id",
            "actor_ref",
            "required",
            "applicable",
            "skip_reason",
            "targets",
            "precondition_evidence_refs",
            "window",
            "interventions",
            "expected",
            "observed",
            "evidence_refs",
            "observer",
            "controls",
            "result",
            "rationale",
        ),
        field=field,
    )
    require_ref(case["case_id"], field + ".case_id")
    require_ref(case["actor_ref"], field + ".actor_ref")
    require_bool(case["required"], field + ".required")
    require_bool(case["applicable"], field + ".applicable")
    if case["skip_reason"] is not None:
        require_string(case["skip_reason"], field + ".skip_reason", limit=2048)
    _validate_targets(case["targets"], field + ".targets", seats)
    _refs(case["precondition_evidence_refs"], field + ".precondition_evidence_refs", nonempty=True)
    _validate_window(case["window"], field + ".window")
    _validate_interventions(case["interventions"], field + ".interventions")
    _validate_expectation(gate_id, case["expected"], field + ".expected")
    _validate_observation(gate_id, case["observed"], field + ".observed")
    common = case["observed"]["common"]
    if common["attempted"]:
        actual_start = require_utc(
            common["actual_start_utc"], field + ".observed.common.actual_start_utc"
        )
        actual_end = require_utc(
            common["actual_end_utc"], field + ".observed.common.actual_end_utc"
        )
        planned_start = require_utc(
            case["window"]["planned_start_utc"], field + ".window.planned_start_utc"
        )
        quiet_until = require_utc(
            case["window"]["quiet_until_utc"], field + ".window.quiet_until_utc"
        )
        if actual_start > planned_start:
            raise RehearsalError("capture-starts-after-planned-event", field + ".observed")
        if common["coverage_result"] == "pass" and actual_end < quiet_until:
            raise RehearsalError("capture-ends-before-quiet-window", field + ".observed")
        if common["deadline_met"] and common["recovery_utc"] is not None:
            recovery = require_utc(
                common["recovery_utc"], field + ".observed.common.recovery_utc"
            )
            deadline = require_utc(
                case["window"]["deadline_utc"], field + ".window.deadline_utc"
            )
            if recovery > deadline:
                raise RehearsalError("late-recovery-marked-on-time", field + ".observed")
        intervention_times = [
            require_utc(item["at_utc"], field + ".interventions.at_utc")
            for item in case["interventions"]
        ]
        if any(item < actual_start or item > actual_end for item in intervention_times):
            raise RehearsalError("intervention-outside-observation-window", field)
        observed_intervention = _optional_utc(
            common["intervention_utc"], field + ".observed.common.intervention_utc"
        )
        if intervention_times and observed_intervention not in intervention_times:
            raise RehearsalError("intervention-time-mismatch", field + ".observed")
    expected = case["expected"]["chain"]
    targets = case["targets"]
    if gate_id == "G1" and (
        expected["seat_ref"] not in targets["seat_refs"]
        or expected["session_ref"] not in targets["session_refs"]
        or expected["envelope_ref"] != targets["envelope_ref"]
    ):
        raise RehearsalError("expectation-target-mismatch", field + ".expected")
    if gate_id == "G2" and (
        expected["dialogue_ref"] != targets["dialogue_ref"]
        or expected["missing_seat_ref"] not in expected["required_seat_refs"]
        or not set(expected["required_seat_refs"]).issubset(set(targets["seat_refs"]))
        or not {expected["old_generation_ref"], expected["new_generation_ref"]}.issubset(
            set(targets["broker_generation_refs"])
        )
    ):
        raise RehearsalError("expectation-target-mismatch", field + ".expected")
    if gate_id == "G3" and (
        expected["seat_ref"] not in targets["seat_refs"]
        or expected["session_ref"] not in targets["session_refs"]
    ):
        raise RehearsalError("expectation-target-mismatch", field + ".expected")
    if gate_id == "G4" and expected["request_ref"] != targets["envelope_ref"]:
        raise RehearsalError("expectation-target-mismatch", field + ".expected")
    if gate_id == "G5" and set(expected["required_seat_refs"]) != set(
        targets["seat_refs"]
    ):
        raise RehearsalError("expectation-target-mismatch", field + ".expected")
    _refs(case["evidence_refs"], field + ".evidence_refs")
    _validate_observer(case["observer"], field + ".observer")
    controls = require_list(case["controls"], field + ".controls", MAX_CONTROLS_PER_CASE)
    control_ids = []
    for position, control in enumerate(controls):
        _validate_control(control, "%s.controls[%d]" % (field, position))
        control_ids.append(control["control_id"])
    require_unique(control_ids, field + ".controls.control_id")
    _result(case["result"], field + ".result")
    require_string(case["rationale"], field + ".rationale", limit=2048)


def _all_evidence_refs(record):
    refs = []
    refs.extend(record["isolation"]["evidence_refs"])
    tuple_value = record["tested_tuple"]
    refs.extend(tuple_value["artifact_identity_evidence_refs"])
    if tuple_value["captured_diff_ref"] is not None:
        refs.append(tuple_value["captured_diff_ref"])
    if tuple_value["python"]["configuration_ref"] is not None:
        refs.append(tuple_value["python"]["configuration_ref"])
    for host in tuple_value["hosts"]:
        refs.extend(host["identity_evidence_refs"])
    preflight = record["preflight"]
    for key in ("installed_compatibility", "loaded_component_identities", "aggregate_restoration_health"):
        refs.extend(preflight[key]["evidence_refs"])
    for item in preflight["exact_seat_readiness"]:
        refs.extend(item["evidence_refs"])
    plan = record["declared_plan"]
    refs.extend([plan["expected_counts_ref"], plan["windows_and_timers_ref"], plan["control_plan_ref"]])
    for gate in record["gates"]:
        for case in gate["cases"]:
            refs.extend(case["precondition_evidence_refs"])
            refs.extend(case["evidence_refs"])
            refs.extend(case["observer"]["validation_evidence_refs"])
            for intervention in case["interventions"]:
                refs.extend(intervention["evidence_refs"])
            for control in case["controls"]:
                refs.extend(control["evidence_refs"])
            if gate["gate_id"] == "G3":
                refs.append(case["observed"]["chain"]["collector_result_ref"])
                refs.append(case["observed"]["chain"]["collector_qualification_ref"])
            if gate["gate_id"] == "G5":
                refs.append(case["observed"]["chain"]["canonical_source_ref"])
                for seat in case["observed"]["chain"]["seat_results"]:
                    refs.extend(seat["evidence_refs"])
    refs.extend(record["cleanup"]["export_evidence_refs"])
    refs.extend(record["cleanup"]["dialogue_deletion"]["evidence_refs"])
    refs.extend(record["cleanup"]["detached_capture_deletion"]["evidence_refs"])
    return refs


def _unknown_limitations(record):
    selected = {
        "tested_tuple.os.version": record["tested_tuple"]["os"]["version"],
        "tested_tuple.os.build": record["tested_tuple"]["os"]["build"],
        "tested_tuple.os.architecture": record["tested_tuple"]["os"]["architecture"],
        "tested_tuple.python.version": record["tested_tuple"]["python"]["version"],
    }
    for position, host in enumerate(record["tested_tuple"]["hosts"]):
        for key in ("version", "build", "transport", "sdk_version"):
            selected["tested_tuple.hosts[%d].%s" % (position, key)] = host[key]
    limitations = record["limitations"]
    missing = []
    for field, value in selected.items():
        if value is None and not any(item.startswith(field + ":") for item in limitations):
            missing.append(field)
    if missing:
        raise RehearsalError("field-specific-limitation-required", missing[0])


def validate_record_structure(record, allow_template=False):
    required = (
        "contract",
        "record_kind",
        "run_id",
        "operator_ref",
        "created_utc",
        "completed_utc",
        "tier",
        "claim",
        "overall_result",
        "limitations",
        "authorization",
        "isolation",
        "tested_tuple",
        "preflight",
        "declared_plan",
        "gates",
        "evidence",
        "private_evidence_index_ref",
        "retention",
        "cleanup",
    )
    optional = ("case_template", "evidence_item_template") if allow_template else ()
    require_keys(record, required, optional, field="record")
    if record["contract"] != CONTRACT:
        raise RehearsalError("unsupported-contract", "record.contract")
    if record["record_kind"] == "template":
        if not allow_template:
            raise RehearsalError("template-cannot-be-assessed", "record.record_kind")
        if record["overall_result"] != "unobserved":
            raise RehearsalError("template-result-must-be-unobserved", "record.overall_result")
        _strings(record["limitations"], "record.limitations", nonempty=True)
        return {"template": True}
    if record["record_kind"] != "run":
        raise RehearsalError("unknown-record-kind", "record.record_kind")
    if "case_template" in record or "evidence_item_template" in record:
        raise RehearsalError("scaffold-field-in-run", "record")
    require_ref(record["run_id"], "record.run_id")
    require_ref(record["operator_ref"], "record.operator_ref")
    created = require_utc(record["created_utc"], "record.created_utc")
    completed = _optional_utc(record["completed_utc"], "record.completed_utc")
    if completed is not None and completed < created:
        raise RehearsalError("invalid-time-order", "record.completed_utc")
    if record["tier"] not in {"smoke", "recovery"}:
        raise RehearsalError("unknown-tier", "record.tier")
    _validate_claim(record["claim"])
    _result(record["overall_result"], "record.overall_result")
    _strings(record["limitations"], "record.limitations")
    _validate_authorization(record["authorization"])
    _validate_isolation(record["isolation"])
    seats = _validate_tested_tuple(record["tested_tuple"])
    _validate_preflight(record["preflight"], seats)
    required_cases = _validate_declared_plan(record["declared_plan"], seats)
    gates = require_list(record["gates"], "record.gates", len(GATE_IDS))
    gate_ids = []
    case_ids = []
    cases_by_key = {}
    for gate_position, gate in enumerate(gates):
        gate_field = "record.gates[%d]" % gate_position
        require_keys(gate, ("gate_id", "result", "rationale", "cases"), field=gate_field)
        if gate["gate_id"] not in GATE_IDS:
            raise RehearsalError("unknown-gate", gate_field + ".gate_id")
        gate_id = gate["gate_id"]
        gate_ids.append(gate_id)
        _result(gate["result"], gate_field + ".result")
        require_string(gate["rationale"], gate_field + ".rationale", limit=2048)
        cases = require_list(gate["cases"], gate_field + ".cases", MAX_CASES)
        for case_position, case in enumerate(cases):
            field = "%s.cases[%d]" % (gate_field, case_position)
            _validate_case(case, gate_id, field, seats)
            key = (gate_id, case["case_id"])
            case_ids.append(case["case_id"])
            cases_by_key[key] = case
    if set(gate_ids) != set(GATE_IDS) or len(gate_ids) != len(GATE_IDS):
        raise RehearsalError("g1-g5-gate-inventory-required", "record.gates")
    require_unique(case_ids, "record.gates.cases.case_id")
    if set(required_cases) - set(cases_by_key):
        raise RehearsalError("missing-required-case", "declared_plan.required_cases")
    for key, declaration in required_cases.items():
        case = cases_by_key[key]
        if not case["required"]:
            raise RehearsalError("requiredness-mismatch", "case.%s" % key[1])
        if set(declaration["seat_refs"]) != set(case["targets"]["seat_refs"]):
            raise RehearsalError("declared-target-mismatch", "case.%s" % key[1])
    for key, case in cases_by_key.items():
        if case["required"] and key not in required_cases:
            raise RehearsalError("undeclared-required-case", "case.%s" % key[1])
    allowed_interventions = {
        (item["action"], item["actor_ref"], case_id)
        for item in record["authorization"]["allowed_interventions"]
        for case_id in item["case_ids"]
    }
    known_case_ids = set(case_ids)
    if any(case_id not in known_case_ids for _, _, case_id in allowed_interventions):
        raise RehearsalError(
            "authorization-references-unknown-case",
            "authorization.allowed_interventions",
        )
    for case in cases_by_key.values():
        for intervention in case["interventions"]:
            key = (intervention["action"], intervention["actor_ref"], case["case_id"])
            if key not in allowed_interventions:
                raise RehearsalError(
                    "intervention-outside-authorization",
                    "case.%s.interventions" % case["case_id"],
                )
    inventory = require_list(record["evidence"], "record.evidence", MAX_EVIDENCE_ITEMS)
    evidence_refs = []
    for position, item in enumerate(inventory):
        field = "record.evidence[%d]" % position
        require_keys(item, ("ref", "sha256", "bytes", "collected_utc", "classification"), field=field)
        evidence_refs.append(require_ref(item["ref"], field + ".ref"))
        require_sha256(item["sha256"], field + ".sha256")
        require_nonnegative_int(item["bytes"], field + ".bytes")
        require_utc(item["collected_utc"], field + ".collected_utc")
        if item["classification"] not in CLASSIFICATIONS:
            raise RehearsalError("unknown-classification", field + ".classification")
    require_unique(evidence_refs, "record.evidence.ref")
    evidence_set = set(evidence_refs)
    for reference in _all_evidence_refs(record):
        if reference not in evidence_set:
            raise RehearsalError("dangling-evidence-reference", "evidence_ref")
    require_ref(record["private_evidence_index_ref"], "record.private_evidence_index_ref")
    retention = require_keys(
        record["retention"],
        ("approved_by", "redacted_record", "private_captures"),
        field="retention",
    )
    require_ref(retention["approved_by"], "retention.approved_by")
    for key in ("redacted_record", "private_captures"):
        item = require_keys(
            retention[key], ("owner_ref", "delete_after_utc"), field="retention." + key
        )
        require_ref(item["owner_ref"], "retention.%s.owner_ref" % key)
        require_utc(item["delete_after_utc"], "retention.%s.delete_after_utc" % key)
    cleanup = require_keys(
        record["cleanup"],
        (
            "owner_ref",
            "exports_verified_utc",
            "export_evidence_refs",
            "dialogue_deletion",
            "detached_capture_deletion",
        ),
        field="cleanup",
    )
    require_ref(cleanup["owner_ref"], "cleanup.owner_ref")
    _optional_utc(cleanup["exports_verified_utc"], "cleanup.exports_verified_utc")
    _refs(cleanup["export_evidence_refs"], "cleanup.export_evidence_refs")
    for key in ("dialogue_deletion", "detached_capture_deletion"):
        item = require_keys(cleanup[key], ("result", "evidence_refs"), field="cleanup." + key)
        _result(item["result"], "cleanup.%s.result" % key)
        _refs(item["evidence_refs"], "cleanup.%s.evidence_refs" % key)
        if item["result"] in {"pass", "fail"} and not item["evidence_refs"]:
            raise RehearsalError("evidence-required", "cleanup.%s.evidence_refs" % key)
    _unknown_limitations(record)
    return {
        "template": False,
        "seats": seats,
        "required_cases": required_cases,
        "cases_by_key": cases_by_key,
    }


def evaluate_control(control):
    if control["observed"] is None or not control["evidence_refs"]:
        return "unobserved", "control-not-observed"
    if control["observed"]["outcome"] != control["expected"]["outcome"]:
        return "fail", "control-observed-unexpected-outcome"
    return "pass", "control-observed-expected-outcome"


def aggregate_results(results):
    if not results:
        return "unobserved"
    return max(results, key=lambda result: PRECEDENCE[result])


def _common_decision(case):
    common = case["observed"]["common"]
    if case["skip_reason"]:
        if common["attempted"]:
            return "fail", "skipped-case-has-observations"
        return "skipped", "case-deliberately-skipped"
    if not case["applicable"]:
        return "unobserved", "inapplicable-case-missing-skip-reason"
    if not common["attempted"]:
        return "unobserved", "case-not-attempted"
    control_results = [evaluate_control(control)[0] for control in case["controls"]]
    if not control_results:
        return "unobserved", "declared-control-inventory-empty"
    aggregate = aggregate_results(control_results)
    if aggregate == "fail":
        return "fail", "required-control-contradicted"
    if aggregate != "pass":
        return "unobserved", "required-control-unobserved"
    if common["preconditions_result"] == "fail":
        return "fail", "case-precondition-contradicted"
    if common["preconditions_result"] != "pass":
        return "unobserved", "case-precondition-unobserved"
    if common["harness_result"] != "pass":
        return "unobserved", "observer-harness-unavailable"
    if common["coverage_result"] != "pass":
        return "unobserved", "observation-window-incomplete"
    if case["observer"]["completeness_result"] != "pass":
        return "unobserved", "observer-completeness-unavailable"
    if not common["deadline_met"]:
        return "fail", "qualified-observation-missed-deadline"
    return None, None


def _evaluate_g1(case):
    chain = case["observed"]["chain"]
    if not chain["task_match"]:
        return "fail", "g1-wrong-task"
    if not chain["envelope_match"]:
        return "fail", "g1-wrong-envelope"
    if chain["manual_steering"]:
        return "fail", "g1-manual-steering-substituted"
    if not all(chain[key] for key in ("notification_sent", "wake_received", "claim_succeeded")):
        return "unobserved", "g1-notification-wake-claim-chain-incomplete"
    return "pass", "g1-notification-wake-claim-chain-qualified"


def _evaluate_g2(case):
    chain = case["observed"]["chain"]
    contradictions = (
        (not chain["generations_distinct"], "g2-generation-not-distinct"),
        (not chain["same_dialogue_phase"], "g2-dialogue-or-phase-mismatch"),
        (not chain["roster_unchanged"], "g2-required-roster-changed"),
        (not chain["accepted_responses_retained"], "g2-accepted-response-lost"),
        (chain["premature_advance"], "g2-premature-advance"),
        (chain["premature_disclosure"], "g2-premature-disclosure"),
        (chain["advance_count"] > 1, "g2-advanced-more-than-once"),
    )
    for condition, reason in contradictions:
        if condition:
            return "fail", reason
    required = (
        "withheld_pending",
        "missing_response_submitted",
        "participant_request_emitted",
        "surviving_relays_available",
        "rebind_authenticated",
        "restore_errors_accounted",
    )
    if chain["advance_count"] != 1 or not all(chain[key] for key in required):
        return "unobserved", "g2-recovery-chain-incomplete"
    return "pass", "g2-barrier-recovered-once"


def _evaluate_g3(case, run_root, context_kind, collector_loader, verified_index):
    chain = case["observed"]["chain"]
    available_refs = None
    if collector_loader is None:
        if run_root is None:
            raise RehearsalError("run-root-required-for-g3")
        result = read_imported_json(
            run_root,
            chain["collector_result_ref"],
            "collector_result",
            verified_index=verified_index,
        )
        qualification = read_imported_json(
            run_root,
            chain["collector_qualification_ref"],
            "collector_qualification",
            verified_index=verified_index,
        )
        index = verified_index if verified_index is not None else load_private_index(run_root)
        available_refs = {item["ref"] for item in index["items"]}
    else:
        result, qualification = collector_loader(chain)
    expected = case["expected"]["chain"]
    claim = result.get("claim", {})
    target = result.get("target", {})
    mismatched = (
        claim.get("expected_count") != expected["expected_count"]
        or claim.get("unit") != expected["count_unit"]
        or claim.get("variant") != expected["variant"]
        or claim.get("envelope_ref") != case["targets"]["envelope_ref"]
        or target.get("seat_ref") != expected["seat_ref"]
        or target.get("session_ref") != expected["session_ref"]
        or target.get("generation_ref") != expected["generation_ref"]
    )
    if mismatched:
        return "fail", "g3-declared-collector-tuple-mismatch", {"limitations": []}
    decision = assess_arrival_count(
        result,
        qualification,
        context_kind=context_kind,
        recovery_delivery_attempted=chain["recovery_delivery_attempted"],
        fresh_control_passed=chain["fresh_control_passed"],
        available_refs=available_refs,
    )
    return decision["result"], "g3-" + decision["reason"], decision


def _evaluate_g4(case):
    chain = case["observed"]["chain"]
    if not chain["response_identity_matches"]:
        return "fail", "g4-logical-response-identity-mismatch"
    if chain["accepted_logical_responses"] > 1:
        return "fail", "g4-additional-logical-response"
    if chain["forward_transitions"] > 1:
        return "fail", "g4-additional-forward-transition"
    if not chain["interruption_boundary_evidenced"]:
        return "unobserved", "g4-live-interruption-boundary-not-evidenced"
    required = (
        "request_claimed_delivered",
        "durable_response_evidenced",
        "submit_attempt_evidenced",
        "reconciled",
        "later_ack_duplicate_safe",
    )
    if chain["accepted_logical_responses"] != 1 or chain["forward_transitions"] != 1:
        return "unobserved", "g4-count-chain-incomplete"
    if not all(chain[key] for key in required):
        return "unobserved", "g4-reconciliation-chain-incomplete"
    return "pass", "g4-durable-response-reconciled-once"


def _evaluate_g5(case):
    expected = case["expected"]["chain"]
    observed = case["observed"]["chain"]
    by_seat = {item["seat_ref"]: item for item in observed["seat_results"]}
    for seat_ref, item in sorted(by_seat.items()):
        if item["digest"] != expected["final_sha256"] or item["bytes"] != expected["final_bytes"]:
            return "fail", "g5-canonical-final-mismatch:%s" % seat_ref
        if item["acknowledged"] and (not item["handled"] or not item["ack_after_handling"]):
            return "fail", "g5-acknowledgement-before-handling:%s" % seat_ref
    missing = sorted(set(expected["required_seat_refs"]) - set(by_seat))
    if missing:
        return "fail", "g5-required-seat-omitted:%s" % missing[0]
    for seat_ref in sorted(expected["required_seat_refs"]):
        item = by_seat[seat_ref]
        if not all(item[key] for key in ("receipt", "verified", "handled", "acknowledged", "ack_after_handling")):
            return "unobserved", "g5-seat-handling-chain-incomplete:%s" % seat_ref
    return "pass", "g5-all-required-seats-handled-canonical-final"


def evaluate_case(
    case,
    gate_id,
    run_root=None,
    context_kind="live",
    collector_loader=None,
    verified_index=None,
):
    common_result, common_reason = _common_decision(case)
    if common_result is not None:
        return {"result": common_result, "reason": common_reason, "diagnostics": {}}
    if gate_id == "G1":
        result, reason = _evaluate_g1(case)
        diagnostics = {}
    elif gate_id == "G2":
        result, reason = _evaluate_g2(case)
        diagnostics = {}
    elif gate_id == "G3":
        result, reason, diagnostics = _evaluate_g3(
            case, run_root, context_kind, collector_loader, verified_index
        )
    elif gate_id == "G4":
        result, reason = _evaluate_g4(case)
        diagnostics = {}
    else:
        result, reason = _evaluate_g5(case)
        diagnostics = {}
    return {"result": result, "reason": reason, "diagnostics": diagnostics}


def assess_record(
    record,
    run_root=None,
    context_kind="live",
    collector_loader=None,
    verified_index=None,
):
    structure = validate_record_structure(record)
    gate_assessments = []
    required_keys = set(structure["required_cases"])
    gate_results = {}
    for gate in sorted(record["gates"], key=lambda item: item["gate_id"]):
        gate_id = gate["gate_id"]
        cases = []
        required_results = []
        for case in sorted(gate["cases"], key=lambda item: item["case_id"]):
            decision = evaluate_case(
                case,
                gate_id,
                run_root=run_root,
                context_kind=context_kind,
                collector_loader=collector_loader,
                verified_index=verified_index,
            )
            cases.append(
                {
                    "case_id": case["case_id"],
                    "required": case["required"],
                    "result": decision["result"],
                    "reason": decision["reason"],
                    "diagnostics": decision["diagnostics"],
                }
            )
            if (gate_id, case["case_id"]) in required_keys:
                required_results.append(decision["result"])
            if case["result"] != decision["result"] or case["rationale"] != decision["reason"]:
                raise RehearsalError("stored-case-result-inconsistent", "case.%s" % case["case_id"])
        gate_result = aggregate_results(required_results)
        gate_reason = "aggregate:%s" % gate_result
        if gate["result"] != gate_result or gate["rationale"] != gate_reason:
            raise RehearsalError("stored-gate-result-inconsistent", "gate.%s" % gate_id)
        gate_results[gate_id] = gate_result
        gate_assessments.append(
            {"gate_id": gate_id, "result": gate_result, "reason": gate_reason, "cases": cases}
        )
    required_gates = record["claim"]["required_gates"]
    overall = aggregate_results([gate_results[gate_id] for gate_id in required_gates])
    if record["overall_result"] != overall:
        raise RehearsalError("stored-overall-result-inconsistent", "record.overall_result")
    return {
        "record_valid": True,
        "claim": copy.deepcopy(record["claim"]),
        "result": overall,
        "gates": gate_assessments,
        "limitations": sorted(record["limitations"]),
    }


def validate_run(run_root, assess=False):
    run_root = Path(run_root)
    _require_private_regular(run_root / "record.json", "record")
    record = strict_load_json(run_root / "record.json", "record")
    state = load_state(run_root)
    context_kind = state["context_kind"]
    validate_record_structure(record)
    verified = verify_evidence(run_root, record["evidence"])
    assessment = assess_record(
        record,
        run_root=run_root,
        context_kind=context_kind,
        verified_index=verified["index"],
    )
    if assess and state["state"] not in {
        "assessment_ready",
        "export_verified",
        "cleanup_recorded",
    }:
        assessment = copy.deepcopy(assessment)
        assessment["calculated_result"] = assessment["result"]
        assessment["result"] = "unobserved"
        assessment["limitations"] = sorted(
            set(assessment["limitations"] + ["runner-state-not-assessment-ready"])
        )
    report = {
        "record_valid": True,
        "claim": copy.deepcopy(record["claim"]),
        "result": assessment["result"] if assess else "structurally-valid",
        "evidence_items_verified": len(verified["public_inventory"]),
        "runner_state": state["state"],
    }
    if assess:
        report["assessment"] = assessment
    return report


def scan_verified_g3_contradictions(run_root):
    """Preserve independently verified duplicate evidence despite other invalid fields."""
    contradictions = []
    try:
        record = strict_load_json(Path(run_root) / "record.json", "record")
        if not isinstance(record, dict) or not isinstance(record.get("gates"), list):
            return contradictions
        verified = verify_evidence(run_root)
        available_refs = {item["ref"] for item in verified["index"]["items"]}
        for gate in record["gates"]:
            if not isinstance(gate, dict) or gate.get("gate_id") != "G3":
                continue
            for case in gate.get("cases", []):
                try:
                    chain = case["observed"]["chain"]
                    result = read_imported_json(
                        run_root,
                        chain["collector_result_ref"],
                        "collector_result",
                        verified_index=verified["index"],
                    )
                    normalized = normalized_arrivals(result, available_refs=available_refs)
                    expected = case["expected"]["chain"]["expected_count"]
                    if is_nonnegative_int(expected) and normalized[
                        "verified_lower_bound"
                    ] > expected:
                        contradictions.append(
                            {
                                "gate_id": "G3",
                                "case_id": case.get("case_id"),
                                "kind": "verified-native-arrival-lower-bound-exceeds-expected",
                                "expected_count": expected,
                                "verified_lower_bound": normalized["verified_lower_bound"],
                            }
                        )
                except (EvidenceError, KeyError, TypeError, ValueError):
                    continue
    except (EvidenceError, OSError, ValueError):
        return contradictions
    return sorted(
        contradictions,
        key=lambda item: (str(item["case_id"]), item["verified_lower_bound"]),
    )


def validate_frozen_declaration(record):
    """Validate the immutable declaration without requiring outcome observations."""
    validate_record_structure(record, allow_template=True)
    require_ref(record["run_id"], "record.run_id")
    require_ref(record["operator_ref"], "record.operator_ref")
    if record["tier"] not in {"smoke", "recovery"}:
        raise RehearsalError("unknown-tier", "record.tier")
    _validate_claim(record["claim"])
    _validate_authorization(record["authorization"])
    _validate_isolation(record["isolation"])
    seats = _validate_tested_tuple(record["tested_tuple"])
    required_cases = _validate_declared_plan(record["declared_plan"], seats)
    gates = require_list(record["gates"], "record.gates", len(GATE_IDS))
    gate_ids = []
    case_ids = []
    cases_by_key = {}
    for gate_position, gate in enumerate(gates):
        field = "record.gates[%d]" % gate_position
        require_keys(gate, ("gate_id", "result", "rationale", "cases"), field=field)
        gate_id = gate["gate_id"]
        if gate_id not in GATE_IDS:
            raise RehearsalError("unknown-gate", field + ".gate_id")
        gate_ids.append(gate_id)
        for case_position, case in enumerate(
            require_list(gate["cases"], field + ".cases", MAX_CASES)
        ):
            case_field = "%s.cases[%d]" % (field, case_position)
            require_keys(
                case,
                (
                    "case_id",
                    "actor_ref",
                    "required",
                    "applicable",
                    "skip_reason",
                    "targets",
                    "precondition_evidence_refs",
                    "window",
                    "interventions",
                    "expected",
                    "observed",
                    "evidence_refs",
                    "observer",
                    "controls",
                    "result",
                    "rationale",
                ),
                field=case_field,
            )
            require_ref(case["case_id"], case_field + ".case_id")
            require_ref(case["actor_ref"], case_field + ".actor_ref")
            require_bool(case["required"], case_field + ".required")
            require_bool(case["applicable"], case_field + ".applicable")
            _validate_targets(case["targets"], case_field + ".targets", seats)
            _validate_window(case["window"], case_field + ".window")
            _validate_expectation(gate_id, case["expected"], case_field + ".expected")
            controls = require_list(
                case["controls"], case_field + ".controls", MAX_CONTROLS_PER_CASE
            )
            control_ids = []
            for control_position, control in enumerate(controls):
                control_field = "%s.controls[%d]" % (case_field, control_position)
                require_keys(
                    control,
                    (
                        "control_id",
                        "actor_ref",
                        "kind",
                        "expected",
                        "observed",
                        "result",
                        "evidence_refs",
                        "rationale",
                    ),
                    field=control_field,
                )
                control_ids.append(
                    require_ref(control["control_id"], control_field + ".control_id")
                )
                require_ref(control["actor_ref"], control_field + ".actor_ref")
                if control["kind"] not in {"observer_fixture", "isolated_live"}:
                    raise RehearsalError("unknown-control-kind", control_field + ".kind")
                expected = require_keys(
                    control["expected"], ("outcome",), field=control_field + ".expected"
                )
                require_ref(expected["outcome"], control_field + ".expected.outcome")
            require_unique(control_ids, case_field + ".controls.control_id")
            key = (gate_id, case["case_id"])
            case_ids.append(case["case_id"])
            cases_by_key[key] = case
    if set(gate_ids) != set(GATE_IDS) or len(gate_ids) != len(GATE_IDS):
        raise RehearsalError("g1-g5-gate-inventory-required", "record.gates")
    require_unique(case_ids, "record.gates.cases.case_id")
    if set(required_cases) != {
        key for key, case in cases_by_key.items() if case["required"]
    }:
        raise RehearsalError("required-case-inventory-mismatch", "declared_plan.required_cases")
    authorized_case_ids = {
        case_id
        for item in record["authorization"]["allowed_interventions"]
        for case_id in item["case_ids"]
    }
    if not authorized_case_ids.issubset(set(case_ids)):
        raise RehearsalError(
            "authorization-references-unknown-case",
            "authorization.allowed_interventions",
        )
    for key, declaration in required_cases.items():
        if set(declaration["seat_refs"]) != set(cases_by_key[key]["targets"]["seat_refs"]):
            raise RehearsalError("declared-target-mismatch", "case.%s" % key[1])
    retention = require_keys(
        record["retention"],
        ("approved_by", "redacted_record", "private_captures"),
        field="retention",
    )
    require_ref(retention["approved_by"], "retention.approved_by")
    for key in ("redacted_record", "private_captures"):
        item = require_keys(
            retention[key], ("owner_ref", "delete_after_utc"), field="retention." + key
        )
        require_ref(item["owner_ref"], "retention.%s.owner_ref" % key)
        require_utc(item["delete_after_utc"], "retention.%s.delete_after_utc" % key)


def frozen_projection(record):
    validate_frozen_declaration(record)
    cases = []
    for gate in sorted(record["gates"], key=lambda item: item["gate_id"]):
        for case in sorted(gate["cases"], key=lambda item: item["case_id"]):
            cases.append(
                {
                    "gate_id": gate["gate_id"],
                    "case_id": case["case_id"],
                    "actor_ref": case["actor_ref"],
                    "required": case["required"],
                    "applicable": case["applicable"],
                    "targets": copy.deepcopy(case["targets"]),
                    "precondition_evidence_refs": copy.deepcopy(
                        case["precondition_evidence_refs"]
                    ),
                    "window": copy.deepcopy(case["window"]),
                    "expected": copy.deepcopy(case["expected"]),
                    "observer_plan": {
                        "contract_ref": case["observer"]["contract_ref"],
                        "validation_evidence_refs": copy.deepcopy(
                            case["observer"]["validation_evidence_refs"]
                        ),
                    },
                    "controls": [
                        {
                            "control_id": control["control_id"],
                            "actor_ref": control["actor_ref"],
                            "kind": control["kind"],
                            "expected": copy.deepcopy(control["expected"]),
                        }
                        for control in sorted(case["controls"], key=lambda item: item["control_id"])
                    ],
                }
            )
    return {
        "format": "rehearsal-frozen-plan/v1",
        "run_id": record["run_id"],
        "operator_ref": record["operator_ref"],
        "tier": record["tier"],
        "claim": copy.deepcopy(record["claim"]),
        "authorization": copy.deepcopy(record["authorization"]),
        "isolation": copy.deepcopy(record["isolation"]),
        "tested_tuple": copy.deepcopy(record["tested_tuple"]),
        "declared_plan": copy.deepcopy(record["declared_plan"]),
        "retention": copy.deepcopy(record["retention"]),
        "cases": cases,
    }


def _inside_repository(path):
    try:
        Path(path).resolve().relative_to(REPOSITORY_ROOT)
        return True
    except ValueError:
        return False


def _mkdir_private(path):
    os.mkdir(str(path), 0o700)
    os.chmod(str(path), 0o700)


def _require_private_regular(path, field):
    try:
        info = Path(path).lstat()
    except OSError as error:
        raise RehearsalError("unreadable-file", field) from error
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise RehearsalError("unsafe-private-file", field)
    return info


def _initial_state(plan, record_digest):
    return {
        "format": STATE_FORMAT,
        "context_kind": plan["context_kind"],
        "run_id": plan["run_id"],
        "state": "draft",
        "sequence": 0,
        "plan_sha256": None,
        "previous_checkpoint_digest": None,
        "checkpoint_refs": [],
        "record_digest_at_checkpoint": record_digest,
        "active_case": None,
        "completed_cases": [],
    }


def validate_plan(plan):
    require_keys(plan, ("format", "context_kind", "run_id", "record"), field="plan")
    if plan["format"] != PLAN_FORMAT:
        raise RehearsalError("unsupported-format", "plan.format")
    if plan["context_kind"] not in {"live", "fixture"}:
        raise RehearsalError("unknown-context-kind", "plan.context_kind")
    require_ref(plan["run_id"], "plan.run_id")
    record = plan["record"]
    validate_record_structure(record, allow_template=True)
    if record["record_kind"] != "template":
        raise RehearsalError("init-requires-template-record", "plan.record.record_kind")
    if record["run_id"] != plan["run_id"]:
        raise RehearsalError("run-id-mismatch", "plan.run_id")
    return plan


def init_run(private_root, plan_path):
    root = Path(private_root)
    if not root.is_absolute():
        raise RehearsalError("absolute-path-required", "private_root")
    if _inside_repository(root):
        raise RehearsalError("private-root-inside-repository", "private_root")
    if root.exists() or root.is_symlink():
        raise RehearsalError("exclusive-private-root-required", "private_root")
    parent = root.parent
    try:
        info = parent.lstat()
    except OSError as error:
        raise RehearsalError("private-root-parent-unavailable", "private_root") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RehearsalError("private-root-parent-invalid", "private_root")
    plan = validate_plan(strict_load_json(plan_path, "plan"))
    record_bytes = canonical_json_bytes(plan["record"])
    old_umask = os.umask(0o077)
    created_root = False
    try:
        _mkdir_private(root)
        created_root = True
        _mkdir_private(root / "objects")
        _mkdir_private(root / "checkpoints")
        write_new_private(root / "record.json", record_bytes)
        write_new_private(root / "private-index.json", canonical_json_bytes(empty_private_index()))
        state = _initial_state(plan, sha256_bytes(record_bytes))
        write_new_private(root / "runner-state.json", canonical_json_bytes(state))
    except Exception:
        if created_root and root.exists() and root.is_dir() and not root.is_symlink():
            shutil.rmtree(root)
        raise
    finally:
        os.umask(old_umask)
    return {"run": str(root), "run_id": plan["run_id"], "state": "draft"}


def validate_state(state):
    require_keys(
        state,
        (
            "format",
            "context_kind",
            "run_id",
            "state",
            "sequence",
            "plan_sha256",
            "previous_checkpoint_digest",
            "checkpoint_refs",
            "record_digest_at_checkpoint",
            "active_case",
            "completed_cases",
        ),
        field="runner_state",
    )
    if state["format"] != STATE_FORMAT:
        raise RehearsalError("unsupported-format", "runner_state.format")
    if state["context_kind"] not in {"live", "fixture"}:
        raise RehearsalError("unknown-context-kind", "runner_state.context_kind")
    require_ref(state["run_id"], "runner_state.run_id")
    if state["state"] not in {
        "draft",
        "plan_frozen",
        "authorized_preflight",
        "case_armed",
        "case_observing",
        "case_sealed",
        "assessment_ready",
        "export_verified",
        "cleanup_recorded",
    }:
        raise RehearsalError("unknown-runner-state", "runner_state.state")
    require_nonnegative_int(state["sequence"], "runner_state.sequence")
    for key in ("plan_sha256", "previous_checkpoint_digest"):
        if state[key] is not None:
            require_sha256(state[key], "runner_state." + key)
    _refs(state["checkpoint_refs"], "runner_state.checkpoint_refs")
    require_sha256(state["record_digest_at_checkpoint"], "runner_state.record_digest_at_checkpoint")
    if state["active_case"] is not None:
        require_ref(state["active_case"], "runner_state.active_case")
    _refs(state["completed_cases"], "runner_state.completed_cases")
    return state


def load_state(run_root):
    path = Path(run_root) / "runner-state.json"
    _require_private_regular(path, "runner_state")
    return validate_state(strict_load_json(path, "runner_state"))


class RunLock:
    def __init__(self, run_root):
        self.path = Path(run_root) / ".runner.lock"
        self.descriptor = -1

    def __enter__(self):
        try:
            self.descriptor = os.open(
                str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
        except FileExistsError as error:
            raise RehearsalError("run-busy") from error
        os.write(self.descriptor, b"locked\n")
        os.fsync(self.descriptor)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.descriptor >= 0:
            os.close(self.descriptor)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def validate_checkpoint_input(value):
    require_keys(
        value,
        (
            "format",
            "checkpoint_id",
            "transition",
            "expected_previous_digest",
            "at_utc",
            "actor_ref",
            "case_id",
            "evidence_refs",
            "details",
        ),
        field="checkpoint",
    )
    if value["format"] != CHECKPOINT_FORMAT:
        raise RehearsalError("unsupported-format", "checkpoint.format")
    require_ref(value["checkpoint_id"], "checkpoint.checkpoint_id")
    transitions = {
        "freeze_plan",
        "record_authorization",
        "arm_case",
        "begin_case",
        "skip_case",
        "seal_case",
        "ready_assessment",
        "verify_export",
        "record_cleanup",
    }
    if value["transition"] not in transitions:
        raise RehearsalError("unknown-transition", "checkpoint.transition")
    if value["expected_previous_digest"] is not None:
        require_sha256(value["expected_previous_digest"], "checkpoint.expected_previous_digest")
    require_utc(value["at_utc"], "checkpoint.at_utc")
    require_ref(value["actor_ref"], "checkpoint.actor_ref")
    if value["case_id"] is not None:
        require_ref(value["case_id"], "checkpoint.case_id")
    _refs(value["evidence_refs"], "checkpoint.evidence_refs")
    details = value["details"]
    transition = value["transition"]
    if transition in {"freeze_plan", "record_authorization", "begin_case", "seal_case", "ready_assessment"}:
        require_keys(details, (), field="checkpoint.details")
    elif transition == "arm_case":
        require_keys(details, ("intervention_action",), field="checkpoint.details")
        require_ref(details["intervention_action"], "checkpoint.details.intervention_action")
    elif transition == "skip_case":
        require_keys(details, ("skip_reason",), field="checkpoint.details")
        require_string(details["skip_reason"], "checkpoint.details.skip_reason", limit=2048)
    elif transition == "verify_export":
        require_keys(details, ("destination", "manifest_sha256"), field="checkpoint.details")
        destination = require_string(details["destination"], "checkpoint.details.destination", limit=4096)
        if not Path(destination).is_absolute():
            raise RehearsalError("absolute-path-required", "checkpoint.details.destination")
        require_sha256(details["manifest_sha256"], "checkpoint.details.manifest_sha256")
    else:
        require_keys(
            details,
            (
                "terminal_handling_result",
                "participants_unbound_result",
                "adapters_closed_result",
                "dialogue_result",
                "detached_capture_result",
                "retained_evidence_result",
            ),
            field="checkpoint.details",
        )
        for key in details:
            _result(details[key], "checkpoint.details." + key)
    return value


def _transition_state(state, checkpoint, record, run_root):
    transition = checkpoint["transition"]
    current = state["state"]
    case_id = checkpoint["case_id"]
    expected_states = {
        "freeze_plan": {"draft"},
        "record_authorization": {"plan_frozen"},
        "arm_case": {"authorized_preflight", "case_sealed"},
        "begin_case": {"case_armed"},
        "skip_case": {"authorized_preflight", "case_sealed"},
        "seal_case": {"case_observing"},
        "ready_assessment": {"case_sealed"},
        "verify_export": {"assessment_ready"},
        "record_cleanup": {"export_verified"},
    }
    if current not in expected_states[transition]:
        raise RehearsalError("invalid-transition", "checkpoint.transition")
    if transition != "freeze_plan":
        frozen = canonical_json_bytes(frozen_projection(record))
        if sha256_bytes(frozen) != state["plan_sha256"]:
            raise RehearsalError("frozen-plan-changed")
    if transition == "freeze_plan":
        projection = canonical_json_bytes(frozen_projection(record))
        plan_path = Path(run_root) / "frozen-plan.json"
        if plan_path.exists():
            _require_private_regular(plan_path, "frozen_plan")
            if plan_path.read_bytes() != projection:
                raise RehearsalError("frozen-plan-conflict")
        state["plan_sha256"] = sha256_bytes(projection)
        state["state"] = "plan_frozen"
    elif transition == "record_authorization":
        _validate_authorization(record["authorization"])
        _validate_isolation(record["isolation"])
        if record["retention"]["approved_by"] is None:
            raise RehearsalError("retention-authorization-required")
        state["state"] = "authorized_preflight"
    elif transition == "arm_case":
        if case_id is None:
            raise RehearsalError("case-id-required", "checkpoint.case_id")
        cases = {
            case["case_id"]: case
            for gate in record["gates"]
            for case in gate["cases"]
        }
        if case_id not in cases or case_id in state["completed_cases"]:
            raise RehearsalError("unknown-or-completed-case", "checkpoint.case_id")
        case = cases[case_id]
        allowed = record["authorization"]["allowed_interventions"]
        action = checkpoint["details"]["intervention_action"]
        if not any(action == item["action"] and case_id in item["case_ids"] for item in allowed):
            raise RehearsalError("intervention-outside-authorization")
        if record["isolation"]["kind"] != "dedicated_account" and record["tier"] == "recovery":
            raise RehearsalError("dedicated-account-required")
        for key in ("installed_compatibility", "loaded_component_identities"):
            if record["preflight"][key]["result"] != "pass":
                raise RehearsalError("required-preflight-unavailable", "preflight." + key)
        readiness = {
            item["seat_ref"]: item["result"]
            for item in record["preflight"]["exact_seat_readiness"]
        }
        if any(readiness.get(seat) != "pass" for seat in case["targets"]["seat_refs"]):
            raise RehearsalError("target-seat-not-ready", "checkpoint.case_id")
        if case["required"] and case["observer"]["completeness_result"] != "pass":
            raise RehearsalError("required-observer-unqualified", "checkpoint.case_id")
        verified = verify_evidence(run_root, record["evidence"])
        known_refs = {item["ref"] for item in verified["index"]["items"]}
        armed_refs = set(case["precondition_evidence_refs"])
        armed_refs.update(case["observer"]["validation_evidence_refs"])
        if not armed_refs.issubset(known_refs):
            raise RehearsalError("armed-evidence-reference-unavailable")
        state["active_case"] = case_id
        state["state"] = "case_armed"
    elif transition == "begin_case":
        if case_id != state["active_case"] or record["record_kind"] != "run":
            raise RehearsalError("armed-run-case-required")
        validate_record_structure(record)
        active = next(
            case
            for gate in record["gates"]
            for case in gate["cases"]
            if case["case_id"] == case_id
        )
        if active["observed"]["common"]["attempted"] or active["result"] != "unobserved":
            raise RehearsalError("historical-observation-before-attempt", "case.%s" % case_id)
        state["state"] = "case_observing"
    elif transition == "skip_case":
        if case_id is None:
            raise RehearsalError("case-id-required", "checkpoint.case_id")
        matches = [
            (gate["gate_id"], case)
            for gate in record["gates"]
            for case in gate["cases"]
            if case["case_id"] == case_id
        ]
        if len(matches) != 1 or case_id in state["completed_cases"]:
            raise RehearsalError("unknown-or-completed-case", "checkpoint.case_id")
        gate_id, case = matches[0]
        if case["skip_reason"] != checkpoint["details"]["skip_reason"]:
            raise RehearsalError("skip-reason-mismatch", "checkpoint.details.skip_reason")
        decision = evaluate_case(case, gate_id, context_kind=state["context_kind"])
        if case["result"] != decision["result"] or case["rationale"] != decision["reason"]:
            raise RehearsalError("stored-case-result-inconsistent", "case.%s" % case_id)
        state["completed_cases"].append(case_id)
        state["state"] = "case_sealed"
    elif transition == "seal_case":
        if case_id != state["active_case"]:
            raise RehearsalError("active-case-mismatch")
        validate_record_structure(record)
        verified = verify_evidence(run_root, record["evidence"])
        gate = next(
            gate for gate in record["gates"] if any(case["case_id"] == case_id for case in gate["cases"])
        )
        case = next(case for case in gate["cases"] if case["case_id"] == case_id)
        decision = evaluate_case(
            case,
            gate["gate_id"],
            run_root=run_root,
            context_kind=state["context_kind"],
            verified_index=verified["index"],
        )
        if case["result"] != decision["result"] or case["rationale"] != decision["reason"]:
            raise RehearsalError("stored-case-result-inconsistent", "case.%s" % case_id)
        state["completed_cases"].append(case_id)
        state["active_case"] = None
        state["state"] = "case_sealed"
    elif transition == "ready_assessment":
        required = {item["case_id"] for item in record["declared_plan"]["required_cases"]}
        if not required.issubset(set(state["completed_cases"])):
            raise RehearsalError("required-cases-not-sealed")
        verified = verify_evidence(run_root, record["evidence"])
        assess_record(
            record,
            run_root=run_root,
            context_kind=state["context_kind"],
            verified_index=verified["index"],
        )
        state["state"] = "assessment_ready"
    elif transition == "verify_export":
        destination = Path(checkpoint["details"]["destination"])
        manifest = destination / "export-manifest.json"
        try:
            data = manifest.read_bytes()
        except OSError as error:
            raise RehearsalError("export-manifest-unavailable") from error
        if sha256_bytes(data) != checkpoint["details"]["manifest_sha256"]:
            raise RehearsalError("export-manifest-hash-mismatch")
        validate_export(destination)
        state["state"] = "export_verified"
    else:
        if record["cleanup"]["exports_verified_utc"] is None:
            raise RehearsalError("export-verification-must-precede-cleanup")
        details = checkpoint["details"]
        if details["dialogue_result"] == "pass" and (
            details["terminal_handling_result"] != "pass"
            or details["participants_unbound_result"] != "pass"
        ):
            raise RehearsalError("terminal-handling-and-unbind-must-precede-deletion")
        if details["adapters_closed_result"] == "pass" and details[
            "participants_unbound_result"
        ] != "pass":
            raise RehearsalError("unbind-must-precede-adapter-closure")
        if details["dialogue_result"] != record["cleanup"]["dialogue_deletion"][
            "result"
        ]:
            raise RehearsalError("cleanup-record-mismatch", "dialogue_result")
        if details["detached_capture_result"] != record["cleanup"][
            "detached_capture_deletion"
        ]["result"]:
            raise RehearsalError("cleanup-record-mismatch", "detached_capture_result")
        if details["dialogue_result"] == "pass" and details["detached_capture_result"] == "unobserved":
            # Allowed as pending, but it is never treated as detached cleanup.
            pass
        state["state"] = "cleanup_recorded"
    return state


def checkpoint_run(run_root, checkpoint_value, preview=False):
    run_root = Path(run_root)
    checkpoint_value = validate_checkpoint_input(checkpoint_value)
    state = load_state(run_root)
    _require_private_regular(run_root / "record.json", "record")
    record_bytes = (run_root / "record.json").read_bytes()
    record = strict_load_json(run_root / "record.json", "record")
    checkpoint_bytes = canonical_json_bytes(checkpoint_value)
    digest = sha256_bytes(checkpoint_bytes)
    if (
        state["previous_checkpoint_digest"] == digest
        and state["checkpoint_refs"]
        and state["checkpoint_refs"][-1] == checkpoint_value["checkpoint_id"]
    ):
        checkpoint_path = (
            run_root / "checkpoints" / (checkpoint_value["checkpoint_id"] + ".json")
        )
        _require_private_regular(checkpoint_path, "checkpoint")
        if checkpoint_path.read_bytes() != checkpoint_bytes:
            raise RehearsalError("checkpoint-id-conflict")
        return {"preview": preview, "state": state, "idempotent": True}
    if checkpoint_value["expected_previous_digest"] != state["previous_checkpoint_digest"]:
        raise RehearsalError("stale-previous-checkpoint-digest")
    if checkpoint_value["evidence_refs"]:
        known = {item["ref"] for item in load_private_index(run_root)["items"]}
        if not set(checkpoint_value["evidence_refs"]).issubset(known):
            raise RehearsalError("dangling-evidence-reference", "checkpoint.evidence_refs")
    candidate = copy.deepcopy(state)
    candidate = _transition_state(candidate, checkpoint_value, record, run_root)
    candidate["sequence"] += 1
    candidate["previous_checkpoint_digest"] = digest
    candidate["checkpoint_refs"].append(checkpoint_value["checkpoint_id"])
    candidate["record_digest_at_checkpoint"] = sha256_bytes(record_bytes)
    validate_state(candidate)
    if preview:
        return {"preview": True, "state": candidate}
    with RunLock(run_root):
        current = load_state(run_root)
        if current != state:
            raise RehearsalError("runner-state-changed")
        _require_private_regular(run_root / "record.json", "record")
        if (run_root / "record.json").read_bytes() != record_bytes:
            raise RehearsalError("runner-record-changed")
        checkpoint_path = run_root / "checkpoints" / (checkpoint_value["checkpoint_id"] + ".json")
        if checkpoint_path.exists():
            _require_private_regular(checkpoint_path, "checkpoint")
            if checkpoint_path.read_bytes() != checkpoint_bytes:
                raise RehearsalError("checkpoint-id-conflict")
        else:
            write_new_private(checkpoint_path, checkpoint_bytes)
        if checkpoint_value["transition"] == "freeze_plan":
            frozen_path = run_root / "frozen-plan.json"
            frozen_bytes = canonical_json_bytes(frozen_projection(record))
            if frozen_path.exists():
                _require_private_regular(frozen_path, "frozen_plan")
                if frozen_path.read_bytes() != frozen_bytes:
                    raise RehearsalError("frozen-plan-conflict")
            else:
                write_new_private(frozen_path, frozen_bytes)
        atomic_write_private(run_root / "runner-state.json", canonical_json_bytes(candidate))
    return {"preview": False, "state": candidate}


def import_run_evidence(run_root, spec):
    spec = validate_import_spec(spec)
    state = load_state(run_root)
    if state["context_kind"] == "live" and any(
        item["classification"] == "private_capture" for item in spec["items"]
    ):
        if state["state"] not in {
            "authorized_preflight",
            "case_armed",
            "case_observing",
            "case_sealed",
        }:
            raise RehearsalError("authorization-must-precede-private-live-capture")
        record = strict_load_json(Path(run_root) / "record.json", "record")
        retention = record.get("retention")
        if not isinstance(retention, dict) or retention.get("approved_by") is None:
            raise RehearsalError("retention-authorization-required")
    with RunLock(run_root):
        return import_evidence(run_root, spec)


FIXTURE_EXPORT_LIMITATION = (
    "Synthetic runner fixture; this artifact records no live receiving-runtime event."
)


def _redacted_record(record, context_kind="live"):
    # Structure validation has already rejected unknown keys; this copy cannot
    # accidentally pass private-index fields through.
    projected = copy.deepcopy(record)
    if context_kind == "fixture":
        projected["limitations"] = sorted(
            set(projected["limitations"] + [FIXTURE_EXPORT_LIMITATION])
        )
    return projected


def deterministic_summary(record, assessment, context_kind="live"):
    gates = []
    for gate in assessment["gates"]:
        gates.append(
            {
                "gate_id": gate["gate_id"],
                "result": gate["result"],
                "cases": [
                    {
                        "case_id": case["case_id"],
                        "required": case["required"],
                        "result": case["result"],
                        "reason": case["reason"],
                    }
                    for case in gate["cases"]
                ],
            }
        )
    summary = {
        "format": (
            "rehearsal-fixture-summary/v1"
            if context_kind == "fixture"
            else "rehearsal-summary/v1"
        ),
        "contract": CONTRACT,
        "run_id": record["run_id"],
        "claim": copy.deepcopy(record["claim"]),
        "result": assessment["result"],
        "gates": gates,
        "limitations": sorted(record["limitations"]),
        "support_gaps": [
            "production-g3-completeness-requires-reviewed-real-capture-qualification",
            "g4-live-interruption-boundary-requires-separately-authorized-evidence",
        ],
    }
    if context_kind == "fixture":
        summary["context_kind"] = "fixture"
        summary["proof_eligible"] = False
        summary["limitations"] = sorted(
            set(summary["limitations"] + [FIXTURE_EXPORT_LIMITATION])
        )
    return summary


def export_run(
    run_root,
    destination,
    private_refs=(),
    allow_fixture_artifacts=False,
):
    run_root = Path(run_root)
    destination = Path(destination)
    if not destination.is_absolute():
        raise RehearsalError("absolute-path-required", "destination")
    if _inside_repository(destination):
        raise RehearsalError("export-inside-repository", "destination")
    if destination.exists() or destination.is_symlink():
        raise RehearsalError("exclusive-export-destination-required", "destination")
    try:
        parent_info = destination.parent.lstat()
    except OSError as error:
        raise RehearsalError("export-parent-unavailable", "destination") from error
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise RehearsalError("export-parent-invalid", "destination")
    state = load_state(run_root)
    if state["state"] != "assessment_ready":
        raise RehearsalError("assessment-ready-required")
    context_kind = state["context_kind"]
    if context_kind == "fixture" and not allow_fixture_artifacts:
        raise RehearsalError("fixture-context-cannot-export-live-proof")
    if context_kind == "live" and allow_fixture_artifacts:
        raise RehearsalError("fixture-artifacts-require-fixture-context")
    record = strict_load_json(run_root / "record.json", "record")
    verified = verify_evidence(run_root, record["evidence"])
    assessment = assess_record(
        record,
        run_root=run_root,
        context_kind=context_kind,
        verified_index=verified["index"],
    )
    public_record = _redacted_record(record, context_kind=context_kind)
    record_bytes = canonical_json_bytes(public_record)
    summary_bytes = canonical_json_bytes(
        deterministic_summary(record, assessment, context_kind=context_kind)
    )
    index = verified["index"]
    assert_no_private_markers(record_bytes, index)
    assert_no_private_markers(summary_bytes, index)
    selected = list(private_refs)
    require_unique(selected, "private_refs")
    by_ref = {item["ref"]: item for item in index["items"]}
    for reference in selected:
        require_ref(reference, "private_refs")
        if reference not in by_ref:
            raise RehearsalError("dangling-evidence-reference", "private_refs")
    parent = destination.parent
    temporary = Path(tempfile.mkdtemp(prefix=".%s." % destination.name, dir=str(parent)))
    os.chmod(str(temporary), 0o700)
    try:
        record_name = (
            "fixture-record.json" if context_kind == "fixture" else "run-record.json"
        )
        record_key = "fixture_record" if context_kind == "fixture" else "run_record"
        write_new_private(temporary / record_name, record_bytes)
        write_new_private(temporary / "summary.json", summary_bytes)
        private_manifest = []
        if selected:
            _mkdir_private(temporary / "private")
        for reference in sorted(selected):
            item = by_ref[reference]
            source = run_root / "objects" / item["object_name"]
            target = temporary / "private" / reference
            data = source.read_bytes()
            if sha256_bytes(data) != item["sha256"] or len(data) != item["bytes"]:
                raise RehearsalError("evidence-changed-before-export", "private_refs")
            write_new_private(target, data)
            private_manifest.append(
                {"ref": reference, "sha256": item["sha256"], "bytes": item["bytes"]}
            )
        manifest = {
            "format": (
                FIXTURE_EXPORT_FORMAT if context_kind == "fixture" else EXPORT_FORMAT
            ),
            "run_id": record["run_id"],
            record_key: {
                "sha256": sha256_bytes(record_bytes),
                "bytes": len(record_bytes),
            },
            "summary": {"sha256": sha256_bytes(summary_bytes), "bytes": len(summary_bytes)},
            "private_objects": private_manifest,
        }
        if context_kind == "fixture":
            manifest["proof_eligible"] = False
        manifest_bytes = canonical_json_bytes(manifest)
        assert_no_private_markers(manifest_bytes, index)
        write_new_private(temporary / "export-manifest.json", manifest_bytes)
        os.rename(str(temporary), str(destination))
        directory_fd = os.open(str(parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    validate_export(destination)
    return {
        "destination": str(destination),
        "manifest_sha256": sha256_bytes((destination / "export-manifest.json").read_bytes()),
        "record_valid": True,
        "claim": copy.deepcopy(record["claim"]),
        "result": assessment["result"],
        "context_kind": context_kind,
        "proof_eligible": context_kind == "live",
    }


def validate_export(destination):
    destination = Path(destination)
    info = destination.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise RehearsalError("unsafe-export-directory")
    _require_private_regular(destination / "export-manifest.json", "export_manifest")
    manifest = strict_load_json(destination / "export-manifest.json", "export_manifest")
    if not isinstance(manifest, dict):
        raise RehearsalError("object-required", "export_manifest")
    if manifest.get("format") == EXPORT_FORMAT:
        require_keys(
            manifest,
            ("format", "run_id", "run_record", "summary", "private_objects"),
            field="export_manifest",
        )
        record_key = "run_record"
        record_name = "run-record.json"
    elif manifest.get("format") == FIXTURE_EXPORT_FORMAT:
        require_keys(
            manifest,
            (
                "format",
                "run_id",
                "fixture_record",
                "summary",
                "private_objects",
                "proof_eligible",
            ),
            field="export_manifest",
        )
        if manifest["proof_eligible"] is not False:
            raise RehearsalError("fixture-export-cannot-be-proof-eligible")
        record_key = "fixture_record"
        record_name = "fixture-record.json"
    else:
        raise RehearsalError("unsupported-format", "export_manifest.format")
    require_ref(manifest["run_id"], "export_manifest.run_id")
    for name, filename in ((record_key, record_name), ("summary", "summary.json")):
        item = require_keys(manifest[name], ("sha256", "bytes"), field="export_manifest." + name)
        require_sha256(item["sha256"], "export_manifest.%s.sha256" % name)
        require_nonnegative_int(item["bytes"], "export_manifest.%s.bytes" % name)
        path = destination / filename
        data = path.read_bytes()
        if len(data) != item["bytes"] or sha256_bytes(data) != item["sha256"]:
            raise RehearsalError("export-object-mismatch", name)
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise RehearsalError("unsafe-file-mode", name)
    if manifest["format"] == FIXTURE_EXPORT_FORMAT:
        fixture_record = strict_load_json(
            destination / "fixture-record.json", "fixture_record"
        )
        fixture_summary = strict_load_json(destination / "summary.json", "summary")
        if not isinstance(fixture_record, dict) or not isinstance(fixture_summary, dict):
            raise RehearsalError("object-required", "fixture_export")
        if FIXTURE_EXPORT_LIMITATION not in fixture_record.get("limitations", []):
            raise RehearsalError("fixture-export-marker-missing", "fixture_record")
        if (
            fixture_summary.get("format") != "rehearsal-fixture-summary/v1"
            or fixture_summary.get("context_kind") != "fixture"
            or fixture_summary.get("proof_eligible") is not False
        ):
            raise RehearsalError("fixture-export-marker-missing", "summary")
    private_items = require_list(manifest["private_objects"], "export_manifest.private_objects", MAX_EVIDENCE_ITEMS)
    refs = []
    for position, item in enumerate(private_items):
        field = "export_manifest.private_objects[%d]" % position
        require_keys(item, ("ref", "sha256", "bytes"), field=field)
        reference = require_ref(item["ref"], field + ".ref")
        refs.append(reference)
        require_sha256(item["sha256"], field + ".sha256")
        require_nonnegative_int(item["bytes"], field + ".bytes")
        path = destination / "private" / reference
        data = path.read_bytes()
        if len(data) != item["bytes"] or sha256_bytes(data) != item["sha256"]:
            raise RehearsalError("export-object-mismatch", reference)
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise RehearsalError("unsafe-file-mode", reference)
    require_unique(refs, "export_manifest.private_objects.ref")
    return manifest


def _print_json(value):
    sys.stdout.buffer.write(canonical_json_bytes(value))


def _parser():
    parser = argparse.ArgumentParser(
        description="File-only council live-rehearsal record and evidence assistant."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    init_parser = commands.add_parser("init", help="create an exclusive private run root")
    init_parser.add_argument("--private-root", required=True)
    init_parser.add_argument("--plan", required=True)
    checkpoint_parser = commands.add_parser("checkpoint", help="validate or record one checkpoint")
    checkpoint_parser.add_argument("--run", required=True)
    checkpoint_parser.add_argument("--input", required=True)
    checkpoint_parser.add_argument("--preview", action="store_true")
    import_parser = commands.add_parser("import-evidence", help="copy a prepared allowlisted bundle")
    import_parser.add_argument("--run", required=True)
    import_parser.add_argument("--input", required=True)
    validate_parser = commands.add_parser("validate", help="validate record and evidence integrity")
    validate_parser.add_argument("--run", required=True)
    assess_parser = commands.add_parser("assess", help="compute the declared claim result")
    assess_parser.add_argument("--run", required=True)
    export_parser = commands.add_parser("export", help="create an exclusive reviewed export candidate")
    export_parser.add_argument("--run", required=True)
    export_parser.add_argument("--destination", required=True)
    export_parser.add_argument("--include-private", action="append", default=[])
    export_parser.add_argument(
        "--fixture-artifacts",
        action="store_true",
        help="export a fixture-labeled, proof-ineligible artifact set",
    )
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        if args.command == "init":
            report = {
                "record_valid": None,
                "claim": None,
                "result": "initialized",
                "initialization": init_run(args.private_root, args.plan),
            }
            exit_code = 0
        elif args.command == "checkpoint":
            value = strict_load_json(args.input, "checkpoint")
            report = {
                "record_valid": None,
                "claim": None,
                "result": "checkpoint-preview" if args.preview else "checkpoint-recorded",
                "checkpoint": checkpoint_run(args.run, value, preview=args.preview),
            }
            exit_code = 0
        elif args.command == "import-evidence":
            value = strict_load_json(args.input, "import")
            report = {
                "record_valid": None,
                "claim": None,
                "result": "evidence-imported",
                "imported": import_run_evidence(args.run, value),
            }
            exit_code = 0
        elif args.command == "validate":
            report = validate_run(args.run, assess=False)
            exit_code = 0
        elif args.command == "assess":
            report = validate_run(args.run, assess=True)
            exit_code = 0 if report["result"] == "pass" else 1
        else:
            report = export_run(
                args.run,
                args.destination,
                args.include_private,
                allow_fixture_artifacts=args.fixture_artifacts,
            )
            exit_code = 0
        _print_json(report)
        return exit_code
    except (EvidenceError, RehearsalError, OSError, ValueError) as error:
        safe = _convert_error(error)
        report = {
            "record_valid": False,
            "claim": None,
            "result": "unusable",
            "error": {"code": safe.code, "field": safe.field},
        }
        if args.command in {"validate", "assess"}:
            report["verified_contradictions"] = scan_verified_g3_contradictions(args.run)
        _print_json(report)
        return 2


if __name__ == "__main__":
    sys.exit(main())
