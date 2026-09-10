#!/usr/bin/env python3
"""Independent record, gate, checkpoint, export, and side-effect tests."""

import ast
import copy
import itertools
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import council_rehearsal as rehearsal
import rehearsal_evidence as evidence
from council_rehearsal import RehearsalError


FIXTURES = Path(__file__).parent / "fixtures" / "live_rehearsal"
SCRIPT = Path(__file__).parent / "council_rehearsal.py"
WALKTHROUGH = (
    Path(__file__).parent.parent
    / "examples"
    / "live-rehearsal"
    / "core-walkthrough"
    / "walkthrough.py"
)
RECORD_TEMPLATE = (
    Path(__file__).parent.parent
    / "examples"
    / "live-rehearsal"
    / "run-record.template.json"
)


def literal_json(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def write_json(path, value):
    path.write_bytes(evidence.canonical_json_bytes(value))
    os.chmod(path, 0o600)


def replace_ref(node, old, new):
    if isinstance(node, dict):
        return {key: replace_ref(value, old, new) for key, value in node.items()}
    if isinstance(node, list):
        return [replace_ref(value, old, new) for value in node]
    return new if node == old else node


def common_observation(**updates):
    value = {
        "attempted": True,
        "preconditions_result": "pass",
        "harness_result": "pass",
        "actual_start_utc": "2026-09-08T20:00:00Z",
        "intervention_utc": "2026-09-08T20:01:00Z",
        "recovery_utc": "2026-09-08T20:03:00Z",
        "actual_end_utc": "2026-09-08T20:09:00Z",
        "coverage_result": "pass",
        "coverage_limitation": None,
        "deadline_met": True,
    }
    value.update(updates)
    return value


def passing_control():
    return {
        "control_id": "control-one",
        "actor_ref": "maintainer-one",
        "kind": "observer_fixture",
        "expected": {"outcome": "reject-invalid"},
        "observed": {"outcome": "reject-invalid"},
        "result": "pass",
        "evidence_refs": ["ev-a"],
        "rationale": "control-observed-expected-outcome",
    }


def evaluator_case(gate_id, chain, expected_chain=None):
    return {
        "case_id": "case-" + gate_id.lower(),
        "applicable": True,
        "skip_reason": None,
        "targets": {"envelope_ref": "envelope-target"},
        "observed": {"common": common_observation(), "chain": chain},
        "expected": {"chain": expected_chain or {}},
        "observer": {"completeness_result": "pass"},
        "controls": [passing_control()],
    }


class RecordValidationTests(unittest.TestCase):
    def setUp(self):
        self.record = literal_json("named-g1-pass.fixture.json")

    def test_literal_limited_run_validates_and_is_order_deterministic(self):
        rehearsal.validate_record_structure(self.record)
        first = evidence.canonical_json_bytes(rehearsal.assess_record(self.record))
        reordered = copy.deepcopy(self.record)
        reordered["gates"].reverse()
        second = evidence.canonical_json_bytes(rehearsal.assess_record(reordered))
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["result"], "pass")

    def test_strict_malformed_records_refuse_exact_rules(self):
        mutations = []
        changed = copy.deepcopy(self.record)
        changed["future"] = True
        mutations.append(changed)
        changed = copy.deepcopy(self.record)
        changed["case_template"] = {}
        mutations.append(changed)
        changed = copy.deepcopy(self.record)
        changed["evidence"][0]["sha256"] = "A" * 64
        mutations.append(changed)
        changed = copy.deepcopy(self.record)
        changed["created_utc"] = "2026-09-08T20:00:00-04:00"
        mutations.append(changed)
        changed = copy.deepcopy(self.record)
        changed["gates"][0]["cases"][0]["expected"]["chain"]["router_cadence_seconds"] = True
        mutations.append(changed)
        for position, item in enumerate(mutations):
            with self.subTest(position=position), self.assertRaises(ValueError):
                rehearsal.validate_record_structure(item)

    def test_missing_duplicate_dangling_and_declared_target_refuse(self):
        changed = copy.deepcopy(self.record)
        changed["gates"][0]["cases"] = []
        with self.assertRaisesRegex(RehearsalError, "missing-required-case"):
            rehearsal.validate_record_structure(changed)
        changed = copy.deepcopy(self.record)
        changed["gates"][0]["cases"].append(copy.deepcopy(changed["gates"][0]["cases"][0]))
        with self.assertRaisesRegex(evidence.EvidenceError, "duplicate-value"):
            rehearsal.validate_record_structure(changed)
        changed = copy.deepcopy(self.record)
        changed["gates"][0]["cases"][0]["evidence_refs"] = ["ev-missing"]
        with self.assertRaisesRegex(RehearsalError, "dangling-evidence-reference"):
            rehearsal.validate_record_structure(changed)
        changed = copy.deepcopy(self.record)
        changed["declared_plan"]["required_cases"][0]["seat_refs"] = ["seat-other"]
        with self.assertRaises(ValueError):
            rehearsal.validate_record_structure(changed)

    def test_null_unknown_needs_field_specific_limitation(self):
        changed = copy.deepcopy(self.record)
        changed["tested_tuple"]["os"]["build"] = None
        with self.assertRaisesRegex(RehearsalError, "field-specific-limitation-required"):
            rehearsal.validate_record_structure(changed)
        changed["limitations"].append("tested_tuple.os.build: fixture intentionally unknown")
        rehearsal.validate_record_structure(changed)

    def test_source_commit_and_tree_accept_git_sha1_or_sha256_only(self):
        changed = copy.deepcopy(self.record)
        changed["tested_tuple"]["source_commit"] = "a" * 40
        changed["tested_tuple"]["source_tree"] = "b" * 40
        rehearsal.validate_record_structure(changed)
        changed["tested_tuple"]["source_commit"] = "a" * 39
        with self.assertRaisesRegex(RehearsalError, "invalid-source-object-id"):
            rehearsal.validate_record_structure(changed)

    def test_hand_edited_results_and_rationale_refuse(self):
        mutators = (
            lambda item: item["gates"][0]["cases"][0].update(result="fail"),
            lambda item: item["gates"][0].update(result="fail"),
            lambda item: item.update(overall_result="fail"),
            lambda item: item["gates"][0]["cases"][0]["controls"][0].update(result="fail"),
            lambda item: item["gates"][0]["cases"][0].update(rationale="edited"),
        )
        for position, mutate in enumerate(mutators):
            changed = copy.deepcopy(self.record)
            mutate(changed)
            with self.subTest(position=position), self.assertRaises(ValueError):
                rehearsal.assess_record(changed)

    def test_verified_g3_duplicate_survives_unrelated_record_invalidity(self):
        with tempfile.TemporaryDirectory(prefix="rehearsal-duplicate-") as temporary:
            root = Path(temporary) / "run"
            root.mkdir(mode=0o700)
            (root / "objects").mkdir(mode=0o700)
            write_json(root / "private-index.json", evidence.empty_private_index())
            support_source = Path(temporary) / "support.bin"
            support_source.write_bytes(b"independent event verification")
            support = evidence.import_evidence(
                root,
                {
                    "format": "rehearsal-import/v1",
                    "collected_utc": "2026-09-08T20:00:00Z",
                    "items": [
                        {
                            "source": str(support_source),
                            "source_identity": "verification-source-fixture",
                            "classification": "private_capture",
                            "content_kind": "support_record",
                            "transformations": ["none"],
                            "qualification_refs": [],
                            "selection_scope": "test_dialogue",
                            "reviewed_safe": True,
                        }
                    ],
                },
            )[0]
            collector = literal_json("collector-result.fixture.json")
            support_ref = support["ref"]
            collector["collector_contract"]["evidence_ref"] = support_ref
            collector["implementation_evidence_ref"] = support_ref
            collector["source_refs"] = [support_ref]
            collector["inventory_ref"] = support_ref
            collector["coverage_ref"] = support_ref
            collector["transform_ledger"][0]["input_refs"] = [support_ref]
            for event in collector["events"]:
                event["source_ref"] = support_ref
                event["capture_refs"] = [support_ref]
                event["verification_refs"] = [support_ref]
            duplicate = copy.deepcopy(collector["events"][0])
            duplicate.update(
                native_event_id="native-two",
                projection_id="projection-two",
                native_record_key="record-two",
                byte_offset=900,
            )
            collector["events"].append(duplicate)
            source = Path(temporary) / "collector.json"
            write_json(source, collector)
            imported = evidence.import_evidence(
                root,
                {
                    "format": "rehearsal-import/v1",
                    "collected_utc": "2026-09-08T20:00:00Z",
                    "items": [
                        {
                            "source": str(source),
                            "source_identity": "private-session-fixture",
                            "classification": "private_capture",
                            "content_kind": "collector_result",
                            "transformations": ["normalize_collector_result"],
                            "qualification_refs": [],
                            "selection_scope": "test_dialogue",
                            "reviewed_safe": True,
                        }
                    ],
                },
            )[0]
            invalid_record = {
                "future_unknown_field": True,
                "gates": [
                    {
                        "gate_id": "G3",
                        "cases": [
                            {
                                "case_id": "case-g3",
                                "expected": {"chain": {"expected_count": 1}},
                                "observed": {
                                    "chain": {"collector_result_ref": imported["ref"]}
                                },
                            }
                        ],
                    }
                ],
            }
            write_json(root / "record.json", invalid_record)
            diagnostics = rehearsal.scan_verified_g3_contradictions(root)
            self.assertEqual(diagnostics[0]["verified_lower_bound"], 2)
            self.assertEqual(diagnostics[0]["expected_count"], 1)


class TemplateScaffoldTests(unittest.TestCase):
    def setUp(self):
        self.template = json.loads(RECORD_TEMPLATE.read_text(encoding="utf-8"))
        self.literal_run = literal_json("named-g1-pass.fixture.json")

    def assert_same_keys(self, scaffold, literal):
        self.assertEqual(set(scaffold), set(literal))

    def test_template_fields_agree_with_independent_literal_record(self):
        rehearsal.validate_record_structure(self.template, allow_template=True)
        self.assertEqual(
            set(self.template) - {"case_template", "evidence_item_template"},
            set(self.literal_run),
        )
        for scaffold, literal in (
            (self.template["claim"], self.literal_run["claim"]),
            (self.template["authorization"], self.literal_run["authorization"]),
            (self.template["isolation"], self.literal_run["isolation"]),
            (self.template["tested_tuple"], self.literal_run["tested_tuple"]),
            (self.template["tested_tuple"]["os"], self.literal_run["tested_tuple"]["os"]),
            (
                self.template["tested_tuple"]["python"],
                self.literal_run["tested_tuple"]["python"],
            ),
            (
                self.template["tested_tuple"]["hosts"][0],
                self.literal_run["tested_tuple"]["hosts"][0],
            ),
            (self.template["preflight"], self.literal_run["preflight"]),
            (
                self.template["preflight"]["installed_compatibility"],
                self.literal_run["preflight"]["installed_compatibility"],
            ),
            (
                self.template["preflight"]["loaded_component_identities"],
                self.literal_run["preflight"]["loaded_component_identities"],
            ),
            (
                self.template["preflight"]["aggregate_restoration_health"],
                self.literal_run["preflight"]["aggregate_restoration_health"],
            ),
            (self.template["declared_plan"], self.literal_run["declared_plan"]),
            (self.template["gates"][0], self.literal_run["gates"][0]),
            (
                self.template["case_template"],
                self.literal_run["gates"][0]["cases"][0],
            ),
            (
                self.template["case_template"]["targets"],
                self.literal_run["gates"][0]["cases"][0]["targets"],
            ),
            (
                self.template["case_template"]["window"],
                self.literal_run["gates"][0]["cases"][0]["window"],
            ),
            (
                self.template["case_template"]["observer"],
                self.literal_run["gates"][0]["cases"][0]["observer"],
            ),
            (self.template["evidence_item_template"], self.literal_run["evidence"][0]),
            (self.template["retention"], self.literal_run["retention"]),
            (self.template["cleanup"], self.literal_run["cleanup"]),
        ):
            self.assert_same_keys(scaffold, literal)
        self.assertEqual(self.template["record_kind"], "template")
        self.assertEqual(self.template["overall_result"], "unobserved")
        self.assertIsNone(self.template["case_template"]["expected"])
        self.assertIsNone(self.template["case_template"]["observed"])
        self.assertEqual(self.template["preflight"]["exact_seat_readiness"], [])
        self.assertEqual([gate["gate_id"] for gate in self.template["gates"]], list(rehearsal.GATE_IDS))
        self.assertTrue(all(gate["cases"] == [] for gate in self.template["gates"]))

    def test_actual_init_accepts_template_and_freeze_refuses_unresolved_declaration(self):
        with tempfile.TemporaryDirectory(prefix="rehearsal-template-") as temporary:
            parent = Path(temporary)
            run_root = parent / "run"
            plan_path = parent / "plan.json"
            checkpoint_path = parent / "freeze.json"
            template = copy.deepcopy(self.template)
            template["run_id"] = "template-init-check"
            write_json(
                plan_path,
                {
                    "format": "rehearsal-plan/v1",
                    "context_kind": "fixture",
                    "run_id": "template-init-check",
                    "record": template,
                },
            )
            initialized = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "init",
                    "--private-root",
                    str(run_root),
                    "--plan",
                    str(plan_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            self.assertEqual(json.loads(initialized.stdout)["result"], "initialized")
            write_json(
                checkpoint_path,
                {
                    "format": "rehearsal-checkpoint/v1",
                    "checkpoint_id": "template-freeze-refusal",
                    "transition": "freeze_plan",
                    "expected_previous_digest": None,
                    "at_utc": "2026-09-10T06:30:00Z",
                    "actor_ref": "maintainer-one",
                    "case_id": None,
                    "evidence_refs": [],
                    "details": {},
                },
            )
            refused = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "checkpoint",
                    "--run",
                    str(run_root),
                    "--input",
                    str(checkpoint_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(refused.returncode, 2, refused.stderr)
            refusal = json.loads(refused.stdout)
            self.assertEqual(refusal["error"]["code"], "invalid-opaque-ref")
            self.assertEqual(refusal["error"]["field"], "record.operator_ref")
            self.assertEqual(rehearsal.load_state(run_root)["state"], "draft")
            self.assertFalse((run_root / "frozen-plan.json").exists())
            self.assertEqual(list((run_root / "checkpoints").iterdir()), [])


class C2PreflightEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rehearsal-c2-preflight-")
        self.root = Path(self.temporary.name) / "run"
        self.root.mkdir(mode=0o700)
        (self.root / "objects").mkdir(mode=0o700)
        write_json(self.root / "private-index.json", evidence.empty_private_index())
        self.c2_path = FIXTURES / "c2-lifecycle-evidence-v1.json"

    def tearDown(self):
        self.temporary.cleanup()

    def import_item(self, source, kind):
        spec = {
            "format": "rehearsal-import/v1",
            "collected_utc": "2026-09-08T20:00:00Z",
            "items": [
                {
                    "source": str(source),
                    "source_identity": "explicit-c2-fixture",
                    "classification": "redacted_record",
                    "content_kind": kind,
                    "transformations": ["none"],
                    "qualification_refs": [],
                    "selection_scope": "test_dialogue",
                    "reviewed_safe": True,
                }
            ],
        }
        return evidence.import_evidence(self.root, spec)[0]

    def record_for(self, imported):
        record = literal_json("named-g1-pass.fixture.json")
        record = replace_ref(record, "ev-a", imported["ref"])
        record["evidence"] = [imported]
        record["tested_tuple"].update(
            release_manifest_sha256=evidence.C2_RELEASE_MANIFEST_SHA256,
            package_id=evidence.C2_PACKAGE_ID,
            runtime_cohort=evidence.C2_RUNTIME_COHORT,
        )
        record["preflight"]["loaded_component_identities"] = {
            "result": "unobserved",
            "evidence_refs": [],
            "limitation": "C2 artifact evidence does not observe loaded host bytes.",
        }
        record["preflight"]["aggregate_restoration_health"] = {
            "result": "unobserved",
            "evidence_refs": [],
            "limitation": "C2 artifact evidence does not observe host restoration.",
        }
        record["preflight"]["exact_seat_readiness"][0].update(
            result="unobserved",
            evidence_refs=[],
            limitation="C2 artifact evidence does not authenticate a seat.",
        )
        return record

    def test_fixed_c2_record_supports_only_matching_installed_compatibility(self):
        imported = self.import_item(self.c2_path, "c2_lifecycle_evidence")
        record = self.record_for(imported)
        rehearsal.validate_record_structure(record)
        verified = evidence.verify_evidence(self.root, record["evidence"])
        rehearsal._live_preflight_evidence(
            record, self.root, "live", verified["index"]
        )

        for field, value in (
            ("release_manifest_sha256", "0" * 64),
            ("package_id", "1" * 64),
            ("runtime_cohort", "2" * 64),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(record)
                changed["tested_tuple"][field] = value
                with self.assertRaisesRegex(
                    RehearsalError, "fixed-c2-installed-evidence-required"
                ):
                    rehearsal._live_preflight_evidence(
                        changed, self.root, "live", verified["index"]
                    )

    def test_c2_record_cannot_promote_loaded_restoration_or_seat_claims(self):
        imported = self.import_item(self.c2_path, "c2_lifecycle_evidence")
        record = self.record_for(imported)
        verified = evidence.verify_evidence(self.root, record["evidence"])
        claims = (
            "loaded_component_identities",
            "aggregate_restoration_health",
            "exact_seat_readiness",
        )
        for name in claims:
            with self.subTest(claim=name):
                changed = copy.deepcopy(record)
                target = (
                    changed["preflight"]["exact_seat_readiness"][0]
                    if name == "exact_seat_readiness"
                    else changed["preflight"][name]
                )
                target.update(
                    result="pass", evidence_refs=[imported["ref"]], limitation=None
                )
                with self.assertRaisesRegex(
                    RehearsalError,
                    "c2-artifact-evidence-cannot-support-stronger-preflight",
                ):
                    rehearsal._live_preflight_evidence(
                        changed, self.root, "live", verified["index"]
                    )

    def test_generic_support_record_cannot_supply_live_installed_claim(self):
        source = Path(self.temporary.name) / "generic.json"
        source.write_text('{"self_declared":true}\n', encoding="utf-8")
        c2_imported = self.import_item(self.c2_path, "c2_lifecycle_evidence")
        imported = self.import_item(source, "support_record")
        record = self.record_for(c2_imported)
        record["evidence"].append(imported)
        record["preflight"]["installed_compatibility"]["evidence_refs"] = [
            imported["ref"]
        ]
        record["tested_tuple"]["artifact_identity_evidence_refs"] = [imported["ref"]]
        verified = evidence.verify_evidence(self.root, record["evidence"])
        with self.assertRaisesRegex(
            RehearsalError, "fixed-c2-installed-evidence-required"
        ):
            rehearsal._live_preflight_evidence(
                record, self.root, "live", verified["index"]
            )

        record["preflight"]["installed_compatibility"]["evidence_refs"] = [
            c2_imported["ref"]
        ]
        record["tested_tuple"]["artifact_identity_evidence_refs"] = [
            c2_imported["ref"]
        ]
        record["preflight"]["loaded_component_identities"].update(
            result="pass", evidence_refs=[imported["ref"]], limitation=None
        )
        with self.assertRaisesRegex(
            RehearsalError, "generic-support-record-cannot-support-live-preflight"
        ):
            rehearsal._live_preflight_evidence(
                record, self.root, "live", verified["index"]
            )


class GateDecisionTests(unittest.TestCase):
    def test_g1_chain_and_negative_controls(self):
        chain = {
            "notification_sent": True,
            "wake_received": True,
            "claim_succeeded": True,
            "task_match": True,
            "envelope_match": True,
            "manual_steering": False,
        }
        case = evaluator_case("G1", chain)
        self.assertEqual(rehearsal.evaluate_case(case, "G1")["result"], "pass")
        for key, value, expected in (
            ("wake_received", False, "unobserved"),
            ("task_match", False, "fail"),
            ("envelope_match", False, "fail"),
            ("manual_steering", True, "fail"),
        ):
            changed = copy.deepcopy(case)
            changed["observed"]["chain"][key] = value
            self.assertEqual(rehearsal.evaluate_case(changed, "G1")["result"], expected)

    def test_g2_chain_same_generation_roster_and_premature_advance(self):
        chain = {
            "generations_distinct": True,
            "same_dialogue_phase": True,
            "roster_unchanged": True,
            "accepted_responses_retained": True,
            "withheld_pending": True,
            "premature_advance": False,
            "premature_disclosure": False,
            "missing_response_submitted": True,
            "advance_count": 1,
            "participant_request_emitted": True,
            "surviving_relays_available": True,
            "rebind_authenticated": True,
            "restore_errors_accounted": True,
        }
        case = evaluator_case("G2", chain)
        self.assertEqual(rehearsal.evaluate_case(case, "G2")["result"], "pass")
        failures = {
            "generations_distinct": False,
            "same_dialogue_phase": False,
            "roster_unchanged": False,
            "accepted_responses_retained": False,
            "premature_advance": True,
            "premature_disclosure": True,
            "advance_count": 2,
        }
        for key, value in failures.items():
            changed = copy.deepcopy(case)
            changed["observed"]["chain"][key] = value
            self.assertEqual(rehearsal.evaluate_case(changed, "G2")["result"], "fail")

    def test_g3_qualification_fresh_control_and_duplicate_lower_bound(self):
        result = literal_json("collector-result.fixture.json")
        qualification = literal_json("collector-qualification.fixture.json")
        expected = {
            "variant": "surviving_relay",
            "seat_ref": "seat-alpha",
            "session_ref": "session-alpha",
            "generation_ref": "generation-alpha",
            "expected_count": 1,
            "count_unit": "native_arrival",
        }
        chain = {
            "collector_result_ref": "ev-result",
            "collector_qualification_ref": "ev-qualification",
            "recovery_delivery_attempted": True,
            "fresh_control_passed": True,
        }
        case = evaluator_case("G3", chain, expected)
        def loader(_chain):
            return result, qualification

        decision = rehearsal.evaluate_case(
            case, "G3", context_kind="fixture", collector_loader=loader
        )
        self.assertEqual(decision["result"], "pass")
        for key in ("recovery_delivery_attempted", "fresh_control_passed"):
            changed = copy.deepcopy(case)
            changed["observed"]["chain"][key] = False
            self.assertEqual(
                rehearsal.evaluate_case(
                    changed, "G3", context_kind="fixture", collector_loader=loader
                )["result"],
                "unobserved",
            )
        duplicate = copy.deepcopy(result)
        event = copy.deepcopy(duplicate["events"][0])
        event.update(
            native_event_id="native-two",
            projection_id="projection-two",
            native_record_key="record-two",
            byte_offset=991,
        )
        duplicate["events"].append(event)
        unqualified = copy.deepcopy(qualification)
        unqualified["provenance"] = "candidate"
        decision = rehearsal.evaluate_case(
            case,
            "G3",
            context_kind="live",
            collector_loader=lambda _chain: (duplicate, unqualified),
        )
        self.assertEqual(decision["result"], "fail")
        self.assertEqual(decision["diagnostics"]["verified_lower_bound"], 2)

    def test_g4_boundary_identity_and_exactly_one_response_transition(self):
        chain = {
            "request_claimed_delivered": True,
            "durable_response_evidenced": True,
            "interruption_boundary_evidenced": True,
            "submit_attempt_evidenced": True,
            "response_identity_matches": True,
            "accepted_logical_responses": 1,
            "raw_retry_attempts": 2,
            "forward_transitions": 1,
            "reconciled": True,
            "later_ack_duplicate_safe": True,
        }
        case = evaluator_case("G4", chain)
        self.assertEqual(rehearsal.evaluate_case(case, "G4")["result"], "pass")
        missing = copy.deepcopy(case)
        missing["observed"]["chain"]["interruption_boundary_evidenced"] = False
        self.assertEqual(rehearsal.evaluate_case(missing, "G4")["result"], "unobserved")
        for key, value in (
            ("response_identity_matches", False),
            ("accepted_logical_responses", 2),
            ("forward_transitions", 2),
        ):
            changed = copy.deepcopy(case)
            changed["observed"]["chain"][key] = value
            self.assertEqual(rehearsal.evaluate_case(changed, "G4")["result"], "fail")

    def test_g5_digest_size_every_seat_and_ack_after_handling(self):
        digest = "a" * 64
        expected = {"final_sha256": digest, "final_bytes": 17, "required_seat_refs": ["seat-a"]}
        seat = {
            "seat_ref": "seat-a",
            "receipt": True,
            "digest": digest,
            "bytes": 17,
            "verified": True,
            "handled": True,
            "acknowledged": True,
            "ack_after_handling": True,
            "evidence_refs": ["ev-a"],
        }
        case = evaluator_case("G5", {"canonical_source_ref": "ev-a", "seat_results": [seat]}, expected)
        self.assertEqual(rehearsal.evaluate_case(case, "G5")["result"], "pass")
        for key, value in (("digest", "b" * 64), ("bytes", 18), ("handled", False), ("ack_after_handling", False)):
            changed = copy.deepcopy(case)
            changed["observed"]["chain"]["seat_results"][0][key] = value
            self.assertEqual(rehearsal.evaluate_case(changed, "G5")["result"], "fail")
        omitted = copy.deepcopy(case)
        omitted["observed"]["chain"]["seat_results"] = []
        self.assertEqual(rehearsal.evaluate_case(omitted, "G5")["result"], "fail")

    def test_failed_harness_truncation_and_timeout_are_unobserved(self):
        chain = {
            "notification_sent": False,
            "wake_received": False,
            "claim_succeeded": False,
            "task_match": True,
            "envelope_match": True,
            "manual_steering": False,
        }
        for updates in (
            {"harness_result": "unobserved"},
            {"coverage_result": "unobserved", "coverage_limitation": "capture rotated"},
            {"deadline_met": False, "coverage_result": "unobserved", "coverage_limitation": "timeout only"},
        ):
            case = evaluator_case("G1", chain)
            case["observed"]["common"].update(updates)
            self.assertEqual(rehearsal.evaluate_case(case, "G1")["result"], "unobserved")
        complete = evaluator_case("G1", chain)
        complete["observed"]["common"]["deadline_met"] = False
        self.assertEqual(rehearsal.evaluate_case(complete, "G1")["result"], "fail")


class AggregationTests(unittest.TestCase):
    def test_exhaustive_precedence_and_empty_inventory(self):
        order = {"pass": 0, "skipped": 1, "unobserved": 2, "fail": 3}
        for length in range(1, 5):
            for combination in itertools.product(tuple(order), repeat=length):
                self.assertEqual(
                    rehearsal.aggregate_results(list(combination)),
                    max(combination, key=lambda value: order[value]),
                )
        self.assertEqual(rehearsal.aggregate_results([]), "unobserved")

    def test_failed_and_unrun_controls_prevent_pass(self):
        chain = {
            "notification_sent": True,
            "wake_received": True,
            "claim_succeeded": True,
            "task_match": True,
            "envelope_match": True,
            "manual_steering": False,
        }
        case = evaluator_case("G1", chain)
        failed = copy.deepcopy(passing_control())
        failed.update(
            observed={"outcome": "accepted-invalid"},
            result="fail",
            rationale="control-observed-unexpected-outcome",
        )
        case["controls"].append(failed)
        self.assertEqual(rehearsal.evaluate_case(case, "G1")["result"], "fail")
        case = evaluator_case("G1", chain)
        case["controls"][0].update(
            observed=None,
            evidence_refs=[],
            result="unobserved",
            rationale="control-not-observed",
        )
        self.assertEqual(rehearsal.evaluate_case(case, "G1")["result"], "unobserved")

    def test_explicit_skip_reason_is_required_for_skipped_case(self):
        chain = {
            "notification_sent": False,
            "wake_received": False,
            "claim_succeeded": False,
            "task_match": True,
            "envelope_match": True,
            "manual_steering": False,
        }
        case = evaluator_case("G1", chain)
        case["applicable"] = False
        case["observed"]["common"]["attempted"] = False
        self.assertEqual(rehearsal.evaluate_case(case, "G1")["result"], "unobserved")
        case["skip_reason"] = "No Codex seat exists in this declared topology."
        self.assertEqual(rehearsal.evaluate_case(case, "G1")["result"], "skipped")


class RunLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rehearsal-runner-")
        self.base = Path(self.temporary.name)
        self.run_root = self.base / "run"
        self.record = literal_json("named-g1-pass.fixture.json")
        self.record["record_kind"] = "template"
        self.record["overall_result"] = "unobserved"
        self.plan = {
            "format": "rehearsal-plan/v1",
            "context_kind": "fixture",
            "run_id": self.record["run_id"],
            "record": self.record,
        }
        self.plan_path = self.base / "plan.json"
        write_json(self.plan_path, self.plan)

    def tearDown(self):
        self.temporary.cleanup()

    def checkpoint(self, transition, previous, case_id=None, details=None, suffix=""):
        return {
            "format": "rehearsal-checkpoint/v1",
            "checkpoint_id": "cp-" + transition + suffix,
            "transition": transition,
            "expected_previous_digest": previous,
            "at_utc": "2026-09-08T20:00:00Z",
            "actor_ref": "maintainer-one",
            "case_id": case_id,
            "evidence_refs": [],
            "details": details or {},
        }

    def prepare_imported_run(self, classification="private_capture"):
        rehearsal.init_run(self.run_root, self.plan_path)
        source = self.base / "selected-evidence.bin"
        source.write_bytes(b"x")
        spec = {
            "format": "rehearsal-import/v1",
            "collected_utc": "2026-09-08T19:58:00Z",
            "items": [
                {
                    "source": str(source),
                    "source_identity": "private-session-fixture",
                    "classification": classification,
                    "content_kind": (
                        "capture" if classification == "private_capture" else "support_record"
                    ),
                    "transformations": ["none"],
                    "qualification_refs": [],
                    "selection_scope": "test_dialogue",
                    "reviewed_safe": True,
                }
            ],
        }
        imported = rehearsal.import_run_evidence(self.run_root, spec)[0]
        record = replace_ref(copy.deepcopy(self.record), "ev-a", imported["ref"])
        record["evidence"] = [imported]
        write_json(self.run_root / "record.json", record)
        return record, imported

    def advance_to_assessment_ready(self, context_kind="fixture"):
        self.plan["context_kind"] = context_kind
        write_json(self.plan_path, self.plan)
        classification = "private_capture" if context_kind == "fixture" else "redacted_record"
        record, imported = self.prepare_imported_run(classification=classification)
        previous = None
        for transition, case_id, details in (
            ("freeze_plan", None, {}),
            ("record_authorization", None, {}),
            ("arm_case", "case-g1", {"intervention_action": "observe-wake"}),
        ):
            result = rehearsal.checkpoint_run(
                self.run_root,
                self.checkpoint(transition, previous, case_id, details),
            )
            previous = result["state"]["previous_checkpoint_digest"]
        passing_record = copy.deepcopy(record)
        passing_record["record_kind"] = "run"
        passing_record["overall_result"] = "pass"
        record["record_kind"] = "run"
        record["completed_utc"] = None
        record["overall_result"] = "unobserved"
        gate = record["gates"][0]
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
            coverage_limitation="Attempt has not started.",
            deadline_met=False,
        )
        case["observer"].update(
            completeness_result="unobserved",
            limitations=["Attempt has not started."],
        )
        case["controls"][0].update(
            observed=None,
            result="unobserved",
            evidence_refs=[],
            rationale="control-not-observed",
        )
        write_json(self.run_root / "record.json", record)
        result = rehearsal.checkpoint_run(
            self.run_root, self.checkpoint("begin_case", previous, "case-g1")
        )
        previous = result["state"]["previous_checkpoint_digest"]
        write_json(self.run_root / "record.json", passing_record)
        for transition in ("seal_case", "ready_assessment"):
            case_id = "case-g1" if transition == "seal_case" else None
            result = rehearsal.checkpoint_run(
                self.run_root, self.checkpoint(transition, previous, case_id)
            )
            previous = result["state"]["previous_checkpoint_digest"]
        record = passing_record
        return record, imported, previous

    def test_init_modes_and_preview_are_read_only(self):
        result = rehearsal.init_run(self.run_root, self.plan_path)
        self.assertEqual(result["state"], "draft")
        self.assertEqual(stat.S_IMODE(self.run_root.stat().st_mode), 0o700)
        for name in ("record.json", "private-index.json", "runner-state.json"):
            self.assertEqual(stat.S_IMODE((self.run_root / name).stat().st_mode), 0o600)
        checkpoint = self.checkpoint("freeze_plan", None)
        preview = rehearsal.checkpoint_run(self.run_root, checkpoint, preview=True)
        self.assertTrue(preview["preview"])
        self.assertFalse((self.run_root / "frozen-plan.json").exists())
        self.assertEqual(list((self.run_root / "checkpoints").iterdir()), [])
        self.assertEqual(rehearsal.load_state(self.run_root)["state"], "draft")

    def test_frozen_edit_stale_digest_and_busy_lock_do_not_advance(self):
        record, _imported = self.prepare_imported_run()
        first = rehearsal.checkpoint_run(self.run_root, self.checkpoint("freeze_plan", None))
        digest = first["state"]["previous_checkpoint_digest"]
        before = (self.run_root / "runner-state.json").read_bytes()
        record["gates"][0]["cases"][0]["expected"]["chain"]["router_cadence_seconds"] = 31
        write_json(self.run_root / "record.json", record)
        with self.assertRaisesRegex(RehearsalError, "frozen-plan-changed"):
            rehearsal.checkpoint_run(
                self.run_root, self.checkpoint("record_authorization", digest)
            )
        self.assertEqual((self.run_root / "runner-state.json").read_bytes(), before)
        with self.assertRaisesRegex(RehearsalError, "stale-previous"):
            rehearsal.checkpoint_run(
                self.run_root, self.checkpoint("record_authorization", None)
            )
        record["gates"][0]["cases"][0]["expected"]["chain"]["router_cadence_seconds"] = 30
        write_json(self.run_root / "record.json", record)
        (self.run_root / ".runner.lock").write_text("held", encoding="utf-8")
        with self.assertRaisesRegex(RehearsalError, "run-busy"):
            rehearsal.checkpoint_run(
                self.run_root, self.checkpoint("record_authorization", digest)
            )

    def test_interrupted_atomic_state_publication_is_retryable(self):
        self.prepare_imported_run()
        checkpoint = self.checkpoint("freeze_plan", None)
        original = rehearsal.atomic_write_private
        with mock.patch.object(rehearsal, "atomic_write_private", side_effect=RuntimeError("stop")):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                rehearsal.checkpoint_run(self.run_root, checkpoint)
        self.assertEqual(rehearsal.load_state(self.run_root)["state"], "draft")
        checkpoint_path = self.run_root / "checkpoints" / "cp-freeze_plan.json"
        self.assertTrue(checkpoint_path.exists())
        with mock.patch.object(rehearsal, "atomic_write_private", side_effect=original):
            result = rehearsal.checkpoint_run(self.run_root, checkpoint)
        self.assertEqual(result["state"]["state"], "plan_frozen")
        repeated = rehearsal.checkpoint_run(self.run_root, checkpoint)
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(repeated["state"]["sequence"], 1)

    def test_private_live_capture_requires_recorded_authorization_first(self):
        self.plan["context_kind"] = "live"
        write_json(self.plan_path, self.plan)
        rehearsal.init_run(self.run_root, self.plan_path)
        source = self.base / "capture.bin"
        source.write_bytes(b"private capture")
        spec = {
            "format": "rehearsal-import/v1",
            "collected_utc": "2026-09-08T20:00:00Z",
            "items": [
                {
                    "source": str(source),
                    "source_identity": "private-session-fixture",
                    "classification": "private_capture",
                    "content_kind": "capture",
                    "transformations": ["none"],
                    "qualification_refs": [],
                    "selection_scope": "test_dialogue",
                    "reviewed_safe": True,
                }
            ],
        }
        with self.assertRaisesRegex(RehearsalError, "authorization-must-precede"):
            rehearsal.import_run_evidence(self.run_root, spec)
        self.assertEqual(list((self.run_root / "objects").iterdir()), [])

    def test_generic_support_record_cannot_arm_a_live_case(self):
        self.plan["context_kind"] = "live"
        write_json(self.plan_path, self.plan)
        self.prepare_imported_run(classification="redacted_record")
        frozen = rehearsal.checkpoint_run(
            self.run_root, self.checkpoint("freeze_plan", None)
        )
        previous = frozen["state"]["previous_checkpoint_digest"]
        authorized = rehearsal.checkpoint_run(
            self.run_root, self.checkpoint("record_authorization", previous)
        )
        previous = authorized["state"]["previous_checkpoint_digest"]
        with self.assertRaisesRegex(
            RehearsalError, "fixed-c2-installed-evidence-required"
        ):
            rehearsal.checkpoint_run(
                self.run_root,
                self.checkpoint(
                    "arm_case",
                    previous,
                    "case-g1",
                    {"intervention_action": "observe-wake"},
                ),
            )
        self.assertEqual(rehearsal.load_state(self.run_root)["state"], "authorized_preflight")

    def test_c2_artifact_record_cannot_arm_stronger_live_preflight(self):
        self.plan["context_kind"] = "live"
        write_json(self.plan_path, self.plan)
        rehearsal.init_run(self.run_root, self.plan_path)
        source = FIXTURES / "c2-lifecycle-evidence-v1.json"
        spec = {
            "format": "rehearsal-import/v1",
            "collected_utc": "2026-09-08T19:58:00Z",
            "items": [
                {
                    "source": str(source),
                    "source_identity": "explicit-c2-fixture",
                    "classification": "redacted_record",
                    "content_kind": "c2_lifecycle_evidence",
                    "transformations": ["none"],
                    "qualification_refs": [],
                    "selection_scope": "test_dialogue",
                    "reviewed_safe": True,
                }
            ],
        }
        imported = rehearsal.import_run_evidence(self.run_root, spec)[0]
        record = replace_ref(copy.deepcopy(self.record), "ev-a", imported["ref"])
        record["evidence"] = [imported]
        record["tested_tuple"].update(
            release_manifest_sha256=evidence.C2_RELEASE_MANIFEST_SHA256,
            package_id=evidence.C2_PACKAGE_ID,
            runtime_cohort=evidence.C2_RUNTIME_COHORT,
        )
        write_json(self.run_root / "record.json", record)
        frozen = rehearsal.checkpoint_run(
            self.run_root, self.checkpoint("freeze_plan", None)
        )
        previous = frozen["state"]["previous_checkpoint_digest"]
        authorized = rehearsal.checkpoint_run(
            self.run_root, self.checkpoint("record_authorization", previous)
        )
        previous = authorized["state"]["previous_checkpoint_digest"]
        with self.assertRaisesRegex(
            RehearsalError,
            "c2-artifact-evidence-cannot-support-stronger-preflight",
        ):
            rehearsal.checkpoint_run(
                self.run_root,
                self.checkpoint(
                    "arm_case",
                    previous,
                    "case-g1",
                    {"intervention_action": "observe-wake"},
                ),
            )
        self.assertEqual(rehearsal.load_state(self.run_root)["state"], "authorized_preflight")

    def test_deliberate_skip_checkpoint_preserves_reason_and_completes_case(self):
        record, _imported = self.prepare_imported_run()
        frozen = rehearsal.checkpoint_run(
            self.run_root, self.checkpoint("freeze_plan", None)
        )
        previous = frozen["state"]["previous_checkpoint_digest"]
        authorized = rehearsal.checkpoint_run(
            self.run_root, self.checkpoint("record_authorization", previous)
        )
        previous = authorized["state"]["previous_checkpoint_digest"]
        case = record["gates"][0]["cases"][0]
        reason = "Declared topology has no applicable Codex seat."
        case["skip_reason"] = reason
        case["observed"]["common"]["attempted"] = False
        case.update(result="skipped", rationale="case-deliberately-skipped")
        write_json(self.run_root / "record.json", record)
        skipped = rehearsal.checkpoint_run(
            self.run_root,
            self.checkpoint(
                "skip_case",
                previous,
                case_id="case-g1",
                details={"skip_reason": reason},
            ),
        )
        self.assertEqual(skipped["state"]["state"], "case_sealed")
        self.assertEqual(skipped["state"]["completed_cases"], ["case-g1"])

    def test_first_attempt_boundary_rejects_prefilled_historical_observation(self):
        record, _imported = self.prepare_imported_run()
        previous = None
        for transition, case_id, details in (
            ("freeze_plan", None, {}),
            ("record_authorization", None, {}),
            ("arm_case", "case-g1", {"intervention_action": "observe-wake"}),
        ):
            result = rehearsal.checkpoint_run(
                self.run_root,
                self.checkpoint(transition, previous, case_id, details),
            )
            previous = result["state"]["previous_checkpoint_digest"]
        record["record_kind"] = "run"
        record["overall_result"] = "pass"
        write_json(self.run_root / "record.json", record)
        with self.assertRaisesRegex(RehearsalError, "historical-observation-before-attempt"):
            rehearsal.checkpoint_run(
                self.run_root,
                self.checkpoint("begin_case", previous, case_id="case-g1"),
            )

    def test_fixture_context_cannot_export_as_live_proof(self):
        self.advance_to_assessment_ready(context_kind="fixture")
        with self.assertRaisesRegex(RehearsalError, "fixture-context-cannot-export"):
            rehearsal.export_run(self.run_root, self.base / "export")

    def test_fixture_artifact_export_is_explicitly_proof_ineligible(self):
        self.advance_to_assessment_ready(context_kind="fixture")
        destination = self.base / "fixture-export"
        result = rehearsal.export_run(
            self.run_root,
            destination,
            allow_fixture_artifacts=True,
        )
        self.assertEqual(result["context_kind"], "fixture")
        self.assertFalse(result["proof_eligible"])
        self.assertTrue((destination / "fixture-record.json").is_file())
        self.assertFalse((destination / "run-record.json").exists())
        manifest = rehearsal.validate_export(destination)
        self.assertEqual(manifest["format"], "rehearsal-fixture-export/v1")
        self.assertFalse(manifest["proof_eligible"])
        exported_record = json.loads(
            (destination / "fixture-record.json").read_text(encoding="utf-8")
        )
        self.assertIn(rehearsal.FIXTURE_EXPORT_LIMITATION, exported_record["limitations"])

    def test_validate_and_assess_exit_conventions_separate_validity_from_verdict(self):
        record, _imported, _previous = self.advance_to_assessment_ready(
            context_kind="fixture"
        )
        validate = subprocess.run(
            [sys.executable, str(SCRIPT), "validate", "--run", str(self.run_root)],
            check=False,
            stdout=subprocess.PIPE,
            text=True,
        )
        passing = subprocess.run(
            [sys.executable, str(SCRIPT), "assess", "--run", str(self.run_root)],
            check=False,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(validate.returncode, 0)
        self.assertEqual(passing.returncode, 0)
        self.assertTrue(json.loads(validate.stdout)["record_valid"])
        case = record["gates"][0]["cases"][0]
        case["observed"]["common"]["harness_result"] = "unobserved"
        case.update(result="unobserved", rationale="observer-harness-unavailable")
        record["gates"][0].update(
            result="unobserved", rationale="aggregate:unobserved"
        )
        record["overall_result"] = "unobserved"
        write_json(self.run_root / "record.json", record)
        nonpassing = subprocess.run(
            [sys.executable, str(SCRIPT), "assess", "--run", str(self.run_root)],
            check=False,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(nonpassing.returncode, 1)
        self.assertTrue(json.loads(nonpassing.stdout)["record_valid"])

    def test_live_export_then_separate_cleanup_checkpoint(self):
        # This test isolates export/cleanup ordering. Fixed loaded-host and seat
        # evidence readers remain in the D-dependent integration slice.
        with mock.patch.object(rehearsal, "_live_preflight_evidence"):
            record, imported, previous = self.advance_to_assessment_ready(
                context_kind="live"
            )
        destination = self.base / "export"
        with self.assertRaisesRegex(
            RehearsalError, "fixture-artifacts-require-fixture-context"
        ):
            rehearsal.export_run(
                self.run_root,
                self.base / "wrong-fixture-export",
                allow_fixture_artifacts=True,
            )
        with mock.patch.object(rehearsal, "_live_preflight_evidence"):
            exported = rehearsal.export_run(self.run_root, destination)
        self.assertEqual(exported["result"], "pass")
        self.assertFalse((destination / "private-index.json").exists())
        self.assertNotIn("private-session-fixture", (destination / "summary.json").read_text())
        verify = self.checkpoint(
            "verify_export",
            previous,
            details={
                "destination": str(destination),
                "manifest_sha256": exported["manifest_sha256"],
            },
        )
        result = rehearsal.checkpoint_run(self.run_root, verify)
        previous = result["state"]["previous_checkpoint_digest"]
        record["cleanup"]["exports_verified_utc"] = "2026-09-08T20:11:00Z"
        record["cleanup"]["dialogue_deletion"] = {
            "result": "pass",
            "evidence_refs": [imported["ref"]],
        }
        write_json(self.run_root / "record.json", record)
        premature = self.checkpoint(
            "record_cleanup",
            previous,
            details={
                "terminal_handling_result": "unobserved",
                "participants_unbound_result": "pass",
                "adapters_closed_result": "pass",
                "dialogue_result": "pass",
                "detached_capture_result": "unobserved",
                "retained_evidence_result": "pass",
            },
            suffix="-premature",
        )
        with self.assertRaisesRegex(RehearsalError, "must-precede-deletion"):
            rehearsal.checkpoint_run(self.run_root, premature)
        cleanup = self.checkpoint(
            "record_cleanup",
            previous,
            details={
                "terminal_handling_result": "pass",
                "participants_unbound_result": "pass",
                "adapters_closed_result": "pass",
                "dialogue_result": "pass",
                "detached_capture_result": "unobserved",
                "retained_evidence_result": "pass",
            },
        )
        result = rehearsal.checkpoint_run(self.run_root, cleanup)
        self.assertEqual(result["state"]["state"], "cleanup_recorded")

    def test_cleanup_before_export_is_an_ordering_refusal(self):
        self.prepare_imported_run()
        with self.assertRaisesRegex(RehearsalError, "invalid-transition"):
            rehearsal.checkpoint_run(
                self.run_root,
                self.checkpoint(
                    "record_cleanup",
                    None,
                    details={
                        "terminal_handling_result": "pass",
                        "participants_unbound_result": "pass",
                        "adapters_closed_result": "pass",
                        "dialogue_result": "pass",
                        "detached_capture_result": "pass",
                        "retained_evidence_result": "pass",
                    },
                ),
            )


class CliAndNoLiveSideEffectTests(unittest.TestCase):
    def run_cli(self, *arguments):
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )

    def test_help_and_read_only_missing_root_create_nothing(self):
        with tempfile.TemporaryDirectory(prefix="rehearsal-cli-") as temporary:
            missing = Path(temporary) / "missing"
            help_result = self.run_cli("--help")
            self.assertEqual(help_result.returncode, 0)
            self.assertIn("file-only", help_result.stdout.lower())
            for command in ("validate", "assess"):
                result = self.run_cli(command, "--run", str(missing))
                self.assertEqual(result.returncode, 2)
                self.assertFalse(missing.exists())
                self.assertFalse(json.loads(result.stdout)["record_valid"])

    def test_source_has_no_network_process_broker_or_native_runtime_surface(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported = set()
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    calls.append(node.func.attr)
                elif isinstance(node.func, ast.Name):
                    calls.append(node.func.id)
        forbidden_imports = {"socket", "urllib", "requests", "council", "council_mcp"}
        self.assertTrue(imported.isdisjoint(forbidden_imports), imported)
        self.assertFalse({"Popen", "run", "system", "spawn", "fork"}.intersection(calls))
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("HOME", source)
        self.assertNotIn("CODEX_HOME", source)

    def test_committed_walkthrough_runs_a_proof_ineligible_fixture_cycle(self):
        with tempfile.TemporaryDirectory(prefix="rehearsal-walkthrough-") as temporary:
            completed = subprocess.run(
                [sys.executable, str(WALKTHROUGH), "--workspace", temporary],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["context_kind"], "fixture")
            self.assertFalse(result["proof_eligible"])
            self.assertEqual(result["runner_state"], "cleanup_recorded")
            self.assertEqual(result["live_actions_performed"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
