#!/usr/bin/env python3
"""Synthetic fault models for qualification evidence collection.

These tests never invoke a native client or the inert adapter.  Their receipts
model runner observations and remain explicitly ineligible for qualification.
"""

import copy
import json
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import council_registration as registration
import council_registration_qualification as qualification
from council_registration import (
    CLAUDE_ENSURE,
    CLAUDE_REMOVE,
    CLAUDE_USER,
    CODEX_ENSURE,
    CODEX_REMOVE,
    CODEX_USER,
    ConfigDocument,
    StdioSpec,
    observe_claude_config,
    observe_codex_config,
)
from council_registration_qualification import (
    ATTEMPT_FORMAT,
    ATTEMPT_JOURNAL_FORMAT,
    CLEAN_FIXTURE_STATE,
    CREDENTIAL_STATE,
    FIXTURE_ACCOUNT_KIND,
    FIXTURE_AUTHORITY,
    FORMAT,
    MAX_OUTPUT_BYTES,
    FixtureAdmission,
    LaunchReceipt,
    NativeAttemptBinding,
    NativeAttemptFamilyIdentity,
    NativeExecutionAdmission,
    NativeImplementationIdentity,
    NativeShapePolicy,
    ObservationReceipt,
    QualificationDecision,
    QualificationCase,
    QualificationAdmission,
    QualificationInputError,
    QualificationSupportDecision,
    RuntimeTuple,
    SemanticNativeResultIdentity,
    build_native_attempt_binding,
    build_native_attempt_family,
    build_semantic_native_result_identity,
    collect_case,
    fixed_argv,
    run_qualified_attempt,
    run_admitted_attempt,
    validate_case_manifest,
    validate_native_shape_policy,
    validate_qualification_admission,
)


FIXTURES = Path(__file__).parent / "fixtures" / "registration"
EMPTY_DIGEST = "0" * 64


class SyntheticTomllib:
    @staticmethod
    def loads(text):
        if not text.strip():
            return {}
        if "[mcp_servers.council]" not in text:
            raise ValueError("unsupported synthetic TOML")
        adapter = text.split('args=["', 1)[1].split('"', 1)[0]
        return {
            "mcp_servers": {
                "council": {
                    "command": "/usr/bin/python3",
                    "args": [
                        adapter
                    ],
                }
            }
        }


class QualificationCollectionTests(unittest.TestCase):
    def setUp(self):
        self.home = "/synthetic/accounts/council-fixture"
        self.claude_path = self.home + "/.claude.json"
        self.codex_path = self.home + "/.codex/config.toml"
        self.adapter = self.home + "/payload/scripts/council_mcp.py"
        self.spec = StdioSpec("/usr/bin/python3", self.adapter)
        self.neutral_cwd = "/synthetic/neutral"
        self.claude_tuple = RuntimeTuple(
            "claude",
            "/synthetic/bin/claude",
            "/synthetic/store/claude-2.1.241",
            "1" * 64,
            "2.1.241",
            "Darwin",
            "arm64",
        )
        self.codex_tuple = RuntimeTuple(
            "codex",
            "/synthetic/bin/codex",
            "/synthetic/store/codex-0.153.4",
            "2" * 64,
            "0.153.4",
            "Darwin",
            "arm64",
        )
        self.admission = FixtureAdmission(
            "fixture-admission-001",
            "3" * 64,
            FIXTURE_AUTHORITY,
            "synthetic_fault_model",
            FIXTURE_ACCOUNT_KIND,
            self.home,
            self.home,
            self.home,
            self.home,
            CLEAN_FIXTURE_STATE,
            CREDENTIAL_STATE,
            (self.claude_path, self.codex_path),
            self.neutral_cwd,
        )
        self.claude_absent = ConfigDocument(
            self.claude_path,
            CLAUDE_USER,
            b'{"unrelated":"SYNTHETIC_CONFIG_SECRET","mcpServers":{}}',
        )
        self.claude_target = ConfigDocument(
            self.claude_path,
            CLAUDE_USER,
            (
                b'{"unrelated":"SYNTHETIC_CONFIG_SECRET","mcpServers":{"council":'
                b'{"type":"stdio","command":"/usr/bin/python3","args":'
                b'["/synthetic/accounts/council-fixture/payload/scripts/council_mcp.py"]}}}'
            ),
        )
        self.codex_absent = ConfigDocument(self.codex_path, CODEX_USER, b"")
        self.codex_target = ConfigDocument(
            self.codex_path,
            CODEX_USER,
            (
                b'[mcp_servers.council]\ncommand="/usr/bin/python3"\n'
                b'args=["/synthetic/accounts/council-fixture/payload/scripts/council_mcp.py"]\n'
            ),
        )

    def observation(self, document, runtime="claude"):
        if runtime == "claude":
            return observe_claude_config(
                document, self.spec, scope_inputs_complete=True
            )
        return observe_codex_config(
            document, self.spec, layer_inputs_complete=True
        )

    def case(
        self,
        *,
        operation=CLAUDE_ENSURE,
        before=None,
        initial_state="absent",
        target=None,
        case_id="claude-fault-case",
        neutral_cwd=None,
        stdio=None,
    ):
        before = before or self.claude_absent
        target = target or self.claude_target
        runtime_tuple = (
            self.claude_tuple
            if operation.startswith("claude_")
            else self.codex_tuple
        )
        return QualificationCase(
            case_id,
            operation,
            runtime_tuple.version,
            runtime_tuple.os_name,
            runtime_tuple.architecture,
            initial_state,
            before,
            stdio or self.spec,
            neutral_cwd or self.neutral_cwd,
            self.observation(target, runtime_tuple.runtime).complement_sha256,
            (before.path,),
        )

    def qualified_case(self, operation=CLAUDE_ENSURE):
        case_id = {
            CLAUDE_ENSURE: "claude-add-absent",
            CLAUDE_REMOVE: "claude-remove-present",
            CODEX_ENSURE: "codex-add-absent",
            CODEX_REMOVE: "codex-remove-present",
        }[operation]
        runtime = "claude" if operation.startswith("claude_") else "codex"
        absent = self.claude_absent if runtime == "claude" else self.codex_absent
        target = self.claude_target if runtime == "claude" else self.codex_target
        if operation.endswith("_remove"):
            return self.case(
                operation=operation,
                before=target,
                initial_state="matching",
                target=absent,
                case_id=case_id,
            )
        return self.case(
            operation=operation, before=absent, target=target, case_id=case_id
        )

    def decision(self, case, runtime_tuple=None, mode=None, **overrides):
        runtime_tuple = runtime_tuple or (
            self.claude_tuple if case.runtime == "claude" else self.codex_tuple
        )
        mode = mode or ("forward" if case.operation.endswith("_ensure") else "inverse")
        required = tuple(sorted(
            case_id for case_id, value in qualification.FIXED_CASES.items()
            if value[1] == case.operation
        ))
        evidence = tuple(
            (
                case_id,
                qualification._case_digest(case) if case_id == case.case_id
                else qualification._digest_json(["case", case_id]),
                qualification._digest_json(["packet", case_id]),
                "genuine_runner_observation",
            )
            for case_id in required
        )
        values = {
            "decision_id": "qualified-decision-001",
            "mode": mode,
            "operation": case.operation,
            "runtime": case.runtime,
            "runtime_tuple_sha256": runtime_tuple.digest(),
            "case_evidence": evidence,
            "independent_review_sha256": "6" * 64,
            "support_matrix_sha256": "7" * 64,
            "reviewer_authority": "independent_genuine_runner_reviewer",
            "qualification_eligible": True,
        }
        values.update(overrides)
        return QualificationDecision(**values)

    def qualified_attempt(self, case, launch, post, runtime_tuple=None,
                          decision=None, mode=None, journal=None):
        runtime_tuple = runtime_tuple or (
            self.claude_tuple if case.runtime == "claude" else self.codex_tuple
        )
        decision = decision or self.decision(case, runtime_tuple, mode)
        mode = mode or decision.mode
        events = []

        def issue(record, expected_sha256):
            events.append(("journal", record))
            if journal is not None:
                return journal(record, expected_sha256)
            return expected_sha256

        def launch_once(argv, supplied_case):
            events.append(("launch", argv))
            return launch

        def observe_once(supplied_case):
            events.append(("observe", supplied_case.case_id))
            return post

        result = run_qualified_attempt(
            decision, case, self.admission, runtime_tuple, mode,
            issue, launch_once, observe_once,
        )
        return result, events

    def native_case(self, operation=CLAUDE_ENSURE):
        runtime = "claude" if operation.startswith("claude_") else "codex"
        source_path = self.claude_path if runtime == "claude" else self.codex_path
        scope = CLAUDE_USER if runtime == "claude" else CODEX_USER
        adapter = self.home + "/.claude/skills/council/scripts/council_mcp.py"
        stdio = StdioSpec("/usr/bin/python3", adapter)
        if runtime == "claude":
            absent = ConfigDocument(
                source_path, scope,
                b'{"unrelated":"SYNTHETIC_CONFIG_SECRET","mcpServers":{}}',
            )
            target = ConfigDocument(
                source_path, scope,
                (
                    b'{"unrelated":"SYNTHETIC_CONFIG_SECRET","mcpServers":{"council":'
                    b'{"type":"stdio","command":"/usr/bin/python3","args":'
                    + ('["%s"]}}}' % adapter).encode()
                ),
            )
        else:
            absent = ConfigDocument(source_path, scope, b"")
            target = ConfigDocument(
                source_path, scope,
                ('[mcp_servers.council]\ncommand="/usr/bin/python3"\nargs=["%s"]\n' % adapter).encode(),
            )
        ensure = operation.endswith("_ensure")
        case_id = {
            CLAUDE_ENSURE: "claude-add-absent",
            CLAUDE_REMOVE: "claude-remove-present",
            CODEX_ENSURE: "codex-add-absent",
            CODEX_REMOVE: "codex-remove-present",
        }[operation]
        return self.case(
            operation=operation, before=absent if ensure else target,
            initial_state="absent" if ensure else "matching",
            target=target if ensure else absent, case_id=case_id,
            neutral_cwd="/private/tmp", stdio=stdio,
        )

    def native_target(self, case):
        inverse = {
            CLAUDE_ENSURE: CLAUDE_REMOVE,
            CLAUDE_REMOVE: CLAUDE_ENSURE,
            CODEX_ENSURE: CODEX_REMOVE,
            CODEX_REMOVE: CODEX_ENSURE,
        }[case.operation]
        return self.native_case(inverse).before

    def native_context(self, case, mode=None):
        runtime_tuple = self.claude_tuple if case.runtime == "claude" else self.codex_tuple
        mode = mode or ("forward" if case.operation.endswith("_ensure") else "inverse")
        policy = validate_native_shape_policy(
            (FIXTURES / "native-v3-shape-policy.json").read_bytes()
        )
        selected = next(
            item for item in policy.policies if item["operation"] == case.operation
        )
        implementation = NativeImplementationIdentity(
            "1" * 64, "2" * 64, 3, 3, 3, 3,
            "3" * 64, "4" * 64, "5" * 64,
            "6" * 64, "7" * 64, "8" * 64,
        )
        evidence = self.decision(case, runtime_tuple).case_evidence
        intended_entry = None
        if case.operation.endswith("_ensure"):
            target = self.native_target(case)
            intended_entry = self.observation(target, case.runtime).entry_sha256
        support = QualificationSupportDecision(
            "native-support-001", case.operation, case.runtime,
            runtime_tuple.digest(), selected["policy_id"], selected["version"],
            policy.digest(), implementation.digest(), intended_entry, evidence,
            "9" * 64, "a" * 64,
            "independent_genuine_runner_reviewer", True, False,
        )
        admission = QualificationAdmission(
            "native-admission-001", case.operation, case.runtime,
            runtime_tuple.digest(), selected["policy_id"], selected["version"],
            policy.digest(), implementation.digest(), support.digest(), intended_entry,
            evidence,
            support.independent_review_sha256, support.support_matrix_sha256,
            "council_lifecycle_qualification_owner", True,
        )
        execution = NativeExecutionAdmission(
            "native-execution-001", case.operation, case.runtime,
            self.home + "/.claude/peer-consults", self.home,
            self.home + "/.claude/skills/council", case.before.path,
            True, "b" * 64,
            "created" if case.operation.endswith("_ensure") else "already_owned",
            "/private/tmp", (case.before.path,),
            ("HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"),
            "c" * 64, implementation.observer_policy_sha256, "d" * 64,
            "council_lifecycle_execution_owner", True,
        )
        family = build_native_attempt_family(
            "native-operation-001", mode, case, execution, runtime_tuple,
            admission, support, implementation, policy,
        )
        binding = build_native_attempt_binding(
            "native-operation-001", 0, mode, case, execution, runtime_tuple,
            admission, support, implementation, policy, family,
        )
        semantic = build_semantic_native_result_identity(
            binding, execution.ownership, family
        )
        return {
            "runtime_tuple": runtime_tuple, "policy": policy,
            "implementation": implementation, "support": support,
            "admission": admission, "execution": execution,
            "family": family, "binding": binding, "semantic": semantic, "mode": mode,
        }

    def run_native(self, case, context, launch, post):
        events = []

        def journal(record, digest):
            events.append(("journal", record))
            return digest

        def launch_once(argv, binding):
            events.append(("launch", argv))
            return launch

        def observe_once(binding):
            events.append(("observe", binding.operation_id))
            return post

        result = run_admitted_attempt(
            context["binding"], context["semantic"], context["family"],
            context["admission"],
            context["support"], context["implementation"], context["policy"],
            case, context["execution"], context["runtime_tuple"],
            journal, launch_once, observe_once,
        )
        return result, events

    def launch_receipt(
        self,
        case,
        runtime_tuple=None,
        *,
        result_kind="exit",
        process_state="terminated",
        returncode=0,
        timed_out=False,
        output_lost=False,
        stdout=b"",
        stderr=b"",
        network_state=None,
    ):
        runtime_tuple = runtime_tuple or (
            self.claude_tuple if case.runtime == "claude" else self.codex_tuple
        )
        argv = fixed_argv(case, runtime_tuple)
        not_started = process_state == "not_started"
        if network_state is None:
            network_state = "not_applicable" if not_started else "no_activity_observed"
        return LaunchReceipt(
            case.case_id,
            argv,
            runtime_tuple.digest(),
            result_kind,
            process_state,
            None if not_started else "7" * 64,
            network_state,
            None if not_started else "8" * 64,
            returncode,
            timed_out,
            output_lost,
            stdout,
            stderr,
        )

    def post_receipt(
        self,
        case,
        after,
        runtime_tuple=None,
        *,
        complement=None,
        changed_paths=None,
        sentinel_started=False,
    ):
        runtime_tuple = runtime_tuple or (
            self.claude_tuple if case.runtime == "claude" else self.codex_tuple
        )
        if complement is None:
            complement = self.observation(
                after, runtime_tuple.runtime
            ).complement_sha256
        if changed_paths is None:
            changed_paths = (case.before.path,)
        return ObservationReceipt(
            case.case_id,
            after,
            runtime_tuple,
            complement,
            tuple(changed_paths),
            sentinel_started,
        )

    def collect(self, case, launch, post, runtime_tuple=None):
        runtime_tuple = runtime_tuple or (
            self.claude_tuple if case.runtime == "claude" else self.codex_tuple
        )
        counts = {"launch": 0, "observe": 0}

        def launch_once(argv, supplied_case):
            self.assertEqual(argv, launch.argv)
            self.assertIs(supplied_case, case)
            counts["launch"] += 1
            return launch

        def observe_once(supplied_case):
            self.assertIs(supplied_case, case)
            counts["observe"] += 1
            return post

        packet = collect_case(
            case,
            self.admission,
            runtime_tuple,
            launch_once,
            observe_once,
        )
        return packet, counts

    def assert_synthetic_only(self, packet, admission=None):
        admission = admission or self.admission
        self.assertEqual(packet["format"], FORMAT)
        self.assertEqual(packet["evidence_kind"], "synthetic_fault_model")
        self.assertFalse(packet["qualification_eligible"])
        self.assertFalse(packet["self_declaration_is_qualification"])
        self.assertEqual(len(packet["case_sha256"]), 64)
        self.assertEqual(len(packet["evidence_gaps"]), 4)
        self.assertEqual(
            packet["authority_assumptions"]["declaration_fields_sha256"],
            admission.digest(),
        )
        self.assertEqual(
            packet["qualification_status"],
            "independent_genuine_runner_review_required",
        )

    def test_fixed_argv_are_exact_and_have_no_shell_form(self):
        cases = (
            (
                self.case(operation=CLAUDE_ENSURE),
                self.claude_tuple,
                (
                    "/synthetic/bin/claude",
                    "mcp",
                    "add",
                    "--scope",
                    "user",
                    "--transport",
                    "stdio",
                    "council",
                    "--",
                    "/usr/bin/python3",
                    self.adapter,
                ),
            ),
            (
                self.case(operation=CLAUDE_REMOVE),
                self.claude_tuple,
                (
                    "/synthetic/bin/claude",
                    "mcp",
                    "remove",
                    "--scope",
                    "user",
                    "council",
                ),
            ),
        )
        codex_before = ConfigDocument(self.codex_path, CODEX_USER, b"")
        codex_target = ConfigDocument(
            self.codex_path,
            CODEX_USER,
            (
                b'[mcp_servers.council]\ncommand="/usr/bin/python3"\n'
                b'args=["/synthetic/accounts/council-fixture/payload/scripts/council_mcp.py"]\n'
            ),
        )
        for operation, expected in (
            (
                CODEX_ENSURE,
                (
                    "/synthetic/bin/codex",
                    "mcp",
                    "add",
                    "council",
                    "--",
                    "/usr/bin/python3",
                    self.adapter,
                ),
            ),
            (
                CODEX_REMOVE,
                ("/synthetic/bin/codex", "mcp", "remove", "council"),
            ),
        ):
            case = self.case(
                operation=operation,
                before=codex_before,
                target=codex_target,
                case_id=operation.replace("_", "-"),
            )
            cases += ((case, self.codex_tuple, expected),)
        for case, runtime_tuple, expected in cases:
            with self.subTest(operation=case.operation):
                self.assertEqual(fixed_argv(case, runtime_tuple), expected)

    def test_successful_exit_with_target_collects_target_but_never_qualifies(self):
        case = self.case()
        packet, counts = self.collect(
            case,
            self.launch_receipt(case),
            self.post_receipt(case, self.claude_target),
        )
        self.assertEqual(packet["classification"], "observed_target")
        self.assertEqual(counts, {"launch": 1, "observe": 1})
        self.assert_synthetic_only(packet)

    def test_exit_zero_with_unchanged_prior_is_not_commit(self):
        case = self.case()
        post = self.post_receipt(
            case,
            self.claude_absent,
            complement=self.observation(case.before).complement_sha256,
            changed_paths=(),
        )
        packet, _ = self.collect(case, self.launch_receipt(case), post)
        self.assertEqual(packet["classification"], "observed_prior")

    def test_pre_spawn_failure_observes_prior_without_retry(self):
        case = self.case()
        launch = self.launch_receipt(
            case,
            result_kind="pre_spawn_failure",
            process_state="not_started",
            returncode=None,
            stderr=b"SYNTHETIC_PRESPAWN_SECRET",
        )
        post = self.post_receipt(
            case,
            self.claude_absent,
            complement=self.observation(case.before).complement_sha256,
            changed_paths=(),
        )
        packet, counts = self.collect(case, launch, post)
        self.assertEqual(packet["classification"], "observed_prior")
        self.assertEqual(counts, {"launch": 1, "observe": 1})
        self.assertNotIn("SYNTHETIC_PRESPAWN_SECRET", json.dumps(packet))

    def test_write_before_output_loss_can_be_observed_target(self):
        case = self.case()
        launch = self.launch_receipt(
            case,
            result_kind="output_lost",
            output_lost=True,
            returncode=None,
        )
        packet, _ = self.collect(
            case, launch, self.post_receipt(case, self.claude_target)
        )
        self.assertEqual(packet["classification"], "observed_target")
        self.assertTrue(packet["process"]["output_lost"])

    def test_nonzero_after_write_uses_observed_state(self):
        case = self.case()
        launch = self.launch_receipt(case, returncode=19)
        packet, _ = self.collect(
            case, launch, self.post_receipt(case, self.claude_target)
        )
        self.assertEqual(packet["classification"], "observed_target")
        self.assertEqual(packet["process"]["returncode"], 19)

    def test_remove_classifies_exact_absence_as_target(self):
        case = self.case(
            operation=CLAUDE_REMOVE,
            before=self.claude_target,
            initial_state="matching",
            target=self.claude_absent,
            case_id="claude-remove-fault-case",
        )
        packet, _ = self.collect(
            case,
            self.launch_receipt(case),
            self.post_receipt(case, self.claude_absent),
        )
        self.assertEqual(packet["classification"], "observed_target")
        self.assert_synthetic_only(packet)

    def test_partial_write_is_unknown_and_never_absence(self):
        case = self.case()
        partial = ConfigDocument(
            self.claude_path, CLAUDE_USER, b'{"mcpServers":{"council":'
        )
        packet, _ = self.collect(
            case,
            self.launch_receipt(case, returncode=8),
            self.post_receipt(
                case,
                partial,
                complement=case.expected_target_complement_sha256,
            ),
        )
        self.assertEqual(packet["classification"], "unknown")
        self.assertIn("third_state", packet["issues"])
        self.assertNotEqual(packet["passive_after"]["state"], "absent")

    def test_timeout_with_surviving_child_is_unknown_writer(self):
        case = self.case()
        launch = self.launch_receipt(
            case,
            result_kind="timeout",
            process_state="surviving",
            returncode=None,
            timed_out=True,
        )
        packet, _ = self.collect(
            case, launch, self.post_receipt(case, self.claude_target)
        )
        self.assertEqual(packet["classification"], "unknown")
        self.assertIn("possible_live_writer", packet["issues"])

    def test_missing_or_positive_network_observation_is_unknown(self):
        case = self.case()
        for state, issue in (
            ("unobserved", "network_unobserved"),
            ("activity_observed", "unexpected_network_activity"),
        ):
            with self.subTest(state=state):
                launch = self.launch_receipt(case, network_state=state)
                packet, _ = self.collect(
                    case, launch, self.post_receipt(case, self.claude_target)
                )
                self.assertEqual(packet["classification"], "unknown")
                self.assertIn(issue, packet["issues"])

    def test_changed_runtime_tuple_is_unknown(self):
        case = self.case()
        changed = RuntimeTuple(
            "claude",
            self.claude_tuple.executable_path,
            self.claude_tuple.executable_realpath,
            "4" * 64,
            self.claude_tuple.version,
            "Darwin",
            "arm64",
        )
        packet, _ = self.collect(
            case,
            self.launch_receipt(case),
            self.post_receipt(case, self.claude_target, changed),
        )
        self.assertEqual(packet["classification"], "unknown")
        self.assertIn("runtime_tuple_changed", packet["issues"])

    def test_complement_and_incidental_write_mismatches_are_unknown(self):
        case = self.case()
        cases = (
            self.post_receipt(case, self.claude_target, complement="5" * 64),
            self.post_receipt(
                case,
                self.claude_target,
                changed_paths=(
                    self.claude_path,
                    self.home + "/SYNTHETIC_SECRET_WRITE_NAME",
                ),
            ),
        )
        expected = ("complement_mismatch", "incidental_write_mismatch")
        for post, issue in zip(cases, expected):
            with self.subTest(issue=issue):
                packet, _ = self.collect(case, self.launch_receipt(case), post)
                self.assertEqual(packet["classification"], "unknown")
                self.assertIn(issue, packet["issues"])
                self.assertNotIn("SYNTHETIC_SECRET_WRITE_NAME", json.dumps(packet))

    def test_unexpected_sentinel_start_is_unknown(self):
        case = self.case()
        packet, _ = self.collect(
            case,
            self.launch_receipt(case),
            self.post_receipt(
                case, self.claude_target, sentinel_started=True
            ),
        )
        self.assertEqual(packet["classification"], "unknown")
        self.assertIn("unexpected_sentinel_start", packet["issues"])

    def test_unknown_result_never_retries_launch_or_observation(self):
        case = self.case()
        third = ConfigDocument(
            self.claude_path,
            CLAUDE_USER,
            b'{"mcpServers":{"council":{"type":"http","url":"x"}}}',
        )
        packet, counts = self.collect(
            case,
            self.launch_receipt(case, returncode=1),
            self.post_receipt(
                case,
                third,
                complement=case.expected_target_complement_sha256,
            ),
        )
        self.assertEqual(packet["classification"], "unknown")
        self.assertEqual(counts, {"launch": 1, "observe": 1})
        self.assertEqual(packet["launch_count"], 1)

    def test_launch_receipt_is_bound_to_exact_argv_and_tuple(self):
        case = self.case()
        correct = self.launch_receipt(case)
        receipts = (
            LaunchReceipt(
                correct.case_id,
                correct.argv + ("unexpected",),
                correct.runtime_tuple_digest,
                correct.result_kind,
                correct.process_state,
                correct.process_generation_sha256,
                correct.network_state,
                correct.network_evidence_sha256,
                correct.returncode,
                correct.timed_out,
                correct.output_lost,
                correct.stdout,
                correct.stderr,
            ),
            LaunchReceipt(
                correct.case_id,
                correct.argv,
                "9" * 64,
                correct.result_kind,
                correct.process_state,
                correct.process_generation_sha256,
                correct.network_state,
                correct.network_evidence_sha256,
                correct.returncode,
                correct.timed_out,
                correct.output_lost,
                correct.stdout,
                correct.stderr,
            ),
        )
        for receipt in receipts:
            calls = {"launch": 0, "observe": 0}

            def launch_once(argv, supplied_case):
                calls["launch"] += 1
                return receipt

            def observe_once(supplied_case):
                calls["observe"] += 1
                raise AssertionError("invalid launch receipt reached observation")

            with self.subTest(receipt=receipt), self.assertRaisesRegex(
                QualificationInputError, "receipt"
            ):
                collect_case(
                    case,
                    self.admission,
                    self.claude_tuple,
                    launch_once,
                    observe_once,
                )
            self.assertEqual(calls, {"launch": 1, "observe": 0})

    def test_launch_output_is_bounded_before_collection(self):
        case = self.case()
        with self.assertRaisesRegex(QualificationInputError, "byte limit"):
            self.launch_receipt(case, stdout=b"x" * (MAX_OUTPUT_BYTES + 1))

    def test_launch_returncode_rejects_boolean(self):
        case = self.case()
        with self.assertRaisesRegex(QualificationInputError, "return code"):
            self.launch_receipt(case, returncode=True)

    def test_observation_receipt_is_bound_to_exact_source(self):
        case = self.case()
        wrong = ObservationReceipt(
            case.case_id,
            ConfigDocument(
                self.home + "/other.json",
                CLAUDE_USER,
                self.claude_target.content,
            ),
            self.claude_tuple,
            case.expected_target_complement_sha256,
            (case.before.path,),
            False,
        )
        with self.assertRaisesRegex(QualificationInputError, "source path"):
            self.collect(case, self.launch_receipt(case), wrong)

    def test_raw_output_and_unrelated_config_values_are_redacted(self):
        case = self.case()
        secret = b"SYNTHETIC_NATIVE_OUTPUT_SECRET_91ba"
        launch = self.launch_receipt(
            case, stdout=secret, stderr=b"error:" + secret
        )
        packet, _ = self.collect(
            case, launch, self.post_receipt(case, self.claude_target)
        )
        encoded = json.dumps(packet, sort_keys=True)
        self.assertNotIn(secret.decode(), encoded)
        self.assertNotIn("SYNTHETIC_CONFIG_SECRET", encoded)
        self.assertEqual(packet["process"]["stdout_bytes"], len(secret))

    def test_genuine_runner_self_declaration_still_cannot_qualify(self):
        values = dict(self.admission.__dict__)
        values["evidence_kind"] = "genuine_runner_observation"
        admission = FixtureAdmission(**values)
        case = self.case()
        launch = self.launch_receipt(case)
        post = self.post_receipt(case, self.claude_target)
        packet = collect_case(
            case,
            admission,
            self.claude_tuple,
            lambda argv, supplied_case: launch,
            lambda supplied_case: post,
        )
        self.assertEqual(packet["evidence_kind"], "genuine_runner_observation")
        self.assertFalse(packet["qualification_eligible"])
        self.assertFalse(packet["self_declaration_is_qualification"])
        self.assertIn("independent", packet["qualification_status"])

    def test_nonfixture_dirty_credential_or_rebound_home_refuses_before_launch(self):
        case = self.case()
        alterations = (
            {"account_kind": "unknown"},
            {"clean_fixture_state": "unknown"},
            {"credential_state": "credential_bearing"},
            {"environment_home": "/synthetic/rebound"},
            {"authority": "environment_flag"},
        )
        for changes in alterations:
            values = dict(self.admission.__dict__)
            values.update(changes)
            admission = FixtureAdmission(**values)
            counts = {"launch": 0, "observe": 0}

            def launch_once(argv, supplied_case):
                counts["launch"] += 1
                raise AssertionError("invalid admission launched")

            def observe_once(supplied_case):
                counts["observe"] += 1
                raise AssertionError("invalid admission observed")

            packet = collect_case(
                case,
                admission,
                self.claude_tuple,
                launch_once,
                observe_once,
            )
            with self.subTest(changes=changes):
                self.assertEqual(packet["collection_status"], "refused_before_launch")
                self.assertEqual(counts, {"launch": 0, "observe": 0})
                self.assert_synthetic_only(packet, admission)

    def test_tuple_source_scope_and_initial_state_bind_before_launch(self):
        cases = []
        wrong_version = RuntimeTuple(
            "claude",
            self.claude_tuple.executable_path,
            self.claude_tuple.executable_realpath,
            self.claude_tuple.executable_sha256,
            "2.1.999",
            "Darwin",
            "arm64",
        )
        cases.append((self.case(), self.admission, wrong_version))
        wrong_scope = ConfigDocument(
            self.claude_path, CODEX_USER, self.claude_absent.content
        )
        cases.append(
            (
                self.case(before=wrong_scope),
                self.admission,
                self.claude_tuple,
            )
        )
        cases.append(
            (
                self.case(initial_state="matching"),
                self.admission,
                self.claude_tuple,
            )
        )
        for case, admission, runtime_tuple in cases:
            counts = {"launch": 0, "observe": 0}

            def no_launch(argv, supplied_case):
                counts["launch"] += 1
                raise AssertionError("invalid case launched")

            def no_observe(supplied_case):
                counts["observe"] += 1
                raise AssertionError("invalid case observed")

            packet = collect_case(
                case, admission, runtime_tuple, no_launch, no_observe
            )
            self.assertEqual(packet["collection_status"], "refused_before_launch")
            self.assertEqual(counts, {"launch": 0, "observe": 0})

    def test_codex_collection_requires_current_stdlib_tomllib(self):
        before = ConfigDocument(self.codex_path, CODEX_USER, b"")
        target = ConfigDocument(
            self.codex_path,
            CODEX_USER,
            (
                b'[mcp_servers.council]\ncommand="/usr/bin/python3"\n'
                b'args=["/synthetic/accounts/council-fixture/payload/scripts/council_mcp.py"]\n'
            ),
        )
        case = self.case(
            operation=CODEX_ENSURE,
            before=before,
            target=target,
            case_id="codex-parser-case",
        )
        counts = {"launch": 0, "observe": 0}

        def launch_once(argv, supplied_case):
            counts["launch"] += 1
            return self.launch_receipt(case, self.codex_tuple)

        def observe_once(supplied_case):
            counts["observe"] += 1
            return self.post_receipt(case, target, self.codex_tuple)

        packet = collect_case(
            case,
            self.admission,
            self.codex_tuple,
            launch_once,
            observe_once,
        )
        if registration._tomllib is None:
            self.assertEqual(packet["collection_status"], "refused_before_launch")
            self.assertEqual(counts, {"launch": 0, "observe": 0})
            self.assertEqual(packet["passive_before"]["state"], "parser_unavailable")
        else:
            self.assertEqual(packet["collection_status"], "evidence_collected")
            self.assertEqual(packet["classification"], "observed_target")
            self.assertEqual(counts, {"launch": 1, "observe": 1})
        self.assert_synthetic_only(packet)

    def test_checked_in_manifest_is_fixed_and_cannot_self_qualify(self):
        raw = (FIXTURES / "native-qualification-cases.json").read_bytes()
        report = validate_case_manifest(raw)
        self.assertEqual(report["case_count"], 14)
        self.assertFalse(report["qualification_eligible"])
        self.assertEqual(
            {item["expected_version"] for item in report["cases"]},
            {"2.1.241", "0.153.4"},
        )
        forged = raw.replace(
            b'"qualification_eligible": false',
            b'"qualification_eligible": true',
        )
        with self.assertRaisesRegex(
            QualificationInputError, "cannot claim qualification"
        ):
            validate_case_manifest(forged)
        wrong_version = raw.replace(b'"2.1.241"', b'"2.1.242"')
        with self.assertRaisesRegex(
            QualificationInputError, "version differs"
        ):
            validate_case_manifest(wrong_version)

    def test_duplicate_manifest_keys_refuse(self):
        with self.assertRaisesRegex(QualificationInputError, "duplicate"):
            validate_case_manifest(
                b'{"format":"x","format":"y","qualification_eligible":false,"cases":[]}'
            )

    def test_inert_fixture_is_source_only_and_not_executed(self):
        source = (FIXTURES / "inert_council_mcp.py").read_text()
        self.assertIn("UNEXPECTED_COUNCIL_SERVER_START", source)
        self.assertFalse((FIXTURES / "UNEXPECTED_COUNCIL_SERVER_START").exists())

    def test_qualification_decision_binds_fixed_case_packets_runtime_and_mode(self):
        for operation, mode in (
            (CLAUDE_ENSURE, "forward"),
            (CLAUDE_REMOVE, "inverse"),
            (CODEX_ENSURE, "forward"),
            (CODEX_REMOVE, "inverse"),
        ):
            case = self.qualified_case(operation)
            decision = self.decision(case, mode=mode)
            public = decision.public_dict()
            with self.subTest(operation=operation):
                self.assertEqual(public["operation"], operation)
                self.assertEqual(public["runtime"], case.runtime)
                self.assertEqual(public["mode"], mode)
                self.assertEqual(decision.digest(), qualification._digest_json(public))
                self.assertTrue(all(
                    item["evidence_kind"] == "genuine_runner_observation"
                    for item in public["case_evidence"]
                ))
                self.assertEqual(
                    [item["case_id"] for item in public["case_evidence"]],
                    sorted(
                        case_id for case_id, value in qualification.FIXED_CASES.items()
                        if value[1] == operation
                    ),
                )

        case = self.qualified_case()
        valid = self.decision(case)
        invalid = (
            {"case_evidence": valid.case_evidence[:-1]},
            {"case_evidence": tuple(
                (*item[:3], "synthetic_fault_model") for item in valid.case_evidence
            )},
            {"reviewer_authority": FIXTURE_AUTHORITY},
            {"runtime": "codex"},
            {"qualification_eligible": False},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(
                QualificationInputError
            ):
                self.decision(case, **changes)

    def test_inverse_and_recovery_modes_are_operation_bound(self):
        ensure = self.qualified_case(CLAUDE_ENSURE)
        remove = self.qualified_case(CLAUDE_REMOVE)
        self.decision(ensure, mode="forward")
        self.decision(remove, mode="inverse")
        self.decision(ensure, mode="recovery")
        self.decision(remove, mode="recovery")
        recovery_result, _ = self.qualified_attempt(
            ensure,
            self.launch_receipt(ensure),
            self.post_receipt(ensure, self.claude_target),
            decision=self.decision(ensure, mode="recovery"),
            mode="recovery",
        )
        self.assertEqual(recovery_result["mode"], "recovery")
        self.assertEqual(recovery_result["classification"], "observed_target")
        for case, mode in ((ensure, "inverse"), (remove, "forward")):
            with self.subTest(operation=case.operation, mode=mode), self.assertRaisesRegex(
                QualificationInputError, "mode differs"
            ):
                self.decision(case, mode=mode)

    def test_qualified_attempt_journals_before_one_launch_and_binds_result(self):
        case = self.qualified_case()
        result, events = self.qualified_attempt(
            case,
            self.launch_receipt(case),
            self.post_receipt(case, self.claude_target),
        )
        self.assertEqual([item[0] for item in events], ["journal", "launch", "observe"])
        journal = events[0][1]
        self.assertEqual(journal["format"], ATTEMPT_JOURNAL_FORMAT)
        self.assertEqual(result["format"], ATTEMPT_FORMAT)
        self.assertEqual(result["classification"], "observed_target")
        self.assertTrue(result["journal_issued_before_launch"])
        self.assertEqual(result["launch_count"], 1)
        self.assertEqual(result["observation_count"], 1)
        self.assertFalse(result["qualification_claimed"])
        self.assertFalse(result["collection"]["qualification_eligible"])
        for key in ("decision_sha256", "runtime_tuple_sha256", "case_sha256"):
            self.assertEqual(len(result[key]), 64)

    def test_wrong_decision_and_journal_fail_before_launch(self):
        case = self.qualified_case()
        launch = self.launch_receipt(case)
        post = self.post_receipt(case, self.claude_target)
        valid = self.decision(case)
        wrong_case_evidence = tuple(
            (case_id, "8" * 64 if case_id == case.case_id else case_sha,
             packet_sha, evidence_kind)
            for case_id, case_sha, packet_sha, evidence_kind in valid.case_evidence
        )
        wrong_case = self.decision(case, case_evidence=wrong_case_evidence)
        wrong_tuple = RuntimeTuple(
            "claude", self.claude_tuple.executable_path,
            self.claude_tuple.executable_realpath, "9" * 64,
            self.claude_tuple.version, "Darwin", "arm64",
        )
        cases = (
            (valid, wrong_tuple, "forward"),
            (valid, self.claude_tuple, "recovery"),
            (wrong_case, self.claude_tuple, "forward"),
        )
        for decision, runtime_tuple, mode in cases:
            calls = []
            with self.subTest(mode=mode), self.assertRaises(QualificationInputError):
                run_qualified_attempt(
                    decision, case, self.admission, runtime_tuple, mode,
                    lambda *_: calls.append("journal"),
                    lambda *_: calls.append("launch"),
                    lambda *_: calls.append("observe"),
                )
            self.assertEqual(calls, [])

        calls = []
        with self.assertRaisesRegex(QualificationInputError, "decision is required"):
            run_qualified_attempt(
                None, case, self.admission, self.claude_tuple, "forward",
                lambda *_: calls.append("journal"),
                lambda *_: calls.append("launch"),
                lambda *_: calls.append("observe"),
            )
        self.assertEqual(calls, [])

        calls = []
        with self.assertRaisesRegex(QualificationInputError, "journal seam"):
            run_qualified_attempt(
                valid, case, self.admission, self.claude_tuple, "forward",
                lambda record, digest: calls.append("journal") or "0" * 64,
                lambda *_: calls.append("launch") or launch,
                lambda *_: calls.append("observe") or post,
            )
        self.assertEqual(calls, ["journal"])

    def test_attempt_uses_passive_state_across_process_outcomes_without_retry(self):
        case = self.qualified_case()
        prior = self.post_receipt(
            case, self.claude_absent,
            complement=self.observation(case.before).complement_sha256,
            changed_paths=(),
        )
        target = self.post_receipt(case, self.claude_target)
        cases = (
            (self.launch_receipt(case), prior, "observed_prior", None),
            (
                self.launch_receipt(
                    case, result_kind="pre_spawn_failure",
                    process_state="not_started", returncode=None,
                ),
                prior,
                "observed_prior",
                None,
            ),
            (
                self.launch_receipt(
                    case, result_kind="output_lost", output_lost=True,
                    returncode=None,
                ),
                target,
                "observed_target",
                None,
            ),
            (self.launch_receipt(case, returncode=19), target, "observed_target", None),
            (
                self.launch_receipt(
                    case, result_kind="timeout", process_state="surviving",
                    returncode=None, timed_out=True,
                ),
                target,
                "unknown",
                "possible_live_writer",
            ),
            (
                self.launch_receipt(
                    case, result_kind="timeout", process_state="unidentified",
                    returncode=None, timed_out=True,
                ),
                target,
                "unknown",
                "possible_live_writer",
            ),
            (
                self.launch_receipt(case, network_state="activity_observed"),
                target,
                "unknown",
                "unexpected_network_activity",
            ),
            (
                self.launch_receipt(case, network_state="unobserved"),
                target,
                "unknown",
                "network_unobserved",
            ),
        )
        for launch, post, classification, issue in cases:
            result, events = self.qualified_attempt(case, launch, post)
            with self.subTest(result_kind=launch.result_kind, issue=issue):
                self.assertEqual(result["classification"], classification)
                self.assertEqual(
                    [item[0] for item in events], ["journal", "launch", "observe"]
                )
                self.assertEqual(events.count(("launch", launch.argv)), 1)
                if issue is not None:
                    self.assertIn(issue, result["issues"])

    def test_attempt_tuple_complement_write_set_sentinel_and_output_are_bounded(self):
        case = self.qualified_case()
        changed_tuple = RuntimeTuple(
            "claude", self.claude_tuple.executable_path,
            self.claude_tuple.executable_realpath, "9" * 64,
            self.claude_tuple.version, "Darwin", "arm64",
        )
        posts = (
            (self.post_receipt(case, self.claude_target, changed_tuple), "runtime_tuple_changed"),
            (self.post_receipt(case, self.claude_target, complement="9" * 64), "complement_mismatch"),
            (
                self.post_receipt(
                    case, self.claude_target,
                    changed_paths=(case.before.path, self.home + "/SYNTHETIC_WRITE_SECRET"),
                ),
                "incidental_write_mismatch",
            ),
            (
                self.post_receipt(case, self.claude_target, sentinel_started=True),
                "unexpected_sentinel_start",
            ),
        )
        for post, issue in posts:
            result, _ = self.qualified_attempt(case, self.launch_receipt(case), post)
            with self.subTest(issue=issue):
                self.assertEqual(result["classification"], "unknown")
                self.assertIn(issue, result["issues"])
                self.assertFalse(result["qualification_claimed"])

        secret = b"SYNTHETIC_ATTEMPT_OUTPUT_SECRET"
        result, _ = self.qualified_attempt(
            case,
            self.launch_receipt(case, stdout=secret, stderr=secret),
            self.post_receipt(case, self.claude_target),
        )
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret.decode(), encoded)
        self.assertNotIn("SYNTHETIC_CONFIG_SECRET", encoded)
        self.assertNotIn("SYNTHETIC_WRITE_SECRET", encoded)

    def test_all_four_native_operations_are_fixed_one_attempt_surfaces(self):
        for operation in (
            CLAUDE_ENSURE, CLAUDE_REMOVE, CODEX_ENSURE, CODEX_REMOVE
        ):
            case = self.qualified_case(operation)
            runtime_tuple = (
                self.claude_tuple if case.runtime == "claude" else self.codex_tuple
            )
            decision = self.decision(case, runtime_tuple)
            if case.runtime == "codex" and registration._tomllib is None:
                self.assertEqual(decision.runtime, "codex")
                continue
            after = (
                self.claude_target if operation == CLAUDE_ENSURE else
                self.claude_absent if operation == CLAUDE_REMOVE else
                self.codex_target if operation == CODEX_ENSURE else self.codex_absent
            )
            result, events = self.qualified_attempt(
                case,
                self.launch_receipt(case, runtime_tuple),
                self.post_receipt(case, after, runtime_tuple),
                runtime_tuple,
                decision,
            )
            with self.subTest(operation=operation):
                self.assertEqual(result["classification"], "observed_target")
                self.assertEqual([item[0] for item in events], ["journal", "launch", "observe"])

    def test_qualification_module_exposes_no_direct_effect_api(self):
        source = Path(qualification.__file__).read_text()
        for forbidden in (
            "import os", "import subprocess", "import socket", "Path.home",
            "os.environ", "open(", "Popen(", "run(",
        ):
            self.assertNotIn(forbidden, source)

    def test_native_v3_shape_policy_is_closed_canonical_and_non_authoritative(self):
        raw = (FIXTURES / "native-v3-shape-policy.json").read_bytes()
        policy = validate_native_shape_policy(raw)
        self.assertIsInstance(policy, NativeShapePolicy)
        self.assertEqual(policy.digest(), qualification._sha256(raw))
        self.assertFalse(policy.public_dict()["qualification_eligible"])
        self.assertEqual(
            [item["operation"] for item in policy.policies],
            [CLAUDE_ENSURE, CLAUDE_REMOVE, CODEX_ENSURE, CODEX_REMOVE],
        )
        for item in policy.policies:
            self.assertTrue(item["source_file_must_exist"])
            self.assertEqual(item["observer_policy_id"], "darwin-whole-process-group-v1")
            if item["runtime"] == "claude":
                self.assertEqual(item["complement_rule"], "raw-selected-entry-mask-v1")
                self.assertEqual(item["normalization"], "none")
                self.assertTrue(item["promised_raw_format_preservation"])
            else:
                self.assertEqual(
                    item["complement_rule"],
                    "semantic-tomllib-without-selected-entry-v1",
                )
                self.assertFalse(item["promised_raw_format_preservation"])

        value = json.loads(raw)
        for index, record in enumerate(value["policies"]):
            for key in record:
                changed = copy.deepcopy(value)
                changed["policies"][index][key] = None
                with self.subTest(operation=record["operation"], key=key), self.assertRaises(
                    QualificationInputError
                ):
                    validate_native_shape_policy(
                        (json.dumps(changed, indent=2, sort_keys=True) + "\n").encode()
                    )
        for changed in (
            {**value, "qualification_eligible": True},
            {**value, "unexpected": False},
        ):
            with self.assertRaises(QualificationInputError):
                validate_native_shape_policy(
                    (json.dumps(changed, indent=2, sort_keys=True) + "\n").encode()
                )
        with self.assertRaisesRegex(QualificationInputError, "canonical"):
            validate_native_shape_policy(raw.rstrip())
        with self.assertRaisesRegex(QualificationInputError, "duplicate"):
            validate_native_shape_policy(raw.replace(b'"format":', b'"format":"x","format":', 1))

    def test_native_v3_implementation_support_and_owner_admission_are_distinct(self):
        case = self.native_case()
        context = self.native_context(case)
        implementation = context["implementation"]
        support = context["support"]
        admission = context["admission"]
        self.assertIsInstance(implementation, NativeImplementationIdentity)
        self.assertIsInstance(support, QualificationSupportDecision)
        self.assertIsInstance(admission, QualificationAdmission)
        self.assertFalse(support.public_dict()["qualification_authority"])
        self.assertEqual(
            admission.fixed_relative_path,
            ".council-lifecycle/v1/native-qualification-admissions/%s.json" % case.operation,
        )
        self.assertEqual(
            validate_qualification_admission(
                admission.public_dict(), support, implementation, context["policy"],
                context["runtime_tuple"], case.operation,
            ),
            admission,
        )
        for field in (
            "package_id", "runtime_cohort", "recoverer_sha256",
            "registration_sha256", "qualification_sha256", "supervisor_sha256",
            "observer_sha256", "observer_policy_sha256",
        ):
            changed = replace(implementation, **{field: "f" * 64})
            with self.subTest(field=field), self.assertRaises(QualificationInputError):
                validate_qualification_admission(
                    admission, support, changed, context["policy"],
                    context["runtime_tuple"], case.operation,
                )
        for field in ("plan_format", "receipt_format", "journal_format", "recovery_format"):
            with self.subTest(field=field), self.assertRaises(QualificationInputError):
                replace(implementation, **{field: True})

        for field in (
            "runtime_tuple_sha256", "policy_sha256", "implementation_sha256",
            "intended_entry_sha256", "independent_review_sha256",
            "support_matrix_sha256",
        ):
            changed = replace(support, **{field: "e" * 64})
            with self.subTest(support_field=field), self.assertRaises(
                QualificationInputError
            ):
                validate_qualification_admission(
                    admission, changed, implementation, context["policy"],
                    context["runtime_tuple"], case.operation,
                )

        admission_record = admission.public_dict()
        for field in (
            "runtime_tuple_sha256", "policy_sha256", "implementation_sha256",
            "support_decision_sha256", "intended_entry_sha256",
            "independent_review_sha256", "support_matrix_sha256",
        ):
            changed = dict(admission_record)
            changed[field] = "e" * 64
            with self.subTest(admission_field=field), self.assertRaises(
                QualificationInputError
            ):
                validate_qualification_admission(
                    changed, support, implementation, context["policy"],
                    context["runtime_tuple"], case.operation,
                )

        fake = {
            "admitted": True,
            "owner_authority": "independent_genuine_runner_reviewer",
            "support_decision_sha256": support.digest(),
        }
        with self.assertRaisesRegex(QualificationInputError, "unsupported fields"):
            validate_qualification_admission(
                fake, support, implementation, context["policy"],
                context["runtime_tuple"], case.operation,
            )

    def test_native_attempt_and_semantic_identity_bind_every_current_input(self):
        case = self.native_case()
        context = self.native_context(case)
        binding = context["binding"]
        semantic = context["semantic"]
        self.assertIsInstance(context["execution"], NativeExecutionAdmission)
        self.assertIsInstance(binding, NativeAttemptBinding)
        self.assertIsInstance(semantic, SemanticNativeResultIdentity)
        self.assertEqual(binding.source_path, self.claude_path)
        self.assertEqual(binding.executable_path, self.claude_tuple.executable_path)
        self.assertEqual(binding.python_executable, "/usr/bin/python3")
        self.assertEqual(
            binding.adapter_path,
            self.home + "/.claude/skills/council/scripts/council_mcp.py",
        )
        self.assertEqual(binding.write_set, (self.claude_path,))
        self.assertEqual(binding.permitted_inverse, CLAUDE_REMOVE)
        self.assertNotIn("post_source_sha256", semantic.public_dict())

        launch = self.launch_receipt(case)
        post = self.post_receipt(case, self.claude_target)
        drifts = (
            replace(binding, source_sha256="e" * 64),
            replace(binding, source_identity_sha256="e" * 64),
            replace(binding, executable_path="/synthetic/bin/other"),
            replace(binding, argv=binding.argv + ("extra",)),
            replace(binding, qualification_admission_sha256="e" * 64),
            replace(binding, implementation_sha256="e" * 64),
            replace(binding, quiescent_decision_sha256="e" * 64),
            replace(binding, environment_sha256="e" * 64),
        )
        for changed in drifts:
            calls = []
            with self.subTest(field=changed), self.assertRaises(QualificationInputError):
                run_admitted_attempt(
                    changed, semantic, context["family"], context["admission"],
                    context["support"],
                    context["implementation"], context["policy"], case,
                    context["execution"], context["runtime_tuple"],
                    lambda *_: calls.append("journal"),
                    lambda *_: calls.append("launch") or launch,
                    lambda *_: calls.append("observe") or post,
                )
            self.assertEqual(calls, [])

        execution_drifts = (
            replace(
                context["execution"], config_path=self.home + "/other.json",
                write_set=(self.home + "/other.json",),
            ),
            replace(context["execution"], state_root=self.home + "/other-state"),
            replace(context["execution"], neutral_cwd="/synthetic/other"),
            replace(context["execution"], environment_keys=("HOME",)),
            replace(context["execution"], observer_policy_sha256="e" * 64),
            replace(context["execution"], quiescent_decision_sha256="e" * 64),
        )
        for changed in execution_drifts:
            calls = []
            with self.subTest(execution=changed), self.assertRaises(
                QualificationInputError
            ):
                run_admitted_attempt(
                    binding, semantic, context["family"], context["admission"],
                    context["support"],
                    context["implementation"], context["policy"], case, changed,
                    context["runtime_tuple"],
                    lambda *_: calls.append("journal"),
                    lambda *_: calls.append("launch") or launch,
                    lambda *_: calls.append("observe") or post,
                )
            self.assertEqual(calls, [])

        changed_case = replace(
            case,
            stdio=StdioSpec("/synthetic/python3", self.adapter),
        )
        calls = []
        with self.assertRaises(QualificationInputError):
            run_admitted_attempt(
                binding, semantic, context["family"], context["admission"],
                context["support"],
                context["implementation"], context["policy"], changed_case,
                context["execution"], context["runtime_tuple"],
                lambda *_: calls.append("journal"),
                lambda *_: calls.append("launch") or launch,
                lambda *_: calls.append("observe") or post,
            )
        self.assertEqual(calls, [])

    def test_native_attempt_family_is_stable_across_two_bound_sequences(self):
        case = self.native_case()
        context = self.native_context(case)
        family = context["family"]
        self.assertIsInstance(family, NativeAttemptFamilyIdentity)
        self.assertEqual(family.max_attempt_sequences, 2)
        self.assertEqual(
            context["binding"].attempt_family_sha256, family.digest()
        )
        self.assertIsNone(
            context["binding"].previous_attempt_terminal_sha256
        )
        execution_one = replace(
            context["execution"],
            execution_id="native-execution-002",
            quiescent_decision_sha256="e" * 64,
        )
        binding_one = build_native_attempt_binding(
            context["binding"].operation_id,
            1,
            context["mode"],
            case,
            execution_one,
            context["runtime_tuple"],
            context["admission"],
            context["support"],
            context["implementation"],
            context["policy"],
            family,
            "f" * 64,
        )
        semantic_one = build_semantic_native_result_identity(
            binding_one, execution_one.ownership, family
        )
        self.assertEqual(semantic_one, context["semantic"])
        public_semantic = semantic_one.public_dict()
        for absent in (
            "sequence",
            "attempt_binding_sha256",
            "execution_admission_sha256",
            "quiescent_decision_sha256",
        ):
            self.assertNotIn(absent, public_semantic)
        self.assertEqual(
            public_semantic["attempt_family_sha256"], family.digest()
        )
        self.assertEqual(public_semantic["max_attempt_sequences"], 2)
        self.assertNotEqual(binding_one.digest(), context["binding"].digest())
        self.assertEqual(binding_one.previous_attempt_terminal_sha256, "f" * 64)
        with self.assertRaisesRegex(QualificationInputError, "family differs"):
            build_native_attempt_binding(
                context["binding"].operation_id,
                1,
                context["mode"],
                case,
                execution_one,
                context["runtime_tuple"],
                context["admission"],
                context["support"],
                context["implementation"],
                context["policy"],
                replace(family, initial_source_sha256="0" * 64),
                "f" * 64,
            )

        semantic = context["semantic"]
        binding = context["binding"]
        launch = self.launch_receipt(case)
        post = self.post_receipt(case, self.native_target(case))
        changed_semantic = replace(semantic, intended_entry_sha256="e" * 64)
        calls = []
        with self.assertRaisesRegex(QualificationInputError, "semantic"):
            run_admitted_attempt(
                binding, changed_semantic, context["family"],
                context["admission"], context["support"],
                context["implementation"], context["policy"], case,
                context["execution"], context["runtime_tuple"],
                lambda *_: calls.append("journal"),
                lambda *_: calls.append("launch") or launch,
                lambda *_: calls.append("observe") or post,
            )
        self.assertEqual(calls, [])

    def test_admitted_native_v3_attempts_cover_all_operations_and_modes(self):
        with mock.patch.object(registration, "_tomllib", SyntheticTomllib):
            for operation in (
                CLAUDE_ENSURE, CLAUDE_REMOVE, CODEX_ENSURE, CODEX_REMOVE
            ):
                case = self.native_case(operation)
                target = self.native_target(case)
                ordinary = "forward" if operation.endswith("_ensure") else "inverse"
                for mode in (ordinary, "recovery"):
                    context = self.native_context(case, mode)
                    result, events = self.run_native(
                        case, context,
                        self.launch_receipt(case, context["runtime_tuple"]),
                        self.post_receipt(case, target, context["runtime_tuple"]),
                    )
                    with self.subTest(operation=operation, mode=mode):
                        self.assertEqual(result["classification"], "observed_target")
                        self.assertEqual(result["mode"], mode)
                        self.assertEqual(result["launch_count"], 1)
                        self.assertEqual(result["observation_count"], 1)
                        self.assertEqual(
                            [item[0] for item in events],
                            ["journal", "launch", "observe"],
                        )
                        self.assertFalse(result["qualification_claimed"])
                        self.assertFalse(result["native_support_claimed"])

    def test_admitted_attempt_classifies_prior_and_uncertainty_without_retry(self):
        case = self.native_case()
        context = self.native_context(case)
        prior = self.post_receipt(
            case, case.before,
            complement=self.observation(case.before).complement_sha256,
            changed_paths=(),
        )
        scenarios = (
            (
                self.launch_receipt(
                    case, result_kind="pre_spawn_failure", process_state="not_started",
                    returncode=None,
                ),
                prior,
                "observed_prior",
                None,
            ),
            (
                self.launch_receipt(
                    case, result_kind="timeout", process_state="surviving",
                    returncode=None, timed_out=True,
                ),
                self.post_receipt(case, self.native_target(case)),
                "unknown",
                "possible_live_writer",
            ),
            (
                self.launch_receipt(case, network_state="activity_observed"),
                self.post_receipt(case, self.native_target(case)),
                "unknown",
                "unexpected_network_activity",
            ),
            (
                self.launch_receipt(
                    case, result_kind="output_lost", output_lost=True, returncode=None,
                ),
                self.post_receipt(case, self.native_target(case)),
                "observed_target",
                None,
            ),
        )
        for launch, post, expected, issue in scenarios:
            result, events = self.run_native(case, context, launch, post)
            with self.subTest(result_kind=launch.result_kind, issue=issue):
                self.assertEqual(result["classification"], expected)
                self.assertEqual(
                    [item[0] for item in events], ["journal", "launch", "observe"]
                )
                if issue:
                    self.assertIn(issue, result["issues"])

    def test_admitted_attempt_observer_drifts_stay_unknown_and_redacted(self):
        case = self.native_case()
        context = self.native_context(case)
        target = self.native_target(case)
        changed_tuple = replace(self.claude_tuple, executable_sha256="e" * 64)
        posts = (
            (self.post_receipt(case, target, changed_tuple), "runtime_tuple_changed"),
            (self.post_receipt(case, target, complement="e" * 64), "complement_mismatch"),
            (
                self.post_receipt(
                    case, target,
                    changed_paths=(case.before.path, self.home + "/SYNTHETIC_WRITE_SECRET"),
                ),
                "incidental_write_mismatch",
            ),
            (self.post_receipt(case, target, sentinel_started=True), "unexpected_sentinel_start"),
        )
        for post, issue in posts:
            result, events = self.run_native(
                case, context, self.launch_receipt(case), post
            )
            with self.subTest(issue=issue):
                self.assertEqual(result["classification"], "unknown")
                self.assertIn(issue, result["issues"])
                self.assertEqual(
                    [item[0] for item in events], ["journal", "launch", "observe"]
                )

        launch_cases = (
            (
                self.launch_receipt(
                    case, result_kind="timeout", process_state="unidentified",
                    returncode=None, timed_out=True,
                ),
                "possible_live_writer",
            ),
            (self.launch_receipt(case, network_state="unobserved"), "network_unobserved"),
        )
        for launch, issue in launch_cases:
            result, _ = self.run_native(
                case, context, launch, self.post_receipt(case, target)
            )
            self.assertEqual(result["classification"], "unknown")
            self.assertIn(issue, result["issues"])

        secret = b"SYNTHETIC_NATIVE_V3_OUTPUT_SECRET"
        result, _ = self.run_native(
            case, context,
            self.launch_receipt(case, returncode=23, stdout=secret, stderr=secret),
            self.post_receipt(case, target),
        )
        self.assertEqual(result["classification"], "observed_target")
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret.decode(), encoded)
        self.assertNotIn("SYNTHETIC_CONFIG_SECRET", encoded)
        self.assertNotIn("SYNTHETIC_WRITE_SECRET", encoded)

    def test_admitted_attempt_authority_and_journal_fail_before_launch(self):
        case = self.native_case()
        context = self.native_context(case)
        target = self.native_target(case)
        launch = self.launch_receipt(case)
        post = self.post_receipt(case, target)
        calls = []
        with self.assertRaisesRegex(QualificationInputError, "journal"):
            run_admitted_attempt(
                context["binding"], context["semantic"], context["family"],
                context["admission"],
                context["support"], context["implementation"], context["policy"],
                case, context["execution"], context["runtime_tuple"],
                lambda record, digest: calls.append("journal") or "0" * 64,
                lambda *_: calls.append("launch") or launch,
                lambda *_: calls.append("observe") or post,
            )
        self.assertEqual(calls, ["journal"])

        changed_support = replace(context["support"], support_matrix_sha256="e" * 64)
        changed_admission = replace(
            context["admission"], support_decision_sha256="e" * 64
        )
        invalid = (
            (changed_support, context["admission"], context["implementation"]),
            (context["support"], changed_admission, context["implementation"]),
            (
                context["support"], context["admission"],
                replace(context["implementation"], supervisor_sha256="e" * 64),
            ),
        )
        for support, admission, implementation in invalid:
            calls = []
            with self.assertRaises(QualificationInputError):
                run_admitted_attempt(
                    context["binding"], context["semantic"], context["family"],
                    admission, support,
                    implementation, context["policy"], case, context["execution"],
                    context["runtime_tuple"],
                    lambda *_: calls.append("journal"),
                    lambda *_: calls.append("launch") or launch,
                    lambda *_: calls.append("observe") or post,
                )
            self.assertEqual(calls, [])

        with self.assertRaises(QualificationInputError):
            replace(context["execution"], source_file_exists=1)
        with self.assertRaises(QualificationInputError):
            replace(context["binding"], sequence=True)

    def test_collector_never_opens_files_or_spawns(self):
        case = self.case()
        launch = self.launch_receipt(case)
        post = self.post_receipt(case, self.claude_target)
        with mock.patch("builtins.open", side_effect=AssertionError("open")), mock.patch.object(
            subprocess, "run", side_effect=AssertionError("spawn")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("spawn")
        ):
            packet, counts = self.collect(case, launch, post)
        self.assertEqual(packet["classification"], "observed_target")
        self.assertEqual(counts, {"launch": 1, "observe": 1})

        qualified = self.qualified_case()
        qualified_launch = self.launch_receipt(qualified)
        qualified_post = self.post_receipt(qualified, self.claude_target)
        with mock.patch("builtins.open", side_effect=AssertionError("open")), mock.patch.object(
            subprocess, "run", side_effect=AssertionError("spawn")
        ), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("spawn")
        ):
            result, events = self.qualified_attempt(
                qualified, qualified_launch, qualified_post
            )
        self.assertEqual(result["classification"], "observed_target")
        self.assertEqual([item[0] for item in events], ["journal", "launch", "observe"])


if __name__ == "__main__":
    unittest.main()
