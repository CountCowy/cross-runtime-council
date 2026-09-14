#!/usr/bin/env python3
"""D-only integration records against the pinned C2 artifact contract."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import council_lifecycle as lifecycle
import council_registration_qualification as qualification
from generate_protocol import normalized_stamps
from council_registration import (
    ArtifactReceiptBinding,
    CLAUDE_ENSURE,
    CLAUDE_USER,
    ConfigDocument,
    NativeAttemptProjection,
    OPENCODE_ENSURE,
    OPENCODE_GLOBAL,
    QualificationReference,
    QuiescentDecisionProjection,
    RegistrationInputError,
    RegistrationResultProjection,
    StdioSpec,
    build_integration_preview,
    canonical_integration_preview_bytes,
    observe_claude_config,
    observe_opencode_config,
    operation_record,
    plan_opencode_candidate,
    validate_c2_contract,
)


SCRIPTS = Path(__file__).resolve().parent
FIXTURES = SCRIPTS / "fixtures/registration"
RECOVERY = lifecycle.recovery


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root):
    records = []
    if root.exists():
        for path in sorted(root.rglob("*")):
            details = path.lstat()
            records.append(
                (
                    str(path.relative_to(root)),
                    details.st_mode,
                    hashlib.sha256(path.read_bytes()).hexdigest()
                    if path.is_file() and not path.is_symlink()
                    else None,
                )
            )
    return records


class SyntheticNativeEffects:
    def __init__(self, target, runtime_tuple, implementation, outcomes=None):
        self.target = target
        self.runtime_tuple = runtime_tuple
        self.implementation = implementation
        self.events = []
        self.outcomes = list(outcomes or ("target",))

    def arm_observer(self, binding):
        self.events.append("observer-armed")
        return {
            "session_sha256": "6" * 64,
            "implementation_sha256": self.implementation.observer_sha256,
            "policy_sha256": binding.observer_policy_sha256,
            "armed_before_release": True,
            "complete": True,
        }

    def spawn_blocked(self, argv, binding, observer):
        self.events.append("supervisor-blocked")
        return object(), {
            "pid": 1234,
            "pgid": 1234,
            "start_generation_sha256": "7" * 64,
            "attempt_lock_identity": {"device": 8, "inode": 9},
            "observer_session_sha256": observer["session_sha256"],
        }

    def release_and_wait(self, handle, binding):
        self.events.append("release-authorized")
        outcome = self.outcomes.pop(0)
        if outcome == "target":
            with open(binding.source_path, "r+b") as stream:
                stream.seek(0)
                stream.write(self.target.content)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
        return qualification.LaunchReceipt(
            (
                binding.runtime + "-add-absent"
                if binding.operation.endswith("_ensure")
                else binding.runtime + "-remove-present"
            ),
            binding.argv,
            self.runtime_tuple.digest(),
            "exit",
            "terminated",
            "a" * 64,
            "no_activity_observed",
            "b" * 64,
            0,
            False,
            False,
            b"",
            b"",
        )

    def positive_absence(self, supervisor):
        self.events.append("positive-absence")
        return True

    def observe_once(self, binding):
        self.events.append("passive-observation")
        after = ConfigDocument(
            binding.source_path,
            binding.source_scope,
            Path(binding.source_path).read_bytes(),
        )
        observation = observe_claude_config(
            after,
            StdioSpec(binding.python_executable, binding.adapter_path),
            scope_inputs_complete=True,
        )
        return qualification.ObservationReceipt(
            (
                binding.runtime + "-add-absent"
                if binding.operation.endswith("_ensure")
                else binding.runtime + "-remove-present"
            ),
            after,
            self.runtime_tuple,
            observation.complement_sha256,
            (binding.source_path,),
            False,
        )


class RegistrationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.interface = json.loads(
            (FIXTURES / "c2-interface-5a4160b.json").read_text()
        )
        self.contract = lifecycle._c2_dependency_contract()
        self.summary = {
            "receipt_id": "receipt-artifact",
            "receipt_sha256": "a" * 64,
            "package_id": "b" * 64,
            "runtime_cohort": "c" * 64,
        }
        self.receipt = ArtifactReceiptBinding.from_summary(self.summary)
        self.spec = StdioSpec(
            "/usr/bin/python3",
            "/Users/fixture/.claude/skills/council/scripts/council_mcp.py",
        )

    def c2_preview(self, *, summary=True, eligible=True, blockers=None):
        current_summary = self.summary if summary else None
        preview = {
            "planning_preview_format": 1,
            "executable": False,
            "non_executable_reason": "fixture mirrors the pinned C2 preview shape",
            "kind": "upgrade" if summary else "install",
            "roots": {
                "state": "/Users/fixture/.claude/peer-consults",
                "payload": "/Users/fixture/.claude/skills/council",
                "opencode": "/Users/fixture/.config/opencode",
            },
            "release": {
                "root": "/private/tmp/release",
                "manifest_sha256": "d" * 64,
                "package_id": "e" * 64,
                "runtime_cohort": "f" * 64,
                "artifact_count": 5,
            },
            "current": {
                "status": "committed" if summary else "legacy_unmanaged",
                "certified": bool(summary),
                "reason": "fixture",
                "summary": current_summary,
            },
            "eligible_for_integration": eligible,
            "blockers": list(blockers or ()),
            "required_gates": [
                "authentic-reader-support",
                "c1-terminal-admission-integration",
                "external-recovery-check-plan",
                "under-lease-liveness-and-ownership-revalidation",
            ],
            "payload_cache_backup": [],
            "units": [],
            "artifacts": [],
        }
        return preview, lifecycle.canonical_preview_bytes(preview)

    def opencode_record(self, content=b'{"plugin":[]}'):
        document = ConfigDocument(
            "/Users/fixture/.config/opencode/opencode.json",
            OPENCODE_GLOBAL,
            content,
        )
        observation = observe_opencode_config(
            document, source_inputs_complete=True
        )
        candidate = plan_opencode_candidate(
            OPENCODE_ENSURE, document, source_inputs_complete=True
        )
        return operation_record(
            "opencode-ensure", OPENCODE_ENSURE, observation, candidate=candidate
        )

    def claude_record(self):
        document = ConfigDocument(
            "/Users/fixture/.claude.json", CLAUDE_USER, b"{}"
        )
        observation = observe_claude_config(
            document, self.spec, scope_inputs_complete=True
        )
        qualification = QualificationReference("1" * 64, "2" * 64)
        return operation_record(
            "claude-ensure",
            CLAUDE_ENSURE,
            observation,
            qualification=qualification,
        )

    def installed_release(self):
        temporary = tempfile.TemporaryDirectory(
            prefix="registration-integration-", dir="/private/tmp"
        )
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        release = root / "release"
        completed = subprocess.run(
            [sys.executable, "-B", "scripts/build_release.py", "--output", str(release)],
            cwd=SCRIPTS.parent,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        state = root / "state"
        payload = root / "payload-parent/council"
        opencode = root / "opencode"
        opencode.mkdir()
        (opencode / "opencode.json").write_bytes(
            b'{"theme":"fixture","plugin":[]}\n'
        )
        lifecycle.execute_operation(
            "install",
            release,
            state,
            payload,
            opencode,
            maintenance_window_confirmed=True,
            transaction_id="txn-registration-install",
        )
        return state, payload, opencode

    def installed_native_release(self):
        temporary = tempfile.TemporaryDirectory(
            prefix="registration-native-v3-", dir="/private/tmp"
        )
        self.addCleanup(temporary.cleanup)
        home = Path(temporary.name) / "home"
        home.mkdir()
        release = Path(temporary.name) / "release"
        completed = subprocess.run(
            [sys.executable, "-B", "scripts/build_release.py", "--output", str(release)],
            cwd=SCRIPTS.parent,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        state = home / ".claude/peer-consults"
        payload = home / ".claude/skills/council"
        opencode = home / ".config/opencode"
        opencode.mkdir(parents=True)
        (opencode / "opencode.json").write_bytes(b'{"plugin":[]}\n')
        lifecycle.execute_operation(
            "install",
            release,
            state,
            payload,
            opencode,
            maintenance_window_confirmed=True,
            transaction_id="txn-native-v3-install",
        )
        return home, state, payload, opencode

    def native_authority(
        self, home, state, payload, operation, *, executable_program=None
    ):
        config_path = home / ".claude.json"
        ensure = operation.endswith("_ensure")
        if ensure:
            config_path.write_bytes(b'{"mcpServers":{}}')
        policy = lifecycle._native_policy()
        summary = lifecycle.inspect_ownership(
            state, payload, home / ".config/opencode"
        )["management"]["summary"]
        implementation = lifecycle._native_implementation(summary, policy)
        executable = home / "bin/claude"
        executable.parent.mkdir(exist_ok=True)
        executable.write_bytes(
            executable_program or b"synthetic-native-runtime"
        )
        executable.chmod(0o700)
        runtime_tuple = qualification.RuntimeTuple(
            "claude",
            str(executable),
            str(executable.resolve()),
            hashlib.sha256(executable.read_bytes()).hexdigest(),
            "2.1.241",
            "Darwin",
            "arm64",
        )
        stdio = StdioSpec(
            "/usr/bin/python3", str(payload / "scripts/council_mcp.py")
        )
        target = ConfigDocument(
            str(config_path),
            CLAUDE_USER,
            (
                (
                    b'{"mcpServers":{"council":{"type":"stdio","command":'
                    b'"/usr/bin/python3","args":["'
                    + str(payload / "scripts/council_mcp.py").encode()
                    + b'"]}}}'
                )
                if ensure
                else b'{"mcpServers":{}}'
            ),
        )
        intended_entry = (
            observe_claude_config(
                target, stdio, scope_inputs_complete=True
            ).entry_sha256
            if ensure
            else None
        )
        selected = next(
            item for item in policy.policies if item["operation"] == operation
        )
        evidence = tuple(
            (
                case_id,
                hashlib.sha256((case_id + "-case").encode()).hexdigest(),
                hashlib.sha256((case_id + "-packet").encode()).hexdigest(),
                "genuine_runner_observation",
            )
            for case_id in qualification._required_cases(operation)
        )
        support = qualification.QualificationSupportDecision(
            "synthetic-support",
            operation,
            "claude",
            runtime_tuple.digest(),
            selected["policy_id"],
            selected["version"],
            policy.digest(),
            implementation.digest(),
            intended_entry,
            evidence,
            "4" * 64,
            "5" * 64,
            "independent_genuine_runner_reviewer",
            True,
            False,
        )
        admission_value = qualification.QualificationAdmission(
            "synthetic-owner-admission",
            operation,
            "claude",
            runtime_tuple.digest(),
            selected["policy_id"],
            selected["version"],
            policy.digest(),
            implementation.digest(),
            support.digest(),
            intended_entry,
            evidence,
            support.independent_review_sha256,
            support.support_matrix_sha256,
            "council_lifecycle_qualification_owner",
            True,
        )
        authority = {
            "format": "council-native-qualification-authority-v1",
            "runtime_tuple": runtime_tuple.public_dict(),
            "qualification_support": support.public_dict(),
            "qualification_admission": admission_value.public_dict(),
        }
        path = state / admission_value.fixed_relative_path
        path.parent.mkdir(mode=0o700, exist_ok=True)
        path.write_bytes(lifecycle.recovery.json_bytes(authority))
        path.chmod(0o600)
        return runtime_tuple, target

    def pending_native_sequence(self, outcomes=("prior", "target")):
        home, state, payload, opencode = self.installed_native_release()
        runtime_tuple, target = self.native_authority(
            home, state, payload, qualification.CLAUDE_ENSURE
        )
        planned = lifecycle.plan_registration(
            "claude", "register", state, payload, opencode, native_home=home
        )
        ownership = lifecycle.inspect_ownership(state, payload, opencode)
        implementation = lifecycle._native_implementation(
            ownership["management"]["summary"], lifecycle._native_policy()
        )
        effects = SyntheticNativeEffects(
            target, runtime_tuple, implementation, outcomes=outcomes
        )
        with self.assertRaisesRegex(Exception, "did not reach its admitted target"):
            lifecycle.execute_registration(
                "claude",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="native-sequence-zero",
                transaction_id="txn-native-pending-%d" % len(self._cleanups),
                native_home=home,
                native_effects=effects,
            )
        admission_value = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        transaction = (
            state
            / ".council-lifecycle/v1/transactions"
            / admission_value["transaction_id"]
        )
        plan = json.loads((transaction / "plan.json").read_text())
        spec = importlib.util.spec_from_file_location(
            "copied_native_%d" % len(self._cleanups),
            plan["recovery"]["tool_path"],
        )
        copied = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(copied)
        decision = {
            "confirmed": True,
            "plan_sha256": planned["plan_sha256"],
            "invocation_id": "native-sequence-one",
            "sequence": 1,
            "goal": "target",
        }
        return state, transaction, copied, decision, effects

    def test_pinned_contract_matches_real_c2_sources_and_recovery_description(self):
        self.assertEqual(
            digest(FIXTURES / "c2-interface-5a4160b.json"),
            "992d9c6a8a66fae58605b076b202b9019af3e8b984da9cde3d2410abe624eb02",
        )
        self.assertEqual(
            self.interface["source_commit"], self.contract["source_commit"]
        )
        self.assertEqual(
            self.interface["source_hashes"], self.contract["source_hashes"]
        )
        self.assertEqual(
            self.interface["recovery_executor"]["unit_ids"],
            self.contract["unit_ids"],
        )
        self.assertEqual(
            self.interface["recovery_executor"]["required_operations"],
            self.contract["required_operations"],
        )
        self.assertEqual(validate_c2_contract(self.contract), self.contract)
        # Verify the pin against the sources this checkout actually loads, not
        # against an ancestor commit object: CI clones at depth 1, so
        # C2_SOURCE_COMMIT is recorded provenance and is never resolvable here.
        # The two C2 readers D does not edit differ from the pinned bytes only
        # in their regenerated identity literals, so re-stamping them with the
        # landed C2 identity must reproduce the pinned bytes exactly.
        landed = self.interface["release"]
        unchanged = ("scripts/council_admission.py", "scripts/council_inspect.py")
        restamped = {}
        for key in unchanged:
            text = normalized_stamps((SCRIPTS.parent / key).read_text())
            self.assertIn('PACKAGE_ID = "unstamped"', text)
            text = text.replace(
                'PACKAGE_ID = "unstamped"',
                'PACKAGE_ID = "%s"' % landed["package_id"],
            ).replace(
                'RUNTIME_COHORT = "unstamped"',
                'RUNTIME_COHORT = "%s"' % landed["runtime_cohort"],
            )
            restamped[key] = hashlib.sha256(text.encode()).hexdigest()
        self.assertEqual(
            {key: self.contract["source_hashes"][key] for key in unchanged},
            restamped,
        )
        description = RECOVERY.describe()
        self.assertEqual(description["recovery_format"], 2)
        self.assertEqual(description["formats"]["plan"], [1, 2])
        self.assertEqual(description["unit_ids"], self.contract["unit_ids"])
        self.assertEqual(
            description["required_operations"],
            self.contract["required_operations"],
        )
        self.assertIn(
            "replace-registration-v1",
            description["registration_required_operations"],
        )
        for interface in self.contract["planner_interfaces"]:
            self.assertTrue(callable(getattr(lifecycle, interface.split("(", 1)[0])))
        for interface in self.contract["inspection_interfaces"]:
            self.assertTrue(
                callable(getattr(lifecycle.inspect, interface.split("(", 1)[0]))
            )
        for interface in self.contract["recovery_interfaces"]:
            self.assertTrue(callable(getattr(RECOVERY, interface.split("(", 1)[0])))

    def test_real_c2_preview_binds_exact_opencode_candidate_and_receipt(self):
        _preview, c2_bytes = self.c2_preview()
        record = self.opencode_record()
        result = build_integration_preview(
            c2_bytes, self.contract, [record], artifact_receipt=self.receipt
        )
        self.assertFalse(result["executable"])
        self.assertTrue(result["records_ready_for_shared_integration"])
        self.assertEqual(result["artifact_receipt"], self.summary)
        self.assertEqual(result["operations"][0]["entry_disposition"], "created")
        self.assertEqual(result["operations"][0]["candidate_outcome"], "candidate")
        self.assertFalse(result["operations"][0]["automatic_apply_eligible"])
        self.assertEqual(
            json.loads(canonical_integration_preview_bytes(result)), result
        )

    def test_native_record_retains_ineligible_qualification_and_refusal(self):
        _preview, c2_bytes = self.c2_preview()
        result = build_integration_preview(
            c2_bytes,
            self.contract,
            [self.claude_record()],
            artifact_receipt=self.receipt,
        )
        self.assertIn(
            "native-behavior-unqualified", result["non_executable_reasons"]
        )
        operation = result["operations"][0]
        self.assertFalse(operation["qualification"]["qualification_eligible"])
        self.assertIsNone(operation["candidate_sha256"])
        self.assertFalse(operation["automatic_apply_eligible"])
        with self.assertRaisesRegex(
            RegistrationInputError, "cannot promote native qualification"
        ):
            QualificationReference("1" * 64, "2" * 64, True)

    def test_matching_preexisting_opencode_entry_remains_unowned_and_unchanged(self):
        record = self.opencode_record(b'{"plugin":["./council-plugin.ts"]}')
        self.assertEqual(record.entry_disposition, "matching_preexisting_unowned")
        self.assertEqual(record.candidate_outcome, "unchanged")
        self.assertIsNone(record.candidate_sha256)
        _preview, c2_bytes = self.c2_preview()
        result = build_integration_preview(
            c2_bytes, self.contract, [record], artifact_receipt=self.receipt
        )
        self.assertTrue(result["records_ready_for_shared_integration"])
        self.assertFalse(result["operations"][0]["automatic_apply_eligible"])

    def test_contract_receipt_and_canonical_preview_drift_refuse(self):
        _preview, c2_bytes = self.c2_preview()
        record = self.opencode_record()
        changed = copy.deepcopy(self.contract)
        changed["format_versions"]["plan"] = 2
        with self.assertRaisesRegex(RegistrationInputError, "format versions changed"):
            validate_c2_contract(changed)
        wrong_receipt = ArtifactReceiptBinding(
            "receipt-artifact", "9" * 64, "b" * 64, "c" * 64
        )
        with self.assertRaisesRegex(RegistrationInputError, "differs from C2"):
            build_integration_preview(
                c2_bytes,
                self.contract,
                [record],
                artifact_receipt=wrong_receipt,
            )
        noncanonical = json.dumps(json.loads(c2_bytes)).encode("utf-8")
        with self.assertRaisesRegex(RegistrationInputError, "not canonical C2 JSON"):
            build_integration_preview(
                noncanonical,
                self.contract,
                [record],
                artifact_receipt=self.receipt,
            )
        changed = copy.deepcopy(self.contract)
        changed["source_commit"] = "0" * 40
        with self.assertRaisesRegex(RegistrationInputError, "source commit changed"):
            validate_c2_contract(changed)
        changed = copy.deepcopy(self.contract)
        changed["source_hashes"]["scripts/council_recover.py"] = "0" * 64
        with self.assertRaisesRegex(RegistrationInputError, "source hashes changed"):
            validate_c2_contract(changed)
        for name in (
            "c2-interface-ad74a68.json",
            "c2-interface-1e2401d.json",
            "c2-interface-453acae.json",
            "c2-interface-8d1ee58.json",
        ):
            with self.subTest(stale_interface=name):
                stale = json.loads((FIXTURES / name).read_text())
                with self.assertRaises(RegistrationInputError):
                    validate_c2_contract(stale)

    def test_c2_v1_still_refuses_registration_native_and_config_operations(self):
        formats = json.loads(
            (SCRIPTS / "fixtures/lifecycle/format-cases-v1.json").read_text()
        )
        self.assertIn("native-or-configuration-operation", formats["refused"])
        for operation in (
            CLAUDE_ENSURE,
            OPENCODE_ENSURE,
        ):
            self.assertNotIn(operation, RECOVERY.REQUIRED_OPERATIONS)
        self.assertEqual(RECOVERY.PLAN_FORMAT, 1)
        self.assertEqual(RECOVERY.RECEIPT_FORMAT, 1)

    def test_blocked_c2_preview_and_refused_registration_remain_nonexecutable(self):
        blocker = {
            "code": "fixture-blocker",
            "unit_id": "payload",
            "path": ".",
            "reason": "fixture",
        }
        _preview, c2_bytes = self.c2_preview(eligible=False, blockers=[blocker])
        document = ConfigDocument(
            "/Users/fixture/.config/opencode/opencode.json",
            OPENCODE_GLOBAL,
            b'{"plugins":[]}',
        )
        observation = observe_opencode_config(
            document, source_inputs_complete=True
        )
        candidate = plan_opencode_candidate(
            OPENCODE_ENSURE, document, source_inputs_complete=True
        )
        record = operation_record(
            "opencode-refused", OPENCODE_ENSURE, observation, candidate=candidate
        )
        result = build_integration_preview(
            c2_bytes, self.contract, [record], artifact_receipt=self.receipt
        )
        self.assertFalse(result["records_ready_for_shared_integration"])
        self.assertIn("c2-artifact-preview-blocked", result["non_executable_reasons"])
        self.assertIn(
            "registration-operation-refused", result["non_executable_reasons"]
        )
        changed = copy.deepcopy(result)
        changed["executable"] = True
        with self.assertRaisesRegex(RegistrationInputError, "remain non-executable"):
            canonical_integration_preview_bytes(changed)

    def test_future_decision_attempt_and_result_records_remain_projections(self):
        decision = QuiescentDecisionProjection(
            "1" * 64,
            "invocation-1",
            "target",
            ("claude", "codex"),
            (
                "/Users/fixture/.claude.json",
                "/Users/fixture/.codex/config.toml",
            ),
            True,
        )
        self.assertTrue(decision.public_dict()["projection_only"])
        attempt = NativeAttemptProjection(
            "claude-ensure",
            1,
            "unknown",
            "2" * 64,
            "3" * 64,
            "4" * 64,
            "5" * 64,
        )
        self.assertFalse(attempt.public_dict()["committed"])
        result = RegistrationResultProjection(
            "claude-ensure",
            "6" * 64,
            "created",
            "stored_config_verified",
            "unknown",
            "required",
            "unobserved",
        )
        self.assertEqual(result.public_dict()["effective_scope"], "unknown")
        self.assertEqual(
            result.public_dict()["authenticated_readiness"], "unobserved"
        )
        with self.assertRaisesRegex(
            RegistrationInputError, "prepared native attempt has outcome evidence"
        ):
            NativeAttemptProjection(
                "claude-ensure",
                0,
                "prepared",
                "2" * 64,
                "3" * 64,
                None,
                None,
            )

    def test_opencode_registration_round_trip_uses_v2_receipt_and_separate_readiness(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        self.assertTrue(planned["executable"])
        before = tree_digest(state.parent)
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "exact plan digest"
        ):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan="0" * 64,
                invocation_id="wrong-plan",
            )
        self.assertEqual(tree_digest(state.parent), before)
        events = []
        result = lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=planned["plan_sha256"],
            invocation_id="register-1",
            transaction_id="txn-registration-ensure",
            failpoint=events.append,
        )
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["registration"]["effective_scope"], "unknown")
        self.assertEqual(
            result["registration"]["authenticated_readiness"], "unobserved"
        )
        config = json.loads((opencode / "opencode.json").read_text())
        self.assertEqual(config["plugin"], ["./council-plugin.ts"])
        receipt = json.loads(
            (
                state
                / ".council-lifecycle/v1/receipts"
                / (result["receipt_id"] + ".json")
            ).read_text()
        )
        self.assertEqual(receipt["receipt_format"], 2)
        self.assertEqual(receipt["registrations"][0]["ownership_origin"], "created")
        registration_replace = events.index(
            "before:replace:registration:opencode-council:target"
        )
        last_artifact_progress = max(
            index
            for index, event in enumerate(events)
            if event.startswith("after:replace:progress:")
            and "registration" not in event
        )
        self.assertGreater(registration_replace, last_artifact_progress)
        status = lifecycle.status(state, payload, opencode)
        self.assertEqual(status["registrations"][0]["host_restart"], "required")

        config["later_user_setting"] = {"preserve": True}
        (opencode / "opencode.json").write_text(
            json.dumps(config, separators=(",", ":")) + "\n"
        )
        remove = lifecycle.plan_registration(
            "opencode", "unregister", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "unregister",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=remove["plan_sha256"],
            invocation_id="unregister-1",
            transaction_id="txn-registration-remove",
        )
        final_config = json.loads((opencode / "opencode.json").read_text())
        self.assertEqual(final_config["plugin"], [])
        self.assertEqual(final_config["later_user_setting"], {"preserve": True})

    def test_interrupted_registration_recovers_only_with_fresh_quiescent_invocation(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )

        def stop(event):
            if event == "after:replace:registration:opencode-council:target":
                raise RuntimeError("registration crash fixture")

        with self.assertRaisesRegex(RuntimeError, "registration crash fixture"):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="register-crash",
                transaction_id="txn-registration-crash",
                failpoint=stop,
            )
        admission_value = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        self.assertEqual(admission_value["status"], "recovery_required")
        transaction = admission_value["transaction_id"]
        plan = json.loads(
            (
                state
                / ".council-lifecycle/v1/transactions"
                / transaction
                / "plan.json"
            ).read_text()
        )
        command = [
            sys.executable,
            "-I",
            "-B",
            plan["recovery"]["tool_path"],
            "recover",
            "--state-root",
            str(state),
        ]
        refused = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("fresh quiescent admission", refused.stderr)
        completed = subprocess.run(
            command
            + [
                "--quiescent-edit",
                "--confirm-plan",
                planned["plan_sha256"],
                "--invocation-id",
                "register-recover",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        recovered = json.loads(completed.stdout)
        self.assertEqual(recovered["status"], "committed")
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"],
            ["./council-plugin.ts"],
        )

    def test_registration_recovery_refuses_a_replayed_quiescent_invocation(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )

        def stop(event):
            if event == "before:replace:registration:opencode-council:target":
                raise RuntimeError("registration replay fixture")

        with self.assertRaisesRegex(RuntimeError, "registration replay fixture"):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="registration-replay-original",
                transaction_id="txn-registration-replay",
                failpoint=stop,
            )
        admission_value = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        self.assertEqual(admission_value["status"], "recovery_required")
        plan = json.loads(
            (
                state
                / ".council-lifecycle/v1/transactions"
                / admission_value["transaction_id"]
                / "plan.json"
            ).read_text()
        )
        command = [
            sys.executable,
            "-I",
            "-B",
            plan["recovery"]["tool_path"],
            "recover",
            "--state-root",
            str(state),
            "--quiescent-edit",
            "--confirm-plan",
            planned["plan_sha256"],
            "--invocation-id",
        ]
        # The identifier recorded inside the readable plan is history, not
        # current authority: the transaction has progressed past its prepared
        # journal, so replaying it must refuse the configuration write.
        self.assertEqual(
            plan["registration"]["quiescent_decision"]["invocation_id"],
            "registration-replay-original",
        )
        replayed = subprocess.run(
            command + ["registration-replay-original"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(replayed.returncode, 0)
        self.assertIn("fresh quiescent invocation", replayed.stderr)
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"], []
        )
        completed = subprocess.run(
            command + ["registration-replay-fresh"], capture_output=True, text=True
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "committed")

    def test_matching_preexisting_registration_is_receipted_unowned_and_never_removed(self):
        state, payload, opencode = self.installed_release()
        config_path = opencode / "opencode.json"
        config_path.write_bytes(b'{"plugin":["./council-plugin.ts"]}\n')
        register_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=register_plan["plan_sha256"],
            invocation_id="register-unowned",
            transaction_id="txn-registration-unowned",
        )
        status = lifecycle.status(state, payload, opencode)
        self.assertEqual(
            status["registrations"][0]["ownership_origin"],
            "matching_preexisting_unowned",
        )
        remove_plan = lifecycle.plan_registration(
            "opencode", "unregister", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "unregister",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=remove_plan["plan_sha256"],
            invocation_id="remove-unowned",
            transaction_id="txn-registration-preserve-unowned",
        )
        self.assertEqual(
            json.loads(config_path.read_text())["plugin"],
            ["./council-plugin.ts"],
        )

    def crashed_registration(self):
        """Leave a format-2 register transaction pending at recovery_required."""
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )

        def stop(event):
            if event == "after:replace:registration:opencode-council:target":
                raise RuntimeError("pending fixture")

        with self.assertRaisesRegex(RuntimeError, "pending fixture"):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="register-pending",
                transaction_id="txn-registration-pending",
                failpoint=stop,
            )
        admission_value = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        self.assertEqual(admission_value["status"], "recovery_required")
        transaction = (
            state
            / ".council-lifecycle/v1/transactions"
            / admission_value["transaction_id"]
        )
        plan = json.loads((transaction / "plan.json").read_text())
        return state, payload, opencode, planned, plan, transaction

    def test_unconfirmed_abort_makes_no_progress_write(self):
        state, payload, opencode, planned, plan, transaction = (
            self.crashed_registration()
        )
        progress_path = transaction / "progress.json"
        before = json.loads(progress_path.read_text())
        self.assertEqual(before["goal"], "target")
        refused = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                plan["recovery"]["tool_path"],
                "recover",
                "--state-root",
                str(state),
                "--abort",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("fresh quiescent admission", refused.stderr)
        # The goal must not have flipped: an unconfirmed abort that persisted
        # `prior` would silently invert the next, properly confirmed recovery.
        self.assertEqual(json.loads(progress_path.read_text()), before)
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                plan["recovery"]["tool_path"],
                "recover",
                "--state-root",
                str(state),
                "--quiescent-edit",
                "--confirm-plan",
                planned["plan_sha256"],
                "--invocation-id",
                "register-after-refused-abort",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "committed")
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"],
            ["./council-plugin.ts"],
        )

    def test_recovery_reclaims_a_stale_registration_temporary(self):
        state, payload, opencode, planned, plan, _transaction = (
            self.crashed_registration()
        )
        # A hard kill between O_EXCL creation and os.replace leaves this behind.
        stale = opencode / ".opencode.json.pending"
        stale.write_bytes(b"{}\n")
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                plan["recovery"]["tool_path"],
                "recover",
                "--state-root",
                str(state),
                "--abort",
                "--quiescent-edit",
                "--confirm-plan",
                planned["plan_sha256"],
                "--invocation-id",
                "abort-over-stale-temporary",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "committed")
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"], []
        )
        self.assertFalse(stale.exists())

    def test_third_digest_refusal_names_the_file_and_every_digest(self):
        state, payload, opencode, planned, plan, transaction = (
            self.crashed_registration()
        )
        config_path = opencode / "opencode.json"
        config_path.write_bytes(
            b'{"theme":"fixture","plugin":["./council-plugin.ts"] }\n'
        )
        refused = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                plan["recovery"]["tool_path"],
                "recover",
                "--state-root",
                str(state),
                "--quiescent-edit",
                "--confirm-plan",
                planned["plan_sha256"],
                "--invocation-id",
                "recover-third-digest",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(refused.returncode, 0)
        operation = plan["registration"]["operations"][0]
        self.assertIn("neither prior nor intended", refused.stderr)
        self.assertIn(str(config_path), refused.stderr)
        self.assertIn(
            hashlib.sha256(config_path.read_bytes()).hexdigest(), refused.stderr
        )
        self.assertIn(operation["target_sha256"], refused.stderr)
        self.assertIn(operation["prior_sha256"], refused.stderr)
        self.assertIn("restore one of those exact", refused.stderr)

    def test_terminate_process_group_reaps_a_surviving_supervisor(self):
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import os,subprocess,sys,time\n"
                "subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(120)'])\n"
                "time.sleep(120)\n",
            ],
            cwd="/private/tmp",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.addCleanup(process.wait)
        pgid = os.getpgid(process.pid)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if len(RECOVERY._process_group_members(pgid)) >= 2:
                break
            time.sleep(0.05)
        self.assertGreaterEqual(len(RECOVERY._process_group_members(pgid)), 2)
        RECOVERY._terminate_process_group(process, pgid)
        self.assertIsNotNone(process.poll())
        self.assertEqual(RECOVERY._process_group_members(pgid), [])

    def test_uninstall_ignores_a_config_file_it_is_not_removing_from(self):
        state, payload, opencode = self.installed_release()
        register_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=register_plan["plan_sha256"],
            invocation_id="register-before-second-config",
            transaction_id="txn-registration-second-config",
        )
        # An unrelated second config the transaction never touches must not
        # abort removal of the entry the receipt owns in opencode.json.
        unrelated = opencode / "opencode.jsonc"
        unrelated.write_bytes(b'{"theme":"unrelated"}\n')
        uninstall_plan = lifecycle._plan_command(
            "uninstall", None, None, (state, payload, opencode)
        )
        self.assertTrue(uninstall_plan["requires_quiescent_edit"])
        self.assertTrue(uninstall_plan["registration"]["executable"])
        self.assertEqual(
            uninstall_plan["registration"]["source_path"],
            str(opencode / "opencode.json"),
        )
        result = lifecycle.execute_operation(
            "uninstall",
            None,
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=uninstall_plan["plan_sha256"],
            invocation_id="uninstall-second-config",
            transaction_id="txn-uninstall-second-config",
        )
        self.assertEqual(result["status"], "uninstalled")
        self.assertFalse(payload.exists())
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"], []
        )
        self.assertEqual(unrelated.read_bytes(), b'{"theme":"unrelated"}\n')

    def test_unregister_ignores_a_config_file_it_is_not_removing_from(self):
        state, payload, opencode = self.installed_release()
        register_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=register_plan["plan_sha256"],
            invocation_id="register-before-unregister-drift",
            transaction_id="txn-registration-unregister-drift",
        )
        (opencode / "opencode.jsonc").write_bytes(b"{}\n")
        remove_plan = lifecycle.plan_registration(
            "opencode", "unregister", state, payload, opencode
        )
        self.assertTrue(remove_plan["executable"])
        lifecycle.execute_registration(
            "opencode",
            "unregister",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=remove_plan["plan_sha256"],
            invocation_id="unregister-second-config",
            transaction_id="txn-unregister-second-config",
        )
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"], []
        )

    def test_repeated_unregister_refuses_once_the_entry_is_gone(self):
        state, payload, opencode = self.installed_release()
        register_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=register_plan["plan_sha256"],
            invocation_id="register-before-repeat-unregister",
            transaction_id="txn-registration-repeat-unregister",
        )
        remove_plan = lifecycle.plan_registration(
            "opencode", "unregister", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "unregister",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=remove_plan["plan_sha256"],
            invocation_id="unregister-before-repeat",
            transaction_id="txn-unregister-before-repeat",
        )
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"], []
        )
        # The removal row records no resulting entry digest, so the receipt
        # owns nothing to remove and names no target for a repeat.
        receipt = lifecycle.inspect_ownership(state, payload, opencode)["receipt"]
        self.assertEqual(lifecycle._owned_opencode_records(receipt), [])
        settled = (opencode / "opencode.json").read_bytes()
        with self.assertRaises(RegistrationInputError):
            lifecycle.plan_registration(
                "opencode", "unregister", state, payload, opencode
            )
        self.assertEqual((opencode / "opencode.json").read_bytes(), settled)
        # With no receipt-named target the one-source rule governs again, so a
        # second configuration file refuses the repeat rather than no-opping.
        (opencode / "opencode.jsonc").write_bytes(b'{"theme":"unrelated"}\n')
        with self.assertRaises(lifecycle.LifecyclePlanningError) as caught:
            lifecycle.plan_registration(
                "opencode", "unregister", state, payload, opencode
            )
        self.assertIn("exactly one opencode.json", str(caught.exception))
        # Uninstall plans an OpenCode removal only while the receipt owns an
        # entry, so the second file does not reach it.
        uninstall_plan = lifecycle._plan_command(
            "uninstall", None, None, (state, payload, opencode)
        )
        self.assertNotIn("registration", uninstall_plan)

    def test_drifted_owned_entry_refusals_name_the_real_cause(self):
        state, payload, opencode = self.installed_release()
        register_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=register_plan["plan_sha256"],
            invocation_id="register-before-hand-delete",
            transaction_id="txn-registration-hand-delete",
        )
        config_path = opencode / "opencode.json"
        value = json.loads(config_path.read_text())
        value["plugin"] = []
        config_path.write_text(json.dumps(value) + "\n")
        preview = lifecycle._plan_command(
            "uninstall", None, None, (state, payload, opencode)
        )
        blocker = [
            item for item in preview["blockers"]
            if item["code"] == "certified_installation_required"
        ]
        self.assertEqual(len(blocker), 1)
        self.assertIn("ambiguous or changed", blocker[0]["reason"])
        self.assertIn("run `status`", blocker[0]["reason"])
        for action in ("register", "unregister"):
            with self.subTest(action=action), self.assertRaises(
                lifecycle.LifecyclePlanningError
            ) as caught:
                lifecycle.plan_registration(
                    "opencode", action, state, payload, opencode
                )
            self.assertIn("ambiguous or changed", str(caught.exception))
            self.assertIn("run `status`", str(caught.exception))

    def test_registration_ownership_appearing_under_the_lease_refuses(self):
        state, payload, opencode = self.installed_release()
        uninstall_plan = lifecycle._plan_command(
            "uninstall", None, None, (state, payload, opencode)
        )
        self.assertNotIn("requires_quiescent_edit", uninstall_plan)
        real_inspect = lifecycle.inspect_ownership
        real_reconcile = lifecycle._reconcile_preparations
        armed = []

        def arm(*args, **kwargs):
            result = real_reconcile(*args, **kwargs)
            armed.append(True)
            return result

        def concurrent_register(*args, **kwargs):
            snapshot = real_inspect(*args, **kwargs)
            if armed and isinstance(snapshot.get("receipt"), dict):
                # Stand in for a `register` that lands between preflight and the
                # writer lease: the config now names backing code uninstall is
                # about to delete.
                snapshot["receipt"] = dict(snapshot["receipt"])
                snapshot["receipt"]["registrations"] = [
                    {
                        "runtime": "opencode",
                        "operation_id": "opencode-council",
                        "source_path": str(opencode / "opencode.json"),
                        "resulting_entry_sha256": "a" * 64,
                        "ownership_origin": "created",
                    }
                ]
            return snapshot

        with mock.patch.object(
            lifecycle, "inspect_ownership", concurrent_register
        ), mock.patch.object(lifecycle, "_reconcile_preparations", arm):
            with self.assertRaisesRegex(
                lifecycle.LifecyclePlanningError,
                "registration ownership changed after quiescent admission",
            ):
                lifecycle.execute_operation(
                    "uninstall",
                    None,
                    state,
                    payload,
                    opencode,
                    transaction_id="txn-uninstall-ownership-race",
                )
        self.assertTrue(payload.exists())

    def test_owned_registration_predicate_excludes_preexisting_unowned(self):
        state, payload, opencode = self.installed_release()
        (opencode / "opencode.json").write_bytes(
            b'{"plugin":["./council-plugin.ts"]}\n'
        )
        register_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=register_plan["plan_sha256"],
            invocation_id="register-preexisting-unowned",
            transaction_id="txn-registration-preexisting-unowned",
        )
        receipt = lifecycle.inspect_ownership(state, payload, opencode)["receipt"]
        self.assertEqual(
            receipt["registrations"][0]["ownership_origin"],
            "matching_preexisting_unowned",
        )
        self.assertIsNotNone(receipt["registrations"][0]["resulting_entry_sha256"])
        # The entry is the user's. Every caller of this predicate - including
        # the native guard - must agree it is not ours to remove or to block on.
        self.assertFalse(lifecycle._active_opencode_registration(receipt))
        self.assertEqual(lifecycle._owned_opencode_records(receipt), [])
        uninstall_plan = lifecycle._plan_command(
            "uninstall", None, None, (state, payload, opencode)
        )
        self.assertNotIn("requires_quiescent_edit", uninstall_plan)

    def test_interrupted_registration_abort_restores_prior_with_fresh_decision(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )

        def stop(event):
            if event == "after:replace:registration:opencode-council:target":
                raise RuntimeError("abort fixture")

        with self.assertRaisesRegex(RuntimeError, "abort fixture"):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="register-before-abort",
                transaction_id="txn-registration-abort",
                failpoint=stop,
            )
        admission_value = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        transaction = admission_value["transaction_id"]
        plan = json.loads(
            (
                state
                / ".council-lifecycle/v1/transactions"
                / transaction
                / "plan.json"
            ).read_text()
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                plan["recovery"]["tool_path"],
                "recover",
                "--state-root",
                str(state),
                "--abort",
                "--quiescent-edit",
                "--confirm-plan",
                planned["plan_sha256"],
                "--invocation-id",
                "abort-recover",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "committed")
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"], []
        )

    def test_owned_registration_local_options_edit_blocks_new_plan(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=planned["plan_sha256"],
            invocation_id="register-before-local-edit",
            transaction_id="txn-registration-before-local-edit",
        )
        path = opencode / "opencode.json"
        value = json.loads(path.read_text())
        value["plugin"] = [["./council-plugin.ts", {"local": True}]]
        path.write_text(json.dumps(value) + "\n")
        # Terminal inspection reports drift instead of refusing, so the ambiguous
        # owned entry leaves the installation uncertified and planning refuses on
        # that certification, carrying the registration reason.
        management = lifecycle.inspect_ownership(
            state, payload, opencode
        )["management"]
        self.assertFalse(management["certified"])
        self.assertIn("ambiguous or changed", management["reason"])
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "receipt-certified artifact install"
        ):
            lifecycle.plan_registration(
                "opencode", "unregister", state, payload, opencode
            )

    def test_managed_uninstall_removes_owned_registration_before_artifacts(self):
        state, payload, opencode = self.installed_release()
        registration_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=registration_plan["plan_sha256"],
            invocation_id="register-before-uninstall",
            transaction_id="txn-register-before-uninstall",
        )
        uninstall_plan = lifecycle._plan_command(
            "uninstall", None, None, (state, payload, opencode)
        )
        self.assertTrue(uninstall_plan["requires_quiescent_edit"])
        events = []
        result = lifecycle.execute_operation(
            "uninstall",
            None,
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=uninstall_plan["plan_sha256"],
            invocation_id="uninstall-owned-registration",
            transaction_id="txn-uninstall-owned-registration",
            failpoint=events.append,
        )
        self.assertEqual(result["status"], "uninstalled")
        self.assertFalse(payload.exists())
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"], []
        )
        receipt = json.loads(
            (
                state
                / ".council-lifecycle/v1/receipts"
                / (result["receipt_id"] + ".json")
            ).read_text()
        )
        self.assertEqual(receipt["receipt_format"], 2)
        self.assertEqual(
            receipt["registrations"][0]["stored_config_result"],
            "stored_config_absent_verified",
        )
        registration_replace = events.index(
            "before:replace:registration:opencode-council:target"
        )
        first_payload_event = min(
            index for index, event in enumerate(events) if ":payload:" in event
        )
        self.assertLess(registration_replace, first_payload_event)

    def generated_release(self):
        temporary = tempfile.TemporaryDirectory(
            prefix="registration-upgrade-release-", dir="/private/tmp"
        )
        self.addCleanup(temporary.cleanup)
        release = Path(temporary.name) / "release"
        completed = subprocess.run(
            [sys.executable, "-B", "scripts/build_release.py", "--output", str(release)],
            cwd=SCRIPTS.parent,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return release

    def registered_release(self, tag):
        state, payload, opencode = self.installed_release()
        register_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=register_plan["plan_sha256"],
            invocation_id="register-before-" + tag,
            transaction_id="txn-register-before-" + tag,
        )
        receipt = lifecycle.inspect_ownership(state, payload, opencode)["receipt"]
        self.assertEqual(receipt["receipt_format"], 2)
        self.assertEqual(len(lifecycle._owned_opencode_records(receipt)), 1)
        self.assertTrue((opencode / "council-plugin.ts").exists())
        return state, payload, opencode

    def assert_refusal_names_cause_and_remedy(self, message):
        self.assertIn("owned OpenCode registration", message)
        self.assertIn("unregister --runtime opencode", message)
        self.assertIn("register --runtime opencode", message)

    def assert_uninstall_still_removes_the_entry_first(
        self, state, payload, opencode, tag
    ):
        uninstall_plan = lifecycle._plan_command(
            "uninstall", None, None, (state, payload, opencode)
        )
        self.assertTrue(uninstall_plan["requires_quiescent_edit"])
        self.assertTrue(uninstall_plan["registration"]["executable"])
        events = []
        result = lifecycle.execute_operation(
            "uninstall",
            None,
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=uninstall_plan["plan_sha256"],
            invocation_id="uninstall-after-" + tag,
            transaction_id="txn-uninstall-after-" + tag,
            failpoint=events.append,
        )
        self.assertEqual(result["status"], "uninstalled")
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"], []
        )
        self.assertFalse((opencode / "council-plugin.ts").exists())
        self.assertFalse(payload.exists())
        registration_replace = events.index(
            "before:replace:registration:opencode-council:target"
        )
        first_payload_event = min(
            index for index, event in enumerate(events) if ":payload:" in event
        )
        self.assertLess(registration_replace, first_payload_event)

    def test_upgrade_refuses_while_an_opencode_registration_is_owned(self):
        state, payload, opencode = self.registered_release("upgrade-guard")
        release = self.generated_release()
        config = opencode / "opencode.json"
        before_config = config.read_bytes()
        before_payload = tree_digest(payload)
        # Upgrade builds no registration plan, so committing it would publish a
        # format-1 receipt that no longer records the entry the config names.
        with self.assertRaises(lifecycle.LifecyclePlanningError) as raised:
            lifecycle.execute_operation(
                "upgrade",
                release,
                state,
                payload,
                opencode,
                transaction_id="txn-upgrade-owned-registration",
            )
        self.assert_refusal_names_cause_and_remedy(str(raised.exception))
        with self.assertRaises(lifecycle.LifecyclePlanningError) as previewed:
            lifecycle._plan_command(
                "upgrade", release, None, (state, payload, opencode)
            )
        self.assert_refusal_names_cause_and_remedy(str(previewed.exception))
        self.assertEqual(config.read_bytes(), before_config)
        self.assertEqual(tree_digest(payload), before_payload)
        self.assertTrue((opencode / "council-plugin.ts").exists())
        receipt = lifecycle.inspect_ownership(state, payload, opencode)["receipt"]
        self.assertEqual(receipt["receipt_format"], 2)
        self.assertEqual(len(lifecycle._owned_opencode_records(receipt)), 1)
        self.assert_uninstall_still_removes_the_entry_first(
            state, payload, opencode, "upgrade-guard"
        )

    def test_rollback_refuses_while_an_opencode_registration_is_owned(self):
        state, payload, opencode = self.registered_release("rollback-guard")
        config = opencode / "opencode.json"
        before_config = config.read_bytes()
        before_payload = tree_digest(payload)
        with self.assertRaises(lifecycle.LifecyclePlanningError) as raised:
            lifecycle.execute_operation(
                "rollback",
                None,
                state,
                payload,
                opencode,
                receipt_id="receipt-registration-install",
                transaction_id="txn-rollback-owned-registration",
            )
        self.assert_refusal_names_cause_and_remedy(str(raised.exception))
        with self.assertRaises(lifecycle.LifecyclePlanningError) as previewed:
            lifecycle._plan_command(
                "rollback",
                None,
                "receipt-registration-install",
                (state, payload, opencode),
            )
        self.assert_refusal_names_cause_and_remedy(str(previewed.exception))
        self.assertEqual(config.read_bytes(), before_config)
        self.assertEqual(tree_digest(payload), before_payload)
        self.assertTrue((opencode / "council-plugin.ts").exists())
        receipt = lifecycle.inspect_ownership(state, payload, opencode)["receipt"]
        self.assertEqual(receipt["receipt_format"], 2)
        self.assertEqual(len(lifecycle._owned_opencode_records(receipt)), 1)
        self.assert_uninstall_still_removes_the_entry_first(
            state, payload, opencode, "rollback-guard"
        )

    def test_the_refused_upgrade_proceeds_once_the_entry_is_unregistered(self):
        """The refusal names a remedy the engine itself can carry out."""
        state, payload, opencode = self.registered_release("upgrade-remedy")
        release = self.generated_release()
        remove_plan = lifecycle.plan_registration(
            "opencode", "unregister", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "unregister",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=remove_plan["plan_sha256"],
            invocation_id="unregister-before-upgrade-remedy",
            transaction_id="txn-unregister-before-upgrade-remedy",
        )
        upgraded = lifecycle.execute_operation(
            "upgrade",
            release,
            state,
            payload,
            opencode,
            transaction_id="txn-upgrade-after-unregister",
        )
        self.assertEqual(upgraded["status"], "committed")
        register_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=register_plan["plan_sha256"],
            invocation_id="register-after-upgrade-remedy",
            transaction_id="txn-register-after-upgrade-remedy",
        )
        receipt = lifecycle.inspect_ownership(state, payload, opencode)["receipt"]
        self.assertEqual(len(lifecycle._owned_opencode_records(receipt)), 1)
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"],
            ["./council-plugin.ts"],
        )

    def test_a_preexisting_unowned_entry_never_blocks_an_upgrade(self):
        """Only owned rows block. The user's own entry is not ours to gate on."""
        state, payload, opencode = self.installed_release()
        config = opencode / "opencode.json"
        config.write_bytes(b'{"plugin":["./council-plugin.ts"]}\n')
        register_plan = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        lifecycle.execute_registration(
            "opencode",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=register_plan["plan_sha256"],
            invocation_id="register-unowned-before-upgrade",
            transaction_id="txn-register-unowned-before-upgrade",
        )
        receipt = lifecycle.inspect_ownership(state, payload, opencode)["receipt"]
        self.assertEqual(
            receipt["registrations"][0]["ownership_origin"],
            "matching_preexisting_unowned",
        )
        self.assertEqual(lifecycle._owned_opencode_records(receipt), [])
        before_config = config.read_bytes()
        upgraded = lifecycle.execute_operation(
            "upgrade",
            self.generated_release(),
            state,
            payload,
            opencode,
            transaction_id="txn-upgrade-preexisting-unowned",
        )
        self.assertEqual(upgraded["status"], "committed")
        self.assertEqual(config.read_bytes(), before_config)

    def test_executor_refuses_an_artifact_plan_whose_prior_receipt_owns_an_entry(self):
        """The recovery backstop, with the planner guard removed.

        Patching the planner predicate false reproduces exactly the shape the
        planner used to emit: a format-1 plan over a prior receipt that still
        owns an OpenCode row, with the in-lease consistency check satisfied
        because the predicate did not change.
        """
        state, payload, opencode = self.registered_release("executor-backstop")
        release = self.generated_release()
        config = opencode / "opencode.json"
        before_config = config.read_bytes()
        plans = []
        refusals = []
        real_cleanup = lifecycle._cleanup_preintent_bundle

        def capture(bundle):
            # Read the published plan and put it straight to the executor's own
            # validator, while the bundle is still on disk under its lease.
            if not plans:
                plan_path = Path(bundle["plan"])
                plans.append(json.loads(plan_path.read_bytes()))
                try:
                    RECOVERY.validate_plan(plan_path, pre_intent=True)
                except RECOVERY.RecoveryError as error:
                    refusals.append(str(error))
            real_cleanup(bundle)

        with mock.patch.object(
            lifecycle, "_active_opencode_registration", lambda receipt: False
        ), mock.patch.object(lifecycle, "_cleanup_preintent_bundle", capture):
            with self.assertRaises(lifecycle.LifecyclePlanningError) as raised:
                lifecycle.execute_operation(
                    "upgrade",
                    release,
                    state,
                    payload,
                    opencode,
                    transaction_id="txn-executor-backstop-upgrade",
                )
        self.assertIn(
            "active OpenCode registration blocks an artifact/native transaction",
            str(raised.exception),
        )
        self.assertEqual(plans[0]["plan_format"], 1)
        self.assertEqual(plans[0]["kind"], "upgrade")
        self.assertEqual(
            refusals,
            ["active OpenCode registration blocks an artifact/native transaction"],
        )
        self.assertEqual(config.read_bytes(), before_config)
        self.assertTrue((opencode / "council-plugin.ts").exists())
        receipt = lifecycle.inspect_ownership(state, payload, opencode)["receipt"]
        self.assertEqual(receipt["receipt_format"], 2)
        self.assertEqual(len(lifecycle._owned_opencode_records(receipt)), 1)

    def test_native_plan_and_apply_remain_unqualified_without_touching_roots(self):
        with tempfile.TemporaryDirectory(
            prefix="registration-native-refusal-", dir="/private/tmp"
        ) as temporary:
            root = Path(temporary)
            before = tree_digest(root)
            planned = lifecycle.plan_registration(
                "claude",
                "register",
                root / "state",
                root / "payload",
                root / "opencode",
            )
            self.assertFalse(planned["executable"])
            self.assertFalse(planned["qualification_eligible"])
            with self.assertRaisesRegex(
                lifecycle.LifecyclePlanningError, "native_behavior_unqualified"
            ):
                lifecycle.execute_registration(
                    "claude",
                    "register",
                    root / "state",
                    root / "payload",
                    root / "opencode",
                    quiescent_edit=True,
                    confirm_plan="0" * 64,
                    invocation_id="native-refusal",
                )
            self.assertEqual(tree_digest(root), before)

    def test_native_v3_owner_admission_executes_through_copied_recovery(self):
        home, state, payload, opencode = self.installed_native_release()
        runtime_tuple, target = self.native_authority(
            home, state, payload, qualification.CLAUDE_ENSURE
        )
        planned = lifecycle.plan_registration(
            "claude",
            "register",
            state,
            payload,
            opencode,
            native_home=home,
        )
        self.assertTrue(planned["executable"])
        self.assertTrue(planned["qualification_eligible"])
        self.assertFalse(planned["native_success_activated"])
        ownership = lifecycle.inspect_ownership(state, payload, opencode)
        implementation = lifecycle._native_implementation(
            ownership["management"]["summary"], lifecycle._native_policy()
        )
        effects = SyntheticNativeEffects(target, runtime_tuple, implementation)
        result = lifecycle.execute_registration(
            "claude",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=planned["plan_sha256"],
            invocation_id="native-v3-register",
            transaction_id="txn-native-v3-register",
            native_home=home,
            native_effects=effects,
        )
        self.assertEqual(result["status"], "committed")
        self.assertEqual(
            effects.events,
            [
                "observer-armed",
                "supervisor-blocked",
                "release-authorized",
                "positive-absence",
                "passive-observation",
            ],
        )
        receipt = json.loads(
            (
                state
                / ".council-lifecycle/v1/receipts"
                / (result["receipt_id"] + ".json")
            ).read_text()
        )
        self.assertEqual(receipt["receipt_format"], 3)
        self.assertEqual(
            receipt["native_registrations"][0]["runtime"], "claude"
        )
        self.assertFalse(
            receipt["native_registrations"][0]["semantic_result_identity"][
                "record"
            ].get("post_source_sha256")
        )
        closure = receipt["native_closure"]
        closure_root = (
            state
            / ".council-lifecycle/v1/recovery/native-v3"
            / closure["implementation_identity_sha256"]
        )
        self.assertEqual(
            sorted(path.name for path in closure_root.iterdir()),
            sorted(lifecycle.recovery.NATIVE_RECOVERY_MODULES),
        )
        status = lifecycle.status(state, payload, opencode)
        self.assertEqual(status["registrations"][0]["runtime"], "claude")
        self.assertEqual(
            status["registrations"][0]["authenticated_readiness"],
            "unobserved",
        )

    def test_native_v3_copied_recovery_observes_target_without_relaunch(self):
        home, state, payload, opencode = self.installed_native_release()
        runtime_tuple, target = self.native_authority(
            home, state, payload, qualification.CLAUDE_ENSURE
        )
        planned = lifecycle.plan_registration(
            "claude", "register", state, payload, opencode, native_home=home
        )
        ownership = lifecycle.inspect_ownership(state, payload, opencode)
        implementation = lifecycle._native_implementation(
            ownership["management"]["summary"], lifecycle._native_policy()
        )
        effects = SyntheticNativeEffects(target, runtime_tuple, implementation)

        def stop(event):
            if event == "after:native-attempt-result":
                raise RuntimeError("native result crash")

        with self.assertRaisesRegex(RuntimeError, "native result crash"):
            lifecycle.execute_registration(
                "claude",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="native-before-crash",
                transaction_id="txn-native-v3-crash",
                native_home=home,
                native_effects=effects,
                failpoint=stop,
            )
        admission_value = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        self.assertEqual(admission_value["status"], "recovery_required")
        plan_path = (
            state
            / ".council-lifecycle/v1/transactions"
            / admission_value["transaction_id"]
            / "plan.json"
        )
        plan = json.loads(plan_path.read_text())
        spec = importlib.util.spec_from_file_location(
            "copied_native_v3_recover", plan["recovery"]["tool_path"]
        )
        copied = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(copied)
        result = copied.recover(
            state,
            quiescent_decision={
                "confirmed": True,
                "plan_sha256": planned["plan_sha256"],
                "invocation_id": "native-recovery-fresh",
                "sequence": 0,
                "goal": "target",
            },
            native_effects=effects,
        )
        self.assertEqual(result["status"], "committed")
        self.assertEqual(effects.events.count("supervisor-blocked"), 1)
        self.assertEqual(effects.events.count("release-authorized"), 1)

    def test_native_v3_inverse_is_a_new_owner_admitted_transaction(self):
        home, state, payload, opencode = self.installed_native_release()
        add_tuple, add_target = self.native_authority(
            home, state, payload, qualification.CLAUDE_ENSURE
        )
        add_plan = lifecycle.plan_registration(
            "claude", "register", state, payload, opencode, native_home=home
        )
        ownership = lifecycle.inspect_ownership(state, payload, opencode)
        implementation = lifecycle._native_implementation(
            ownership["management"]["summary"], lifecycle._native_policy()
        )
        lifecycle.execute_registration(
            "claude",
            "register",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=add_plan["plan_sha256"],
            invocation_id="native-add-before-inverse",
            transaction_id="txn-native-v3-before-inverse",
            native_home=home,
            native_effects=SyntheticNativeEffects(
                add_target, add_tuple, implementation
            ),
        )
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "must be unregistered"
        ):
            lifecycle.execute_operation(
                "uninstall",
                None,
                state,
                payload,
                opencode,
                transaction_id="txn-native-still-active",
            )

        remove_tuple, remove_target = self.native_authority(
            home, state, payload, qualification.CLAUDE_REMOVE
        )
        remove_plan = lifecycle.plan_registration(
            "claude", "unregister", state, payload, opencode, native_home=home
        )
        ownership = lifecycle.inspect_ownership(state, payload, opencode)
        implementation = lifecycle._native_implementation(
            ownership["management"]["summary"], lifecycle._native_policy()
        )
        result = lifecycle.execute_registration(
            "claude",
            "unregister",
            state,
            payload,
            opencode,
            quiescent_edit=True,
            confirm_plan=remove_plan["plan_sha256"],
            invocation_id="native-inverse-fresh",
            transaction_id="txn-native-v3-inverse",
            native_home=home,
            native_effects=SyntheticNativeEffects(
                remove_target, remove_tuple, implementation
            ),
        )
        self.assertEqual(result["status"], "committed")
        self.assertEqual(
            json.loads((home / ".claude.json").read_text())["mcpServers"], {}
        )
        receipt = json.loads(
            (
                state
                / ".council-lifecycle/v1/receipts"
                / (result["receipt_id"] + ".json")
            ).read_text()
        )
        semantic = receipt["native_registrations"][0][
            "semantic_result_identity"
        ]["record"]
        self.assertEqual(semantic["mode"], "inverse")
        self.assertEqual(semantic["intended_state"], "absent")
        uninstalled = lifecycle.execute_operation(
            "uninstall",
            None,
            state,
            payload,
            opencode,
            transaction_id="txn-after-native-inverse",
        )
        self.assertEqual(uninstalled["status"], "uninstalled")

    def test_native_v3_fixed_supervisor_stays_pending_without_network_evidence(self):
        home, state, payload, opencode = self.installed_native_release()
        target_bytes = (
            b'{"mcpServers":{"council":{"type":"stdio","command":'
            b'"/usr/bin/python3","args":["'
            + str(payload / "scripts/council_mcp.py").encode()
            + b'"]}}}'
        )
        program = (
            "#!/usr/bin/python3\n"
            "import os\n"
            "path = os.path.join(os.environ['HOME'], '.claude.json')\n"
            "with open(path, 'r+b') as stream:\n"
            "    stream.seek(0)\n"
            "    stream.write(%r)\n"
            "    stream.truncate()\n" % target_bytes
        ).encode()
        self.native_authority(
            home,
            state,
            payload,
            qualification.CLAUDE_ENSURE,
            executable_program=program,
        )
        planned = lifecycle.plan_registration(
            "claude", "register", state, payload, opencode, native_home=home
        )
        with self.assertRaisesRegex(
            Exception, "did not reach its admitted target"
        ):
            lifecycle.execute_registration(
                "claude",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="native-fixed-supervisor",
                transaction_id="txn-native-fixed-supervisor",
                native_home=home,
            )
        admission_value = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        self.assertEqual(admission_value["status"], "recovery_required")
        progress = json.loads(
            (
                state
                / ".council-lifecycle/v1/transactions"
                / admission_value["transaction_id"]
                / "progress.json"
            ).read_text()
        )
        self.assertEqual(
            progress["native_registrations"][0]["attempts"][0]["state"],
            "unknown",
        )
        transaction = (
            state
            / ".council-lifecycle/v1/transactions"
            / admission_value["transaction_id"]
        )
        plan = json.loads((transaction / "plan.json").read_text())
        spec = importlib.util.spec_from_file_location(
            "copied_native_unknown", plan["recovery"]["tool_path"]
        )
        copied = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(copied)
        with self.assertRaisesRegex(Exception, "terminal observed prior"):
            copied.recover(
                state,
                quiescent_decision={
                    "confirmed": True,
                    "plan_sha256": planned["plan_sha256"],
                    "invocation_id": "native-unknown-sequence-one",
                    "sequence": 1,
                    "goal": "target",
                },
            )
        progress = json.loads((transaction / "progress.json").read_text())
        self.assertEqual(
            len(progress["native_registrations"][0]["attempts"]), 1
        )
        self.assertEqual(
            json.loads((home / ".claude.json").read_text())["mcpServers"][
                "council"
            ]["type"],
            "stdio",
        )

    def test_native_v3_fresh_sequence_one_preserves_prepared_receipt(self):
        home, state, payload, opencode = self.installed_native_release()
        runtime_tuple, target = self.native_authority(
            home, state, payload, qualification.CLAUDE_ENSURE
        )
        planned = lifecycle.plan_registration(
            "claude", "register", state, payload, opencode, native_home=home
        )
        ownership = lifecycle.inspect_ownership(state, payload, opencode)
        implementation = lifecycle._native_implementation(
            ownership["management"]["summary"], lifecycle._native_policy()
        )
        effects = SyntheticNativeEffects(
            target, runtime_tuple, implementation, outcomes=("prior", "target")
        )
        with self.assertRaisesRegex(
            Exception, "did not reach its admitted target"
        ):
            lifecycle.execute_registration(
                "claude",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="native-sequence-zero",
                transaction_id="txn-native-v3-sequence-one",
                native_home=home,
                native_effects=effects,
            )
        admission_value = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        transaction = (
            state
            / ".council-lifecycle/v1/transactions"
            / admission_value["transaction_id"]
        )
        receipt_before = (transaction / "receipt.json").read_bytes()
        plan = json.loads((transaction / "plan.json").read_text())
        spec = importlib.util.spec_from_file_location(
            "copied_native_v3_sequence_recover", plan["recovery"]["tool_path"]
        )
        copied = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(copied)
        with self.assertRaisesRegex(Exception, "fresh quiescent invocation"):
            copied.recover(
                state,
                quiescent_decision={
                    "confirmed": True,
                    "plan_sha256": planned["plan_sha256"],
                    "invocation_id": "native-sequence-zero",
                    "sequence": 0,
                    "goal": "target",
                },
                native_effects=effects,
            )
        self.assertEqual(effects.events.count("supervisor-blocked"), 1)
        result = copied.recover(
            state,
            quiescent_decision={
                "confirmed": True,
                "plan_sha256": planned["plan_sha256"],
                "invocation_id": "native-sequence-one",
                "sequence": 1,
                "goal": "target",
            },
            native_effects=effects,
        )
        self.assertEqual(result["status"], "committed")
        self.assertEqual((transaction / "receipt.json").read_bytes(), receipt_before)
        progress = json.loads((transaction / "progress.json").read_text())
        attempts = progress["native_registrations"][0]["attempts"]
        self.assertEqual([item["sequence"] for item in attempts], [0, 1])
        self.assertEqual(
            [item["state"] for item in attempts],
            ["observed_prior", "observed_target"],
        )
        self.assertEqual(effects.events.count("supervisor-blocked"), 2)
        self.assertNotEqual(
            attempts[0]["execution_admission"]["sha256"],
            attempts[1]["execution_admission"]["sha256"],
        )
        self.assertEqual(
            attempts[1]["previous_attempt_terminal_sha256"],
            copied._native_terminal_summary_digest(
                progress["native_registrations"][0]["attempt_family"]["sha256"],
                attempts[0],
            ),
        )

    def test_native_v3_sequence_one_append_is_crash_safe(self):
        for boundary, expected_count in (
            ("before:replace:native:append-sequence-one", 1),
            ("after:replace:native:append-sequence-one", 2),
        ):
            with self.subTest(boundary=boundary):
                state, transaction, copied, decision, effects = (
                    self.pending_native_sequence()
                )

                def stop(event):
                    if event == boundary:
                        raise RuntimeError("sequence append crash")

                with self.assertRaisesRegex(RuntimeError, "sequence append crash"):
                    copied.recover(
                        state,
                        quiescent_decision=decision,
                        native_effects=effects,
                        failpoint=stop,
                    )
                progress = json.loads((transaction / "progress.json").read_text())
                self.assertEqual(
                    len(progress["native_registrations"][0]["attempts"]),
                    expected_count,
                )
                result = copied.recover(
                    state,
                    quiescent_decision=decision,
                    native_effects=effects,
                )
                self.assertEqual(result["status"], "committed")
                self.assertEqual(effects.events.count("supervisor-blocked"), 2)

    def test_native_v3_sequence_chain_and_current_identity_drift_refuse(self):
        state, transaction, copied, decision, effects = self.pending_native_sequence()

        def stop(event):
            if event == "after:replace:native:append-sequence-one":
                raise RuntimeError("sequence appended")

        with self.assertRaisesRegex(RuntimeError, "sequence appended"):
            copied.recover(
                state,
                quiescent_decision=decision,
                native_effects=effects,
                failpoint=stop,
            )
        progress_path = transaction / "progress.json"
        progress = json.loads(progress_path.read_text())
        progress["native_registrations"][0]["attempts"][1][
            "previous_attempt_terminal_sha256"
        ] = "0" * 64
        progress_path.write_bytes(copied.json_bytes(progress))
        with self.assertRaisesRegex(
            Exception, "attempt identity differs|prior sequence link differs"
        ):
            copied.recover(
                state,
                quiescent_decision=decision,
                native_effects=effects,
            )
        self.assertEqual(effects.events.count("supervisor-blocked"), 1)

        state, _transaction, copied, decision, effects = self.pending_native_sequence()
        config = Path(effects.target.path)
        config.write_bytes(b'{"mcpServers":{},"changed":true}')
        with self.assertRaisesRegex(Exception, "prior identity changed"):
            copied.recover(
                state,
                quiescent_decision=decision,
                native_effects=effects,
            )
        self.assertEqual(effects.events.count("supervisor-blocked"), 1)

    def test_native_v3_sequence_one_prior_exhausts_family(self):
        state, transaction, copied, decision, effects = self.pending_native_sequence(
            outcomes=("prior", "prior")
        )
        with self.assertRaisesRegex(Exception, "did not reach its admitted target"):
            copied.recover(
                state,
                quiescent_decision=decision,
                native_effects=effects,
            )
        progress = json.loads((transaction / "progress.json").read_text())
        self.assertEqual(
            progress["native_registrations"][0]["attempts"][1]["state"],
            "observed_prior",
        )
        exhausted = dict(decision)
        exhausted["invocation_id"] = "native-sequence-two"
        exhausted["sequence"] = 2
        with self.assertRaises(Exception):
            copied.recover(
                state,
                quiescent_decision=exhausted,
                native_effects=effects,
            )
        self.assertEqual(effects.events.count("supervisor-blocked"), 2)

    def test_pending_status_projects_native_state_without_executing_closure(self):
        state, _transaction, _copied, _decision, _effects = (
            self.pending_native_sequence(outcomes=("prior", "target"))
        )
        home = state.parents[1]
        with mock.patch.object(
            RECOVERY,
            "_load_native_recovery_closure",
            side_effect=AssertionError("pending status executed copied bytes"),
        ):
            result = lifecycle.status(
                state,
                home / ".claude/skills/council",
                home / ".config/opencode",
            )
        self.assertEqual(result["management"]["status"], "recovery_required")
        self.assertEqual(len(result["registrations"]), 1)
        registration = result["registrations"][0]
        self.assertEqual(registration["runtime"], "claude")
        self.assertEqual(registration["stored_config_result"], "pending_recovery")
        self.assertEqual(registration["recovery_state"], "observed_prior")
        self.assertEqual(registration["authenticated_readiness"], "unobserved")

    def test_native_preparation_record_claims_the_copied_closure(self):
        home, state, payload, opencode = self.installed_native_release()
        self.native_authority(
            home, state, payload, qualification.CLAUDE_ENSURE
        )
        planned = lifecycle.plan_registration(
            "claude", "register", state, payload, opencode, native_home=home
        )
        observed = {}

        def inspect_preparation(event):
            if event != (
                "after:prepare-native-closure-module:"
                "council_registration_qualification.py"
            ):
                return
            records = list(
                (state / RECOVERY.PREPARATION_ROOT_NAME).glob("*.json")
            )
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text())
            claims = {
                Path(item["path"]).name: item["expected"]
                for item in record["claims"]
                if "/native-v3/" in item["path"]
                and item["path"].endswith(".py")
            }
            self.assertEqual(set(claims), set(RECOVERY.NATIVE_RECOVERY_MODULES))
            self.assertTrue(
                all(
                    value["exists"] is True
                    and value["kind"] == "file"
                    and value["mode"] == 0o600
                    for value in claims.values()
                )
            )
            observed["claims"] = claims
            raise RuntimeError("inspect native preparation")

        with self.assertRaisesRegex(RuntimeError, "inspect native preparation"):
            lifecycle.execute_registration(
                "claude",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="native-preparation-record",
                transaction_id="txn-native-preparation-record",
                native_home=home,
                _preparation_failpoint=inspect_preparation,
            )
        self.assertEqual(len(observed["claims"]), 3)
        self.assertFalse(
            any((state / RECOVERY.PREPARATION_ROOT_NAME).glob("*.json"))
        )

    def test_opencode_execution_refuses_ambiguous_missing_and_linked_config_sources(self):
        state, payload, opencode = self.installed_release()
        primary = opencode / "opencode.json"
        secondary = opencode / "opencode.jsonc"
        secondary.write_bytes(b"{}\n")
        before = tree_digest(state.parent)
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "exactly one"
        ):
            lifecycle.plan_registration(
                "opencode", "register", state, payload, opencode
            )
        self.assertEqual(tree_digest(state.parent), before)
        secondary.unlink()
        linked = opencode / "linked-config.json"
        os.link(primary, linked)
        try:
            with self.assertRaisesRegex(
                lifecycle.LifecyclePlanningError, "single-linked"
            ):
                lifecycle.plan_registration(
                    "opencode", "register", state, payload, opencode
                )
        finally:
            linked.unlink()
        primary.unlink()
        before = tree_digest(state.parent)
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "exactly one"
        ):
            lifecycle.plan_registration(
                "opencode", "register", state, payload, opencode
            )
        self.assertEqual(tree_digest(state.parent), before)

    def test_registration_replace_refuses_a_swapped_config_entry(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        config = opencode / "opencode.json"
        prior = config.read_bytes()
        displaced = opencode / "opencode.before-swap.json"
        sentinel = b'{"sentinel":"outside replacement"}\n'
        swapped = {"done": False}

        def swap_before_replace(event):
            if (
                event == "before:replace:registration:opencode-council:target"
                and not swapped["done"]
            ):
                config.replace(displaced)
                config.write_bytes(sentinel)
                swapped["done"] = True

        with self.assertRaisesRegex(Exception, "target changed before replace"):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="registration-source-swap",
                transaction_id="txn-registration-source-swap",
                failpoint=swap_before_replace,
            )
        self.assertTrue(swapped["done"])
        self.assertEqual(config.read_bytes(), sentinel)
        self.assertEqual(displaced.read_bytes(), prior)
        self.assertFalse((opencode / ".opencode.json.pending").exists())

    def test_registration_replace_refuses_a_swapped_config_parent(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        prior = (opencode / "opencode.json").read_bytes()
        displaced = opencode.with_name("opencode-before-swap")
        sentinel = b'{"sentinel":"replacement parent"}\n'
        swapped = {"done": False}

        def swap_before_replace(event):
            if (
                event == "before:replace:registration:opencode-council:target"
                and not swapped["done"]
            ):
                opencode.replace(displaced)
                opencode.mkdir()
                (opencode / "opencode.json").write_bytes(sentinel)
                swapped["done"] = True

        with self.assertRaisesRegex(Exception, "parent changed before mutation"):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="registration-parent-swap",
                transaction_id="txn-registration-parent-swap",
                failpoint=swap_before_replace,
            )
        self.assertTrue(swapped["done"])
        self.assertEqual((opencode / "opencode.json").read_bytes(), sentinel)
        self.assertEqual((displaced / "opencode.json").read_bytes(), prior)
        self.assertFalse((displaced / ".opencode.json.pending").exists())

    def test_opencode_preparation_record_claims_the_execution_preview(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )
        observed = {}

        def inspect_preparation(event):
            if event != "after:prepare-registration-preview":
                return
            records = list(
                (state / RECOVERY.PREPARATION_ROOT_NAME).glob("*.json")
            )
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text())
            claim = next(
                item
                for item in record["claims"]
                if item["path"].endswith("/registration-preview.json")
            )
            preview = Path(claim["path"])
            self.assertEqual(claim["expected"]["kind"], "file")
            self.assertEqual(
                claim["expected"]["sha256"], digest(preview)
            )
            observed["path"] = preview
            raise RuntimeError("inspect OpenCode preparation")

        with self.assertRaisesRegex(RuntimeError, "inspect OpenCode preparation"):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="opencode-preparation-record",
                transaction_id="txn-opencode-preparation-record",
                _preparation_failpoint=inspect_preparation,
            )
        self.assertIn("path", observed)
        self.assertFalse(observed["path"].exists())
        self.assertFalse(
            any((state / RECOVERY.PREPARATION_ROOT_NAME).glob("*.json"))
        )

    def test_pending_status_projects_opencode_registration_state(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )

        def stop_before_replace(event):
            if event == "before:replace:registration:opencode-council:target":
                raise RuntimeError("pending registration status")

        with self.assertRaisesRegex(RuntimeError, "pending registration status"):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="registration-pending-status",
                transaction_id="txn-registration-pending-status",
                failpoint=stop_before_replace,
            )
        result = lifecycle.status(state, payload, opencode)
        self.assertEqual(result["management"]["status"], "recovery_required")
        self.assertEqual(len(result["registrations"]), 1)
        registration = result["registrations"][0]
        self.assertEqual(registration["runtime"], "opencode")
        self.assertEqual(registration["stored_config_result"], "pending_recovery")
        self.assertEqual(registration["recovery_state"], "pending")
        self.assertEqual(registration["authenticated_readiness"], "unobserved")

    def test_pending_registration_status_prints_the_confirmed_recovery_vector(self):
        state, payload, opencode = self.installed_release()
        planned = lifecycle.plan_registration(
            "opencode", "register", state, payload, opencode
        )

        def stop_before_replace(event):
            if event == "before:replace:registration:opencode-council:target":
                raise RuntimeError("pending registration vector")

        with self.assertRaisesRegex(RuntimeError, "pending registration vector"):
            lifecycle.execute_registration(
                "opencode",
                "register",
                state,
                payload,
                opencode,
                quiescent_edit=True,
                confirm_plan=planned["plan_sha256"],
                invocation_id="registration-pending-vector",
                transaction_id="txn-registration-pending-vector",
                failpoint=stop_before_replace,
            )
        pending = lifecycle.status(state, payload, opencode)["pending_recovery"]
        command = pending["recovery_command"]
        # The confirmation flags carry the registration preview digest, never
        # plan.json's, which is what pending_recovery.plan_sha256 reports.
        self.assertEqual(
            command[-5:],
            [
                "--quiescent-edit",
                "--confirm-plan",
                planned["plan_sha256"],
                "--invocation-id",
                "<fresh-invocation-id>",
            ],
        )
        self.assertNotEqual(pending["plan_sha256"], planned["plan_sha256"])
        # Run verbatim: only the invocation-ID placeholder is refused.
        verbatim = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(verbatim.returncode, 0)
        self.assertIn("invocation_id", verbatim.stderr)
        completed = subprocess.run(
            [
                "registration-pending-vector-recover"
                if item == "<fresh-invocation-id>"
                else item
                for item in command
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "committed")
        self.assertEqual(
            json.loads((opencode / "opencode.json").read_text())["plugin"],
            ["./council-plugin.ts"],
        )

    def test_registration_specific_durability_boundaries_recover_to_target(self):
        boundaries = (
            "before:replace:registration:opencode-council:target",
            "after:replace:registration:opencode-council:target",
            "after:replace:progress:registration:opencode-council",
            "after:write-immutable:target-receipt",
            "after:replace:terminal-admission",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                state, payload, opencode = self.installed_release()
                planned = lifecycle.plan_registration(
                    "opencode", "register", state, payload, opencode
                )

                def stop(event):
                    if event == boundary:
                        raise RuntimeError("durability boundary")

                with self.assertRaisesRegex(RuntimeError, "durability boundary"):
                    lifecycle.execute_registration(
                        "opencode",
                        "register",
                        state,
                        payload,
                        opencode,
                        quiescent_edit=True,
                        confirm_plan=planned["plan_sha256"],
                        invocation_id="boundary-%d" % index,
                        transaction_id="txn-registration-boundary-%d" % index,
                        failpoint=stop,
                    )
                admission_value = json.loads(
                    (state / ".council-lifecycle/admission.json").read_text()
                )
                if admission_value["status"] == "recovery_required":
                    transaction = admission_value["transaction_id"]
                    plan = json.loads(
                        (
                            state
                            / ".council-lifecycle/v1/transactions"
                            / transaction
                            / "plan.json"
                        ).read_text()
                    )
                    command = [
                        sys.executable,
                        "-I",
                        "-B",
                        plan["recovery"]["tool_path"],
                        "recover",
                        "--state-root",
                        str(state),
                        "--quiescent-edit",
                        "--confirm-plan",
                        planned["plan_sha256"],
                        "--invocation-id",
                        "recover-boundary-%d" % index,
                    ]
                    completed = subprocess.run(
                        command, capture_output=True, text=True
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                else:
                    self.assertEqual(admission_value["status"], "committed")
                self.assertEqual(
                    json.loads((opencode / "opencode.json").read_text())["plugin"],
                    ["./council-plugin.ts"],
                )


if __name__ == "__main__":
    unittest.main()
