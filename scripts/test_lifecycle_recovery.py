#!/usr/bin/env python3
"""Disposable filesystem tests for the standalone lifecycle recovery core."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parent / "council_recover.py"
SPEC = importlib.util.spec_from_file_location("council_recover_source", SOURCE)
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_bytes(source.json_bytes(value))
    path.chmod(0o600)


def make_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def write_payload(path: Path, label: str, *, cache: bool = False) -> None:
    make_directory(path)
    for relative, data in {
        "SKILL.md": (label + " skill\n").encode(),
        "scripts/runtime.py": ("VALUE = %r\n" % label).encode(),
    }.items():
        destination = path / relative
        make_directory(destination.parent)
        destination.write_bytes(data)
        destination.chmod(0o644)
    if cache:
        cache_path = path / "scripts/__pycache__/runtime.cpython-39.pyc"
        make_directory(cache_path.parent)
        cache_path.write_bytes(b"stale-cache-" + label.encode())
        cache_path.chmod(0o600)


def write_file(path: Path, data: bytes, mode: int = 0o644) -> None:
    make_directory(path.parent)
    path.write_bytes(data)
    path.chmod(mode)


class Fixture:
    def __init__(self, parent: Path, *, initial: bool = False, cache: bool = False,
                 target_uninstalled: bool = False, preserve_unowned: bool = False):
        self.root = parent
        self.state = parent / "state"
        self.payload_parent = parent / "payload-parent"
        self.payload = self.payload_parent / "council"
        self.opencode = parent / "opencode"
        for path in (self.state, self.payload_parent, self.opencode, self.opencode / "tools"):
            make_directory(path)
        self.lock = self.state / "broker.lock"
        self.lock.write_bytes(b"stable-lock")
        self.lock.chmod(0o600)
        self.lock_inode = self.lock.stat().st_ino
        retained = self.state / "registrations/fixture.json"
        write_file(retained, b'{"fixture":true}\n', 0o600)
        self.lifecycle = self.state / ".council-lifecycle"
        self.v1 = self.lifecycle / "v1"
        for path in (
            self.lifecycle,
            self.v1,
            self.v1 / "receipts",
            self.v1 / "recovery",
            self.v1 / "transactions",
        ):
            make_directory(path)
        tool_data = SOURCE.read_bytes()
        self.tool_digest = hashlib.sha256(tool_data).hexdigest()
        self.tool = self.v1 / "recovery" / (self.tool_digest + ".py")
        self.tool.write_bytes(tool_data)
        self.tool.chmod(0o600)
        spec = importlib.util.spec_from_file_location(
            "council_recover_fixture_" + self.tool_digest[:12], self.tool
        )
        self.engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.engine)
        self.transaction_id = "txn-fixture"
        self.receipt_id = "receipt-fixture"
        self.transaction = self.v1 / "transactions" / self.transaction_id
        make_directory(self.transaction)
        self.roots = {
            "state": str(self.state.resolve()),
            "payload": str(self.payload.absolute()),
            "opencode": str(self.opencode.resolve()),
        }
        if initial:
            make_directory(self.payload)
            write_payload(self.payload, "prior", cache=cache)
            for unit_id, relative in source.EXTERNAL_DESTINATIONS.items():
                write_file(self.opencode / relative, ("prior-%s\n" % unit_id).encode())
        self.units = []
        for unit_id in source.UNIT_IDS:
            destination = source._unit_destination(self.roots, unit_id)
            kind = "directory" if unit_id == "payload" else "file"
            objects = source._unit_objects(destination, self.transaction_id, unit_id)
            initial_state = source.capture_state(destination, kind)
            prior_state = initial_state
            if initial and unit_id == "payload" and cache:
                clean_prior = Path(objects["prior"])
                write_payload(clean_prior, "prior")
                prior_state = source.capture_state(clean_prior, kind)
            elif initial:
                prior_object = Path(objects["prior"])
                if kind == "directory":
                    write_payload(prior_object, "prior")
                else:
                    write_file(prior_object, destination.read_bytes())
                prior_state = source.capture_state(prior_object, kind)
            target_object = Path(objects["target"])
            preserve_this = preserve_unowned and unit_id == "opencode-plugin"
            if not target_uninstalled:
                if kind == "directory":
                    write_payload(target_object, "target")
                else:
                    write_file(target_object, ("target-%s\n" % unit_id).encode())
                target_state = source.capture_state(target_object, kind)
            elif preserve_this:
                write_file(target_object, destination.read_bytes())
                target_state = source.capture_state(target_object, kind)
            else:
                target_state = source.absent_state(kind)
            self.units.append(
                {
                    "unit_id": unit_id,
                    "destination": str(destination),
                    "parent_identity": source.physical_identity(destination.parent),
                    "initial": initial_state,
                    "prior": prior_state,
                    "target": target_state,
                    "objects": objects,
                }
            )
        self.package_id = hashlib.sha256(b"fixture-package").hexdigest()
        self.runtime_cohort = hashlib.sha256(b"fixture-cohort").hexdigest()
        artifacts = {}
        selected = "initial" if target_uninstalled else "target"
        for unit in self.units:
            state_value = unit[selected]
            if unit["unit_id"] == "payload":
                for artifact in state_value["artifacts"]:
                    if artifact["kind"] == "file" and "__pycache__" not in Path(artifact["path"]).parts:
                        artifacts["payload/" + artifact["path"]] = artifact["sha256"]
            else:
                artifacts[source.EXTERNAL_MANIFEST_PATHS[unit["unit_id"]]] = state_value["sha256"]
        manifest = {
            "format": 1,
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "artifacts": dict(sorted(artifacts.items())),
            "opencode_sources": source.OPENCODE_SOURCES,
        }
        self.manifest_path = self.transaction / "source-manifest.json"
        write_json(self.manifest_path, manifest)
        support = {
            "source_sha256": hashlib.sha256(b"reader-source").hexdigest(),
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "import_closure_sha256": hashlib.sha256(b"reader-closure").hexdigest(),
            "fixture_corpus_sha256": hashlib.sha256(b"reader-corpus").hexdigest(),
            "features": ["audit", "dialogues", "lifecycle-v1", "outbox", "registrations"],
            "state_reader": "pass",
            "managed_writer_admission": "pass",
            "external_recoverer": "pass",
            "formats": {"admission": 1, "plan": 1, "journal": 1, "receipt": 1, "recovery": 1},
        }
        self.support_path = self.transaction / "reader-support.json"
        write_json(self.support_path, support)
        if initial:
            prior_receipt_id = "receipt-prior"
            prior_receipt_path = self.v1 / "receipts" / (prior_receipt_id + ".json")
            prior_artifacts = []
            for unit in self.units:
                relatives = ["."]
                if unit["unit_id"] == "payload":
                    relatives.extend(item["path"] for item in unit["initial"]["artifacts"])
                for relative in sorted(relatives):
                    intended = source._leaf_state(unit["initial"], relative)
                    kind = "directory" if unit["unit_id"] == "payload" and relative == "." else None
                    prior_leaf = {"exists": False, "sha256": None, "mode": None, "kind": kind}
                    destination = Path(unit["destination"]) if relative == "." else Path(unit["destination"]) / relative
                    unowned = preserve_unowned and unit["unit_id"] == "opencode-plugin"
                    prior_artifacts.append(
                        {
                            "unit_id": unit["unit_id"],
                            "path": relative,
                            "destination": str(destination),
                            "prior": intended if unowned else prior_leaf,
                            "intended": intended,
                            "ownership": "matching_preexisting_unowned" if unowned else "created",
                            "local_change": "none",
                        }
                    )
            prior_receipt = {
                "receipt_format": 1,
                "receipt_id": prior_receipt_id,
                "transaction_id": "txn-prior",
                "roots": self.roots,
                "package_id": self.package_id,
                "runtime_cohort": self.runtime_cohort,
                "source_manifest_sha256": file_hash(self.manifest_path),
                "prior_receipt": None,
                "recovery": {"format": 1, "tool_sha256": self.tool_digest},
                "reader_support_sha256": file_hash(self.support_path),
                "artifacts": prior_artifacts,
            }
            write_json(prior_receipt_path, prior_receipt)
            prior_committed = {
                "receipt_id": prior_receipt_id,
                "receipt_sha256": file_hash(prior_receipt_path),
                "package_id": self.package_id,
                "runtime_cohort": self.runtime_cohort,
            }
            prior_status = "committed"
        else:
            prior_committed = None
            prior_status = "uninstalled"
        self.prior_admission = {
            "format": 1,
            "namespace_version": 1,
            "roots": self.roots,
            "status": prior_status,
            "transaction_id": None,
            "committed": prior_committed,
        }
        write_json(self.lifecycle / "admission.json", self.prior_admission)
        receipt_artifacts = []
        for unit_id, relative in source._receipt_artifact_keys(self.units):
            unit = next(item for item in self.units if item["unit_id"] == unit_id)
            prior = source._leaf_state(unit["initial"], relative)
            intended = source._leaf_state(unit["target"], relative)
            destination = Path(unit["destination"]) if relative == "." else Path(unit["destination"]) / relative
            if preserve_unowned and unit_id == "opencode-plugin":
                ownership = "matching_preexisting_unowned"
            else:
                ownership = "created" if not prior["exists"] else "already_owned"
            receipt_artifacts.append(
                {
                    "unit_id": unit_id,
                    "path": relative,
                    "destination": str(destination),
                    "prior": prior,
                    "intended": intended,
                    "ownership": ownership,
                    "local_change": "none",
                }
            )
        self.receipt = {
            "receipt_format": 1,
            "receipt_id": self.receipt_id,
            "transaction_id": self.transaction_id,
            "roots": self.roots,
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "source_manifest_sha256": file_hash(self.manifest_path),
            "prior_receipt": None if prior_committed is None else {
                "receipt_id": prior_committed["receipt_id"],
                "receipt_sha256": prior_committed["receipt_sha256"],
            },
            "recovery": {"format": 1, "tool_sha256": self.tool_digest},
            "reader_support_sha256": file_hash(self.support_path),
            "artifacts": receipt_artifacts,
        }
        self.receipt_path = self.transaction / "receipt.json"
        write_json(self.receipt_path, self.receipt)
        committed = {
            "receipt_id": self.receipt_id,
            "receipt_sha256": file_hash(self.receipt_path),
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
        }
        target_admission = {
            "format": 1,
            "namespace_version": 1,
            "roots": self.roots,
            "status": "uninstalled" if target_uninstalled else "committed",
            "transaction_id": None,
            "committed": None if target_uninstalled else committed,
        }
        self.plan = {
            "plan_format": 1,
            "transaction_id": self.transaction_id,
            "kind": "uninstall" if target_uninstalled else "upgrade" if initial else "install",
            "roots": self.roots,
            "root_identities": {
                "state": source.physical_identity(self.state),
                "payload_parent": source.physical_identity(self.payload_parent),
                "opencode": source.physical_identity(self.opencode),
                "lifecycle": source.physical_identity(self.lifecycle),
                "v1": source.physical_identity(self.v1),
                "receipts": source.physical_identity(self.v1 / "receipts"),
                "recovery": source.physical_identity(self.v1 / "recovery"),
                "transactions": source.physical_identity(self.v1 / "transactions"),
                "transaction": source.physical_identity(self.transaction),
            },
            "lock_identity": source.physical_identity(self.lock),
            "prior_admission": self.prior_admission,
            "outcomes": {"target": target_admission, "prior": self.prior_admission},
            "target_receipt_id": self.receipt_id,
            "source_manifest": {"path": "source-manifest.json", "sha256": file_hash(self.manifest_path)},
            "proposed_receipt": {"path": "receipt.json", "sha256": file_hash(self.receipt_path)},
            "recovery": {
                "format": 1,
                "tool_path": str(self.tool),
                "tool_sha256": self.tool_digest,
                "python_path": str(Path(sys.executable).resolve()),
                "python_version": list(sys.version_info[:3]),
            },
            "required_operations": list(source.REQUIRED_OPERATIONS),
            "allowed_goals": ["target", "prior"],
            "units": self.units,
            "retained_state": source.retained_state_fingerprint(self.state),
            "reader_support": {"path": "reader-support.json", "sha256": file_hash(self.support_path)},
        }
        self.plan_path = self.transaction / "plan.json"
        write_json(self.plan_path, self.plan)
        self.progress = {
            "journal_format": 1,
            "transaction_id": self.transaction_id,
            "plan_sha256": file_hash(self.plan_path),
            "sequence": 0,
            "goal": "target",
            "units": [{"unit_id": unit_id, "phase": "pending"} for unit_id in source.UNIT_IDS],
        }
        self.progress_path = self.transaction / "progress.json"
        write_json(self.progress_path, self.progress)

    def publish_intent(self) -> None:
        pending = copy.deepcopy(self.prior_admission)
        pending["status"] = "recovery_required"
        pending["transaction_id"] = self.transaction_id
        write_json(self.lifecycle / "admission.json", pending)

    def rewrite_plan(self, mutate) -> None:
        plan = json.loads(self.plan_path.read_text())
        mutate(plan)
        write_json(self.plan_path, plan)
        progress = json.loads(self.progress_path.read_text())
        progress["plan_sha256"] = file_hash(self.plan_path)
        write_json(self.progress_path, progress)

    def snapshot(self):
        result = []
        for path in sorted(self.root.rglob("*")):
            details = path.lstat()
            relative = str(path.relative_to(self.root))
            if path.is_symlink():
                result.append((relative, "link", os.readlink(path), stat.S_IMODE(details.st_mode)))
            elif path.is_file():
                result.append((relative, "file", file_hash(path), stat.S_IMODE(details.st_mode)))
            else:
                result.append((relative, "directory", None, stat.S_IMODE(details.st_mode)))
        return result

    def assert_goal(self, testcase: unittest.TestCase, goal: str) -> None:
        for unit in self.units:
            testcase.assertTrue(
                self.engine.state_matches(Path(unit["destination"]), unit[goal]),
                unit["unit_id"],
            )
        testcase.assertEqual(self.lock.stat().st_ino, self.lock_inode)


class LifecycleRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="council-lifecycle-core-")
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, **kwargs) -> Fixture:
        path = self.root / ("fixture-%d" % len(list(self.root.glob("fixture-*"))))
        make_directory(path)
        return Fixture(path, **kwargs)

    def test_describe_matches_literal_format_fixture(self):
        expected = json.loads(
            (Path(__file__).parent / "fixtures/lifecycle/describe-v1.json").read_text()
        )
        self.assertEqual(source.describe(), expected)
        described = subprocess.run(
            [sys.executable, "-I", "-B", str(SOURCE), "describe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(described.returncode, 0, described.stderr)
        self.assertEqual(json.loads(described.stdout), expected)
        cases = json.loads(
            (Path(__file__).parent / "fixtures/lifecycle/format-cases-v1.json").read_text()
        )
        self.assertEqual(cases["format"], 1)
        self.assertIn("borrowed-validated-lease", cases["supported"])
        self.assertIn("native-or-configuration-operation", cases["refused"])

    def test_check_plan_is_exact_and_read_only(self):
        fixture = self.fixture()
        before = fixture.snapshot()
        result = fixture.engine.check_plan(fixture.plan_path)
        self.assertEqual(result["status"], "plan-valid")
        self.assertEqual(result["units"], list(source.UNIT_IDS))
        self.assertEqual(fixture.snapshot(), before)
        empty = self.root / "empty"
        make_directory(empty)
        environment = dict(os.environ, PYTHONPATH=str(self.root / "poison"))
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(fixture.tool), "check-plan", str(fixture.plan_path)],
            cwd=empty,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "plan-valid")
        self.assertEqual(fixture.snapshot(), before)
        nonisolated = subprocess.run(
            [sys.executable, str(fixture.tool), "check-plan", str(fixture.plan_path)],
            cwd=empty,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(nonisolated.returncode, 1)
        self.assertIn("requires Python -I -B", nonisolated.stderr)
        self.assertEqual(fixture.snapshot(), before)

    def test_forward_recovery_commits_all_five_units_and_receipt_last(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        events = []
        result = fixture.engine.recover(fixture.state, failpoint=events.append)
        self.assertEqual(result["status"], "committed")
        fixture.assert_goal(self, "target")
        admission = json.loads((fixture.lifecycle / "admission.json").read_text())
        self.assertEqual(admission, fixture.plan["outcomes"]["target"])
        final_receipt = fixture.v1 / "receipts" / (fixture.receipt_id + ".json")
        self.assertEqual(final_receipt.read_bytes(), fixture.receipt_path.read_bytes())
        self.assertLess(
            events.index("after:replace-immutable:final-receipt"),
            events.index("before:replace:terminal-admission"),
        )
        self.assertEqual(fixture.engine.recover(fixture.state), result)

    def test_abort_is_sticky_and_restores_validated_prior_after_partial_target(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        def stop_after_payload(event):
            if event == "after:rename:payload:activate-target":
                raise RuntimeError("stop after payload activation")

        with self.assertRaisesRegex(RuntimeError, "payload activation"):
            fixture.engine.recover(fixture.state, failpoint=stop_after_payload)
        self.assertTrue(
            fixture.engine.state_matches(Path(fixture.units[0]["destination"]), fixture.units[0]["target"])
        )
        result = fixture.engine.recover(fixture.state, abort=True)
        self.assertEqual(result["status"], "uninstalled")
        fixture.assert_goal(self, "prior")
        progress = json.loads(fixture.progress_path.read_text())
        self.assertEqual(progress["goal"], "prior")
        self.assertEqual(fixture.engine.recover(fixture.state), result)
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "terminal"):
            fixture.engine.recover(fixture.state, abort=True)

    def test_managed_abort_reactivates_the_clean_prior_set(self):
        fixture = self.fixture(initial=True)
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        def stop_after_two_units(event):
            if event == "after:rename:opencode-plugin:activate-target":
                raise RuntimeError("partial managed update")

        with self.assertRaises(RuntimeError):
            fixture.engine.recover(fixture.state, failpoint=stop_after_two_units)
        result = fixture.engine.recover(fixture.state, abort=True)
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["receipt_id"], "receipt-prior")
        fixture.assert_goal(self, "prior")
        self.assertEqual(json.loads(fixture.progress_path.read_text())["goal"], "prior")

    def test_abort_discards_only_a_known_partial_forward_stage(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        def stop_in_stage(event):
            if event == "after:replace-materialized-file:payload:target:SKILL.md":
                raise RuntimeError("partial target stage")

        with self.assertRaises(RuntimeError):
            fixture.engine.recover(fixture.state, failpoint=stop_in_stage)
        stage = Path(fixture.units[0]["objects"]["stage"])
        self.assertTrue((stage / "SKILL.md").is_file())
        result = fixture.engine.recover(fixture.state, abort=True)
        self.assertEqual(result["status"], "uninstalled")
        self.assertFalse(stage.exists())
        fixture.assert_goal(self, "prior")

    def test_unknown_destination_and_recovery_objects_fail_closed(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        write_payload(fixture.payload, "unknown")
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "unknown content"):
            fixture.engine.recover(fixture.state)
        admission = json.loads((fixture.lifecycle / "admission.json").read_text())
        self.assertEqual(admission["status"], "recovery_required")
        self.assertFalse((fixture.opencode / "council-plugin.ts").exists())

        fixture2 = self.fixture()
        stage = Path(fixture2.units[0]["objects"]["stage"])
        stage.symlink_to(fixture2.units[0]["objects"]["target"])
        fixture2.publish_intent()
        with self.assertRaises(fixture2.engine.RecoveryError):
            fixture2.engine.recover(fixture2.state)

    def test_strict_formats_reject_unknown_operations_types_and_bounds(self):
        fixture = self.fixture()
        fixture.rewrite_plan(lambda plan: plan["required_operations"].append("native-config-edit"))
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "unsupported or incomplete operations"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        fixture.rewrite_plan(lambda plan: plan["root_identities"]["state"].__setitem__("device", True))
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "integer"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        data = fixture.plan_path.read_text()
        fixture.plan_path.write_text(data.replace('"plan_format": 1', '"plan_format": 1, "plan_format": 1', 1))
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "duplicate JSON key"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        fixture.plan_path.write_bytes(b'{"padding":"' + b"x" * source.MAX_METADATA_BYTES + b'"}')
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "1 MiB"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        receipt = json.loads(fixture.receipt_path.read_text())
        receipt["artifacts"][0]["destination"] = "/tmp/elsewhere"
        write_json(fixture.receipt_path, receipt)
        fixture.rewrite_plan(
            lambda plan: plan["proposed_receipt"].__setitem__("sha256", file_hash(fixture.receipt_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "destination"):
            fixture.engine.check_plan(fixture.plan_path)

    def test_direct_and_borrowed_leases_share_the_same_inode(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        class Borrowed:
            def __init__(self, lease):
                self.lease = lease
                self.calls = 0

            def validate_for_recovery(self, state_root):
                self.calls += 1
                return self.lease.validate_for_recovery(state_root)

        alias = self.root / "state-alias"
        alias.symlink_to(fixture.state)
        with fixture.engine.acquire_recovery_lease(alias) as lease:
            adapter = Borrowed(lease)
            result = fixture.engine._execute_with_lease(fixture.state, adapter)
            self.assertEqual(result["status"], "committed")
            self.assertGreater(adapter.calls, 5)
            with self.assertRaisesRegex(fixture.engine.RecoveryError, "already held"):
                fixture.engine.acquire_recovery_lease(fixture.state)
            child = subprocess.run(
                [sys.executable, "-I", "-B", str(fixture.tool), "recover", "--state-root", str(alias)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(child.returncode, 1)
            self.assertIn("already held", child.stderr)
            self.assertFalse(lease.closed)
        self.assertTrue(lease.closed)

    def test_forked_child_cannot_validate_or_release_parent_lease(self):
        fixture = self.fixture()
        with fixture.engine.acquire_recovery_lease(fixture.state) as lease:
            child = os.fork()
            if child == 0:
                try:
                    lease.validate()
                except fixture.engine.RecoveryError:
                    lease.close()
                    os._exit(0)
                os._exit(3)
            _pid, status_value = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status_value), 0)
            with self.assertRaisesRegex(fixture.engine.RecoveryError, "already held"):
                fixture.engine.acquire_recovery_lease(fixture.state)
            lease.validate()

    def test_displaced_lock_and_retained_state_changes_refuse(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        old_lock = fixture.state / "broker.lock.old"
        fixture.lock.rename(old_lock)
        fixture.lock.write_bytes(b"replacement")
        fixture.lock.chmod(0o600)
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "lock"):
            fixture.engine.recover(fixture.state)
        self.assertFalse(fixture.payload.exists())

        fixture2 = self.fixture()
        fixture2.publish_intent()
        write_file(fixture2.state / "registrations/new.json", b"{}\n", 0o600)
        with self.assertRaisesRegex(fixture2.engine.RecoveryError, "retained state"):
            fixture2.engine.recover(fixture2.state)

    def test_external_cli_recovers_without_payload_or_import_environment(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        poison = self.root / "poison"
        make_directory(poison)
        for name in ("council.py", "council_admission.py", "json.py"):
            (poison / name).write_text("raise RuntimeError('poison imported')\n")
        empty = self.root / "empty-cwd"
        make_directory(empty)
        environment = dict(os.environ, PYTHONPATH=str(poison), PYTHONDONTWRITEBYTECODE="1")
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(fixture.tool), "recover", "--state-root", str(fixture.state)],
            cwd=empty,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "committed")
        fixture.assert_goal(self, "target")
        self.assertFalse((empty / "__pycache__").exists())
        self.assertFalse((poison / "__pycache__").exists())

    def test_uninstall_preserves_matching_unowned_external_and_raw_cache_backup(self):
        fixture = self.fixture(
            initial=True,
            cache=True,
            target_uninstalled=True,
            preserve_unowned=True,
        )
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        result = fixture.engine.recover(fixture.state)
        self.assertEqual(result["status"], "uninstalled")
        fixture.assert_goal(self, "target")
        self.assertFalse(fixture.payload.exists())
        unowned = fixture.opencode / "council-plugin.ts"
        self.assertEqual(unowned.read_bytes(), b"prior-opencode-plugin\n")
        payload_backup = Path(fixture.units[0]["objects"]["backup"])
        self.assertTrue((payload_backup / "scripts/__pycache__/runtime.cpython-39.pyc").is_file())
        self.assertEqual(fixture.lock.stat().st_ino, fixture.lock_inode)
        self.assertEqual(file_hash(fixture.tool), fixture.tool_digest)
        self.assertTrue(fixture.plan_path.is_file())
        before = fixture.snapshot()
        refused = subprocess.run(
            [sys.executable, "-I", "-B", str(fixture.tool), "recover", "--state-root",
             str(fixture.state), "--purge-state"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(fixture.snapshot(), before)

    def test_rollback_uses_the_same_fixed_forward_target_machine(self):
        fixture = self.fixture(initial=True)
        fixture.rewrite_plan(lambda plan: plan.__setitem__("kind", "rollback"))
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        self.assertEqual(fixture.engine.recover(fixture.state)["status"], "committed")
        fixture.assert_goal(self, "target")

    def test_cache_is_retained_in_backup_but_forward_activates_clean_target(self):
        fixture = self.fixture(initial=True, cache=True)
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        result = fixture.engine.recover(fixture.state)
        self.assertEqual(result["status"], "committed")
        fixture.assert_goal(self, "target")
        self.assertFalse((fixture.payload / "scripts/__pycache__").exists())
        self.assertTrue(
            (Path(fixture.units[0]["objects"]["backup"])
             / "scripts/__pycache__/runtime.cpython-39.pyc").is_file()
        )

    def test_every_forward_durability_boundary_recovers_after_process_exit(self):
        for initial in (False, True):
            probe = self.fixture(initial=initial)
            probe.publish_intent()
            events = []
            probe.engine.recover(probe.state, failpoint=events.append)
            self.assertGreater(len(events), 40)
            for boundary in range(len(events)):
                with self.subTest(initial=initial, boundary=boundary, event=events[boundary]):
                    fixture = self.fixture(initial=initial)
                    fixture.publish_intent()
                    child = os.fork()
                    if child == 0:
                        observed = {"index": -1}

                        def crash(_event):
                            observed["index"] += 1
                            if observed["index"] == boundary:
                                os._exit(97)

                        fixture.engine.recover(fixture.state, failpoint=crash)
                        os._exit(0)
                    _pid, status_value = os.waitpid(child, 0)
                    self.assertEqual(os.waitstatus_to_exitcode(status_value), 97)
                    fixture.engine.recover(fixture.state)
                    fixture.assert_goal(self, "target")
                    admission = json.loads((fixture.lifecycle / "admission.json").read_text())
                    self.assertEqual(admission["status"], "committed")

    def test_every_abort_durability_boundary_keeps_prior_goal_sticky(self):
        def partial_forward(fixture):
            fixture.publish_intent()

            def stop(event):
                if event == "after:rename:payload:activate-target":
                    raise RuntimeError("partial")

            with self.assertRaises(RuntimeError):
                fixture.engine.recover(fixture.state, failpoint=stop)

        for initial in (False, True):
            probe = self.fixture(initial=initial)
            partial_forward(probe)
            events = []
            probe.engine.recover(probe.state, abort=True, failpoint=events.append)
            self.assertGreater(len(events), 20)
            boundaries = list(range(len(events)))
            if initial:
                # The synthetic prior receipt has no older transaction plan. The fresh-install
                # case covers crashes during/after terminal publication; this case adds every
                # inverse materialization boundary before the identical publication sequence.
                boundaries = boundaries[:events.index("before:replace:terminal-admission")]
            for boundary in boundaries:
                with self.subTest(initial=initial, boundary=boundary, event=events[boundary]):
                    fixture = self.fixture(initial=initial)
                    partial_forward(fixture)
                    child = os.fork()
                    if child == 0:
                        observed = {"index": -1}

                        def crash(_event):
                            observed["index"] += 1
                            if observed["index"] == boundary:
                                os._exit(98)

                        fixture.engine.recover(fixture.state, abort=True, failpoint=crash)
                        os._exit(0)
                    _pid, status_value = os.waitpid(child, 0)
                    self.assertEqual(os.waitstatus_to_exitcode(status_value), 98)
                    progress = json.loads(fixture.progress_path.read_text())
                    if progress["sequence"]:
                        self.assertEqual(progress["goal"], "prior")
                    admission = json.loads((fixture.lifecycle / "admission.json").read_text())
                    if admission["status"] == "recovery_required":
                        fixture.engine.recover(fixture.state, abort=True)
                    else:
                        fixture.engine.recover(fixture.state)
                    fixture.assert_goal(self, "prior")
                    self.assertEqual(
                        json.loads(fixture.progress_path.read_text())["goal"], "prior"
                    )

    def test_every_partial_stage_discard_boundary_recovers_after_process_exit(self):
        def partial_stage(fixture):
            fixture.publish_intent()

            def stop(event):
                if event == "after:replace-materialized-file:payload:target:SKILL.md":
                    raise RuntimeError("partial stage")

            with self.assertRaises(RuntimeError):
                fixture.engine.recover(fixture.state, failpoint=stop)

        probe = self.fixture()
        partial_stage(probe)
        events = []
        probe.engine.recover(probe.state, abort=True, failpoint=events.append)
        self.assertTrue(any("unlink-stage" in event for event in events))
        for boundary in range(len(events)):
            with self.subTest(boundary=boundary, event=events[boundary]):
                fixture = self.fixture()
                partial_stage(fixture)
                child = os.fork()
                if child == 0:
                    observed = {"index": -1}

                    def crash(_event):
                        observed["index"] += 1
                        if observed["index"] == boundary:
                            os._exit(99)

                    fixture.engine.recover(fixture.state, abort=True, failpoint=crash)
                    os._exit(0)
                _pid, status_value = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status_value), 99)
                admission = json.loads((fixture.lifecycle / "admission.json").read_text())
                if admission["status"] == "recovery_required":
                    fixture.engine.recover(fixture.state, abort=True)
                else:
                    fixture.engine.recover(fixture.state)
                fixture.assert_goal(self, "prior")

    def test_fsync_failure_and_premature_terminal_marker_do_not_claim_success(self):
        fixture = self.fixture()
        fixture.publish_intent()
        with mock.patch.object(fixture.engine.os, "fsync", side_effect=OSError("ENOSPC")):
            with self.assertRaisesRegex(OSError, "ENOSPC"):
                fixture.engine.recover(fixture.state)
        self.assertEqual(
            json.loads((fixture.lifecycle / "admission.json").read_text())["status"],
            "recovery_required",
        )

        fixture2 = self.fixture()
        fixture2.publish_intent()

        def stop_after_payload(event):
            if event == "after:rename:payload:activate-target":
                raise RuntimeError("payload only")

        with self.assertRaises(RuntimeError):
            fixture2.engine.recover(fixture2.state, failpoint=stop_after_payload)
        final_receipt = fixture2.v1 / "receipts" / (fixture2.receipt_id + ".json")
        final_receipt.write_bytes(fixture2.receipt_path.read_bytes())
        final_receipt.chmod(0o600)
        write_json(fixture2.lifecycle / "admission.json", fixture2.plan["outcomes"]["target"])
        with self.assertRaisesRegex(fixture2.engine.RecoveryError, "coherent"):
            fixture2.engine.recover(fixture2.state)

    def test_preintent_changes_collisions_and_hardlinks_are_rejected_read_only(self):
        fixture = self.fixture()
        write_payload(fixture.payload, "late")
        before = fixture.snapshot()
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "changed before intent"):
            fixture.engine.check_plan(fixture.plan_path)
        self.assertEqual(fixture.snapshot(), before)

        fixture2 = self.fixture()
        plan = json.loads(fixture2.plan_path.read_text())
        payload = plan["units"][0]["target"]
        duplicate = copy.deepcopy(next(item for item in payload["artifacts"] if item["path"] == "SKILL.md"))
        duplicate["path"] = "skill.md"
        payload["artifacts"].append(duplicate)
        payload["artifacts"].sort(key=lambda item: item["path"])
        payload["sha256"] = source._inventory_digest(payload["artifacts"])
        write_json(fixture2.plan_path, plan)
        progress = json.loads(fixture2.progress_path.read_text())
        progress["plan_sha256"] = file_hash(fixture2.plan_path)
        write_json(fixture2.progress_path, progress)
        with self.assertRaisesRegex(fixture2.engine.RecoveryError, "collision"):
            fixture2.engine.check_plan(fixture2.plan_path)

        fixture3 = self.fixture()
        target = Path(fixture3.units[1]["objects"]["target"])
        linked = target.with_name(target.name + ".linked")
        os.link(target, linked)
        with self.assertRaisesRegex(fixture3.engine.RecoveryError, "recovery object"):
            fixture3.engine.check_plan(fixture3.plan_path)

        for git_kind in ("directory", "file", "symlink"):
            with self.subTest(git_kind=git_kind):
                fixture4 = self.fixture()
                payload_source = Path(fixture4.units[0]["objects"]["target"])
                git_path = payload_source / ".git"
                if git_kind == "directory":
                    make_directory(git_path)
                elif git_kind == "file":
                    write_file(git_path, b"gitdir: elsewhere\n")
                else:
                    git_path.symlink_to("elsewhere")
                with self.assertRaises(fixture4.engine.RecoveryError):
                    fixture4.engine.check_plan(fixture4.plan_path)

    def test_manifest_reader_receipt_progress_and_python_links_are_exact(self):
        fixture = self.fixture()
        manifest = json.loads(fixture.manifest_path.read_text())
        manifest["artifacts"]["opencode/native-registration.json"] = hashlib.sha256(b"x").hexdigest()
        write_json(fixture.manifest_path, manifest)
        fixture.rewrite_plan(
            lambda plan: plan["source_manifest"].__setitem__("sha256", file_hash(fixture.manifest_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "exactly four"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        support = json.loads(fixture.support_path.read_text())
        support["managed_writer_admission"] = "unknown"
        write_json(fixture.support_path, support)
        fixture.rewrite_plan(
            lambda plan: plan["reader_support"].__setitem__("sha256", file_hash(fixture.support_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "not an accepted result"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        receipt = json.loads(fixture.receipt_path.read_text())
        receipt["unexpected"] = "operation"
        write_json(fixture.receipt_path, receipt)
        fixture.rewrite_plan(
            lambda plan: plan["proposed_receipt"].__setitem__("sha256", file_hash(fixture.receipt_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "unexpected receipt keys"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        progress = json.loads(fixture.progress_path.read_text())
        progress["sequence"] = True
        write_json(fixture.progress_path, progress)
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "integer"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        fixture.rewrite_plan(
            lambda plan: plan["recovery"].__setitem__("python_version", [3, 9, 999])
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "Python version"):
            fixture.engine.check_plan(fixture.plan_path)

    def test_prior_receipt_prevents_silent_adoption_or_dropped_ownership(self):
        fixture = self.fixture(initial=True, target_uninstalled=True, preserve_unowned=True)
        receipt = json.loads(fixture.receipt_path.read_text())
        plugin = next(
            item for item in receipt["artifacts"]
            if item["unit_id"] == "opencode-plugin"
        )
        plugin["ownership"] = "already_owned"
        write_json(fixture.receipt_path, receipt)
        fixture.rewrite_plan(
            lambda plan: plan["proposed_receipt"].__setitem__("sha256", file_hash(fixture.receipt_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "adopt"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture2 = self.fixture(initial=True)
        prior_path = fixture2.v1 / "receipts/receipt-prior.json"
        prior = json.loads(prior_path.read_text())
        prior["artifacts"] = [
            item for item in prior["artifacts"]
            if not (item["unit_id"] == "opencode-protocol" and item["path"] == ".")
        ]
        write_json(prior_path, prior)
        committed = fixture2.prior_admission["committed"]
        committed["receipt_sha256"] = file_hash(prior_path)
        write_json(fixture2.lifecycle / "admission.json", fixture2.prior_admission)
        fixture2.rewrite_plan(
            lambda plan: plan["prior_admission"]["committed"].__setitem__(
                "receipt_sha256", file_hash(prior_path)
            )
        )
        receipt = json.loads(fixture2.receipt_path.read_text())
        receipt["prior_receipt"]["receipt_sha256"] = file_hash(prior_path)
        write_json(fixture2.receipt_path, receipt)
        fixture2.rewrite_plan(
            lambda plan: plan["proposed_receipt"].__setitem__("sha256", file_hash(fixture2.receipt_path))
        )
        with self.assertRaisesRegex(fixture2.engine.RecoveryError, "absent from the prior"):
            fixture2.engine.check_plan(fixture2.plan_path)

    def test_terminal_receipt_or_artifact_corruption_never_uses_progress_as_authority(self):
        fixture = self.fixture()
        fixture.publish_intent()
        fixture.engine.recover(fixture.state)
        fixture.progress_path.unlink()
        self.assertEqual(fixture.engine.recover(fixture.state)["status"], "committed")
        (fixture.payload / "SKILL.md").write_text("local edit\n")
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "coherent"):
            fixture.engine.recover(fixture.state)

        fixture2 = self.fixture()
        fixture2.publish_intent()
        fixture2.engine.recover(fixture2.state)
        final_receipt = fixture2.v1 / "receipts" / (fixture2.receipt_id + ".json")
        final_receipt.write_text("{}\n")
        with self.assertRaisesRegex(fixture2.engine.RecoveryError, "digest"):
            fixture2.engine.recover(fixture2.state)


if __name__ == "__main__":
    unittest.main()
