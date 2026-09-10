#!/usr/bin/env python3
"""Disposable tests for read-only release and ownership planning."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import council_lifecycle as lifecycle
import council_recover as recovery
from test_lifecycle_recovery import Fixture, make_directory, write_file


def tree_snapshot(root: Path):
    values = []
    for path in sorted(root.rglob("*")):
        details = path.lstat()
        relative = str(path.relative_to(root))
        if path.is_symlink():
            values.append((relative, "link", os.readlink(path), details.st_mode))
        elif path.is_file():
            values.append((relative, "file", hashlib.sha256(path.read_bytes()).hexdigest(), details.st_mode))
        else:
            values.append((relative, "directory", None, details.st_mode))
    return values


def synthetic_release(root: Path, label: str = "target", *, preserved_plugin: bool = False) -> Path:
    release = root / ("release-" + label)
    make_directory(release)
    payload = {
        "SKILL.md": (label + " skill\n").encode(),
        "scripts/runtime.py": ("VALUE = %r\n" % label).encode(),
        "scripts/opencode_council_plugin.ts": (
            b"preexisting-unowned\n" if preserved_plugin else (label + " plugin\n").encode()
        ),
        "scripts/council_protocol.ts": (label + " protocol\n").encode(),
        "scripts/opencode_delivery_registry.ts": (label + " registry\n").encode(),
        "scripts/tools/council.ts": (label + " tool\n").encode(),
    }
    for relative, data in payload.items():
        write_file(release / "payload" / relative, data)
    for destination, source_name in recovery.OPENCODE_SOURCES.items():
        write_file(release / "opencode" / destination, payload[source_name])
    artifacts = {}
    for path in sorted((release / "payload").rglob("*")):
        if path.is_file():
            name = "payload/" + str(path.relative_to(release / "payload").as_posix())
            artifacts[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted((release / "opencode").rglob("*")):
        if path.is_file():
            name = "opencode/" + str(path.relative_to(release / "opencode").as_posix())
            artifacts[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {
        "format": 1,
        "package_id": hashlib.sha256((label + " package").encode()).hexdigest(),
        "runtime_cohort": hashlib.sha256((label + " cohort").encode()).hexdigest(),
        "runtime_sources": [
            "scripts/runtime.py",
            "scripts/council_protocol.ts",
            "scripts/opencode_council_plugin.ts",
            "scripts/opencode_delivery_registry.ts",
            "scripts/tools/council.ts",
        ],
        "opencode_sources": recovery.OPENCODE_SOURCES,
        "artifacts": dict(sorted(artifacts.items())),
    }
    write_file(release / "release_manifest.json", recovery.json_bytes(manifest))
    return release


class LifecyclePlanningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="council-lifecycle-planner-")
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def roots(self, prefix=""):
        state = self.root / (prefix + "state")
        payload_parent = self.root / (prefix + "payload-parent")
        opencode = self.root / (prefix + "opencode")
        for path in (state, payload_parent, opencode, opencode / "tools"):
            make_directory(path)
        lock = state / "broker.lock"
        write_file(lock, b"stable", 0o600)
        return state, payload_parent / "council", opencode

    def actual_release(self, label):
        output = self.root / (label + "-release")
        completed = subprocess.run(
            [sys.executable, "-B", "scripts/build_release.py", "--output", str(output)],
            cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    def test_actual_build_release_output_is_a_positive_oracle(self):
        output = self.root / "actual-release"
        completed = subprocess.run(
            [sys.executable, "-B", "scripts/build_release.py", "--output", str(output)],
            cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        before = tree_snapshot(output)
        snapshot = lifecycle.validate_release(output)
        manifest = json.loads((output / "release_manifest.json").read_text())
        self.assertEqual(snapshot["artifact_count"], len(manifest["artifacts"]))
        self.assertEqual(snapshot["runtime_sources"], manifest["runtime_sources"])
        for name in (
            "payload/scripts/council_lifecycle.py",
            "payload/scripts/council_recover.py",
            "payload/scripts/test_lifecycle.py",
            "payload/scripts/test_lifecycle_recovery.py",
        ):
            self.assertIn(name, manifest["artifacts"])
        self.assertEqual(tree_snapshot(output), before)

    def test_release_validation_is_exact_and_read_only(self):
        release = synthetic_release(self.root)
        before = tree_snapshot(release)
        snapshot = lifecycle.validate_release(release)
        self.assertEqual(snapshot["artifact_count"], 10)
        self.assertEqual(snapshot, lifecycle.validate_release(release))
        self.assertEqual(tree_snapshot(release), before)
        self.assertEqual(
            {item["unit_id"] for item in snapshot["artifacts"]},
            set(recovery.UNIT_IDS),
        )

    def test_release_missing_extra_changed_and_nonregular_content_refuses(self):
        cases = ("missing", "extra", "changed", "symlink", "hardlink")
        for case in cases:
            with self.subTest(case=case):
                release = synthetic_release(self.root, case)
                target = release / "payload/SKILL.md"
                if case == "missing":
                    target.unlink()
                elif case == "extra":
                    write_file(release / "payload/extra.txt", b"extra")
                elif case == "changed":
                    target.write_bytes(b"changed")
                elif case == "symlink":
                    target.unlink()
                    target.symlink_to("scripts/runtime.py")
                else:
                    os.link(target, release / "payload/hardlink.txt")
                before = tree_snapshot(release)
                with self.assertRaises(recovery.RecoveryError):
                    lifecycle.validate_release(release)
                self.assertEqual(tree_snapshot(release), before)

    def test_runtime_sources_mapping_and_manifest_types_are_strict(self):
        release = synthetic_release(self.root)
        manifest_path = release / "release_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["runtime_sources"].append("scripts/missing.py")
        write_file(manifest_path, recovery.json_bytes(manifest))
        with self.assertRaisesRegex(recovery.RecoveryError, "runtime source"):
            lifecycle.validate_release(release)

        release = synthetic_release(self.root, "bool")
        manifest_path = release / "release_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["format"] = True
        write_file(manifest_path, recovery.json_bytes(manifest))
        with self.assertRaisesRegex(recovery.RecoveryError, "integer"):
            lifecycle.validate_release(release)

        release = synthetic_release(self.root, "mapping")
        manifest_path = release / "release_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["opencode_sources"]["native.json"] = "native.json"
        write_file(manifest_path, recovery.json_bytes(manifest))
        with self.assertRaisesRegex(recovery.RecoveryError, "mapping"):
            lifecycle.validate_release(release)

        release = synthetic_release(self.root, "duplicate")
        manifest_path = release / "release_manifest.json"
        data = manifest_path.read_text()
        manifest_path.write_text(data.replace('"format": 1', '"format": 1, "format": 1', 1))
        with self.assertRaisesRegex(recovery.RecoveryError, "duplicate JSON key"):
            lifecycle.validate_release(release)

        release = synthetic_release(self.root, "collision-path")
        original = release / "payload/SKILL.md"
        collision = release / "payload/skill.md"
        write_file(collision, original.read_bytes())
        manifest_path = release / "release_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["artifacts"]["payload/skill.md"] = hashlib.sha256(collision.read_bytes()).hexdigest()
        write_file(manifest_path, recovery.json_bytes(manifest))
        with self.assertRaisesRegex(recovery.RecoveryError, "collision"):
            lifecycle.validate_release(release)

    def test_fresh_plan_is_non_executable_and_deterministic(self):
        release = lifecycle.validate_release(synthetic_release(self.root))
        state, payload, opencode = self.roots()
        before = tree_snapshot(self.root)
        ownership = lifecycle.inspect_ownership(state, payload, opencode)
        preview = lifecycle.plan_ownership("install", release, ownership)
        self.assertTrue(preview["eligible_for_integration"])
        self.assertFalse(preview["executable"])
        self.assertIn("user-maintenance-window-for-first-adoption", preview["required_gates"])
        encoded = lifecycle.canonical_preview_bytes(preview)
        self.assertEqual(encoded, lifecycle.canonical_preview_bytes(
            lifecycle.plan_ownership("install", release, ownership)
        ))
        self.assertNotIn(b"transaction_id", encoded)
        self.assertNotIn(b"proposed_receipt", encoded)
        self.assertEqual(tree_snapshot(self.root), before)

    def test_matching_unowned_external_stays_unowned(self):
        release_root = synthetic_release(self.root)
        release = lifecycle.validate_release(release_root)
        state, payload, opencode = self.roots()
        write_file(
            opencode / "council-plugin.ts",
            (release_root / "opencode/council-plugin.ts").read_bytes(),
        )
        ownership = lifecycle.inspect_ownership(state, payload, opencode)
        preview = lifecycle.plan_ownership("install", release, ownership)
        plugin = next(
            item for item in preview["artifacts"]
            if item["unit_id"] == "opencode-plugin" and item["path"] == "."
        )
        self.assertEqual(plugin["ownership"], "matching_preexisting_unowned")
        self.assertEqual(plugin["prior"], plugin["intended"])

    def test_unmanaged_payload_clone_and_external_collision_are_blockers(self):
        release = lifecycle.validate_release(synthetic_release(self.root))
        for git_kind in ("directory", "file"):
            with self.subTest(git_kind=git_kind):
                state, payload, opencode = self.roots(git_kind + "-")
                make_directory(payload)
                if git_kind == "directory":
                    make_directory(payload / ".git")
                else:
                    write_file(payload / ".git", b"gitdir: elsewhere\n")
                ownership = lifecycle.inspect_ownership(state, payload, opencode)
                preview = lifecycle.plan_ownership("install", release, ownership)
                self.assertFalse(preview["eligible_for_integration"])
                self.assertIn("source_clone", {item["code"] for item in preview["blockers"]})

        state, payload, opencode = self.roots("collision-")
        write_file(opencode / "council-plugin.ts", b"different")
        preview = lifecycle.plan_ownership(
            "install", release, lifecycle.inspect_ownership(state, payload, opencode)
        )
        self.assertIn("unowned_collision", {item["code"] for item in preview["blockers"]})

        state, payload, opencode = self.roots("symlink-clone-")
        make_directory(payload)
        (payload / ".git").symlink_to("elsewhere")
        with self.assertRaises(recovery.RecoveryError):
            lifecycle.inspect_ownership(state, payload, opencode)

    def test_certified_upgrade_and_uninstall_use_receipt_ownership(self):
        fixture = Fixture(self.root / "managed")
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        fixture.engine.recover(fixture.state)
        release = lifecycle.validate_release(synthetic_release(self.root, "upgrade"))
        ownership = lifecycle.inspect_ownership(
            fixture.state, fixture.payload, fixture.opencode
        )
        upgrade = lifecycle.plan_ownership("upgrade", release, ownership)
        self.assertTrue(upgrade["eligible_for_integration"])
        self.assertIn("already_owned", {item["ownership"] for item in upgrade["artifacts"]})
        self.assertIn("created", {item["ownership"] for item in upgrade["artifacts"]})

        unowned = Fixture(self.root / "managed-unowned", preserve_unowned=True)
        unowned.engine.check_plan(unowned.plan_path)
        unowned.publish_intent()
        unowned.engine.recover(unowned.state)
        unowned_ownership = lifecycle.inspect_ownership(
            unowned.state, unowned.payload, unowned.opencode
        )
        upgrade = lifecycle.plan_ownership("upgrade", release, unowned_ownership)
        plugin = next(
            item for item in upgrade["artifacts"]
            if item["unit_id"] == "opencode-plugin" and item["path"] == "."
        )
        self.assertEqual(plugin["ownership"], "unresolved")
        self.assertFalse(upgrade["eligible_for_integration"])
        self.assertIn(
            "unowned_change_requires_adoption",
            {item["code"] for item in upgrade["blockers"]},
        )
        uninstall = lifecycle.plan_ownership("uninstall", None, unowned_ownership)
        plugin = next(
            item for item in uninstall["artifacts"]
            if item["unit_id"] == "opencode-plugin" and item["path"] == "."
        )
        self.assertEqual(plugin["ownership"], "matching_preexisting_unowned")
        self.assertEqual(plugin["prior"], plugin["intended"])

    def test_managed_local_change_missing_extra_and_pending_state_refuse(self):
        actions = ("edit", "missing", "extra", "pending")
        for action in actions:
            with self.subTest(action=action):
                fixture = Fixture(self.root / ("managed-" + action))
                fixture.publish_intent()
                fixture.engine.recover(fixture.state)
                if action == "edit":
                    (fixture.payload / "SKILL.md").write_text("changed\n")
                elif action == "missing":
                    (fixture.payload / "SKILL.md").unlink()
                elif action == "extra":
                    write_file(fixture.payload / "extra.txt", b"extra")
                else:
                    fixture.prepare_managed_transaction("upgrade")
                    fixture.publish_intent()
                with self.assertRaises(recovery.RecoveryError):
                    lifecycle.inspect_ownership(
                        fixture.state, fixture.payload, fixture.opencode
                    )

    def test_known_cache_is_listed_for_backup_and_not_in_target(self):
        fixture = Fixture(self.root / "managed-cache")
        fixture.publish_intent()
        fixture.engine.recover(fixture.state)
        cache = fixture.payload / "scripts/__pycache__/runtime.cpython-39.pyc"
        write_file(cache, b"cache", 0o600)
        ownership = lifecycle.inspect_ownership(
            fixture.state, fixture.payload, fixture.opencode
        )
        release = lifecycle.validate_release(synthetic_release(self.root, "cache-target"))
        preview = lifecycle.plan_ownership("upgrade", release, ownership)
        self.assertEqual(
            [item["path"] for item in preview["payload_cache_backup"]],
            ["scripts/__pycache__", "scripts/__pycache__/runtime.cpython-39.pyc"],
        )
        payload_target = next(item for item in preview["units"] if item["unit_id"] == "payload")["target"]
        self.assertFalse(any("__pycache__" in item["path"] for item in payload_target["artifacts"]))

        write_file(fixture.payload / "scripts/__pycache__/unexpected.txt", b"not bytecode")
        with self.assertRaisesRegex(recovery.RecoveryError, "unknown file type"):
            lifecycle.inspect_ownership(fixture.state, fixture.payload, fixture.opencode)

    def test_rollback_and_receipt_backed_reinstall_previews_remain_non_executable(self):
        fixture = Fixture(self.root / "rollback")
        fixture.publish_intent()
        fixture.engine.recover(fixture.state)
        release = lifecycle.retained_release(fixture.state, fixture.receipt_id)
        ownership = lifecycle.inspect_ownership(
            fixture.state, fixture.payload, fixture.opencode
        )
        rollback = lifecycle.plan_ownership("rollback", release, ownership)
        self.assertTrue(rollback["eligible_for_integration"])
        self.assertIn("supported-managed-rollback-target", rollback["required_gates"])
        self.assertFalse(rollback["executable"])

        uninstalled = Fixture(self.root / "reinstall", preserve_unowned=True)
        uninstalled.publish_intent()
        uninstalled.engine.recover(uninstalled.state)
        uninstalled.prepare_managed_transaction("uninstall")
        uninstalled.publish_intent()
        uninstalled.engine.recover(uninstalled.state)
        for transaction in list((uninstalled.v1 / "transactions").iterdir()):
            shutil.rmtree(transaction)
        write_file(uninstalled.state / "registrations/later.json", b"{}\n", 0o600)
        reinstall_release = lifecycle.validate_release(
            synthetic_release(self.root, "reinstall-target", preserved_plugin=True)
        )
        ownership = lifecycle.inspect_ownership(
            uninstalled.state, uninstalled.payload, uninstalled.opencode
        )
        reinstall = lifecycle.plan_ownership("install", reinstall_release, ownership)
        self.assertTrue(reinstall["eligible_for_integration"])
        plugin = next(
            item for item in reinstall["artifacts"]
            if item["unit_id"] == "opencode-plugin" and item["path"] == "."
        )
        self.assertEqual(plugin["ownership"], "matching_preexisting_unowned")

    def test_terminal_wrapper_ignores_history_and_retained_state_but_uncertified_marker_blocks(self):
        fixture = Fixture(self.root / "history")
        fixture.publish_intent()
        fixture.engine.recover(fixture.state)
        for transaction in list((fixture.v1 / "transactions").iterdir()):
            shutil.rmtree(transaction)
        write_file(fixture.state / "registrations/later.json", b"{}\n", 0o600)
        snapshot = lifecycle.inspect_ownership(
            fixture.state, fixture.payload, fixture.opencode
        )
        self.assertTrue(snapshot["management"]["certified"])

        state, payload, opencode = self.roots("uncertified-")
        lifecycle_root = state / ".council-lifecycle"
        make_directory(lifecycle_root)
        admission = {
            "format": 1,
            "namespace_version": 1,
            "roots": {
                "state": str(state), "payload": str(payload), "opencode": str(opencode)
            },
            "status": "uninstalled",
            "transaction_id": None,
            "committed": None,
        }
        write_file(lifecycle_root / "admission.json", recovery.json_bytes(admission), 0o600)
        uncertified = lifecycle.inspect_ownership(state, payload, opencode)
        self.assertFalse(uncertified["management"]["certified"])
        preview = lifecycle.plan_ownership(
            "install", lifecycle.validate_release(synthetic_release(self.root, "uncertified")),
            uncertified,
        )
        self.assertIn("uncertified_lifecycle_marker", {
            item["code"] for item in preview["blockers"]
        })

    def test_absent_root_plan_and_status_are_read_only(self):
        release = lifecycle.validate_release(synthetic_release(self.root, "absent-roots"))
        roots = (
            self.root / "missing/state",
            self.root / "missing/payload-parent/council",
            self.root / "missing/opencode",
        )
        before = tree_snapshot(self.root)
        ownership = lifecycle.inspect_ownership(*roots)
        preview = lifecycle.plan_ownership("install", release, ownership)
        observed = lifecycle.status(*roots)
        self.assertTrue(preview["eligible_for_integration"])
        self.assertEqual(observed["management"]["status"], "legacy_unmanaged")
        self.assertEqual(tree_snapshot(self.root), before)

    def test_isolated_cli_contract_and_purge_refusal(self):
        source = Path(lifecycle.__file__).resolve()
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(source), "--help"],
            cwd=self.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for command in ("status", "plan", "install", "upgrade", "rollback", "uninstall"):
            self.assertIn(command, completed.stdout)
        parser = lifecycle._parser()
        self.assertEqual(
            parser.parse_args(["plan", "install", "--release", "/fixture"]).kind,
            "install",
        )
        self.assertEqual(
            parser.parse_args(["rollback", "--receipt", "receipt-fixture"]).receipt,
            "receipt-fixture",
        )
        with mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                parser.parse_args(["uninstall", "--purge-state"])

    def test_actual_release_install_update_rollback_and_uninstall(self):
        release = self.actual_release("integration")
        roots = (
            self.root / "integration/state",
            self.root / "integration/payload-parent/council",
            self.root / "integration/opencode",
        )
        outcomes = []
        cases = (
            ("install", release, {"maintenance_window_confirmed": True,
                                  "transaction_id": "txn-integration-install"}),
            ("upgrade", release, {"transaction_id": "txn-integration-upgrade"}),
            ("rollback", None, {"receipt_id": "receipt-integration-install",
                                "transaction_id": "txn-integration-rollback"}),
            ("uninstall", None, {"transaction_id": "txn-integration-uninstall"}),
        )
        for kind, source_root, arguments in cases:
            result = lifecycle.execute_operation(kind, source_root, *roots, **arguments)
            outcomes.append(result["status"])
            self.assertEqual(result["recovery_command"][1:3], ["-I", "-B"])
        self.assertEqual(outcomes, ["committed", "committed", "committed", "uninstalled"])
        terminal = lifecycle.status(*roots)
        self.assertTrue(terminal["management"]["certified"])
        self.assertEqual(terminal["management"]["status"], "uninstalled")
        self.assertTrue((roots[0] / ".council-lifecycle").is_dir())
        self.assertTrue((roots[0] / "broker.lock").is_file())
        self.assertFalse(roots[1].exists())

    def test_retained_state_change_cannot_publish_bootstrap_intent(self):
        release = lifecycle.validate_release(self.actual_release("blocked"))
        state, payload, opencode = self.roots("blocked-")
        preview = lifecycle.plan_ownership(
            "install", release, lifecycle.inspect_ownership(state, payload, opencode)
        )
        snapshot = lifecycle.inspect.snapshot_registrations(state)
        with lifecycle.admission.acquire_writer_lease(state) as lease:
            bundle = lifecycle.prepare_transaction(
                preview, release, lease, transaction_id="txn-registration-change"
            )
            make_directory(state / "registrations")
            write_file(state / "registrations/new.json", b"{}\n", 0o600)
            with self.assertRaisesRegex(
                lifecycle.LifecyclePlanningError, "retained state changed"
            ):
                lifecycle.publish_and_execute(
                    bundle, lease, lifecycle.inspect, snapshot, now=2_000_000_000
                )
        self.assertFalse((state / ".council-lifecycle").exists())
        self.assertFalse(payload.exists())

    def test_planning_case_catalog_records_current_boundary(self):
        catalog = json.loads(
            (Path(__file__).parent / "fixtures/lifecycle/planning-cases-v1.json").read_text()
        )
        self.assertEqual(catalog["format"], 1)
        self.assertIn("actual-build-release", catalog["supported"])
        self.assertIn("transaction-publication", catalog["deferred"])


if __name__ == "__main__":
    unittest.main()
