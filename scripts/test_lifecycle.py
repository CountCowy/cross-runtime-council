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
from build_release import RUNTIME_FILES, identity
from generate_protocol import normalized_stamps
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
    payload = {"SKILL.md": (label + " skill\n").encode()}
    for name in RUNTIME_FILES:
        declaration = "export const " if name.endswith(".ts") else ""
        payload[name] = (
            declaration + 'PACKAGE_ID = "unstamped"\n' +
            declaration + 'RUNTIME_COHORT = "unstamped"\n' +
            "VALUE = %r\n" % (label + "-" + name)
        ).encode()
    if preserved_plugin:
        payload["scripts/opencode_council_plugin.ts"] += b"preexisting-unowned\n"
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
        "package_id": "0" * 64,
        "runtime_cohort": "0" * 64,
        "runtime_sources": list(RUNTIME_FILES),
        "opencode_sources": recovery.OPENCODE_SOURCES,
        "artifacts": dict(sorted(artifacts.items())),
    }
    _restamp_release(release, manifest)
    return release


def _restamp_release(release: Path, manifest=None) -> None:
    manifest_path = release / "release_manifest.json"
    if manifest is None:
        manifest = json.loads(manifest_path.read_text())
    normalized = {}
    payload = {}
    for path in sorted((release / "payload").rglob("*")):
        if path.is_file():
            payload[str(path.relative_to(release / "payload").as_posix())] = path.read_bytes()
    for name in RUNTIME_FILES:
        normalized[name] = normalized_stamps(payload[name].decode()).encode()
    package_inputs = dict(payload)
    package_inputs.update(normalized)
    package_id = identity(package_inputs)
    runtime_cohort = identity(normalized)
    for name in RUNTIME_FILES:
        data = normalized[name].decode()
        data = data.replace('PACKAGE_ID = "unstamped"', 'PACKAGE_ID = "' + package_id + '"')
        data = data.replace('RUNTIME_COHORT = "unstamped"', 'RUNTIME_COHORT = "' + runtime_cohort + '"')
        payload[name] = data.encode()
        write_file(release / "payload" / name, payload[name])
    for destination, source_name in recovery.OPENCODE_SOURCES.items():
        write_file(release / "opencode" / destination, payload[source_name])
    artifacts = {
        "payload/" + name: hashlib.sha256(data).hexdigest()
        for name, data in payload.items()
    }
    artifacts.update({
        "opencode/" + destination: hashlib.sha256(payload[source]).hexdigest()
        for destination, source in recovery.OPENCODE_SOURCES.items()
    })
    manifest.update(
        package_id=package_id,
        runtime_cohort=runtime_cohort,
        runtime_sources=list(RUNTIME_FILES),
        opencode_sources=recovery.OPENCODE_SOURCES,
        artifacts=dict(sorted(artifacts.items())),
    )
    write_file(manifest_path, recovery.json_bytes(manifest))


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
        self.assertEqual(snapshot["artifact_count"], 15)
        self.assertEqual(snapshot, lifecycle.validate_release(release))
        self.assertEqual(tree_snapshot(release), before)
        self.assertEqual(
            {item["unit_id"] for item in snapshot["artifacts"]},
            set(recovery.UNIT_IDS),
        )

    def test_release_identity_is_derived_from_payload_and_embedded_stamps(self):
        for mutation in ("package", "cohort", "runtime-sources", "embedded"):
            with self.subTest(mutation=mutation):
                release = self.actual_release("identity-" + mutation)
                manifest_path = release / "release_manifest.json"
                manifest = json.loads(manifest_path.read_text())
                if mutation == "package":
                    manifest["package_id"] = "0" * 64
                elif mutation == "cohort":
                    manifest["runtime_cohort"] = "0" * 64
                elif mutation == "runtime-sources":
                    manifest["runtime_sources"] = list(reversed(manifest["runtime_sources"]))
                else:
                    source = release / "payload/scripts/council.py"
                    data = source.read_bytes().replace(
                        manifest["package_id"].encode(), b"0" * 64, 1
                    )
                    write_file(source, data)
                    manifest["artifacts"]["payload/scripts/council.py"] = hashlib.sha256(
                        data
                    ).hexdigest()
                write_file(manifest_path, recovery.json_bytes(manifest))
                with self.assertRaises(lifecycle.LifecyclePlanningError):
                    lifecycle.validate_release(release)

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
                    target.symlink_to("scripts/council.py")
                else:
                    os.link(target, release / "payload/hardlink.txt")
                before = tree_snapshot(release)
                with self.assertRaises(recovery.RecoveryError):
                    lifecycle.validate_release(release)
                self.assertEqual(tree_snapshot(release), before)

    def test_large_release_artifact_streams_without_metadata_limit(self):
        release = self.actual_release("large-artifact")
        large = release / "payload/large.bin"
        data = b"large-artifact\n" * 100000
        write_file(large, data)
        _restamp_release(release)
        roots = (
            self.root / "large/state",
            self.root / "large/payload-parent/council",
            self.root / "large/opencode",
        )
        result = lifecycle.execute_operation(
            "install", release, *roots,
            maintenance_window_confirmed=True,
            transaction_id="txn-large-artifact",
        )
        self.assertEqual(result["status"], "committed")
        self.assertEqual((roots[1] / "large.bin").read_bytes(), data)

    def test_streamed_source_digest_change_refuses_and_cleans_preintent(self):
        release = self.actual_release("stream-change")
        changing = release / "payload/changing.bin"
        write_file(changing, b"before")
        _restamp_release(release)
        snapshot = lifecycle.validate_release(release)
        state, payload, opencode = self.roots("stream-change-")
        preview = lifecycle.plan_ownership(
            "install", snapshot, lifecycle.inspect_ownership(state, payload, opencode)
        )
        original = lifecycle._copy_file

        def change_before_copy(source, destination, expected_sha256, mode=0o644,
                               *arguments):
            if source == changing:
                write_file(changing, b"after")
            return original(
                source, destination, expected_sha256, mode, *arguments
            )

        with lifecycle.admission.acquire_writer_lease(state) as lease:
            with mock.patch.object(lifecycle, "_copy_file", side_effect=change_before_copy):
                with self.assertRaisesRegex(
                    lifecycle.LifecyclePlanningError, "differs from its digest"
                ):
                    lifecycle.prepare_transaction(
                        preview, snapshot, lease, transaction_id="txn-stream-change"
                    )
        self.assertFalse((state / ".council-lifecycle").exists())
        self.assertFalse(any(payload.parent.glob(".council-lifecycle-txn-stream-change-*")))

    def test_oversized_control_records_refuse_before_artifact_staging(self):
        release = self.actual_release("oversized-control")
        manifest = json.loads((release / "release_manifest.json").read_text())
        for index in range(7000):
            write_file(release / ("payload/bulk/%04d.txt" % index), b"x")
        _restamp_release(release, manifest)
        snapshot = lifecycle.validate_release(release)
        state, payload, opencode = self.roots("oversized-")
        preview = lifecycle.plan_ownership(
            "install", snapshot, lifecycle.inspect_ownership(state, payload, opencode)
        )
        with lifecycle.admission.acquire_writer_lease(state) as lease:
            with self.assertRaisesRegex(
                lifecycle.LifecyclePlanningError, "1 MiB metadata limit"
            ):
                lifecycle.prepare_transaction(
                    preview, snapshot, lease, transaction_id="txn-oversized-control"
                )
        self.assertFalse((state / ".council-lifecycle").exists())
        self.assertFalse(any(payload.parent.glob(".council-lifecycle-txn-oversized-control-*")))
        self.assertFalse(any(opencode.glob(".council-lifecycle-txn-oversized-control-*")))

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
        self.assertFalse(reinstall["eligible_for_integration"])
        self.assertIn(
            "unowned_change_requires_adoption",
            {item["code"] for item in reinstall["blockers"]},
        )
        plugin = next(
            item for item in reinstall["artifacts"]
            if item["unit_id"] == "opencode-plugin" and item["path"] == "."
        )
        self.assertEqual(plugin["ownership"], "unresolved")

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

    def test_pending_status_returns_validated_transaction_and_current_recovery_command(self):
        fixture = Fixture(self.root / "pending-status")
        fixture.publish_intent()
        observed = lifecycle.status(
            fixture.state, fixture.payload, fixture.opencode
        )
        pending = observed["pending_recovery"]
        self.assertEqual(observed["management"]["status"], "recovery_required")
        self.assertEqual(pending["transaction_id"], fixture.transaction_id)
        self.assertEqual(
            pending["plan_sha256"], hashlib.sha256(fixture.plan_path.read_bytes()).hexdigest()
        )
        self.assertEqual(pending["recovery_command"][1:3], ["-I", "-B"])
        self.assertEqual(
            pending["recovery_command"][3], fixture.plan["recovery"]["tool_path"]
        )
        self.assertEqual(pending["python_contract"]["implementation"], "CPython")
        self.assertEqual(pending["python_contract"]["minimum"], [3, 9])

        fixture.rewrite_plan(
            lambda plan: plan["recovery"].__setitem__("tool_sha256", "0" * 64)
        )
        with self.assertRaises(
            (lifecycle.LifecyclePlanningError, lifecycle.recovery.RecoveryError,
             FileNotFoundError)
        ):
            lifecycle.status(fixture.state, fixture.payload, fixture.opencode)

        for case in ("missing-plan", "cross-root"):
            probe = Fixture(self.root / ("pending-status-" + case))
            probe.publish_intent()
            if case == "missing-plan":
                probe.plan_path.unlink()
            else:
                admission_path = probe.lifecycle / "admission.json"
                admission = json.loads(admission_path.read_text())
                admission["roots"]["payload"] = str(self.root / "alternate-payload")
                write_file(
                    admission_path, recovery.json_bytes(admission), 0o600
                )
            before = tree_snapshot(probe.root)
            with self.subTest(case=case), self.assertRaises(
                (lifecycle.LifecyclePlanningError, lifecycle.recovery.RecoveryError,
                 FileNotFoundError)
            ):
                lifecycle.status(probe.state, probe.payload, probe.opencode)
            self.assertEqual(tree_snapshot(probe.root), before)

        unmanaged = self.roots("pending-unmanaged-")
        self.assertEqual(
            lifecycle.status(*unmanaged)["management"]["status"],
            "legacy_unmanaged",
        )

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

    def test_absent_roots_below_symlinked_ancestor_refuse_without_access(self):
        target = self.root / "ancestor-target"
        make_directory(target)
        sentinel = target / "sentinel"
        write_file(sentinel, b"unchanged")
        link = self.root / "ancestor-link"
        link.symlink_to(target, target_is_directory=True)
        before = tree_snapshot(target)
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "nonphysical ancestor"
        ):
            lifecycle.inspect_ownership(
                link / "state", link / "payload-parent/council", link / "opencode"
            )
        self.assertEqual(tree_snapshot(target), before)

    def test_fixed_unit_ancestors_are_physical_and_revalidated(self):
        state, payload, opencode = self.roots("unit-ancestor-")
        outside = self.root / "outside-tools"
        make_directory(outside)
        write_file(outside / "council.ts", b"outside\n")
        (opencode / "tools").rmdir()
        (opencode / "tools").symlink_to(outside, target_is_directory=True)
        outside_before = tree_snapshot(outside)
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "nonphysical ancestor"
        ):
            lifecycle.inspect_ownership(state, payload, opencode)
        self.assertEqual(tree_snapshot(outside), outside_before)

        state, payload, opencode = self.roots("missing-tools-")
        (opencode / "tools").rmdir()
        observed = lifecycle.inspect_ownership(state, payload, opencode)
        tool = next(
            item for item in observed["units"]
            if item["unit_id"] == "opencode-tool"
        )
        self.assertFalse(tool["state"]["exists"])

        release = self.actual_release("ancestor-revalidation")
        state, payload, opencode = self.roots("ancestor-revalidation-")
        outside = self.root / "outside-revalidation"
        make_directory(outside)
        calls = {"count": 0}
        original = lifecycle.inspect_ownership

        def replace_before_under_lease(*roots):
            calls["count"] += 1
            if calls["count"] == 3:
                (opencode / "tools").rmdir()
                (opencode / "tools").symlink_to(outside, target_is_directory=True)
            return original(*roots)

        with mock.patch.object(
            lifecycle, "inspect_ownership", side_effect=replace_before_under_lease
        ), self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "nonphysical ancestor"
        ):
            lifecycle.execute_operation(
                "install", release, state, payload, opencode,
                maintenance_window_confirmed=True,
                transaction_id="txn-ancestor-revalidation",
            )
        self.assertEqual(tree_snapshot(outside), [])

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

    def test_lifecycle_cli_refuses_non_darwin_before_root_observation(self):
        with mock.patch.object(lifecycle.sys, "platform", "linux"), mock.patch.object(
            lifecycle, "_production_roots", side_effect=AssertionError("roots observed")
        ), mock.patch("sys.stderr"), self.assertRaises(SystemExit) as raised:
            lifecycle.main(["status"])
        self.assertEqual(raised.exception.code, 2)

        state, payload, opencode = self.roots("darwin-status-")
        with mock.patch.object(lifecycle.sys, "platform", "darwin"):
            observed = lifecycle.status(state, payload, opencode)
        self.assertEqual(observed["management"]["status"], "legacy_unmanaged")

    def test_reader_support_binds_runtime_and_exact_policy_corpus(self):
        release_root = self.actual_release("reader-support")
        release = lifecycle.validate_release(release_root)
        support = lifecycle.reader_support_record(release)
        self.assertEqual(support["package_id"], release["package_id"])
        self.assertEqual(support["runtime_cohort"], release["runtime_cohort"])
        self.assertEqual(support["state_reader"], "pass")
        self.assertEqual(support["managed_writer_admission"], "pass")
        self.assertEqual(support["external_recoverer"], "pass")

        policy_path = release_root / "payload/scripts/fixtures/lifecycle/reader-support-v1.json"
        policy = json.loads(policy_path.read_text())
        policy["results"]["state_reader"] = "unknown"
        write_file(policy_path, recovery.json_bytes(policy))
        manifest_path = release_root / "release_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        _restamp_release(release_root, manifest)
        changed = lifecycle.validate_release(release_root)
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "policy is not qualified"
        ):
            lifecycle.reader_support_record(changed)

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
            if kind == "install":
                artifacts = lifecycle.inspect.inspect_artifacts(
                    roots[1], roots[2], state_root=roots[0]
                )
                self.assertEqual(artifacts["provenance"], "managed_receipt_manifest")
                self.assertEqual(artifacts["mismatch_count"], 0)
                self.assertFalse((roots[1] / "release_manifest.json").exists())
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
            plan = json.loads(Path(bundle["plan"]).read_text())
            prepared_objects = [
                Path(value)
                for unit in plan["units"]
                for name, value in unit["objects"].items()
                if name in ("target", "prior")
            ]
            make_directory(state / "registrations")
            write_file(state / "registrations/new.json", b"{}\n", 0o600)
            with self.assertRaisesRegex(
                lifecycle.LifecyclePlanningError, "retained state changed"
            ):
                lifecycle.publish_and_execute(
                    bundle, lease, lifecycle.inspect, snapshot, now=2_000_000_000
                )
        self.assertFalse((state / ".council-lifecycle").exists())
        self.assertFalse(Path(bundle["control_root"]).exists())
        self.assertFalse(any(path.exists() or path.is_symlink() for path in prepared_objects))
        self.assertFalse(payload.exists())

    def test_recovery_command_failure_cleans_managed_preintent_preparation(self):
        release = self.actual_release("sink-failure")
        roots = (
            self.root / "sink/state",
            self.root / "sink/payload-parent/council",
            self.root / "sink/opencode",
        )
        lifecycle.execute_operation(
            "install", release, *roots, maintenance_window_confirmed=True,
            transaction_id="txn-sink-install",
        )
        before = tree_snapshot(self.root)

        def fail_sink(_command):
            raise RuntimeError("synthetic sink failure")

        with self.assertRaisesRegex(RuntimeError, "sink failure"):
            lifecycle.execute_operation(
                "upgrade", release, *roots,
                transaction_id="txn-sink-upgrade",
                recovery_command_sink=fail_sink,
            )
        self.assertEqual(tree_snapshot(self.root), before)

    def test_internal_staging_failure_cleans_only_current_preparation(self):
        release = lifecycle.validate_release(self.actual_release("copy-failure"))
        state, payload, opencode = self.roots("copy-failure-")
        preview = lifecycle.plan_ownership(
            "install", release, lifecycle.inspect_ownership(state, payload, opencode)
        )
        original = lifecycle._copy_state
        calls = {"count": 0}

        def fail_after_copy(*arguments):
            original(*arguments)
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("synthetic copy failure")

        with lifecycle.admission.acquire_writer_lease(state) as lease:
            with mock.patch.object(lifecycle, "_copy_state", side_effect=fail_after_copy):
                with self.assertRaisesRegex(RuntimeError, "copy failure"):
                    lifecycle.prepare_transaction(
                        preview, release, lease, transaction_id="txn-copy-failure"
                    )
        self.assertFalse((state / ".council-lifecycle").exists())
        self.assertFalse(any(payload.parent.glob(".council-lifecycle-txn-copy-failure-*")))
        self.assertFalse(any(opencode.glob(".council-lifecycle-txn-copy-failure-*")))

    def test_process_exit_at_preparation_boundaries_is_reconciled(self):
        release = self.actual_release("preparation-crash")
        probe_roots = self.roots("preparation-probe-")
        snapshot = lifecycle.validate_release(release)
        preview = lifecycle.plan_ownership(
            "install", snapshot, lifecycle.inspect_ownership(*probe_roots)
        )
        events = []
        with lifecycle.admission.acquire_writer_lease(probe_roots[0]) as lease:
            bundle = lifecycle.prepare_transaction(
                preview, snapshot, lease, transaction_id="txn-preparation-probe",
                failpoint=events.append,
            )
            lifecycle._cleanup_preintent_bundle(bundle)
        categories = {
            "record": [event for event in events
                       if event == "after:replace:preparation-record"],
            "control": [event for event in events
                        if event.startswith("after:prepare-directory:")],
            "copy": [event for event in events
                     if event == "after:prepare-recoverer-copy" or
                     event.startswith("after:prepare-artifact-copy:")],
        }
        self.assertEqual(
            {name: len(values) for name, values in categories.items()},
            {"record": 52, "control": 6, "copy": 6},
        )

        for category, expected_events in categories.items():
            for occurrence in range(len(expected_events)):
                with self.subTest(category=category, occurrence=occurrence):
                    roots = self.roots("preparation-%s-%d-" % (category, occurrence))
                    child = os.fork()
                    if child == 0:
                        seen = {"count": 0}

                        def crash(event):
                            matches = (
                                event == "after:replace:preparation-record"
                                if category == "record" else
                                event.startswith("after:prepare-directory:")
                                if category == "control" else
                                event == "after:prepare-recoverer-copy" or
                                event.startswith("after:prepare-artifact-copy:")
                            )
                            if matches:
                                if seen["count"] == occurrence:
                                    os._exit(97)
                                seen["count"] += 1

                        lifecycle.execute_operation(
                            "install", release, *roots,
                            maintenance_window_confirmed=True,
                            transaction_id="txn-crashed-preparation",
                            _preparation_failpoint=crash,
                        )
                        os._exit(0)
                    _pid, child_status = os.waitpid(child, 0)
                    self.assertEqual(os.waitstatus_to_exitcode(child_status), 97)
                    result = lifecycle.execute_operation(
                        "install", release, *roots,
                        maintenance_window_confirmed=True,
                        transaction_id="txn-reconciled-preparation",
                    )
                    self.assertEqual(result["status"], "committed")
                    self.assertEqual(
                        list((roots[0] / recovery.PREPARATION_ROOT_NAME).iterdir()), []
                    )
                    self.assertEqual(
                        list(roots[0].glob(".council-lifecycle.prepare-*")), []
                    )

    def test_first_and_later_preparation_record_pending_states_reconcile_safely(self):
        release = self.actual_release("preparation-record-pending")
        cases = (
            ("empty", "before:write:preparation-record", 0),
            ("truncated", "before:write:preparation-record", 0),
            ("complete", "after:write:preparation-record", 0),
            ("later-complete", "after:write:preparation-record", 1),
        )
        for case, selected, occurrence in cases:
            with self.subTest(case=case):
                roots = self.roots("preparation-record-%s-" % case)
                child = os.fork()
                if child == 0:
                    seen = {"count": 0}

                    def crash(event):
                        if event == selected:
                            if seen["count"] == occurrence:
                                os._exit(93)
                            seen["count"] += 1

                    lifecycle.execute_operation(
                        "install", release, *roots,
                        maintenance_window_confirmed=True,
                        transaction_id="txn-record-" + case,
                        _preparation_failpoint=crash,
                    )
                    os._exit(0)
                _pid, child_status = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(child_status), 93)
                if case == "truncated":
                    pending = next(
                        (roots[0] / recovery.PREPARATION_ROOT_NAME).glob(".*.pending")
                    )
                    pending.write_bytes(b"{")
                    pending.chmod(0o600)
                result = lifecycle.execute_operation(
                    "install", release, *roots,
                    maintenance_window_confirmed=True,
                    transaction_id="txn-record-retry-" + case,
                )
                self.assertEqual(result["status"], "committed")
                self.assertEqual(
                    list((roots[0] / recovery.PREPARATION_ROOT_NAME).iterdir()), []
                )

        roots = self.roots("preparation-record-later-malformed-")
        child = os.fork()
        if child == 0:
            seen = {"count": 0}

            def crash_later(event):
                if event == "before:write:preparation-record":
                    if seen["count"] == 1:
                        os._exit(94)
                    seen["count"] += 1

            lifecycle.execute_operation(
                "install", release, *roots,
                maintenance_window_confirmed=True,
                transaction_id="txn-later-malformed",
                _preparation_failpoint=crash_later,
            )
            os._exit(0)
        _pid, child_status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(child_status), 94)
        pending = next(
            (roots[0] / recovery.PREPARATION_ROOT_NAME).glob(".*.pending")
        )
        self.assertEqual(pending.stat().st_size, 0)
        with self.assertRaises(lifecycle.recovery.RecoveryError):
            lifecycle.execute_operation(
                "install", release, *roots,
                maintenance_window_confirmed=True,
                transaction_id="txn-after-later-malformed",
            )
        self.assertTrue(pending.is_file())

    def test_unbound_preparation_pending_type_link_and_intent_refuse(self):
        for case in ("symlink", "hardlink"):
            with self.subTest(case=case):
                roots = self.roots("preparation-pending-%s-" % case)
                record_root = roots[0] / recovery.PREPARATION_ROOT_NAME
                make_directory(record_root)
                pending = record_root / ".txn-unbound.json.pending"
                outside = self.root / ("pending-outside-" + case)
                write_file(outside, b"outside\n", 0o600)
                if case == "symlink":
                    pending.symlink_to(outside)
                else:
                    os.link(outside, pending)
                before = outside.read_bytes()
                with self.assertRaisesRegex(
                    lifecycle.LifecyclePlanningError, "pending record changed"
                ):
                    with lifecycle.admission.acquire_writer_lease(roots[0]) as lease:
                        with lease.operation():
                            lifecycle._reconcile_preparations(roots[0], lease)
                self.assertEqual(outside.read_bytes(), before)
                self.assertTrue(pending.exists() or pending.is_symlink())

        fixture = Fixture(self.root / "preparation-published-intent")
        fixture.publish_intent()
        record_root = fixture.state / recovery.PREPARATION_ROOT_NAME
        make_directory(record_root)
        pending = record_root / (".%s.json.pending" % fixture.transaction_id)
        write_file(pending, b"", 0o600)
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "published intent|transaction content"
        ):
            lifecycle._remove_stale_preparation_pending(
                pending, None, fixture.state
            )
        self.assertTrue(pending.is_file())

    def test_incomplete_prepared_outputs_reconcile_write_and_copy_interruptions(self):
        release = self.actual_release("incomplete-prepared-output")
        roots = self.roots("incomplete-enospc-")
        transaction_id = "txn-incomplete-enospc"
        source_manifest = (
            roots[0] / (".council-lifecycle.prepare-" + transaction_id)
            / "v1/transactions" / transaction_id / "source-manifest.json"
        )

        def no_space(event):
            if event == "before:prepare-write:source-manifest":
                source_manifest.write_bytes(b"partial")
                source_manifest.chmod(0o600)
                raise OSError("ENOSPC")

        with self.assertRaisesRegex(OSError, "ENOSPC"):
            lifecycle.execute_operation(
                "install", release, *roots,
                maintenance_window_confirmed=True,
                transaction_id=transaction_id,
                _preparation_failpoint=no_space,
            )
        self.assertFalse(source_manifest.exists())
        self.assertEqual(
            lifecycle.execute_operation(
                "install", release, *roots,
                maintenance_window_confirmed=True,
                transaction_id="txn-after-incomplete-enospc",
            )["status"],
            "committed",
        )

        probe_roots = self.roots("incomplete-boundary-probe-")
        snapshot = lifecycle.validate_release(release)
        preview = lifecycle.plan_ownership(
            "install", snapshot, lifecycle.inspect_ownership(*probe_roots)
        )
        events = []
        with lifecycle.admission.acquire_writer_lease(probe_roots[0]) as lease:
            bundle = lifecycle.prepare_transaction(
                preview, snapshot, lease,
                transaction_id="txn-incomplete-boundary-probe",
                failpoint=events.append,
            )
            lifecycle._cleanup_preintent_bundle(bundle)
        boundaries = [
            event for event in events
            if event.startswith((
                "before:prepare-write:", "after:prepare-write:",
                "before:prepare-copy:", "after:prepare-copy:",
                "before:prepare-tree:", "after:prepare-tree:",
            ))
        ]
        self.assertEqual(len(boundaries), 26)
        for boundary in range(len(boundaries)):
            with self.subTest(boundary=boundary, event=boundaries[boundary]):
                roots = self.roots("incomplete-boundary-%d-" % boundary)
                child = os.fork()
                if child == 0:
                    seen = {"count": 0}

                    def crash(event):
                        if event.startswith((
                            "before:prepare-write:", "after:prepare-write:",
                            "before:prepare-copy:", "after:prepare-copy:",
                            "before:prepare-tree:", "after:prepare-tree:",
                        )):
                            if seen["count"] == boundary:
                                os._exit(95)
                            seen["count"] += 1

                    lifecycle.execute_operation(
                        "install", release, *roots,
                        maintenance_window_confirmed=True,
                        transaction_id="txn-incomplete-boundary",
                        _preparation_failpoint=crash,
                    )
                    os._exit(0)
                _pid, child_status = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(child_status), 95)
                result = lifecycle.execute_operation(
                    "install", release, *roots,
                    maintenance_window_confirmed=True,
                    transaction_id="txn-incomplete-retry",
                )
                self.assertEqual(result["status"], "committed")
                self.assertEqual(
                    list((roots[0] / recovery.PREPARATION_ROOT_NAME).iterdir()), []
                )

    def test_incomplete_prepared_output_substitution_and_unknown_child_refuse(self):
        release = self.actual_release("incomplete-substitution")
        roots = self.roots("incomplete-substitution-")
        child = os.fork()
        if child == 0:
            def stop_copy(event):
                if event == "before:prepare-copy:recovery-tool":
                    os._exit(96)

            lifecycle.execute_operation(
                "install", release, *roots,
                maintenance_window_confirmed=True,
                transaction_id="txn-incomplete-substitution",
                _preparation_failpoint=stop_copy,
            )
            os._exit(0)
        _pid, child_status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(child_status), 96)
        tool = next(
            (roots[0] / ".council-lifecycle.prepare-txn-incomplete-substitution"
             / "v1/recovery").glob("*.py")
        )
        tool.unlink()
        write_file(tool, b"", 0o600)
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "output identity changed"
        ):
            lifecycle.execute_operation(
                "install", release, *roots,
                maintenance_window_confirmed=True,
                transaction_id="txn-after-incomplete-substitution",
            )
        self.assertEqual(tool.read_bytes(), b"")

        roots = self.roots("incomplete-unknown-child-")
        child = os.fork()
        if child == 0:
            def stop_tree(event):
                if event.startswith("before:prepare-tree:"):
                    os._exit(97)

            lifecycle.execute_operation(
                "install", release, *roots,
                maintenance_window_confirmed=True,
                transaction_id="txn-incomplete-unknown-child",
                _preparation_failpoint=stop_tree,
            )
            os._exit(0)
        _pid, child_status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(child_status), 97)
        target = roots[1].parent / (
            ".council-lifecycle-txn-incomplete-unknown-child-payload-target"
        )
        write_file(target / "unexpected.txt", b"unexpected\n")
        with self.assertRaisesRegex(
            lifecycle.LifecyclePlanningError, "unexpected content"
        ):
            lifecycle.execute_operation(
                "install", release, *roots,
                maintenance_window_confirmed=True,
                transaction_id="txn-after-incomplete-unknown-child",
            )
        self.assertEqual((target / "unexpected.txt").read_bytes(), b"unexpected\n")

    def test_abandoned_preparation_with_changed_content_is_preserved(self):
        release = self.actual_release("preparation-change")
        for case in ("changed", "extra", "hardlink", "symlink"):
            with self.subTest(case=case):
                roots = self.roots("preparation-change-%s-" % case)
                child = os.fork()
                if child == 0:
                    def crash(event):
                        if event.startswith("after:prepare-artifact-copy:"):
                            os._exit(98)

                    lifecycle.execute_operation(
                        "install", release, *roots,
                        maintenance_window_confirmed=True,
                        transaction_id="txn-preparation-change",
                        _preparation_failpoint=crash,
                    )
                    os._exit(0)
                _pid, child_status = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(child_status), 98)
                target = roots[1].parent / (
                    ".council-lifecycle-txn-preparation-change-payload-target"
                )
                outside = self.root / ("preparation-change-outside-" + case)
                if case == "changed":
                    write_file(target / "SKILL.md", b"changed\n")
                elif case == "extra":
                    write_file(target / "extra.txt", b"extra\n")
                elif case == "hardlink":
                    os.link(target / "SKILL.md", outside)
                else:
                    shutil.rmtree(target)
                    make_directory(outside)
                    write_file(outside / "sentinel", b"outside\n")
                    target.symlink_to(outside, target_is_directory=True)
                with self.assertRaises(lifecycle.LifecyclePlanningError):
                    lifecycle.execute_operation(
                        "install", release, *roots,
                        maintenance_window_confirmed=True,
                        transaction_id="txn-preparation-after-change",
                    )
                self.assertTrue(target.exists() or target.is_symlink())
                if case == "symlink":
                    self.assertEqual((outside / "sentinel").read_bytes(), b"outside\n")

    def test_published_intent_preparation_record_is_retired_without_cleanup(self):
        release = self.actual_release("preparation-intent")
        roots = self.roots("preparation-intent-")
        child = os.fork()
        if child == 0:
            original = lifecycle.recovery._sync_directory

            def crash(path, failpoint, label):
                if label == "bootstrap-intent":
                    os._exit(99)
                return original(path, failpoint, label)

            with mock.patch.object(lifecycle.recovery, "_sync_directory", side_effect=crash):
                lifecycle.execute_operation(
                    "install", release, *roots,
                    maintenance_window_confirmed=True,
                    transaction_id="txn-preparation-intent",
                )
            os._exit(0)
        _pid, child_status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(child_status), 99)
        preparation_records = list(
            (roots[0] / recovery.PREPARATION_ROOT_NAME).glob("*.json")
        )
        self.assertEqual(len(preparation_records), 1)
        pending = lifecycle.status(*roots)
        self.assertEqual(pending["management"]["status"], "recovery_required")
        completed = subprocess.run(
            pending["pending_recovery"]["recovery_command"],
            cwd=self.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        upgraded = lifecycle.execute_operation(
            "upgrade", release, *roots,
            transaction_id="txn-after-preparation-intent",
        )
        self.assertEqual(upgraded["status"], "committed")
        self.assertEqual(
            list((roots[0] / recovery.PREPARATION_ROOT_NAME).iterdir()), []
        )

    def test_every_operation_recovers_from_a_preintent_process_exit(self):
        release = self.actual_release("operation-preintent")
        for kind in ("install", "upgrade", "rollback", "uninstall"):
            with self.subTest(kind=kind):
                roots = self.roots("operation-preintent-%s-" % kind)
                receipt_id = None
                if kind != "install":
                    installed = lifecycle.execute_operation(
                        "install", release, *roots,
                        maintenance_window_confirmed=True,
                        transaction_id="txn-%s-base" % kind,
                    )
                    receipt_id = installed["receipt_id"]
                release_argument = release if kind in ("install", "upgrade") else None
                arguments = {
                    "maintenance_window_confirmed": kind == "install",
                    "receipt_id": receipt_id if kind == "rollback" else None,
                }
                child = os.fork()
                if child == 0:
                    def crash(event):
                        if event.startswith("after:prepare-artifact-copy:"):
                            os._exit(96)

                    lifecycle.execute_operation(
                        kind, release_argument, *roots,
                        transaction_id="txn-%s-preintent-crash" % kind,
                        _preparation_failpoint=crash,
                        **arguments,
                    )
                    os._exit(0)
                _pid, child_status = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(child_status), 96)
                result = lifecycle.execute_operation(
                    kind, release_argument, *roots,
                    transaction_id="txn-%s-preintent-retry" % kind,
                    **arguments,
                )
                self.assertEqual(
                    result["status"],
                    "uninstalled" if kind == "uninstall" else "committed",
                )
                self.assertEqual(
                    list((roots[0] / recovery.PREPARATION_ROOT_NAME).iterdir()), []
                )

    def test_postintent_failure_retains_recovery_evidence(self):
        release = lifecycle.validate_release(self.actual_release("postintent"))
        state, payload, opencode = self.roots("postintent-")
        preview = lifecycle.plan_ownership(
            "install", release, lifecycle.inspect_ownership(state, payload, opencode)
        )
        snapshot = lifecycle.inspect.snapshot_registrations(state)
        with lifecycle.admission.acquire_writer_lease(state) as lease:
            bundle = lifecycle.prepare_transaction(
                preview, release, lease, transaction_id="txn-postintent"
            )
            with mock.patch.object(
                bundle["loaded_recoverer"], "_execute_with_lease",
                side_effect=RuntimeError("synthetic postintent failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "postintent failure"):
                    lifecycle.publish_and_execute(
                        bundle, lease, lifecycle.inspect, snapshot,
                        now=2_000_000_000,
                    )
        admission = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        self.assertEqual(admission["status"], "recovery_required")
        self.assertTrue(
            (state / ".council-lifecycle/v1/transactions/txn-postintent/plan.json").is_file()
        )
        self.assertTrue(any(payload.parent.glob(".council-lifecycle-txn-postintent-*")))

    def test_bootstrap_intent_sync_failure_preserves_published_recovery(self):
        release = lifecycle.validate_release(self.actual_release("intent-sync"))
        state, payload, opencode = self.roots("intent-sync-")
        preview = lifecycle.plan_ownership(
            "install", release, lifecycle.inspect_ownership(state, payload, opencode)
        )
        snapshot = lifecycle.inspect.snapshot_registrations(state)
        with lifecycle.admission.acquire_writer_lease(state) as lease:
            bundle = lifecycle.prepare_transaction(
                preview, release, lease, transaction_id="txn-intent-sync"
            )
            original = lifecycle.recovery._sync_directory

            def fail_intent_sync(path, failpoint, label):
                if label == "bootstrap-intent":
                    raise OSError("synthetic intent sync failure")
                return original(path, failpoint, label)

            with mock.patch.object(
                lifecycle.recovery, "_sync_directory", side_effect=fail_intent_sync
            ):
                with self.assertRaisesRegex(OSError, "intent sync failure"):
                    lifecycle.publish_and_execute(
                        bundle, lease, lifecycle.inspect, snapshot,
                        now=2_000_000_000,
                    )
        admission = json.loads(
            (state / ".council-lifecycle/admission.json").read_text()
        )
        self.assertEqual(admission["status"], "recovery_required")
        self.assertTrue(any(payload.parent.glob(".council-lifecycle-txn-intent-sync-*")))

    def test_preintent_cleanup_preserves_unexpected_prepared_content(self):
        release = lifecycle.validate_release(self.actual_release("cleanup-unknown"))
        state, payload, opencode = self.roots("cleanup-unknown-")
        preview = lifecycle.plan_ownership(
            "install", release, lifecycle.inspect_ownership(state, payload, opencode)
        )
        snapshot = lifecycle.inspect.snapshot_registrations(state)
        with lifecycle.admission.acquire_writer_lease(state) as lease:
            bundle = lifecycle.prepare_transaction(
                preview, release, lease, transaction_id="txn-cleanup-unknown"
            )
            unexpected = Path(bundle["plan"]).parent / "unexpected.txt"
            write_file(unexpected, b"unowned")
            make_directory(state / "registrations")
            write_file(state / "registrations/new.json", b"{}\n", 0o600)
            with self.assertRaisesRegex(
                lifecycle.LifecyclePlanningError, "unexpected content"
            ):
                lifecycle.publish_and_execute(
                    bundle, lease, lifecycle.inspect, snapshot,
                    now=2_000_000_000,
                )
        self.assertEqual(unexpected.read_bytes(), b"unowned")
        self.assertFalse((state / ".council-lifecycle").exists())

    def test_planning_case_catalog_records_current_boundary(self):
        catalog = json.loads(
            (Path(__file__).parent / "fixtures/lifecycle/planning-cases-v1.json").read_text()
        )
        self.assertEqual(catalog["format"], 1)
        self.assertIn("actual-build-release", catalog["supported"])
        self.assertIn("atomic-first-namespace-publication", catalog["supported"])
        self.assertEqual(catalog["deferred"], [])


if __name__ == "__main__":
    unittest.main()
