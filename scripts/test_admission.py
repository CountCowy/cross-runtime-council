"""Independent C1 exclusion, read-only, authentication and delayed-child cases."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import council
import council_admission as admission
import council_inspect as inspection
import council_opencode

SCRIPTS = Path(__file__).resolve().parent
CAP = "alpha-test-capability-" + "a" * 40
OTHER = "wrong-test-capability-" + "b" * 40


def inventory(root):
    if not root.exists():
        return None
    return {
        str(p.relative_to(root)): (
            p.lstat().st_mode,
            p.lstat().st_mtime_ns,
            p.read_bytes() if p.is_file() and not p.is_symlink() else None,
        )
        for p in root.rglob("*")
    }


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def envelope(root, cohort=council.RUNTIME_COHORT, status="committed"):
    receipt = b'{"fixture_only":true}\n'
    namespace = root / admission.NAMESPACE
    path = namespace / "v1/receipts/fixture.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(receipt)
    value = {
        "format": 1,
        "namespace_version": 1,
        "roots": {
            "state": str(root.resolve()),
            "payload": str((root.parent / "payload").resolve()),
            "opencode": str((root.parent / "opencode").resolve()),
        },
        "status": status,
        "transaction_id": "fixture" if status == "recovery_required" else None,
        "committed": {
            "receipt_id": "fixture",
            "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
            "package_id": "a" * 64,
            "runtime_cohort": cohort,
        },
    }
    write(namespace / "admission.json", value)
    return value


def bind(broker, **overrides):
    args = dict(
        runtime="codex",
        participant="alpha",
        label="Alpha",
        project="fixture",
        target_thread_id="exact-alpha",
        binding_capability=CAP,
    )
    args.update(overrides)
    return broker.bind(**args)


def relay_route(runtime="claude", **overrides):
    normalized = runtime.lower()
    route = {
        "runtime": runtime,
        "participant": "alpha",
        "label": "Alpha",
        "project": "fixture",
        "bound_at": "fixture",
        "lease_minutes": 5,
        "lease_expires_epoch": 200,
        "capability_hash": "a" * 64,
        "binding_generation": "gen-alpha",
        "runtime_cohort": council.RUNTIME_COHORT,
        "transport": (
            "claude_mcp_child_relay"
            if normalized == "claude"
            else "opencode_plugin_relay"
        ),
        "relay_path": "/private/tmp/fixture.sock",
        "relay_pid": 123,
        "relay_process_start_epoch": 456,
    }
    if normalized == "claude":
        route["relay_owner_hash"] = "b" * 64
    else:
        route["target_session_id"] = "session-alpha"
    route.update(overrides)
    return route


def isolate_admission_roots(test, base):
    inspect = admission.inspect_admission

    def fixture_inspect(root, payload_root=None, opencode_root=None):
        return inspect(
            root, payload_root or base / "payload", opencode_root or base / "opencode"
        )

    patch = mock.patch.object(
        admission, "inspect_admission", side_effect=fixture_inspect
    )
    patch.start()
    test.addCleanup(patch.stop)


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="c1-inspect-", dir="/private/tmp"
        )
        self.addCleanup(self.temp.cleanup)
        isolate_admission_roots(self, Path(self.temp.name))
        self.root = Path(self.temp.name) / "state"

    def actual_offline_release(self):
        """Build from committed HEAD plus only this side worker's allowed files."""
        base = Path(self.temp.name)
        source = base / "release-source"
        release = base / "offline-release"
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=SCRIPTS.parent, text=True
        ).strip()
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-hardlinks",
                "--no-checkout",
                str(SCRIPTS.parent),
                str(source),
            ],
            check=True,
        )
        subprocess.run(
            ["git", "checkout", "--quiet", "--detach", head],
            cwd=source,
            check=True,
        )
        for relative in (
            "scripts/council_inspect.py",
            "scripts/test_admission.py",
            "docs/maintenance-admission.md",
            "docs/development.md",
        ):
            target = source / relative
            target.write_bytes((SCRIPTS.parent / relative).read_bytes())
        subprocess.run(
            [sys.executable, "-B", "scripts/build_release.py", "--write"],
            cwd=source,
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                sys.executable,
                "-B",
                "scripts/build_release.py",
                "--output",
                str(release),
            ],
            cwd=source,
            check=True,
            capture_output=True,
            text=True,
        )
        return release

    def test_absent_corrupt_dormant_retention_and_staged_inspection_never_mutates(self):
        before = inventory(self.root)
        with (
            mock.patch(
                "council.CouncilBroker", side_effect=AssertionError("constructor")
            ),
            mock.patch("socket.socket", side_effect=AssertionError("transport")),
        ):
            self.assertFalse(inspection.inspect_state(self.root)["root_exists"])
        self.assertEqual(inventory(self.root), before)
        write(
            self.root / "dialogues/dlg-fixture/manifest.json",
            {
                "phase": "awaiting_extension",
                "schema_version": council.DIALOGUE_SCHEMA_VERSION,
            },
        )
        (self.root / "dialogues/dlg-fixture/audit.jsonl").write_bytes(
            b'{"event":"complete"}\n{"torn":'
        )
        write(self.root / "outbox/alpha/message.json", {"status": "staged"})
        write(self.root / "retention.json", {"days": 1})
        write(self.root / "tombstones/dlg-old.json", {"phase": "deleting"})
        (self.root / "registrations").mkdir()
        (self.root / "registrations/broken.json").write_text("{")
        before = inventory(self.root)
        with (
            mock.patch(
                "council.CouncilBroker", side_effect=AssertionError("constructor")
            ),
            mock.patch(
                "council.repair_jsonl_tail", side_effect=AssertionError("repair")
            ),
            mock.patch("os.replace", side_effect=AssertionError("rename")),
            mock.patch("os.chmod", side_effect=AssertionError("chmod")),
            mock.patch("pathlib.Path.mkdir", side_effect=AssertionError("mkdir")),
            mock.patch("pathlib.Path.unlink", side_effect=AssertionError("unlink")),
            mock.patch("socket.socket", side_effect=AssertionError("transport")),
        ):
            report = inspection.inspect_state(self.root)
        self.assertEqual(inventory(self.root), before)
        self.assertTrue(report["registrations"]["blocked"])
        self.assertEqual(report["artifacts"]["torn_audit_count"], 1)
        self.assertEqual(
            report["registrations"]["authenticated_readiness"], "unobserved"
        )

    def test_enumeration_permission_error_is_blocking_and_read_only(self):
        (self.root / "registrations").mkdir(parents=True)
        before = inventory(self.root)
        with mock.patch("os.scandir", side_effect=PermissionError("fixture denied")):
            report = inspection.inspect_state(self.root)
        self.assertTrue(report["registrations"]["blocked"])
        self.assertIsNotNone(report["registrations"]["inventory_error"])
        self.assertTrue(report["artifacts"]["inventory_error"])
        self.assertEqual(inventory(self.root), before)

    def test_inspector_uses_broker_route_and_configuration_validators(self):
        route = {
            "runtime": "claude",
            "participant": "alpha",
            "label": "Alpha",
            "project": "fixture",
            "bound_at": "fixture",
            "lease_minutes": 5,
            "lease_expires_epoch": 200,
            "capability_hash": "a" * 64,
            "binding_generation": "gen-alpha",
            "runtime_cohort": council.RUNTIME_COHORT,
            "transport": "claude_mcp_child_relay",
            "relay_path": "/private/tmp/fixture.sock",
            "relay_pid": 123,
            "relay_process_start_epoch": 456,
            "relay_owner_hash": "not-a-hash",
        }
        broker = council.CouncilBroker.__new__(council.CouncilBroker)
        for runtime, exact in (
            ("claude", {"relay_owner_hash": "not-a-hash"}),
            (
                "opencode",
                {
                    "transport": "opencode_plugin_relay",
                    "target_session_id": "bad session",
                },
            ),
        ):
            candidate = dict(route, runtime=runtime, **exact)
            record = ("alpha.json", None, None, candidate, None)
            self.assertFalse(inspection._route_compatible(record))
            with self.assertRaises(council.CouncilError):
                broker._validated_persisted_registration(candidate)

        write(self.root / "retention.json", {"days": "30"})
        write(
            self.root / "router.json",
            {"target_thread_id": ["thread"], "capability_hash": None},
        )
        write(
            self.root / "opencode-runtime.json",
            {
                "executable": "/fixture/opencode",
                "sha256": "bad",
                "cdhash": "b" * 40,
                "configured_at_epoch": 1,
            },
        )
        before = inventory(self.root)
        report = inspection.inspect_state(self.root, now=100)
        self.assertEqual(report["artifacts"]["malformed_count"], 3)
        self.assertEqual(inventory(self.root), before)
        with self.assertRaises(council.CouncilError):
            council.load_retention_days(self.root)
        broker.router_config_path = self.root / "router.json"
        with self.assertRaises(council.CouncilError):
            broker._router_config()
        self.assertFalse(
            council._pinned_opencode_parent(
                "/fixture/opencode", self.root, os.getpid()
            )
        )

    def test_artifact_dispatch_uses_root_relative_family_and_nested_schema(self):
        with council.CouncilBroker(self.root) as broker:
            broker.bind(
                "codex",
                "retention",
                "Retention",
                "fixture",
                target_thread_id="thread-retention",
                binding_capability=CAP,
            )
        report = inspection.inspect_state(self.root)
        self.assertEqual(report["artifacts"]["malformed_count"], 0)

        path = self.root / "outbox/retention/message.json"
        write(
            path,
            {
                "status": "pending",
                "envelope": {
                    "schema_version": council.SCHEMA_VERSION,
                    "payload": {
                        "schema_version": 999,
                        "dialogue_schema_version": 999,
                    },
                },
            },
        )
        report = inspection.inspect_state(self.root)
        self.assertEqual(report["artifacts"]["unsupported_schema_count"], 0)
        value = json.loads(path.read_text())
        value["envelope"]["schema_version"] = 999
        write(path, value)
        report = inspection.inspect_state(self.root)
        self.assertEqual(report["artifacts"]["unsupported_schema_count"], 1)

    def test_missing_required_artifact_schema_fields_are_unsupported(self):
        cases = (
            (
                "manifest-schema",
                "dialogues/dlg-fixture/manifest.json",
                {"dialogue_schema_version": council.DIALOGUE_SCHEMA_VERSION},
                1,
            ),
            (
                "manifest-dialogue-schema",
                "dialogues/dlg-fixture/manifest.json",
                {"schema_version": council.SCHEMA_VERSION},
                1,
            ),
            ("final-both-schemas", "dialogues/dlg-fixture/final.json", {}, 2),
            (
                "submission-schema",
                "dialogues/dlg-fixture/submissions/alpha.json",
                {},
                1,
            ),
            ("outbox-envelope", "outbox/alpha/message.json", {"status": "staged"}, 1),
            (
                "outbox-envelope-schema",
                "outbox/alpha/message.json",
                {"status": "staged", "envelope": {}},
                1,
            ),
        )
        for label, relative, value, expected in cases:
            with self.subTest(label=label):
                root = Path(self.temp.name) / ("missing-" + label)
                write(root / relative, value)
                before = inventory(root)
                report = inspection.inspect_state(root)
                self.assertEqual(report["artifacts"]["malformed_count"], 0)
                self.assertEqual(
                    report["artifacts"]["unsupported_schema_count"], expected
                )
                self.assertFalse(report["artifacts"].get("inventory_error", False))
                self.assertEqual(inventory(root), before)

    def test_unicode_and_recursive_json_become_malformed_evidence(self):
        route = {
            "runtime": "codex",
            "participant": "alpha",
            "label": "\ud800",
            "project": "fixture",
            "bound_at": "fixture",
            "lease_minutes": 5,
            "lease_expires_epoch": 1,
            "capability_hash": "a" * 64,
            "binding_generation": "gen-alpha",
            "runtime_cohort": council.RUNTIME_COHORT,
            "target_thread_id": "thread-alpha",
        }
        write(self.root / "registrations/alpha.json", route)
        report = inspection.inspect_state(self.root, now=2)
        self.assertEqual(report["registrations"]["incompatible_count"], 1)
        self.assertTrue(report["registrations"]["blocked"])

        deep = "[" * 1100 + "0" + "]" * 1100
        registration_root = Path(self.temp.name) / "deep-registration"
        registration = registration_root / "registrations/alpha.json"
        registration.parent.mkdir(parents=True)
        registration.write_text(deep)
        snapshot = inspection.snapshot_registrations(registration_root)
        self.assertEqual(snapshot.records[0][4], "malformed_registration")

        admission_root = Path(self.temp.name) / "deep-admission"
        marker = admission_root / admission.NAMESPACE / "admission.json"
        marker.parent.mkdir(parents=True)
        marker.write_text(deep)
        inspected = admission.inspect_admission(admission_root)
        self.assertTrue(inspected["managed"])
        self.assertEqual(inspected["status"], "invalid")

        artifact_root = Path(self.temp.name) / "deep-artifact"
        artifact_root.mkdir()
        (artifact_root / "retention.json").write_text(deep)
        inspected = inspection.inspect_state(artifact_root)
        self.assertEqual(inspected["artifacts"]["malformed_count"], 1)

        payload_root = Path(self.temp.name) / "deep-payload"
        payload_root.mkdir()
        (payload_root / "release_manifest.json").write_text(deep)
        opencode_root = Path(self.temp.name) / "deep-opencode"
        opencode_root.mkdir()
        inspected = inspection.inspect_artifacts(payload_root, opencode_root)
        self.assertEqual(inspected["error"], "missing_or_invalid_release_manifest")

    def test_release_artifact_coverage_hashes_and_missing_provenance(self):
        from build_release import RUNTIME_FILES

        self.assertEqual(set(RUNTIME_FILES), inspection.EXPECTED_RUNTIME_SOURCES)
        payload = Path(self.temp.name) / "payload"
        external = Path(self.temp.name) / "opencode"
        self.assertEqual(
            inspection.inspect_artifacts(payload, external)["provenance"], "unavailable"
        )
        manifest = {
            "format": 1,
            "package_id": "a" * 64,
            "runtime_cohort": council.RUNTIME_COHORT,
            "runtime_sources": list(RUNTIME_FILES),
            "artifacts": {},
        }
        names = ["payload/" + name for name in RUNTIME_FILES] + [
            "opencode/" + name
            for name in (
                "council-plugin.ts",
                "council_protocol.ts",
                "opencode_delivery_registry.ts",
                "tools/council.ts",
            )
        ]
        for name in names:
            parts = Path(name).parts
            path = (payload if parts[0] == "payload" else external).joinpath(*parts[1:])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture")
            manifest["artifacts"][name] = hashlib.sha256(b"fixture").hexdigest()
        write(payload / "release_manifest.json", manifest)
        before = inventory(payload)
        self.assertTrue(
            inspection.inspect_artifacts(payload, external)[
                "artifact_cohort_compatible"
            ]
        )
        self.assertEqual(inventory(payload), before)
        (external / "council-plugin.ts").write_text("different")
        self.assertFalse(
            inspection.inspect_artifacts(payload, external)[
                "artifact_cohort_compatible"
            ]
        )
        manifest["runtime_sources"] = []
        write(payload / "release_manifest.json", manifest)
        self.assertEqual(
            inspection.inspect_artifacts(payload, external)["provenance"], "unavailable"
        )

    def test_actual_offline_release_root_is_inspected_without_layout_fabrication(self):
        release = self.actual_offline_release()
        absent_state = Path(self.temp.name) / "absent-release-state"
        self.assertFalse((release / "payload/release_manifest.json").exists())
        before = inventory(release)
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(release / "payload/scripts/council_inspect.py"),
                "--state-root",
                str(absent_state),
                "--release-root",
                str(release),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(result.stdout)
        manifest = json.loads((release / "release_manifest.json").read_text())
        artifacts = report["release_artifacts"]
        self.assertEqual(artifacts["provenance"], "manifest_observed")
        self.assertEqual(artifacts["verified_count"], len(manifest["artifacts"]))
        self.assertEqual(artifacts["mismatch_count"], 0)
        self.assertTrue(artifacts["artifact_cohort_compatible"])
        self.assertFalse(absent_state.exists())
        self.assertEqual(inventory(release), before)

        # Neither pre-fix two-root interpretation can inspect this real layout.
        child_roots = inspection.inspect_artifacts(
            release / "payload", release / "opencode"
        )
        flattened_roots = inspection.inspect_artifacts(release, release)
        self.assertEqual(
            child_roots["error"], "missing_or_invalid_release_manifest"
        )
        self.assertEqual(flattened_roots["verified_count"], 0)
        self.assertEqual(
            flattened_roots["mismatch_count"], len(manifest["artifacts"])
        )

    def test_release_root_rejects_mixed_wrong_and_malformed_layouts(self):
        release = self.actual_offline_release()
        mixed = inspection.inspect_artifacts(
            release / "payload",
            release / "opencode",
            release_root=release,
        )
        wrong = inspection.inspect_artifacts(release_root=release / "payload")
        missing_payload = inspection.inspect_artifacts(
            opencode_root=release / "opencode"
        )
        missing_opencode = inspection.inspect_artifacts(
            payload_root=release / "payload"
        )
        malformed_root = Path(self.temp.name) / "malformed-release"
        malformed_root.mkdir()
        (malformed_root / "release_manifest.json").write_text("{")
        malformed = inspection.inspect_artifacts(release_root=malformed_root)
        for report in (
            mixed,
            wrong,
            missing_payload,
            missing_opencode,
            malformed,
        ):
            self.assertEqual(
                report["error"], "missing_or_invalid_release_manifest"
            )
            self.assertEqual(report["provenance"], "unavailable")
            self.assertEqual(report["verified_count"], 0)

    def test_positive_liveness_matrix_and_cached_probes(self):
        route = relay_route()
        record = ("alpha.json", None, None, route, None)
        cases = [
            (inspection.ProcessEvidence("absent"), "dead"),
            (inspection.ProcessEvidence("unknown"), "unknown"),
            (inspection.ProcessEvidence("present"), "unknown"),
            (
                inspection.ProcessEvidence("present", ("kernel-microseconds", 456)),
                "unknown",
            ),
            (
                inspection.ProcessEvidence(
                    "present", ("legacy-ps-lstart-seconds", 457)
                ),
                "unknown",
            ),
            (
                inspection.ProcessEvidence(
                    "present", ("legacy-ps-lstart-seconds", 456)
                ),
                "live",
            ),
        ]
        for evidence, expected in cases:
            with self.subTest(evidence=evidence):
                self.assertEqual(
                    inspection.classify_registration(record, 100, lambda _: evidence),
                    expected,
                )
        for expiry in (True, False, float("nan"), float("inf"), None, "0"):
            route["lease_expires_epoch"] = expiry
            self.assertEqual(inspection.classify_registration(record, 100), "unknown")
        route.update(
            runtime="codex",
            lease_expires_epoch=200,
            target_thread_id="thread-alpha",
        )
        self.assertEqual(
            inspection.classify_registration(
                record, 100, lambda _: inspection.ProcessEvidence("absent")
            ),
            "unknown",
        )
        route["lease_expires_epoch"] = 100
        self.assertEqual(inspection.classify_registration(record, 100), "expired")
        for error in (
            ProcessLookupError(3, "gone"),
            PermissionError(1, "denied"),
            OSError(5, "io"),
        ):
            with mock.patch("os.kill", side_effect=error):
                self.assertEqual(
                    inspection.probe_process(123).status,
                    "absent" if error.errno == 3 else "unknown",
                )
        route.update(runtime="claude", lease_expires_epoch=200)
        probe = mock.Mock(return_value=inspection.ProcessEvidence("unknown"))
        snapshot = inspection.RegistrationSnapshot(
            self.root, None, None, (record, record)
        )
        inspection.registration_report(snapshot, 100, probe)
        probe.assert_called_once_with(123)

    def test_mixed_case_runtime_uses_normalized_liveness_fields(self):
        cases = (
            (inspection.ProcessEvidence("absent"), "dead"),
            (
                inspection.ProcessEvidence(
                    "present", ("legacy-ps-lstart-seconds", 456)
                ),
                "live",
            ),
            (inspection.ProcessEvidence("unknown"), "unknown"),
            (
                inspection.ProcessEvidence(
                    "present", ("legacy-ps-lstart-seconds", 457)
                ),
                "unknown",
            ),
        )
        for runtime in ("Claude", "OpenCode"):
            route = relay_route(runtime)
            before = dict(route)
            record = ("alpha.json", None, None, route, None)
            for evidence, expected in cases:
                with self.subTest(runtime=runtime, evidence=evidence):
                    probe = mock.Mock(return_value=evidence)
                    self.assertEqual(
                        inspection.classify_registration(record, 100, probe),
                        expected,
                    )
                    probe.assert_called_once_with(123)
                    self.assertEqual(route, before)

    def test_owned_child_liveness_and_positive_death(self):
        child = subprocess.Popen(
            [sys.executable, "-B", "-c", "import sys; sys.stdin.read()"],
            stdin=subprocess.PIPE,
        )
        try:
            epoch = council._process_start_epoch(child.pid)
            self.assertIsNotNone(epoch)
            record = (
                "alpha.json",
                None,
                None,
                relay_route(
                    lease_expires_epoch=time.time() + 60,
                    relay_pid=child.pid,
                    relay_process_start_epoch=epoch,
                ),
                None,
            )
            self.assertEqual(
                inspection.classify_registration(record, time.time()), "live"
            )
            child.stdin.close()
            child.wait(timeout=3)
            self.assertEqual(
                inspection.classify_registration(record, time.time()), "dead"
            )
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)

    def test_exact_under_lease_set_bytes_inode_and_legacy_generation(self):
        with council.CouncilBroker(self.root) as broker:
            bind(broker)
        path = self.root / "registrations/alpha.json"
        route = json.loads(path.read_text())
        route.pop("binding_generation")
        route["lease_expires_epoch"] = 1
        write(path, route)
        snapshot = inspection.snapshot_registrations(self.root)
        before = inventory(self.root)
        with admission.acquire_writer_lease(self.root) as lease:
            self.assertTrue(
                inspection.revalidate_under_lease(snapshot, lease, 2)["valid"]
            )
            self.assertEqual(inventory(self.root), before)
            self.assertNotIn("binding_generation", json.loads(path.read_text()))
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(path.read_bytes())
            replacement.replace(path)
            self.assertFalse(
                inspection.revalidate_under_lease(snapshot, lease, 2)["valid"]
            )
            snapshot = inspection.snapshot_registrations(self.root)
            write(self.root / "registrations/new.json", route)
            self.assertFalse(
                inspection.revalidate_under_lease(snapshot, lease, 2)["valid"]
            )
            snapshot = inspection.snapshot_registrations(self.root)
            path.unlink()
            self.assertFalse(
                inspection.revalidate_under_lease(snapshot, lease, 2)["valid"]
            )

    def test_revalidation_detects_registry_change_during_liveness_probe(self):
        route = {
            "runtime": "claude",
            "participant": "alpha",
            "label": "Alpha",
            "project": "fixture",
            "bound_at": "fixture",
            "lease_minutes": 5,
            "lease_expires_epoch": 200,
            "capability_hash": "a" * 64,
            "relay_owner_hash": "b" * 64,
            "relay_path": "/private/tmp/fixture.sock",
            "relay_pid": 123,
            "relay_process_start_epoch": 456,
            "transport": "claude_mcp_child_relay",
        }
        path = self.root / "registrations/alpha.json"
        write(path, route)
        snapshot = inspection.snapshot_registrations(self.root)

        def raced_probe(_pid):
            write(path, dict(route, binding_generation="gen-new"))
            return inspection.ProcessEvidence("absent")

        with admission.acquire_writer_lease(self.root) as lease:
            result = inspection.revalidate_under_lease(
                snapshot, lease, 100, raced_probe
            )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "registration_snapshot_changed")

    def test_dead_relay_is_not_restored_and_report_redacts_route_material(self):
        route = {
            "runtime": "claude",
            "participant": "alpha",
            "label": "Alpha",
            "project": "fixture",
            "bound_at": "fixture",
            "lease_minutes": 5,
            "lease_expires_epoch": 200,
            "capability_hash": "a" * 64,
            "relay_owner_hash": "b" * 64,
            "relay_path": "/private/secret.sock",
            "relay_pid": 123,
            "relay_process_start_epoch": 456,
            "runtime_cohort": "0" * 64,
            "transport": "claude_mcp_child_relay",
        }
        write(self.root / "registrations/alpha.json", route)
        before = inventory(self.root)
        report = inspection.inspect_state(
            self.root, 100, lambda _: inspection.ProcessEvidence("absent")
        )
        self.assertFalse(report["registrations"]["blocked"])
        self.assertEqual(report["registrations"]["observed_restore_unready_count"], 1)
        serialized = json.dumps(report)
        for private in ("a" * 64, "b" * 64, "secret.sock", "alpha"):
            self.assertNotIn(private, serialized)
        self.assertEqual(inventory(self.root), before)


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="c1-lease-", dir="/private/tmp")
        self.addCleanup(self.temp.cleanup)
        isolate_admission_roots(self, Path(self.temp.name))
        self.root = Path(self.temp.name) / "state"

    def child(self, source, *args):
        return subprocess.run(
            [sys.executable, "-B", "-c", source, str(self.root), *map(str, args)],
            env={**os.environ, "PYTHONPATH": str(SCRIPTS)},
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_direct_constructor_alias_nested_borrow_close_and_displaced_lock(self):
        with council.CouncilBroker(self.root) as broker:
            bind(broker)
            alias = self.root.parent / "alias"
            alias.symlink_to(self.root, target_is_directory=True)
            before = inventory(self.root)
            for target in (self.root, alias):
                with self.assertRaisesRegex(admission.AdmissionError, "already held"):
                    council.CouncilBroker(target)
            self.assertEqual(inventory(self.root), before)
            with council.CouncilBroker(alias, lease=broker._lease) as borrowed:
                borrowed.configure_router("router")
            broker.ping()
            result = self.child(
                "from council_admission import acquire_writer_lease; import sys; from pathlib import Path; acquire_writer_lease(Path(sys.argv[1]))"
            )
            self.assertNotEqual(result.returncode, 0)
            lock = self.root / "broker.lock"
            lock.rename(self.root / "displaced.lock")
            lock.write_text("new inode")
            with self.assertRaisesRegex(admission.AdmissionError, "inode changed"):
                broker.ping()
        with self.assertRaises(admission.AdmissionError):
            broker.ping()

    def test_borrowed_close_drains_active_calls_without_releasing_outer_lease(self):
        with admission.acquire_writer_lease(self.root) as lease:
            borrowed = council.CouncilBroker(self.root, lease=lease)
            entered, release, closed = (
                threading.Event(),
                threading.Event(),
                threading.Event(),
            )
            original = council.atomic_json

            def blocked_write(*args, **kwargs):
                entered.set()
                self.assertTrue(release.wait(3))
                return original(*args, **kwargs)

            with mock.patch("council.atomic_json", side_effect=blocked_write):
                writer = threading.Thread(
                    target=lambda: borrowed.configure_router("drained")
                )
                writer.start()
                self.assertTrue(entered.wait(3))

                def close():
                    borrowed.close()
                    closed.set()

                closer = threading.Thread(target=close)
                closer.start()
                self.assertFalse(closed.wait(0.05))
                release.set()
                self.assertTrue(closed.wait(3))
                writer.join(3)
                closer.join(3)
            lease.validate()
            with self.assertRaises(admission.AdmissionError):
                admission.acquire_writer_lease(self.root)
            with lease.operation():
                # Closing an idle borrowed broker inside an outer lease operation
                # must neither unlock nor reject the caller's nesting contract.
                with council.CouncilBroker(self.root, lease=lease):
                    pass
            self.assertEqual(
                json.loads((self.root / "router.json").read_text())["target_thread_id"],
                "drained",
            )

    def test_forked_broker_refuses_before_touching_inherited_mutexes(self):
        with council.CouncilBroker(self.root) as broker:
            original = broker._calls

            class InheritedMutex:
                def __enter__(self):
                    raise AssertionError("inherited mutex touched")

                def __exit__(self, *_):
                    pass

            broker._calls = InheritedMutex()
            try:
                with mock.patch.object(
                    admission.os, "getpid", return_value=broker._lease.pid + 1
                ):
                    with self.assertRaisesRegex(
                        admission.AdmissionError, "another process"
                    ):
                        broker.ping()
            finally:
                broker._calls = original

    def test_fork_cannot_borrow_or_unlock_parent(self):
        with admission.acquire_writer_lease(self.root) as lease:
            pid = os.fork()
            if pid == 0:
                try:
                    try:
                        lease.validate()
                    except admission.AdmissionError:
                        lease.close()
                        os._exit(0)
                    os._exit(7)
                except BaseException:
                    os._exit(8)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            result = self.child(
                "from council_admission import acquire_writer_lease; import sys; from pathlib import Path; acquire_writer_lease(Path(sys.argv[1]))"
            )
            self.assertNotEqual(result.returncode, 0)
            lease.validate()

    def test_owner_unlocks_after_drain_while_forked_child_survives(self):
        lease = admission.acquire_writer_lease(self.root)
        ready_read, ready_write = os.pipe()
        release_read, release_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(ready_read)
                os.close(release_write)
                os.write(ready_write, b"ready")
                os.close(ready_write)
                os.read(release_read, 1)
                os.close(release_read)
                os._exit(0)
            except BaseException:
                os._exit(8)
        os.close(ready_write)
        os.close(release_read)
        try:
            self.assertEqual(os.read(ready_read, 5), b"ready")
            lease.close()
            with admission.acquire_writer_lease(self.root):
                pass
        finally:
            os.close(ready_read)
            os.write(release_write, b"x")
            os.close(release_write)
            _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_fork_inside_nested_operation_cannot_inherit_active_ownership(self):
        with admission.acquire_writer_lease(self.root) as lease:
            with lease.operation():
                pid = os.fork()
                if pid == 0:
                    try:
                        with lease.operation():
                            os._exit(9)
                    except admission.AdmissionError:
                        os._exit(0)
                _, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_forked_unwind_refuses_before_inherited_cleanup_mutexes(self):
        lease = admission.acquire_writer_lease(self.root)
        ready = threading.Event()
        release = threading.Event()

        def hold_lease_condition():
            with lease._condition:
                ready.set()
                release.wait()

        try:
            try:
                with lease.operation():
                    holder = threading.Thread(target=hold_lease_condition)
                    holder.start()
                    self.assertTrue(ready.wait(2))
                    pid = os.fork()
                    if pid == 0:
                        signal.signal(signal.SIGALRM, lambda *_: os._exit(9))
                        signal.alarm(1)
                    else:
                        release.set()
                        holder.join(2)
            except admission.AdmissionError:
                if lease.pid != os.getpid():
                    lease.close()
                    os._exit(0)
                raise
            if pid == 0:
                os._exit(8)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertEqual(lease._active, 0)
            lease.validate()
        finally:
            if lease.pid == os.getpid():
                lease.close()

        @admission.lease_methods
        class Probe:
            def __init__(self, owned):
                self._lease = owned
                self._calls = threading.Condition()
                self._closed = False
                self._closing = False
                self._call_counts = {}

            def fork_unwind(self):
                entered = threading.Event()
                unblock = threading.Event()

                def hold_call_condition():
                    with self._calls:
                        entered.set()
                        unblock.wait()

                thread = threading.Thread(target=hold_call_condition)
                thread.start()
                if not entered.wait(2):
                    raise AssertionError("call-condition holder did not start")
                child = os.fork()
                if child == 0:
                    signal.signal(signal.SIGALRM, lambda *_: os._exit(9))
                    signal.alarm(1)
                else:
                    unblock.set()
                    thread.join(2)
                return child

        lease = admission.acquire_writer_lease(self.root)
        probe = Probe(lease)
        try:
            try:
                pid = probe.fork_unwind()
            except admission.AdmissionError:
                if lease.pid != os.getpid():
                    lease.close()
                    os._exit(0)
                raise
            if pid == 0:
                os._exit(8)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertEqual(probe._call_counts, {})
            self.assertEqual(lease._active, 0)
            lease.validate()
        finally:
            if lease.pid == os.getpid():
                lease.close()

    def test_offline_commands_lose_without_touching_record_or_state(self):
        with council.CouncilBroker(self.root) as broker:
            bind(broker)
            (self.root / "broker.lock").write_text("existing diagnostic record")
            before = inventory(self.root)
            commands = [
                ["delete", "--dialogue-id", "dlg-fixture"],
                ["configure-router", "--target-thread-id", "router"],
                ["configure-opencode", "--executable", "/missing"],
                ["configure-retention", "--days", "5"],
                ["configure-retention", "--disable"],
            ]
            for command in commands:
                with self.subTest(command=command):
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-B",
                            str(SCRIPTS / "council.py"),
                            "--state-root",
                            str(self.root),
                            *command,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("lock is already held", result.stderr)
                    self.assertEqual(inventory(self.root), before)

    def test_crashed_process_releases_lock_for_offline_writer(self):
        result = self.child(
            "from council_admission import acquire_writer_lease; import os,sys; from pathlib import Path; lease=acquire_writer_lease(Path(sys.argv[1])); os._exit(17)"
        )
        self.assertEqual(result.returncode, 17)
        with council.CouncilBroker(self.root) as broker:
            broker.configure_router("after-crash")
        self.assertEqual(
            json.loads((self.root / "router.json").read_text())["target_thread_id"],
            "after-crash",
        )

    def test_managed_envelope_strictness_and_loaded_old_writer_refusal(self):
        self.root.mkdir()
        self.assertEqual(admission.inspect_admission(self.root)["status"], "unmanaged")
        value = envelope(self.root)
        self.assertTrue(admission.inspect_admission(self.root)["receipt_bound"])
        with council.CouncilBroker(self.root):
            pass
        mutations = [
            lambda x: x.update(format=True),
            lambda x: x.update(namespace_version=2),
            lambda x: x.update(status="future"),
            lambda x: x.update(transaction_id="../escape"),
            lambda x: x["roots"].update(state="/wrong"),
            lambda x: x["committed"].update(receipt_id="../../outside"),
            lambda x: x["committed"].update(receipt_sha256="0" * 64),
            lambda x: x["committed"].update(runtime_cohort="0" * 64),
        ]
        for mutate in mutations:
            candidate = json.loads(json.dumps(value))
            mutate(candidate)
            write(self.root / admission.NAMESPACE / "admission.json", candidate)
            before = inventory(self.root)
            with self.assertRaises(admission.AdmissionError):
                council.CouncilBroker(self.root)
            self.assertEqual(inventory(self.root), before)
        for status in ("recovery_required", "uninstalled"):
            envelope(self.root, status=status)
            with self.assertRaises(admission.AdmissionError):
                council.CouncilBroker(self.root)
        envelope(self.root, cohort="0" * 64)
        with admission.acquire_writer_lease(self.root) as lease:
            with self.assertRaises(admission.AdmissionError):
                admission.admit_runtime_writer(lease, council.RUNTIME_COHORT)
        path = self.root / admission.NAMESPACE / "admission.json"
        path.write_text('{"format":1,"format":1}')
        self.assertFalse(admission.inspect_admission(self.root)["envelope_valid"])
        path.unlink()
        path.symlink_to("missing")
        self.assertFalse(admission.inspect_admission(self.root)["envelope_valid"])
        shutil.rmtree(self.root / admission.NAMESPACE)
        (self.root / admission.NAMESPACE).symlink_to("missing")
        self.assertTrue(admission.inspect_admission(self.root)["managed"])

    def test_real_handler_drain_and_early_unlock_negative_control(self):
        # A real accepted status handler pauses immediately before durable work.
        for early_unlock in (False, True):
            root = self.root / str(early_unlock)
            broker = council.CouncilBroker(root)
            bind(broker)
            started, release, done = (
                threading.Event(),
                threading.Event(),
                threading.Event(),
            )
            original = broker.status

            def paused_status(**kwargs):
                started.set()
                self.assertTrue(release.wait(5))
                if early_unlock:
                    # Independent control recreates the old unguarded write.
                    (root / "after-unlock").write_text("bad")
                    return {}
                return original(**kwargs)

            broker.status = paused_status
            server = council.ThreadingUnixServer(
                str(root / "broker.sock"), council.BrokerRequestHandler
            )
            server.broker = broker
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.start()
            client = socket.socket(socket.AF_UNIX)
            client.connect(str(root / "broker.sock"))
            client.sendall(
                json.dumps(
                    {
                        "action": "status",
                        "runtime_cohort": council.RUNTIME_COHORT,
                        "arguments": {"participant": "alpha", "_auth_capability": CAP},
                    }
                ).encode()
                + b"\n"
            )
            self.assertTrue(started.wait(3))

            def shutdown():
                server.shutdown()
                if early_unlock:
                    # Simulate the predecessor lock release, bypassing new API.
                    os.close(broker._lease.fd)
                    broker._lease.closed = True
                server.server_close()
                broker.close()
                done.set()

            stopper = threading.Thread(target=shutdown)
            stopper.start()
            server_thread.join(3)
            time.sleep(0.05)
            if early_unlock:
                with admission.acquire_writer_lease(root):
                    release.set()
                    self.assertTrue(done.wait(3))
                    self.assertTrue((root / "after-unlock").exists())
            else:
                with self.assertRaises(admission.AdmissionError):
                    admission.acquire_writer_lease(root)
                self.assertFalse(done.is_set())
                release.set()
                self.assertTrue(done.wait(3))
                with admission.acquire_writer_lease(root):
                    pass
            client.close()
            stopper.join(3)


class CohortTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="c1-cohort-", dir="/private/tmp")
        self.addCleanup(self.temp.cleanup)
        isolate_admission_roots(self, Path(self.temp.name))
        self.root = Path(self.temp.name) / "state"
        self.broker = council.CouncilBroker(self.root)
        self.addCleanup(lambda: self.broker.close())
        bind(self.broker)

    def test_authentication_precedes_cohort_for_every_participant_action(self):
        actions = {
            "unbind": "participant",
            "start": "initiator",
            "submit": "participant",
            "extend": "participant",
            "request_extension": "participant",
            "cancel": "participant",
            "status": "participant",
            "wait": "participant",
            "ack": "participant",
            "retry": "participant",
        }
        for action, field in actions.items():
            for cohort in (None, {}, "stale", council.RUNTIME_COHORT):
                for capability in (None, OTHER):
                    with self.subTest(
                        action=action, cohort=cohort, capability=capability
                    ):
                        before = inventory(self.root)
                        with self.assertRaises(council.CouncilError) as caught:
                            self.broker.handle(
                                {
                                    "action": action,
                                    "runtime_cohort": cohort,
                                    "arguments": {
                                        field: "alpha",
                                        "_auth_capability": capability,
                                    },
                                }
                            )
                        self.assertEqual(caught.exception.reason, "not_authorized")
                        self.assertEqual(inventory(self.root), before)
                if cohort != council.RUNTIME_COHORT:
                    before = inventory(self.root)
                    with self.assertRaises(council.CouncilError) as caught:
                        self.broker.handle(
                            {
                                "action": action,
                                "runtime_cohort": cohort,
                                "arguments": {field: "alpha", "_auth_capability": CAP},
                            }
                        )
                    self.assertEqual(caught.exception.reason, "version_mismatch")
                    self.assertEqual(inventory(self.root), before)

    def test_incompatible_expired_request_never_deletes_route(self):
        self.broker.registrations["alpha"]["lease_expires_epoch"] = 1
        before = inventory(self.root)
        with self.assertRaises(council.CouncilError) as caught:
            self.broker.handle(
                {
                    "action": "status",
                    "runtime_cohort": "old",
                    "arguments": {"participant": "alpha", "_auth_capability": CAP},
                }
            )
        self.assertEqual(caught.exception.reason, "binding_expired")
        self.assertEqual(inventory(self.root), before)

    def test_same_cohort_restores_but_legacy_routes_require_authenticated_rebind(self):
        for legacy in (False, True):
            self.broker.close()
            if legacy:
                path = self.root / "registrations/alpha.json"
                route = json.loads(path.read_text())
                route.pop("runtime_cohort", None)
                write(path, route)
            self.broker = council.CouncilBroker(self.root)
            request = {
                "action": "wait",
                "runtime_cohort": council.RUNTIME_COHORT,
                "arguments": {"participant": "alpha", "_auth_capability": CAP},
            }
            if legacy:
                with self.assertRaises(council.CouncilError) as caught:
                    self.broker.handle(request)
                self.assertEqual(caught.exception.reason, "version_mismatch")
            else:
                self.assertEqual(self.broker.handle(request), {"message": None})
            args = dict(
                runtime="codex",
                participant="alpha",
                label="Alpha",
                project="fixture",
                target_thread_id="exact-alpha",
                binding_capability=CAP,
            )
            for cohort, target, capability in (
                ("old", "exact-alpha", CAP),
                (council.RUNTIME_COHORT, "other-task", CAP),
                (council.RUNTIME_COHORT, "exact-alpha", OTHER),
            ):
                before = inventory(self.root)
                with self.assertRaises(council.CouncilError):
                    self.broker.handle(
                        {
                            "action": "bind",
                            "runtime_cohort": cohort,
                            "arguments": dict(
                                args,
                                target_thread_id=target,
                                binding_capability=capability,
                            ),
                        },
                        trusted_mcp_runtime="codex",
                    )
                self.assertEqual(inventory(self.root), before)
            result = self.broker.handle(
                {
                    "action": "bind",
                    "runtime_cohort": council.RUNTIME_COHORT,
                    "arguments": args,
                },
                trusted_mcp_runtime="codex",
            )
            self.assertTrue(result["duplicate"])
            self.assertEqual(self.broker.handle(request), {"message": None})

    def test_surviving_mcp_router_participants_and_idle_codex_wake_after_restart(self):
        import council_mcp as mcp

        self.broker.close()
        self.root = Path(self.temp.name) / "mcp-state"
        self.broker = council.CouncilBroker(self.root)
        self.broker.configure_router("router-task")
        owner = self
        calls = []

        class LocalClient:
            def request(self, action, **arguments):
                calls.append(action)
                return owner.broker.handle(
                    {
                        "action": action,
                        "runtime_cohort": council.RUNTIME_COHORT,
                        "arguments": arguments,
                    },
                    trusted_mcp_runtime=arguments.get("runtime")
                    if action == "bind"
                    else "codex"
                    if action == "router_bind"
                    else None,
                )

        def tool(name, args, actor):
            value = mcp.call_tool(name, args, {"threadId": actor})
            return json.loads(value["content"][0]["text"])

        with (
            mock.patch.dict(mcp.ROUTER_CAPABILITIES, {}, clear=True),
            mock.patch.dict(mcp.PENDING_ROUTER_ROTATIONS, {}, clear=True),
            mock.patch.dict(mcp.BINDING_CAPABILITIES, {}, clear=True),
            mock.patch.dict(mcp.PENDING_BINDING_ROTATIONS, {}, clear=True),
            mock.patch("council_mcp.CouncilClient", return_value=LocalClient()),
        ):
            for actor in ("alpha", "beta"):
                tool(
                    "council_bind",
                    {
                        "runtime": "codex",
                        "participant": actor,
                        "label": actor,
                        "project": "fixture",
                    },
                    "thread-" + actor,
                )
            calls.clear()
            self.assertEqual(
                tool("council_pending_wakes", {"limit": 20}, "router-task"),
                {"notifications": []},
            )
            self.assertEqual(calls, ["router_bind", "pending_wakes"])
            router_capability = mcp.ROUTER_CAPABILITIES["router-task"]
            participant_capabilities = dict(mcp.BINDING_CAPABILITIES)
            dialogue = tool(
                "council_start",
                {
                    "initiator": "alpha",
                    "peer": "beta",
                    "topic": "Restart",
                    "brief": "Wake the idle peer",
                    "premises": [],
                },
                "thread-alpha",
            )["dialogue_id"]
            router_before = (self.root / "router.json").read_bytes()
            routes_before = {
                p.name: p.read_bytes() for p in (self.root / "registrations").iterdir()
            }
            self.broker.close()
            self.broker = council.CouncilBroker(self.root)
            calls.clear()
            # Beta has sent no request since restart. The authenticated router
            # can still wake its compatible, previously authorized exact task.
            notifications = tool("council_pending_wakes", {"limit": 20}, "router-task")[
                "notifications"
            ]
            self.assertEqual(calls, ["pending_wakes"])
            self.assertEqual(len(notifications), 1)
            self.assertEqual(notifications[0]["target_thread_id"], "thread-beta")
            self.assertEqual(mcp.ROUTER_CAPABILITIES["router-task"], router_capability)
            self.assertEqual(mcp.BINDING_CAPABILITIES, participant_capabilities)
            self.assertEqual((self.root / "router.json").read_bytes(), router_before)
            self.assertEqual(
                {
                    p.name: p.read_bytes()
                    for p in (self.root / "registrations").iterdir()
                },
                routes_before,
            )
            notice = notifications[0]
            tool(
                "council_wake_ack",
                {
                    key: notice[key]
                    for key in (
                        "participant",
                        "message_id",
                        "notification_id",
                        "notification_kind",
                    )
                }
                | {"delivered": True},
                "router-task",
            )
            message = tool(
                "council_wait",
                {"participant": "beta", "timeout_seconds": 0},
                "thread-beta",
            )["message"]
            self.assertEqual(message["dialogue_id"], dialogue)
            self.assertEqual(message["kind"], "proposal_request")
            self.assertEqual(
                len(
                    tool("council_status", {"participant": "alpha"}, "thread-alpha")[
                        "dialogues"
                    ]
                ),
                1,
            )
            self.assertNotIn("router_bind", calls)

    def test_authenticated_router_does_not_wake_legacy_or_incompatible_routes(self):
        for cohort in (None, "0" * 64):
            self.broker.close()
            self.root = Path(self.temp.name) / (
                "recipient-legacy" if cohort is None else "recipient-old"
            )
            self.broker = council.CouncilBroker(self.root)
            bind(self.broker)
            bind(
                self.broker,
                participant="beta",
                target_thread_id="exact-beta",
                binding_capability=OTHER,
            )
            self.broker.configure_router("router")
            self.broker.router_bind("router", CAP)
            self.broker.start(
                "alpha",
                "beta",
                "Recipient cohort",
                "Do not wake incompatible state",
                [],
            )
            self.broker.close()
            path = self.root / "registrations/beta.json"
            route = json.loads(path.read_text())
            if cohort is None:
                route.pop("runtime_cohort")
            else:
                route["runtime_cohort"] = cohort
            write(path, route)
            self.broker = council.CouncilBroker(self.root)
            before = inventory(self.root)
            request = {
                "action": "pending_wakes",
                "runtime_cohort": council.RUNTIME_COHORT,
                "arguments": {"_router_capability": CAP},
            }
            self.assertEqual(self.broker.handle(request), {"notifications": []})
            self.assertEqual(inventory(self.root), before)
            with self.assertRaises(council.CouncilError) as rejected:
                self.broker.handle(
                    {
                        "action": "wait",
                        "runtime_cohort": council.RUNTIME_COHORT,
                        "arguments": {"participant": "beta", "_auth_capability": OTHER},
                    }
                )
            self.assertEqual(rejected.exception.reason, "version_mismatch")
            self.broker.handle(
                {
                    "action": "bind",
                    "runtime_cohort": council.RUNTIME_COHORT,
                    "arguments": {
                        "runtime": "codex",
                        "participant": "beta",
                        "label": "Beta",
                        "project": "fixture",
                        "target_thread_id": "exact-beta",
                        "binding_capability": OTHER,
                    },
                },
                trusted_mcp_runtime="codex",
            )
            self.assertEqual(len(self.broker.handle(request)["notifications"]), 1)

    def test_router_authentication_restoration_and_rotation(self):
        self.broker.configure_router("router")
        args = {"target_thread_id": "router", "router_capability": CAP}
        self.broker.handle(
            {
                "action": "router_bind",
                "runtime_cohort": council.RUNTIME_COHORT,
                "arguments": args,
            },
            trusted_mcp_runtime="codex",
        )
        self.broker.close()
        self.broker = council.CouncilBroker(self.root)
        for action in ("pending_wakes", "wake_ack"):
            for capability, reason in ((OTHER, "unknown"), (CAP, "version_mismatch")):
                before = inventory(self.root)
                with self.assertRaises(council.CouncilError) as caught:
                    self.broker.handle(
                        {
                            "action": action,
                            "runtime_cohort": "old",
                            "arguments": {"_router_capability": capability},
                        }
                    )
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(inventory(self.root), before)
        self.broker.handle(
            {
                "action": "router_bind",
                "runtime_cohort": council.RUNTIME_COHORT,
                "arguments": args,
            },
            trusted_mcp_runtime="codex",
        )
        self.assertEqual(
            self.broker.handle(
                {
                    "action": "pending_wakes",
                    "runtime_cohort": council.RUNTIME_COHORT,
                    "arguments": {"_router_capability": CAP},
                }
            ),
            {"notifications": []},
        )

    def test_delayed_plugin_old_bridge_new_refuses_before_client(self):
        for cohort in (None, "old", {}):
            request = {
                "action": "ping",
                "runtime_cohort": cohort,
                "arguments": {"runtime_cohort": council.RUNTIME_COHORT},
            }
            stdin = mock.Mock(buffer=io.BytesIO(json.dumps(request).encode() + b"\n"))
            stdout = io.StringIO()
            with (
                mock.patch("sys.stdin", stdin),
                contextlib.redirect_stdout(stdout),
                mock.patch("council_opencode.CouncilClient") as client,
            ):
                self.assertEqual(council_opencode.main(), 2)
            self.assertEqual(
                json.loads(stdout.getvalue())["reason"], "version_mismatch"
            )
            client.assert_not_called()
        request = {
            "action": "ping",
            "runtime_cohort": council.RUNTIME_COHORT,
            "arguments": {},
        }
        with (
            mock.patch(
                "sys.stdin",
                mock.Mock(buffer=io.BytesIO(json.dumps(request).encode() + b"\n")),
            ),
            contextlib.redirect_stdout(io.StringIO()),
            mock.patch("council_opencode.CouncilClient") as client,
        ):
            client.return_value.request.return_value = {}
            self.assertEqual(council_opencode.main(), 0)
            client.assert_called_once_with(origin_cohort=council.RUNTIME_COHORT)

    def test_bridge_origin_substitution_mutant_fails_the_refusal_oracle(self):
        copied = Path(self.temp.name) / "mutant-scripts"
        copied.mkdir()
        for name in (
            "council.py",
            "council_protocol.py",
            "council_admission.py",
            "council_opencode.py",
        ):
            (copied / name).write_bytes((SCRIPTS / name).read_bytes())
        program = "\n".join(
            [
                "import sys; sys.path.insert(0, " + repr(str(copied)) + ")",
                "import council_opencode as bridge",
                "class FakeClient:",
                "    def __init__(self, **kwargs): pass",
                "    def request(self, *args, **kwargs): return {}",
                "bridge.CouncilClient = FakeClient",
                "raise SystemExit(bridge.main())",
            ]
        )

        def invoke():
            return subprocess.run(
                [sys.executable, "-I", "-B", "-c", program],
                input=json.dumps(
                    {
                        "action": "ping",
                        "runtime_cohort": "stale-plugin",
                        "arguments": {},
                    }
                )
                + "\n",
                capture_output=True,
                text=True,
                timeout=5,
            )

        def refuses_origin(response):
            self.assertEqual(response.returncode, 2, response.stderr)
            self.assertEqual(json.loads(response.stdout)["reason"], "version_mismatch")

        refuses_origin(invoke())
        path = copied / "council_opencode.py"
        original = path.read_text()
        mutant = original.replace(
            'origin = request.get("runtime_cohort")', "origin = RUNTIME_COHORT"
        )
        self.assertNotEqual(mutant, original)
        path.write_text(mutant)
        # Substituting the newly loaded bridge's stamp must be caught by the
        # same refusal oracle. No broker or live state participates in control.
        with self.assertRaises(AssertionError):
            refuses_origin(invoke())

    def test_explicit_ping_checks_legacy_broker_cohort_response(self):
        client = council.CouncilClient(self.root)
        for response in (
            {"broker_version": council.BROKER_VERSION},
            {"broker_version": council.BROKER_VERSION, "runtime_cohort": "old"},
        ):
            with (
                mock.patch.object(client, "_send", return_value=response),
                self.assertRaises(council.CouncilError) as caught,
            ):
                client.request("ping")
            self.assertEqual(caught.exception.reason, "version_mismatch")

    def test_known_mismatch_never_starts_a_broker(self):
        client = council.CouncilClient(self.root)
        with (
            mock.patch.object(
                client,
                "_send",
                side_effect=council.CouncilError("old", reason="version_mismatch"),
            ),
            mock.patch("subprocess.Popen") as spawn,
        ):
            with self.assertRaises(council.CouncilError):
                client.ensure_daemon()
            spawn.assert_not_called()


class ProcessBarrierTests(unittest.TestCase):
    def test_startup_status_channel_is_bounded_and_strict(self):
        process = mock.Mock()
        process.poll.return_value = None

        def read_status(payload, timeout=0.2):
            read_descriptor, write_descriptor = os.pipe()
            stream = os.fdopen(read_descriptor, "rb", buffering=0)
            try:
                if payload is not None:
                    os.write(write_descriptor, payload)
                return council.read_daemon_startup_status(
                    stream, process, time.monotonic() + timeout
                )
            finally:
                stream.close()
                os.close(write_descriptor)

        self.assertEqual(
            read_status(b'{"ok":true,"reason":null,"retryable":false}\n'),
            {"ok": True, "reason": None, "retryable": False},
        )
        for payload in (b"not-json\n", b"x" * 1025):
            with self.subTest(payload=payload[:20]):
                with self.assertRaises(council.CouncilError) as caught:
                    read_status(payload)
                self.assertEqual(caught.exception.reason, "malformed_response")
        with self.assertRaises(council.CouncilError) as caught:
            read_status(None, timeout=0.03)
        self.assertEqual(caught.exception.reason, "broker_unavailable")

    def test_malformed_startup_status_terminates_and_reaps_owned_child(self):
        with tempfile.TemporaryDirectory(
            prefix="c1-startup-child-", dir="/private/tmp"
        ) as directory:
            root = Path(directory) / "state"
            real_popen = subprocess.Popen
            spawned = []

            def malformed_child(*_args, **kwargs):
                child = real_popen(
                    [
                        sys.executable,
                        "-B",
                        "-c",
                        "import sys,time; print('not-json',flush=True); time.sleep(60)",
                    ],
                    stdin=kwargs["stdin"],
                    stdout=kwargs["stdout"],
                    stderr=kwargs["stderr"],
                    start_new_session=kwargs["start_new_session"],
                    close_fds=kwargs["close_fds"],
                )
                spawned.append(child)
                return child

            client = council.CouncilClient(root)
            unavailable = council.CouncilError(
                "fixture unavailable", reason="broker_unavailable"
            )
            with (
                mock.patch.object(client, "_send", side_effect=unavailable),
                mock.patch("council.subprocess.Popen", side_effect=malformed_child),
                self.assertRaises(council.CouncilError) as caught,
            ):
                client.ensure_daemon()
            self.assertEqual(caught.exception.reason, "malformed_response")
            self.assertEqual(len(spawned), 1)
            self.assertIsNotNone(spawned[0].poll())
            self.assertTrue(spawned[0].stdout.closed)

    def test_startup_timeout_preserves_valid_slow_child_for_later_call(self):
        with tempfile.TemporaryDirectory(
            prefix="c1-startup-slow-", dir="/private/tmp"
        ) as directory:
            root = Path(directory) / "state"
            real_popen = subprocess.Popen
            spawned = []

            def delayed_child(command, **kwargs):
                program = (
                    "import os,sys,time; time.sleep(.25); "
                    "os.execv(sys.argv[1],sys.argv[1:])"
                )
                child = real_popen(
                    [sys.executable, "-B", "-c", program, *command], **kwargs
                )
                spawned.append(child)
                return child

            with mock.patch.dict(
                os.environ, {"COUNCIL_TEST_ALLOW_UNTRUSTED_DAEMON": "1"}
            ):
                with (
                    mock.patch("council.DAEMON_STARTUP_TIMEOUT_SECONDS", 0.05),
                    mock.patch(
                        "council.subprocess.Popen", side_effect=delayed_child
                    ),
                    self.assertRaises(council.CouncilError) as caught,
                ):
                    council.CouncilClient(root).ensure_daemon()
                self.assertEqual(caught.exception.reason, "broker_unavailable")
                self.assertEqual(len(spawned), 1)
                self.assertIsNone(spawned[0].poll())
                self.assertTrue(spawned[0].stdout.closed)
                try:
                    deadline = time.monotonic() + 2
                    with mock.patch(
                        "council.trusted_broker_runtime", return_value=None
                    ):
                        while True:
                            try:
                                result = council.CouncilClient(
                                    root, autostart=False
                                ).request("ping")
                                break
                            except council.CouncilError as error:
                                if (
                                    error.reason
                                    not in ("broker_unavailable", "transport_lost")
                                    or time.monotonic() >= deadline
                                ):
                                    raise
                                time.sleep(0.02)
                        with (
                            mock.patch.dict(
                                os.environ,
                                {"COUNCIL_TEST_ALLOW_UNTRUSTED_DAEMON": ""},
                            ),
                            self.assertRaisesRegex(
                                council.CouncilError,
                                "not a broker launched by an admitted runtime",
                            ),
                        ):
                            council.CouncilClient(
                                root, autostart=False
                            ).request("ping")
                        result = council.CouncilClient(
                            root, autostart=False
                        ).request("ping")
                    self.assertEqual(
                        result["runtime_cohort"], council.RUNTIME_COHORT
                    )
                finally:
                    spawned[0].terminate()
                    spawned[0].wait(timeout=3)
            with admission.acquire_writer_lease(root):
                pass

    def test_slow_initial_frame_has_total_deadline_before_unlock(self):
        with tempfile.TemporaryDirectory(
            prefix="c1-frame-deadline-", dir="/private/tmp"
        ) as directory:
            root = Path(directory) / "state"
            lease = admission.acquire_writer_lease(root)
            server = council.ThreadingUnixServer(
                str(root / "broker.sock"), council.BrokerRequestHandler
            )
            server.broker = mock.Mock(root=root)
            server.initial_frame_timeout_seconds = 0.3
            serving = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}
            )
            serving.start()
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(root / "broker.sock"))
            stop = threading.Event()

            def drip():
                while not stop.wait(0.02):
                    try:
                        client.sendall(b"x")
                    except OSError:
                        return

            sender = threading.Thread(target=drip)
            sender.start()
            time.sleep(0.05)
            server.shutdown()
            serving.join(timeout=1)
            closed = threading.Event()

            def close_and_unlock():
                server.server_close()
                lease.close()
                closed.set()

            closer = threading.Thread(target=close_and_unlock)
            closer.start()
            bounded = closed.wait(1.0)
            stop.set()
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
            sender.join(timeout=1)
            closer.join(timeout=6)
            self.assertTrue(bounded)
            with admission.acquire_writer_lease(root):
                pass

    def test_autostart_reports_maintenance_before_socket_creation(self):
        with tempfile.TemporaryDirectory(
            prefix="c1-startup-maintenance-", dir="/private/tmp"
        ) as directory:
            root = Path(directory) / "state"
            (root / admission.NAMESPACE).mkdir(parents=True)
            with mock.patch.dict(
                os.environ, {"COUNCIL_TEST_ALLOW_UNTRUSTED_DAEMON": "1"}
            ):
                for _ in range(2):
                    started = time.monotonic()
                    with self.assertRaises(council.CouncilError) as caught:
                        council.CouncilClient(root).ensure_daemon()
                    self.assertEqual(caught.exception.reason, "maintenance_required")
                    self.assertEqual(
                        str(caught.exception),
                        "Council broker startup failed: maintenance_required",
                    )
                    self.assertLess(time.monotonic() - started, 1.5)
            self.assertFalse((root / "broker.sock").exists())

    def test_two_clients_observe_winning_daemon_after_retryable_lock_race(self):
        with tempfile.TemporaryDirectory(
            prefix="c1-startup-race-", dir="/private/tmp"
        ) as directory:
            base = Path(directory)
            copied = base / "scripts"
            copied.mkdir()
            for name in (
                "council.py",
                "council_admission.py",
                "council_protocol.py",
            ):
                shutil.copy2(SCRIPTS / name, copied / name)
            source = (copied / "council.py").read_text()
            seam = """    try:\n        admit_runtime_writer(lease, RUNTIME_COHORT)\n    except BaseException:\n"""
            replacement = """    try:\n        admit_runtime_writer(lease, RUNTIME_COHORT)\n        barrier = os.environ.get(\"COUNCIL_TEST_STARTUP_BARRIER\")\n        if barrier:\n            Path(barrier + \".entered\").touch()\n            while not Path(barrier + \".release\").exists():\n                time.sleep(0.01)\n    except BaseException:\n"""
            self.assertIn(seam, source)
            (copied / "council.py").write_text(source.replace(seam, replacement, 1))
            state = base / "state"
            barrier = base / "startup"
            env = {
                **os.environ,
                "PYTHONPATH": str(copied),
                "COUNCIL_STATE_ROOT": str(state),
                "COUNCIL_TEST_ALLOW_UNTRUSTED_DAEMON": "1",
                "COUNCIL_TEST_STARTUP_BARRIER": str(barrier),
            }
            waiting_client = (
                "import council,sys; "
                "council.CouncilClient().ensure_daemon(); "
                "print('ready',flush=True); sys.stdin.read()"
            )
            one_shot_client = (
                "import council; council.CouncilClient().ensure_daemon(); "
                "print('ready',flush=True)"
            )
            winner = subprocess.Popen(
                [sys.executable, "-B", "-c", waiting_client],
                cwd=copied,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            loser = None
            try:
                deadline = time.monotonic() + 2
                while not Path(str(barrier) + ".entered").exists():
                    if time.monotonic() >= deadline:
                        self.fail("winning daemon did not enter startup barrier")
                    time.sleep(0.01)
                self.assertFalse((state / "broker.sock").exists())
                with self.assertRaises(admission.AdmissionError):
                    admission.acquire_writer_lease(state)
                loser = subprocess.Popen(
                    [sys.executable, "-B", "-c", one_shot_client],
                    cwd=copied,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                time.sleep(0.1)
                Path(str(barrier) + ".release").touch()
                self.assertEqual(winner.stdout.readline().strip(), "ready")
                loser_stdout, loser_stderr = loser.communicate(timeout=4)
                self.assertEqual(loser.returncode, 0, loser_stderr)
                self.assertEqual(loser_stdout.strip(), "ready")
            finally:
                Path(str(barrier) + ".release").touch()
                if winner.stdin:
                    winner.stdin.close()
                winner.wait(timeout=4)
                if loser is not None and loser.poll() is None:
                    loser.kill()
                    loser.wait(timeout=2)
            self.assertEqual(winner.returncode, 0, winner.stderr.read())
            winner.stdout.close()
            winner.stderr.close()
            if loser is not None:
                loser.stdout.close()
                loser.stderr.close()
            deadline = time.monotonic() + 3
            released = False
            while time.monotonic() < deadline:
                try:
                    with admission.acquire_writer_lease(state):
                        released = True
                        break
                except admission.AdmissionError:
                    time.sleep(0.05)
            self.assertTrue(released, "winning daemon did not release its owned root")

    def test_real_process_acceptance_drain_for_status_wait_bind_and_retry(self):
        for action in ("status", "wait", "bind", "retry"):
            with (
                self.subTest(action=action),
                tempfile.TemporaryDirectory(
                    prefix="c1-drain-", dir="/private/tmp"
                ) as directory,
            ):
                root = Path(directory) / "state"
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-B",
                        str(SCRIPTS / "admission_process_fixture.py"),
                        str(root),
                        action,
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                client = socket.socket(socket.AF_UNIX)
                client.settimeout(5)
                try:
                    self.assertEqual(child.stdout.readline().strip(), "ready")
                    cap = "process-fixture-capability-" + "a" * 40
                    args = {"participant": "alpha", "_auth_capability": cap}
                    if action == "bind":
                        args = dict(
                            runtime="codex",
                            participant="alpha",
                            label="alpha",
                            project="fixture",
                            target_thread_id="thread-alpha",
                            binding_capability=cap,
                        )
                    client.connect(str(root / "broker.sock"))
                    client.sendall(
                        json.dumps(
                            {
                                "action": action,
                                "runtime_cohort": council.RUNTIME_COHORT,
                                "arguments": args,
                            }
                        ).encode()
                        + b"\n"
                    )
                    self.assertEqual(child.stdout.readline().strip(), "accepted")
                    child.stdin.write("shutdown\n")
                    child.stdin.flush()
                    self.assertEqual(
                        child.stdout.readline().strip(), "acceptance-stopped"
                    )
                    with self.assertRaises(admission.AdmissionError):
                        admission.acquire_writer_lease(root)
                    self.assertFalse((root / "router.json").exists())
                    child.stdin.write("release\n")
                    child.stdin.flush()
                    response = json.loads(client.makefile("rb").readline())
                    self.assertTrue(response["ok"], response)
                    self.assertEqual(child.stdout.readline().strip(), "closed")
                    child.wait(timeout=5)
                    self.assertEqual(child.returncode, 0, child.stderr.read())
                    with admission.acquire_writer_lease(root):
                        self.assertEqual(
                            json.loads((root / "router.json").read_text())[
                                "target_thread_id"
                            ],
                            "completed-" + action,
                        )
                finally:
                    client.close()
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
                    child.stdin.close()
                    child.stdout.close()
                    child.stderr.close()

    def test_already_loaded_old_bridge_keeps_its_generation_after_source_swap(self):
        with tempfile.TemporaryDirectory(
            prefix="c1-delayed-", dir="/private/tmp"
        ) as directory:
            base = Path(directory)
            scripts = base / "scripts"
            scripts.mkdir()
            for name in (
                "council.py",
                "council_protocol.py",
                "council_admission.py",
                "council_opencode.py",
            ):
                data = (SCRIPTS / name).read_text()
                (scripts / name).write_text(
                    data.replace(council.RUNTIME_COHORT, "0" * 64)
                )
            root = base / "state"
            with council.CouncilBroker(root) as broker:
                bind(broker)
                server = council.ThreadingUnixServer(
                    str(root / "broker.sock"), council.BrokerRequestHandler
                )
                server.broker = broker
                serving = threading.Thread(target=server.serve_forever)
                serving.start()
                # The child loads generation B and waits before consuming its
                # request. Only the initial availability ping is suppressed so
                # this case reaches the authenticated generation A dispatch.
                program = "import council_opencode as bridge; bridge.CouncilClient.ensure_daemon=lambda self:None; print('loaded',flush=True); raise SystemExit(bridge.main())"
                env = {
                    **os.environ,
                    "COUNCIL_STATE_ROOT": str(root),
                    "COUNCIL_TEST_ALLOW_UNTRUSTED_DAEMON": "1",
                }
                child = subprocess.Popen(
                    [sys.executable, "-B", "-c", program],
                    cwd=scripts,
                    env=env,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    self.assertEqual(child.stdout.readline().strip(), "loaded")
                    for name in (
                        "council.py",
                        "council_protocol.py",
                        "council_admission.py",
                        "council_opencode.py",
                    ):
                        (scripts / name).write_bytes((SCRIPTS / name).read_bytes())
                    before = inventory(root)
                    stdout, stderr = child.communicate(
                        json.dumps(
                            {
                                "action": "status",
                                "runtime_cohort": "0" * 64,
                                "arguments": {
                                    "participant": "alpha",
                                    "_auth_capability": CAP,
                                },
                            }
                        )
                        + "\n",
                        timeout=8,
                    )
                    self.assertEqual(child.returncode, 2, stderr)
                    self.assertEqual(json.loads(stdout)["reason"], "version_mismatch")
                    self.assertEqual(inventory(root), before)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=3)
                    server.shutdown()
                    serving.join()
                    server.server_close()

    def test_old_plugin_launches_new_bridge_and_parent_exit_does_not_bypass_origin(
        self,
    ):
        with tempfile.TemporaryDirectory(
            prefix="c1-parent-exit-", dir="/private/tmp"
        ) as directory:
            base = Path(directory)
            state = base / "state"
            request = base / "request.json"
            output = base / "response.json"
            request.write_text(
                json.dumps(
                    {"action": "ping", "runtime_cohort": "old-plugin", "arguments": {}}
                )
                + "\n"
            )
            # The launcher exits before its delayed bridge reads the request.
            # A local file barrier replaces host scheduling, not bridge checks.
            barrier = base / "release"
            child_program = (
                "import pathlib,time,runpy; barrier=pathlib.Path(%r); print('loaded',flush=True); \nwhile not barrier.exists(): time.sleep(.01)\nrunpy.run_path(%r,run_name='__main__')"
                % (str(barrier), str(SCRIPTS / "council_opencode.py"))
            )
            launcher = (
                "import subprocess,sys; child=subprocess.Popen([sys.executable,'-B','-c',%r],stdin=open(%r),stdout=open(%r,'w'),stderr=subprocess.DEVNULL); print(child.pid)"
                % (child_program, str(request), str(output))
            )
            result = subprocess.run(
                [sys.executable, "-B", "-c", launcher],
                cwd=SCRIPTS,
                env={**os.environ, "COUNCIL_STATE_ROOT": str(state)},
                capture_output=True,
                text=True,
                timeout=3,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            pid = int(result.stdout.strip())
            try:
                deadline = time.monotonic() + 4
                while (
                    not output.exists() or "loaded" not in output.read_text()
                ) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertIn("loaded", output.read_text())
                barrier.write_text("release")
                while (
                    len(output.read_text().splitlines()) < 2
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                response = json.loads(output.read_text().splitlines()[1])
                self.assertEqual(response["reason"], "version_mismatch")
                self.assertFalse(state.exists())
            finally:
                barrier.touch()
                # The bridge has bounded local work; completion above consumes
                # its final response. No host process is signalled.
                self.assertGreater(pid, 1)


class LegacyFenceTests(unittest.TestCase):
    def test_legacy_shell_mutation_paths_are_replaced_by_the_fixed_engine(self):
        for command in ("install", "upgrade", "rollback", "uninstall"):
            text = (SCRIPTS.parent / "install" / (command + ".sh")).read_text()
            self.assertIn("exec python3 -I -B", text)
            self.assertIn("scripts/council_lifecycle.py", text)
            self.assertIn(" " + command + ' "$@"', text)
            for forbidden in ("rm -rf", "git pull", "mktemp", "broker.sock"):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
