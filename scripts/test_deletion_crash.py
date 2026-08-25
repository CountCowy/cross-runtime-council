#!/usr/bin/env python3
"""Release-blocking deletion x recovery crash harness.

Injects a crash at every mutation boundary of the terminal-dialogue deletion
sequence, then at every mutation boundary of the startup recovery pass that
completes an interrupted deletion, and asserts one bimodal invariant after a
clean restart in every case:

  A. no tombstone -> the dialogue is fully intact (byte inventory unchanged)
     and a re-run of the deletion converges; or
  B. tombstone present -> the dialogue directory is gone, no outbox record
     references the dialogue, nothing was orphan-quarantined instead of
     deleted, and re-running the deletion is an idempotent duplicate.

A control dialogue in the same state root must survive every scenario
untouched. The injection model crashes BETWEEN mutations; atomicity WITHIN a
mutation is provided by atomic_json (temp file + rename), unlink, and rmdir
being atomic operations. Mutations are injected by wrapping council.atomic_json,
council.remove_file, and council.remove_empty_dir, which the deletion and
recovery paths call as module globals.
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import council
from council import CouncilBroker, CouncilError, read_json

CAP_ALPHA = "alpha-capability-" + "s" * 40
CAP_BETA = "beta-capability-" + "f" * 40
TEST_CLAIM_ID_SALT = "ab" * 32
OPERATION_CEILING = 10**9


class InjectedCrash(Exception):
    pass


def state_inventory(root):
    """Relative paths of every file under the state root (content markers only)."""
    return sorted(
        str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()
    )


def dialogue_records(root, dialogue_id):
    outbox = root / "outbox"
    paths = []
    for participant_dir in sorted(outbox.iterdir()) if outbox.exists() else []:
        if not participant_dir.is_dir():
            continue
        for path in sorted(participant_dir.glob("*.json")):
            envelope = read_json(path).get("envelope") or {}
            if envelope.get("dialogue_id") == dialogue_id:
                paths.append(path)
    return paths


class CrashInjector:
    """Wrap the deletion path's three mutation primitives with a countdown."""

    def __init__(self, crash_at, wrap_atomic_json):
        self.crash_at = crash_at
        self.operations = 0
        self.wrap_atomic_json = wrap_atomic_json
        self.real_atomic_json = council.atomic_json
        self.real_remove_file = council.remove_file
        self.real_remove_empty_dir = council.remove_empty_dir

    def _guard(self):
        self.operations += 1
        if self.operations == self.crash_at:
            raise InjectedCrash()

    def __enter__(self):
        real_atomic_json = self.real_atomic_json
        real_remove_file = self.real_remove_file
        real_remove_empty_dir = self.real_remove_empty_dir

        def crashing_atomic_json(path, value, mode=0o600):
            self._guard()
            real_atomic_json(path, value, mode)

        def crashing_remove_file(path):
            self._guard()
            real_remove_file(path)

        def crashing_remove_empty_dir(path):
            self._guard()
            real_remove_empty_dir(path)

        if self.wrap_atomic_json:
            council.atomic_json = crashing_atomic_json
        council.remove_file = crashing_remove_file
        council.remove_empty_dir = crashing_remove_empty_dir
        return self

    def __exit__(self, *exc_info):
        council.atomic_json = self.real_atomic_json
        council.remove_file = self.real_remove_file
        council.remove_empty_dir = self.real_remove_empty_dir
        return False


class DeletionCrashMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.salt_patch = mock.patch(
            "council.new_claim_id_salt", return_value=TEST_CLAIM_ID_SALT
        )
        cls.salt_patch.start()
        cls.cdhash_patch = mock.patch(
            "council._codesign_cdhash", return_value="c" * 40
        )
        cls.cdhash_patch.start()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.template = Path(cls.temporary.name) / "template"
        cls.target_id, cls.control_id = cls.build_fixture(cls.template)
        cls.template_inventory = state_inventory(cls.template)
        cls.control_inventory = sorted(
            entry
            for entry in cls.template_inventory
            if cls.control_id in entry or "registrations" in entry
        )
        cls.copy_counter = 0

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()
        cls.cdhash_patch.stop()
        cls.salt_patch.stop()

    @classmethod
    def build_fixture(cls, root):
        broker = CouncilBroker(root)
        broker.bind(
            "codex",
            "alpha",
            "Alpha",
            "test",
            target_thread_id="thread-alpha",
            binding_capability=CAP_ALPHA,
        )
        broker.bind(
            "codex",
            "beta",
            "Beta",
            "test",
            target_thread_id="thread-beta",
            binding_capability=CAP_BETA,
        )

        def cancelled_dialogue(topic):
            dialogue = broker.start(
                "alpha",
                "beta",
                topic,
                "Compare two safe automated wake paths.",
                [{"source": "user", "claim": "no manual relay"}],
            )["dialogue_id"]
            broker.cancel(dialogue, "alpha", "crash harness fixture")
            return dialogue

        target = cancelled_dialogue("Deletion target plan")
        control = cancelled_dialogue("Control plan that must survive")
        # Settle every reconciliation write, then verify the fixture is
        # restart-stable so later restarts mutate nothing on their own.
        CouncilBroker(root)
        settled = state_inventory(root)
        CouncilBroker(root)
        if state_inventory(root) != settled:
            raise AssertionError("fixture is not restart-stable")
        if not dialogue_records(root, target):
            raise AssertionError("fixture target has no outbox records")
        if not dialogue_records(root, control):
            raise AssertionError("fixture control has no outbox records")
        return target, control

    @classmethod
    def fresh_copy(cls, source):
        cls.copy_counter += 1
        destination = Path(cls.temporary.name) / ("run-%04d" % cls.copy_counter)
        shutil.copytree(source, destination)
        return destination

    def run_crashing_delete(self, root, crash_at):
        broker = CouncilBroker(root)
        with CrashInjector(crash_at, wrap_atomic_json=True) as injector:
            try:
                broker.delete_terminal_dialogue(self.target_id, "crash harness")
                crashed = False
            except InjectedCrash:
                crashed = True
        return injector.operations, crashed

    def run_crashing_recovery(self, root, crash_at, wrap_atomic_json=False):
        with CrashInjector(crash_at, wrap_atomic_json=wrap_atomic_json) as injector:
            try:
                CouncilBroker(root)
                crashed = False
            except InjectedCrash:
                crashed = True
        return injector.operations, crashed

    def assert_bimodal_invariant(self, root):
        broker = CouncilBroker(root)
        tombstone = root / "tombstones" / ("%s.json" % self.target_id)
        dialogue_dir = root / "dialogues" / self.target_id
        if tombstone.exists():
            self.assertFalse(dialogue_dir.exists())
            self.assertEqual(dialogue_records(root, self.target_id), [])
            outbox = root / "outbox"
            for participant_dir in sorted(outbox.iterdir()):
                if not participant_dir.is_dir():
                    continue
                for path in participant_dir.glob("*.json"):
                    self.assertNotEqual(read_json(path).get("status"), "orphaned")
            repeat = broker.delete_terminal_dialogue(
                self.target_id, "idempotency probe"
            )
            self.assertEqual(
                repeat,
                {
                    "dialogue_id": self.target_id,
                    "deleted": True,
                    "duplicate": True,
                },
            )
        else:
            self.assertEqual(state_inventory(root), self.template_inventory)
            resumed = broker.delete_terminal_dialogue(self.target_id, "resume")
            self.assertTrue(resumed["deleted"])
            self.assertTrue(tombstone.exists())
            self.assertFalse(dialogue_dir.exists())
            self.assertEqual(dialogue_records(root, self.target_id), [])
        control_manifest = read_json(
            root / "dialogues" / self.control_id / "manifest.json"
        )
        self.assertEqual(control_manifest["phase"], "cancelled")
        self.assertEqual(
            sorted(
                entry
                for entry in state_inventory(root)
                if self.control_id in entry or "registrations" in entry
            ),
            self.control_inventory,
        )
        with self.assertRaises(CouncilError):
            broker._load_manifest(self.target_id)

    def test_clean_delete_operation_count_is_stable(self):
        root = self.fresh_copy(self.template)
        operations, crashed = self.run_crashing_delete(root, OPERATION_CEILING)
        self.assertFalse(crashed)
        # tombstone write + one unlink per outbox record + manifest + audit
        # log + the dialogue directory rmdir; anything below this means a
        # mutation stopped flowing through the injectable primitives.
        self.assertGreaterEqual(operations, 5)
        self.assert_bimodal_invariant(root)

    def test_crash_at_every_deletion_boundary_recovers(self):
        baseline_root = self.fresh_copy(self.template)
        total_operations, crashed = self.run_crashing_delete(
            baseline_root, OPERATION_CEILING
        )
        self.assertFalse(crashed)
        for crash_at in range(1, total_operations + 1):
            with self.subTest(crash_at=crash_at):
                root = self.fresh_copy(self.template)
                operations, crashed = self.run_crashing_delete(root, crash_at)
                self.assertTrue(crashed)
                self.assertEqual(operations, crash_at)
                self.assert_bimodal_invariant(root)

    def test_crash_at_every_recovery_boundary_still_converges(self):
        # Interrupt the deletion right after its tombstone commits, then
        # crash the startup recovery pass at every one of its own mutation
        # boundaries, and require convergence after a clean restart.
        interrupted_template = self.fresh_copy(self.template)
        _, crashed = self.run_crashing_delete(interrupted_template, 2)
        self.assertTrue(crashed)
        self.assertTrue(
            (
                interrupted_template
                / "tombstones"
                / ("%s.json" % self.target_id)
            ).exists()
        )
        recovery_root = self.fresh_copy(interrupted_template)
        recovery_operations, crashed = self.run_crashing_recovery(
            recovery_root, OPERATION_CEILING
        )
        self.assertFalse(crashed)
        self.assertGreaterEqual(recovery_operations, 1)
        self.assert_bimodal_invariant(recovery_root)
        for crash_at in range(1, recovery_operations + 1):
            with self.subTest(crash_at=crash_at):
                root = self.fresh_copy(interrupted_template)
                operations, crashed = self.run_crashing_recovery(root, crash_at)
                self.assertTrue(crashed)
                self.assertEqual(operations, crash_at)
                self.assert_bimodal_invariant(root)

    def assert_retention_converged(self, root):
        # A clean restart re-applies retention deterministically, so the only
        # legal steady state after any crash is fully swept: tombstoned with
        # zero content, zero references, and the control dialogue untouched.
        CouncilBroker(root)
        tombstone = root / "tombstones" / ("%s.json" % self.target_id)
        self.assertTrue(tombstone.exists())
        self.assertEqual(read_json(tombstone)["reason"], "retention_sweep")
        self.assertFalse((root / "dialogues" / self.target_id).exists())
        self.assertEqual(dialogue_records(root, self.target_id), [])
        control_manifest = read_json(
            root / "dialogues" / self.control_id / "manifest.json"
        )
        self.assertEqual(control_manifest["phase"], "cancelled")
        self.assertTrue(dialogue_records(root, self.control_id))

    def test_retention_sweep_crash_matrix(self):
        # Age the target past a 30-day window (the control stays recent),
        # then crash the startup sweep at every mutation boundary.
        aged = self.fresh_copy(self.template)
        manifest_path = aged / "dialogues" / self.target_id / "manifest.json"
        manifest = read_json(manifest_path)
        manifest["cancelled_at"] = "2020-01-01T00:00:00+00:00"
        council.atomic_json(manifest_path, manifest)
        council.atomic_json(
            aged / "retention.json",
            {"days": 30, "configured_at": "2020-01-01T00:00:00+00:00"},
        )
        probe = self.fresh_copy(aged)
        total_operations, crashed = self.run_crashing_recovery(
            probe, OPERATION_CEILING, wrap_atomic_json=True
        )
        self.assertFalse(crashed)
        self.assertGreaterEqual(total_operations, 6)
        self.assert_retention_converged(probe)
        for crash_at in range(1, total_operations + 1):
            with self.subTest(crash_at=crash_at):
                root = self.fresh_copy(aged)
                operations, crashed = self.run_crashing_recovery(
                    root, crash_at, wrap_atomic_json=True
                )
                self.assertTrue(crashed)
                self.assertEqual(operations, crash_at)
                self.assert_retention_converged(root)

    def test_double_crash_matrix_delete_then_recovery(self):
        baseline_root = self.fresh_copy(self.template)
        total_operations, crashed = self.run_crashing_delete(
            baseline_root, OPERATION_CEILING
        )
        self.assertFalse(crashed)
        for delete_crash_at in range(2, total_operations + 1):
            interrupted = self.fresh_copy(self.template)
            _, crashed = self.run_crashing_delete(interrupted, delete_crash_at)
            self.assertTrue(crashed)
            recovery_crash_at = 1
            while True:
                with self.subTest(
                    delete_crash_at=delete_crash_at,
                    recovery_crash_at=recovery_crash_at,
                ):
                    root = self.fresh_copy(interrupted)
                    _, crashed = self.run_crashing_recovery(
                        root, recovery_crash_at
                    )
                    self.assert_bimodal_invariant(root)
                if not crashed:
                    break
                recovery_crash_at += 1


if __name__ == "__main__":
    unittest.main(verbosity=2)
