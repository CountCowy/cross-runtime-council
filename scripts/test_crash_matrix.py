#!/usr/bin/env python3
"""Deterministic crash matrix over the broker's durable transactions (v0.20).

Each test scripts one real transaction class and sweeps it: row k re-runs the
scenario on a fresh state root, crashes at the k-th durable-mutation seam
(council.FAILPOINT_HOOK), recovers with a fresh broker, asserts the full
artifact oracle, and asserts a scenario postcondition (bimodality, idempotent
retry, or a converged terminal state). The sweep is exhaustive by
construction: it adds rows until the transaction completes without crashing,
so a new durable mutation grows the matrix automatically instead of being
silently uncovered; minimum-row guards catch the opposite failure, where a
refactor that bypassed the failpoint layer would shrink a sweep toward zero
rows and pass vacuously.

Release gate (docs/verification-map.md): the mutant corpus — inverted
failpoint behaviors — must be killed by this matrix before v0.20 ships.
"""

import unittest
from pathlib import Path

import council
from council import CouncilBroker, read_json
from recovery_invariants import MANIFEST_PHASES, check_state_root
from test_council import (
    CAP_ALPHA,
    TerminalDialogueFixture,
    convergence_challenge,
    exchange,
    proposal,
    representation_check,
    synthesis,
)
from test_recovery_invariants import SeamCrash, write_json_0600

MAX_MATRIX_ROWS = 200
CAP_GAMMA = "cap-gamma-matrix-" + "g" * 24
CAP_DELTA = "cap-delta-matrix-" + "d" * 24

# Every durable seam the matrix must cross at least once, per the coverage
# map. A seam missing here is a seam the matrix silently stopped exercising.
MATRIX_SEAMS = {
    "atomic_json:registration",
    "atomic_json:manifest",
    "atomic_json:submission",
    "atomic_json:final",
    "atomic_json:outbox-record",
    "atomic_json:tombstone",
    "append_jsonl:audit-log",
    "remove_file:registration",
    "remove_file:outbox-record",
    "remove_file:manifest",
    "remove_file:audit-log",
    "remove_file:submission",
    "remove_file:final",
    "remove_empty_dir:submissions-dir",
    "remove_empty_dir:dialogue-dir",
}


class CrashMatrixTests(TerminalDialogueFixture):
    def setUp(self):
        super().setUp()
        self._original_epoch_now = council.epoch_now
        self.addCleanup(setattr, council, "epoch_now", self._original_epoch_now)
        self.addCleanup(setattr, council, "FAILPOINT_HOOK", None)
        self._row_index = 0

    def reset_state(self):
        council.epoch_now = self._original_epoch_now
        council.FAILPOINT_HOOK = None
        self._row_index += 1
        self.root = Path(self.temporary.name) / ("state-%d" % self._row_index)
        self.broker = CouncilBroker(self.root)

    def advance_clock(self, seconds):
        base = self._original_epoch_now
        council.epoch_now = lambda: base() + seconds

    def crash_at_row(self, k):
        state = {"seen": 0}

        def hook(_name):
            state["seen"] += 1
            if state["seen"] == k:
                raise SeamCrash("durable seam %d" % k)

        council.FAILPOINT_HOOK = hook

    def sweep(self, scenario, setup, operate, postcondition, minimum_rows):
        """Crash at every durable seam of the scripted transaction in turn."""
        rows = 0
        crashed = True
        while crashed:
            rows += 1
            self.assertLessEqual(
                rows, MAX_MATRIX_ROWS, "%s sweep never completed" % scenario
            )
            with self.subTest(scenario=scenario, row=rows):
                self.reset_state()
                context = setup()
                self.crash_at_row(rows)
                crashed = False
                try:
                    operate(context)
                except SeamCrash:
                    crashed = True
                finally:
                    council.FAILPOINT_HOOK = None
                recovered = CouncilBroker(self.root)
                self.assertEqual(check_state_root(self.root), [])
                postcondition(recovered, context, crashed)
                self.assertEqual(check_state_root(self.root), [])
        completed = rows - 1
        self.assertGreaterEqual(
            completed,
            minimum_rows,
            "%s matrix silently shrank to %d rows" % (scenario, completed),
        )

    # Scenario preludes (never crashed; rows crash only inside operate).

    def started_dialogue(self):
        self.bind_pair()
        return self.broker.start(
            "alpha",
            "beta",
            "Matrix",
            "Crash-matrix scenario.",
            [{"source": "user", "claim": "matrix fixture"}],
        )["dialogue_id"]

    def dialogue_before_completion(self):
        dialogue = self.started_dialogue()
        submit = self.broker.submit
        submit(dialogue, "alpha", "proposal", 0, proposal("alpha"))
        submit(dialogue, "beta", "proposal", 0, proposal("beta"))
        submit(dialogue, "alpha", "exchange", 1, exchange("alpha", True))
        submit(dialogue, "beta", "exchange", 1, exchange("beta", True))
        submit(dialogue, "alpha", "exchange", 2, exchange("alpha", False, 2))
        submit(dialogue, "beta", "exchange", 2, exchange("beta", False, 2))
        submit(dialogue, "alpha", "convergence_challenge", 2, convergence_challenge())
        submit(dialogue, "beta", "convergence_challenge", 2, convergence_challenge())
        submit(dialogue, "alpha", "synthesis", 2, synthesis())
        return dialogue

    def manifest(self, dialogue):
        return read_json(self.root / "dialogues" / dialogue / "manifest.json")

    # Class 1 — single-file atomic replace.

    def test_bind_transaction(self):
        def operate(_context):
            self.broker.bind(
                "codex",
                "alpha",
                "Alpha",
                "test",
                target_thread_id="thread-alpha",
                binding_capability=CAP_ALPHA,
            )

        def postcondition(recovered, _context, _crashed):
            recovered.bind(
                "codex",
                "alpha",
                "Alpha",
                "test",
                target_thread_id="thread-alpha",
                binding_capability=CAP_ALPHA,
            )
            self.assertEqual(recovered.ping()["bound_count"], 1)

        self.sweep("bind", dict, operate, postcondition, minimum_rows=1)

    def test_claim_transaction(self):
        def operate(_context):
            self.broker.wait("beta")

        def postcondition(recovered, _context, crashed):
            message = recovered.wait("beta")["message"]
            if crashed:
                self.assertEqual(message["kind"], "proposal_request")
            else:
                self.assertIsNone(message)

        self.sweep(
            "claim",
            lambda: {"dialogue": self.started_dialogue()},
            operate,
            postcondition,
            minimum_rows=1,
        )

    # Class 3 — multi-file forward transactions (class 2, the audit append,
    # is a seam inside each of these; test_matrix_covers_every_durable_seam
    # pins that the sweeps actually cross it).

    def test_start_transaction(self):
        def setup():
            self.bind_pair()
            return {}

        def operate(_context):
            self.broker.start(
                "alpha",
                "beta",
                "Matrix",
                "Crash-matrix scenario.",
                [{"source": "user", "claim": "matrix fixture"}],
            )

        def postcondition(recovered, _context, _crashed):
            dialogues_dir = self.root / "dialogues"
            manifests = (
                sorted(dialogues_dir.glob("dlg-*/manifest.json"))
                if dialogues_dir.exists()
                else []
            )
            if not manifests:
                started = recovered.start(
                    "alpha",
                    "beta",
                    "Matrix retry",
                    "Crash-matrix scenario.",
                    [{"source": "user", "claim": "matrix fixture"}],
                )
                self.assertIn("dialogue_id", started)
                return
            manifest = read_json(manifests[0])
            self.assertIn(manifest["phase"], MANIFEST_PHASES)
            if manifest["phase"] not in ("complete", "cancelled"):
                recovered.cancel(
                    manifests[0].parent.name, "alpha", "matrix row cleanup"
                )

        self.sweep("start", setup, operate, postcondition, minimum_rows=5)

    def test_submission_transaction(self):
        def operate(context):
            self.broker.submit(
                context["dialogue"], "alpha", "proposal", 0, proposal("alpha")
            )

        def postcondition(recovered, context, _crashed):
            recovered.submit(
                context["dialogue"], "alpha", "proposal", 0, proposal("alpha")
            )

        self.sweep(
            "submission",
            lambda: {"dialogue": self.started_dialogue()},
            operate,
            postcondition,
            minimum_rows=3,
        )

    def test_completion_transaction(self):
        def operate(context):
            self.broker.submit(
                context["dialogue"],
                "beta",
                "representation_check",
                2,
                representation_check(),
            )

        def postcondition(recovered, context, _crashed):
            dialogue = context["dialogue"]
            if self.manifest(dialogue)["phase"] != "complete":
                result = recovered.submit(
                    dialogue, "beta", "representation_check", 2, representation_check()
                )
                self.assertEqual(result["phase"], "complete")
            self.assertTrue(
                (self.root / "dialogues" / dialogue / "final.json").is_file()
            )

        self.sweep(
            "completion",
            lambda: {"dialogue": self.dialogue_before_completion()},
            operate,
            postcondition,
            minimum_rows=10,
        )

    # Class 4 — deletion and tombstoning.

    def test_deletion_transaction(self):
        def operate(context):
            self.broker.delete_terminal_dialogue(context["dialogue"], "matrix row")

        def postcondition(recovered, context, _crashed):
            dialogue = context["dialogue"]
            tombstone = self.root / "tombstones" / ("%s.json" % dialogue)
            dialogue_dir = self.root / "dialogues" / dialogue
            if not tombstone.exists():
                self.assertTrue((dialogue_dir / "manifest.json").is_file())
                recovered.delete_terminal_dialogue(dialogue, "matrix row retry")
            self.assertTrue(tombstone.exists())
            self.assertFalse(dialogue_dir.exists())

        self.sweep(
            "deletion",
            lambda: {"dialogue": self.completed_dialogue()},
            operate,
            postcondition,
            minimum_rows=20,
        )

    # Class 5 — supersession and acknowledgement fan-out.

    def test_cancel_transaction(self):
        def operate(context):
            self.broker.cancel(context["dialogue"], "alpha", "matrix row")

        def postcondition(recovered, context, _crashed):
            dialogue = context["dialogue"]
            if self.manifest(dialogue)["phase"] != "cancelled":
                recovered.cancel(dialogue, "alpha", "matrix row retry")
            self.assertEqual(self.manifest(dialogue)["phase"], "cancelled")

        self.sweep(
            "cancel",
            lambda: {"dialogue": self.started_dialogue()},
            operate,
            postcondition,
            minimum_rows=6,
        )

    def test_acknowledgement_transaction(self):
        def setup():
            dialogue = self.started_dialogue()
            message = self.broker.wait("beta")["message"]
            self.broker.submit(dialogue, "beta", "proposal", 0, proposal("beta"))
            return {"message_id": message["message_id"]}

        def operate(context):
            self.broker.ack("beta", context["message_id"])

        def postcondition(recovered, context, _crashed):
            recovered.ack("beta", context["message_id"])

        self.sweep("acknowledgement", setup, operate, postcondition, minimum_rows=1)

    # Class 6 — window-expiry recovery transitions.

    def test_wake_lease_transaction(self):
        def setup():
            self.started_dialogue()
            self.broker.bind(
                "codex",
                "gamma",
                "Gamma",
                "test",
                target_thread_id="thread-gamma",
                binding_capability=CAP_GAMMA,
            )
            self.broker.bind(
                "codex",
                "delta",
                "Delta",
                "test",
                target_thread_id="thread-delta",
                binding_capability=CAP_DELTA,
            )
            self.broker.start(
                "gamma",
                "delta",
                "Matrix second",
                "Crash-matrix scenario.",
                [{"source": "user", "claim": "matrix fixture"}],
            )
            return {}

        def operate(_context):
            self.broker.pending_wakes()

        def postcondition(recovered, _context, _crashed):
            recovered.pending_wakes()
            for path in sorted((self.root / "outbox").rglob("msg-*.json")):
                record = read_json(path)
                if record.get("status") == "pending":
                    self.assertEqual(record.get("wake_status"), "leased")

        self.sweep("wake-lease", setup, operate, postcondition, minimum_rows=2)

    def test_expired_claim_reclaim_transaction(self):
        def setup():
            self.started_dialogue()
            message = self.broker.wait("beta")["message"]
            self.advance_clock(council.CLAIM_SECONDS + 1)
            return {"message_id": message["message_id"]}

        def operate(_context):
            self.broker.wait("beta")

        def postcondition(recovered, context, crashed):
            message = recovered.wait("beta")["message"]
            if crashed:
                self.assertEqual(message["message_id"], context["message_id"])
            else:
                self.assertIsNone(message)

        self.sweep(
            "expired-claim-reclaim", setup, operate, postcondition, minimum_rows=1
        )

    def test_retention_sweep_transaction(self):
        def setup():
            dialogue = self.completed_dialogue()
            write_json_0600(self.root / "retention.json", {"days": 1})
            self.advance_clock(2 * 86400)
            return {"dialogue": dialogue}

        def operate(_context):
            CouncilBroker(self.root)

        def postcondition(_recovered, context, _crashed):
            dialogue = context["dialogue"]
            tombstone = read_json(self.root / "tombstones" / ("%s.json" % dialogue))
            self.assertEqual(tombstone["reason"], "retention_sweep")
            self.assertFalse((self.root / "dialogues" / dialogue).exists())

        self.sweep("retention-sweep", setup, operate, postcondition, minimum_rows=20)

    def test_expired_registration_restart_transaction(self):
        def setup():
            self.broker.bind(
                "codex",
                "alpha",
                "Alpha",
                "test",
                target_thread_id="thread-alpha",
                binding_capability=CAP_ALPHA,
            )
            self.advance_clock(council.DEFAULT_LEASE_MINUTES * 60 + 1)
            return {}

        def operate(_context):
            CouncilBroker(self.root)

        def postcondition(recovered, _context, _crashed):
            self.assertEqual(
                sorted((self.root / "registrations").glob("*.json")), []
            )
            self.assertEqual(recovered.ping()["bound_count"], 0)

        self.sweep(
            "expired-registration-restart", setup, operate, postcondition, minimum_rows=1
        )

    def test_matrix_covers_every_durable_seam(self):
        """One clean pass over every scenario shape must cross every seam the
        coverage map documents — a seam missing here means the matrix quietly
        stopped exercising it."""
        seams = set()
        self.reset_state()
        council.FAILPOINT_HOOK = seams.add
        try:
            dialogue = self.started_dialogue()
            message = self.broker.wait("beta")["message"]
            self.broker.pending_wakes()
            self.broker.submit(dialogue, "alpha", "proposal", 0, proposal("alpha"))
            self.broker.submit(dialogue, "beta", "proposal", 0, proposal("beta"))
            self.broker.ack("beta", message["message_id"])
            submit = self.broker.submit
            submit(dialogue, "alpha", "exchange", 1, exchange("alpha", True))
            submit(dialogue, "beta", "exchange", 1, exchange("beta", True))
            submit(dialogue, "alpha", "exchange", 2, exchange("alpha", False, 2))
            submit(dialogue, "beta", "exchange", 2, exchange("beta", False, 2))
            submit(
                dialogue, "alpha", "convergence_challenge", 2, convergence_challenge()
            )
            submit(
                dialogue, "beta", "convergence_challenge", 2, convergence_challenge()
            )
            submit(dialogue, "alpha", "synthesis", 2, synthesis())
            submit(
                dialogue, "beta", "representation_check", 2, representation_check()
            )
            self.broker.delete_terminal_dialogue(dialogue, "matrix coverage")
            cancelled = self.broker.start(
                "alpha",
                "beta",
                "Matrix cancel",
                "Crash-matrix scenario.",
                [{"source": "user", "claim": "matrix fixture"}],
            )["dialogue_id"]
            self.broker.cancel(cancelled, "alpha", "matrix coverage")
            self.advance_clock(council.DEFAULT_LEASE_MINUTES * 60 + 1)
            CouncilBroker(self.root)
        finally:
            council.FAILPOINT_HOOK = None
        missing = MATRIX_SEAMS - seams
        self.assertFalse(missing, "matrix flows never crossed %s" % sorted(missing))
        unnamed = {name for name in seams if name.endswith(":other")}
        self.assertFalse(
            unnamed, "durable mutations hit unclassified seams %s" % sorted(unnamed)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
