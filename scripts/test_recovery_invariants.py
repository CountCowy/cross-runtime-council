#!/usr/bin/env python3
"""Fixture tests for the recovery-invariant artifact oracles.

Every oracle must (a) pass on clean post-recovery roots produced by the real
broker and (b) catch a seeded violation of the documented invariant it
encodes. The oracles themselves live in recovery_invariants.py and are also
run by the deletion x recovery crash harness after every injected crash.
"""

import inspect
import json
import os
import unittest
from pathlib import Path

import council
from council import CouncilBroker, read_json
from recovery_invariants import check_state_root
from test_council import TerminalDialogueFixture


class SeamCrash(Exception):
    pass


def write_json_0600(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(path, 0o600)


class RecoveryInvariantTests(TerminalDialogueFixture):
    def assert_violation(self, fragment):
        violations = check_state_root(self.root)
        self.assertTrue(
            any(fragment in violation for violation in violations),
            "expected a violation containing %r, got %r" % (fragment, violations),
        )

    def outbox_records(self):
        return sorted((self.root / "outbox").rglob("msg-*.json"))

    def manifest_path(self, dialogue):
        return self.root / "dialogues" / dialogue / "manifest.json"

    def test_clean_roots_pass_every_oracle(self):
        self.assertEqual(check_state_root(self.root), [])
        dialogue = self.completed_dialogue()
        self.assertEqual(check_state_root(self.root), [])
        self.broker.delete_terminal_dialogue(dialogue, "oracle fixture")
        self.assertEqual(check_state_root(self.root), [])
        cancelled = self.start_cancelled()
        self.assertEqual(check_state_root(self.root), [])
        self.broker.delete_terminal_dialogue(cancelled, "oracle fixture")
        self.assertEqual(check_state_root(self.root), [])

    def test_restart_reconciles_answered_delivered_record(self):
        dialogue = self.completed_dialogue()
        flipped = None
        for path in self.outbox_records():
            record = read_json(path)
            envelope = record.get("envelope") or {}
            if (
                envelope.get("dialogue_id") == dialogue
                and envelope.get("kind") == "representation_check_request"
            ):
                record["status"] = "delivered"
                record["delivered_at"] = record.get("created_at")
                write_json_0600(path, record)
                flipped = path
                break
        self.assertIsNotNone(flipped)
        self.assertEqual(check_state_root(self.root), [])
        CouncilBroker(self.root)
        self.assertEqual(read_json(flipped)["status"], "acknowledged")
        self.assertEqual(check_state_root(self.root), [])

    def test_detects_staged_leftover(self):
        self.completed_dialogue()
        source = self.outbox_records()[0]
        record = read_json(source)
        record["status"] = "staged"
        record["transition_id"] = "tx-" + "f" * 32
        write_json_0600(source.parent / "msg-seeded-staged.json", record)
        self.assert_violation("I1 outbox-transactions")

    def test_detects_retained_audit_intent(self):
        dialogue = self.completed_dialogue()
        manifest = read_json(self.manifest_path(dialogue))
        manifest["pending_audit_events"] = {"tx-" + "e" * 32: ["dialogue_completed"]}
        write_json_0600(self.manifest_path(dialogue), manifest)
        self.assert_violation("I2 audit-intents")

    def test_detects_audit_tail_damage_and_duplicates(self):
        dialogue = self.completed_dialogue()
        audit = self.root / "dialogues" / dialogue / "audit.jsonl"
        with open(audit, "ab") as handle:
            handle.write(b'{"broken')
        self.assert_violation("I3 audit-log")
        lines = audit.read_bytes().splitlines()[:-1]
        repaired = b"\n".join(lines) + b"\n" + lines[-1] + b"\n"
        audit.write_bytes(repaired)
        self.assert_violation("byte-for-byte")

    def test_detects_tombstoned_dialogue_with_content(self):
        dialogue = self.completed_dialogue()
        self.broker.delete_terminal_dialogue(dialogue, "oracle fixture")
        write_json_0600(
            self.root / "dialogues" / dialogue / "manifest.json",
            {"phase": "complete"},
        )
        self.assert_violation("I4 deletion")

    def test_detects_orphaned_reference_to_tombstoned_dialogue(self):
        dialogue = self.completed_dialogue()
        template = read_json(self.outbox_records()[0])
        self.broker.delete_terminal_dialogue(dialogue, "oracle fixture")
        template["envelope"]["dialogue_id"] = dialogue
        write_json_0600(
            self.root / "outbox" / "alpha" / "msg-seeded-orphan.json", template
        )
        self.assert_violation("I4 deletion")

    def test_detects_manifest_inconsistencies(self):
        dialogue = self.completed_dialogue()
        final = self.root / "dialogues" / dialogue / "final.json"
        final_bytes = final.read_bytes()
        final.unlink()
        self.assert_violation("final.json is missing")
        final.write_bytes(final_bytes)
        os.chmod(final, 0o600)

        manifest = read_json(self.manifest_path(dialogue))
        manifest["current_round"] = manifest["authorized_rounds"] + 5
        write_json_0600(self.manifest_path(dialogue), manifest)
        self.assert_violation("round counts are out of order")

        manifest["current_round"] = manifest["authorized_rounds"]
        manifest["submissions"]["proposal"]["alpha"] = "submissions/nowhere.json"
        write_json_0600(self.manifest_path(dialogue), manifest)
        self.assert_violation("missing submission")

    def test_detects_terminal_digest_mismatch(self):
        dialogue = self.completed_dialogue()
        final = self.root / "dialogues" / dialogue / "final.json"
        final.write_bytes(final.read_bytes() + b" ")
        os.chmod(final, 0o600)
        self.assert_violation("I6 terminal-reference")

    def test_detects_route_file_hygiene_failures(self):
        self.bind_pair()
        registration_dir = self.root / "registrations"
        seeded = registration_dir / "gamma.json"
        write_json_0600(
            seeded,
            {
                "participant": "gamma",
                "runtime": "codex",
                "project": "test",
                "capability_hash": "not-a-hash",
                "lease_expires_epoch": 1.0,
                "bound_at": "2026-01-01T00:00:00+00:00",
                "binding_capability": "raw-secret-material",
            },
        )
        violations = check_state_root(self.root)
        self.assertTrue(any("non-hash capability field" in item for item in violations))
        self.assertTrue(any("is not a sha256 hash" in item for item in violations))

    def test_detects_world_readable_artifacts(self):
        dialogue = self.completed_dialogue()
        manifest = self.manifest_path(dialogue)
        os.chmod(manifest, 0o644)
        self.assert_violation("I8 permissions")
        os.chmod(manifest, 0o600)
        dialogue_dir = self.root / "dialogues" / dialogue
        os.chmod(dialogue_dir, 0o755)
        self.assert_violation("I8 permissions")
        os.chmod(dialogue_dir, 0o700)
        self.assertEqual(check_state_root(self.root), [])

    def test_detects_unanswered_live_request_for_terminal_dialogue(self):
        dialogue = self.completed_dialogue()
        template = read_json(self.outbox_records()[0])
        template["status"] = "pending"
        template["envelope"] = dict(
            template["envelope"],
            dialogue_id=dialogue,
            kind="exchange_request",
            recipient="gamma",
            message_id="msg-seeded-unanswered",
            round=1,
        )
        write_json_0600(
            self.root / "outbox" / "alpha" / "msg-seeded-unanswered.json", template
        )
        self.assert_violation("I9 supersession")

    def test_answered_live_request_is_exempt(self):
        dialogue = self.completed_dialogue()
        for path in self.outbox_records():
            record = read_json(path)
            envelope = record.get("envelope") or {}
            if (
                envelope.get("dialogue_id") == dialogue
                and envelope.get("kind") not in ("dialogue_complete", "cancelled")
                and record.get("status") == "pending"
            ):
                break
        else:
            self.fail("fixture produced no pending answered request")
        self.assertEqual(check_state_root(self.root), [])

    def test_detects_ledger_conservation_failures(self):
        dialogue = self.completed_dialogue()
        manifest = read_json(self.manifest_path(dialogue))
        for item in manifest["raw_claim_ledger"]:
            item["origin_participant"] = "alpha"
        write_json_0600(self.manifest_path(dialogue), manifest)
        self.assert_violation("I10 ledger")

        manifest = read_json(self.manifest_path(dialogue))
        manifest["retired_claims"] = [
            {"claim_id": "claim-seeded", "duplicate_of": "claim-missing-target"}
        ]
        write_json_0600(self.manifest_path(dialogue), manifest)
        self.assert_violation("unknown duplicate target")


class NamedFailpointTests(TerminalDialogueFixture):
    """The named-failpoint layer: stable seam names before every durable
    mutation, and crash-at-seam recovery asserted with the full oracle."""

    def install_hook(self, hook):
        council.FAILPOINT_HOOK = hook
        self.addCleanup(setattr, council, "FAILPOINT_HOOK", None)

    def crash_at(self, seam_name, occurrence=1):
        state = {"seen": 0}

        def hook(name):
            if name == seam_name:
                state["seen"] += 1
                if state["seen"] == occurrence:
                    raise SeamCrash(seam_name)

        self.install_hook(hook)

    def test_seam_names_cover_real_flows(self):
        names = set()
        self.install_hook(names.add)
        dialogue = self.completed_dialogue()
        self.broker.delete_terminal_dialogue(dialogue, "failpoint fixture")
        council.FAILPOINT_HOOK = None
        expected = {
            "atomic_json:registration",
            "atomic_json:manifest",
            "atomic_json:submission",
            "atomic_json:final",
            "atomic_json:outbox-record",
            "atomic_json:tombstone",
            "append_jsonl:audit-log",
            "remove_file:outbox-record",
            "remove_file:manifest",
            "remove_file:audit-log",
            "remove_file:submission",
            "remove_file:final",
            "remove_empty_dir:submissions-dir",
            "remove_empty_dir:dialogue-dir",
        }
        missing = expected - names
        self.assertFalse(missing, "flows never touched seams %s" % sorted(missing))
        unnamed = {name for name in names if name.endswith(":other")}
        self.assertFalse(
            unnamed, "durable mutations hit unclassified seams %s" % sorted(unnamed)
        )

    def test_crash_before_tombstone_write_recovers_intact(self):
        dialogue = self.completed_dialogue()
        self.crash_at("atomic_json:tombstone")
        with self.assertRaises(SeamCrash):
            self.broker.delete_terminal_dialogue(dialogue, "failpoint fixture")
        council.FAILPOINT_HOOK = None
        broker = CouncilBroker(self.root)
        self.assertEqual(check_state_root(self.root), [])
        self.assertFalse(
            (self.root / "tombstones" / ("%s.json" % dialogue)).exists()
        )
        self.assertTrue((self.root / "dialogues" / dialogue).is_dir())
        result = broker.delete_terminal_dialogue(dialogue, "failpoint fixture")
        self.assertTrue(result["deleted"])
        self.assertEqual(check_state_root(self.root), [])

    def test_crash_at_first_deletion_unlink_converges_tombstoned(self):
        dialogue = self.completed_dialogue()
        self.crash_at("remove_file:outbox-record")
        with self.assertRaises(SeamCrash):
            self.broker.delete_terminal_dialogue(dialogue, "failpoint fixture")
        council.FAILPOINT_HOOK = None
        # The tombstone committed before the crash, so restart must finish
        # the deletion on its own.
        CouncilBroker(self.root)
        self.assertEqual(check_state_root(self.root), [])
        self.assertTrue(
            (self.root / "tombstones" / ("%s.json" % dialogue)).exists()
        )
        self.assertFalse((self.root / "dialogues" / dialogue).exists())

    def test_crash_at_audit_append_during_completion_recovers(self):
        self.bind_pair()
        from test_council import (
            convergence_challenge,
            exchange,
            proposal,
            representation_check,
            synthesis,
        )

        dialogue = self.broker.start(
            "alpha",
            "beta",
            "Failpoint plan",
            "Crash the completion audit append.",
            [{"source": "user", "claim": "failpoint fixture"}],
        )["dialogue_id"]
        self.broker.submit(dialogue, "alpha", "proposal", 0, proposal("alpha"))
        self.broker.submit(dialogue, "beta", "proposal", 0, proposal("beta"))
        self.broker.submit(dialogue, "alpha", "exchange", 1, exchange("alpha", True))
        self.broker.submit(dialogue, "beta", "exchange", 1, exchange("beta", True))
        self.broker.submit(
            dialogue, "alpha", "exchange", 2, exchange("alpha", False, 2)
        )
        self.broker.submit(dialogue, "beta", "exchange", 2, exchange("beta", False, 2))
        self.broker.submit(
            dialogue, "alpha", "convergence_challenge", 2, convergence_challenge()
        )
        self.broker.submit(
            dialogue, "beta", "convergence_challenge", 2, convergence_challenge()
        )
        self.broker.submit(dialogue, "alpha", "synthesis", 2, synthesis())
        self.crash_at("append_jsonl:audit-log")
        with self.assertRaises(SeamCrash):
            self.broker.submit(
                dialogue, "beta", "representation_check", 2, representation_check()
            )
        council.FAILPOINT_HOOK = None
        broker = CouncilBroker(self.root)
        self.assertEqual(check_state_root(self.root), [])
        manifest = read_json(self.root / "dialogues" / dialogue / "manifest.json")
        if manifest["phase"] != "complete":
            result = broker.submit(
                dialogue, "beta", "representation_check", 2, representation_check()
            )
            self.assertEqual(result["phase"], "complete")
        self.assertEqual(check_state_root(self.root), [])
        self.assertTrue(self.final_path(dialogue).is_file())


class InjectableTimeSourceTests(TerminalDialogueFixture):
    """Stage 2 recovery-window inventory: every persisted recovery window is
    deterministically crossable by rebinding the single wall-clock seam
    (council.epoch_now); no persisted window reads any other clock."""

    def install_clock(self):
        original = council.epoch_now
        clock = {"offset": 0.0}
        council.epoch_now = lambda: original() + clock["offset"]
        self.addCleanup(setattr, council, "epoch_now", original)
        return clock

    def test_epoch_now_is_the_single_wall_clock_seam(self):
        source = Path(council.__file__).read_text(encoding="utf-8")
        self.assertEqual(
            source.count("time.time()"),
            1,
            "a persisted window may be reading the wall clock outside epoch_now",
        )
        self.assertIn("return time.time()", inspect.getsource(council.epoch_now))

    def test_every_persisted_window_crosses_deterministically(self):
        clock = self.install_clock()
        self.bind_pair()
        self.broker.start(
            "alpha",
            "beta",
            "Window inventory",
            "Cross every persisted recovery window.",
            [{"source": "user", "claim": "window fixture"}],
        )

        def beta_wakes():
            return [
                item
                for item in self.broker.pending_wakes()["notifications"]
                if item["participant"] == "beta"
            ]

        # W3 wake lease: a leased wake is invisible until the lease expires.
        first = beta_wakes()
        self.assertEqual([item["notification_kind"] for item in first], ["wake"])
        self.assertEqual(beta_wakes(), [])
        clock["offset"] = council.WAKE_LEASE_SECONDS + 1
        second = beta_wakes()
        self.assertEqual([item["notification_kind"] for item in second], ["wake"])
        self.assertEqual(second[0]["message_id"], first[0]["message_id"])

        # W4 wake retry back-off: a delivered wake is quiet until the retry
        # window passes; the attempt cap then routes to needs_attention (W5).
        self.broker.wake_ack(
            "beta", second[0]["message_id"], second[0]["notification_id"], "wake", True
        )
        self.assertEqual(beta_wakes(), [])
        clock["offset"] += council.WAKE_RETRY_SECONDS + 1
        attention = beta_wakes()
        self.assertEqual(
            [item["notification_kind"] for item in attention], ["needs_attention"]
        )
        self.assertEqual(beta_wakes(), [])
        clock["offset"] += council.WAKE_LEASE_SECONDS + 1
        self.assertEqual(
            [item["notification_kind"] for item in beta_wakes()], ["needs_attention"]
        )

        # W2 claim window: an expired claim is re-claimable, same message.
        claimed = self.broker.wait("beta")["message"]
        self.assertEqual(claimed["kind"], "proposal_request")
        self.assertIsNone(self.broker.wait("beta")["message"])
        clock["offset"] += council.CLAIM_SECONDS + 1
        reclaimed = self.broker.wait("beta")["message"]
        self.assertEqual(reclaimed["message_id"], claimed["message_id"])

        # W1 binding lease: expiry frees both seats.
        clock["offset"] = council.DEFAULT_LEASE_MINUTES * 60 + 1
        self.assertEqual(self.broker.ping()["bound_count"], 0)

    def test_retention_window_crosses_deterministically(self):
        clock = self.install_clock()
        dialogue = self.completed_dialogue()
        write_json_0600(self.root / "retention.json", {"days": 1})
        clock["offset"] = 2 * 86400
        CouncilBroker(self.root)
        self.assertFalse((self.root / "dialogues" / dialogue).exists())
        tombstone = read_json(self.root / "tombstones" / ("%s.json" % dialogue))
        self.assertEqual(tombstone["reason"], "retention_sweep")
        self.assertEqual(check_state_root(self.root), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
