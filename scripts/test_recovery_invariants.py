#!/usr/bin/env python3
"""Fixture tests for the recovery-invariant artifact oracles.

Every oracle must (a) pass on clean post-recovery roots produced by the real
broker and (b) catch a seeded violation of the documented invariant it
encodes. The oracles themselves live in recovery_invariants.py and are also
run by the deletion x recovery crash harness after every injected crash.
"""

import json
import os
import unittest

from council import CouncilBroker, read_json
from recovery_invariants import check_state_root
from test_council import TerminalDialogueFixture


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
