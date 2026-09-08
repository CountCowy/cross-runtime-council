#!/usr/bin/env python3
"""Offline exact predecessor/state tuples, with independent preservation oracles.

Both candidates are reader evidence only. Neither supports managed writer
admission; no result of this harness authorizes managed binary rollback.
"""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures/predecessors"
PINS = {
    "pre-c1": (
        "a3f35b07207e85af1aafbd21933182aa87570e1b",
        "83653266060703005f93c07105b0bf201be5e025a057d3d3062b5d4207063bde",
        "1c51e97ec674f9265e0d15e720a11a60ba04ec8a664aecd0d367719dd16e17c4",
    ),
    "public-v0.19": (
        "f376101e1ee2092fe01152232f48c306b4a1ba21",
        "be0ee3eabe59b2b41f101fd0c457ff5073303739ac078bc55d2476d64f2a8274",
        None,
    ),
}
REQUIRED_CASES = {
    "router-configured-unbound",
    "router-bound",
    "triad-proposals",
    "claimed-and-wake-leased",
    "triad-exchange",
    "triad-challenge",
    "triad-synthesis",
    "triad-representation",
    "triad-revision",
    "triad-revision-check",
    "triad-complete",
    "inert-lifecycle-uninstalled",
    "inert-lifecycle-committed",
    "inert-lifecycle-pending",
    "unknown-lifecycle-format",
    "router-malformed",
    "stale-binding-generation",
    "interrupted-tombstone-deletion",
    "deleted",
    "dyad-proposals",
    "dormant-awaiting-extension",
    "extension-lost-ack",
    "cancellation-lost-ack",
    "audit-torn-tail",
    "audit-missing-newline",
    "unknown-dialogue-schema",
    "corrupt-manifest",
    "legacy-generation-missing",
    "expired-registration",
    "duplicate-route",
    "malformed-registration",
    "claude-dead-relay",
    "opencode-dead-relay",
    "retention-off",
    "retention-on",
    "retention-malformed",
    "opencode-pin",
    "opencode-pin-malformed",
    "staged-after-commit",
    "delivered-lost-ack",
    "attention",
    "staged-before-commit",
    "orphan-final",
    "pending-audit-intent",
    "retention-expired-terminal",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_reader(label, descriptor, root=FIXTURES):
    pin = PINS[label]
    if (
        descriptor["commit"] != pin[0]
        or descriptor["managed_writer_admission"] is not False
    ):
        raise ValueError("unknown reader tuple or managed-writer claim")
    expected_names = {"LICENSE", "NOTICE", "scripts/council.py"}
    if pin[2]:
        expected_names.add("scripts/council_protocol.py")
    if set(descriptor["files"]) != expected_names:
        raise ValueError("incomplete frozen import closure")
    for name, identity in descriptor["files"].items():
        path = root / label / name
        if path.is_symlink():
            raise ValueError("symlink reader")
        data = path.read_bytes()
        blob = hashlib.sha1(
            b"blob " + str(len(data)).encode() + b"\0" + data
        ).hexdigest()
        if sha(data) != identity["sha256"] or blob != identity["git_blob"]:
            raise ValueError("frozen source identity mismatch")
    if descriptor["files"]["scripts/council.py"]["sha256"] != pin[1]:
        raise ValueError("reader is not the pinned predecessor")
    if (
        pin[2]
        and descriptor["files"]["scripts/council_protocol.py"]["sha256"] != pin[2]
    ):
        raise ValueError("helper is not the pinned predecessor")


def validate_corpus(corpus):
    if corpus["format"] != 1 or set(corpus["cases"]) != REQUIRED_CASES:
        raise ValueError("missing or unsupported corpus families")
    for digest, data in corpus["objects"].items():
        if sha(data.encode()) != digest:
            raise ValueError("corrupt corpus object")
    for case in corpus["cases"].values():
        if not case["files"]:
            raise ValueError("empty corpus case")
        for path, digest in case["files"].items():
            if (
                Path(path).is_absolute()
                or ".." in Path(path).parts
                or digest not in corpus["objects"]
            ):
                raise ValueError("invalid corpus file")
    # Independent expectations: all phases and all seven real submission kinds
    # must exist in artifact bytes, not just in self-reported coverage tags.
    phases, kinds = set(), set()
    for case in corpus["cases"].values():
        for path, digest in case["files"].items():
            try:
                value = json.loads(corpus["objects"][digest])
            except ValueError:
                continue
            if path.endswith("manifest.json"):
                phases.add(value.get("phase"))
            if "/submissions/" in path:
                kinds.add(value.get("kind"))
    statuses = set()
    wake_leased = False
    for case in corpus["cases"].values():
        for path, digest in case["files"].items():
            if path.startswith("outbox/"):
                record = json.loads(corpus["objects"][digest])
                statuses.add(record.get("status"))
                wake_leased = wake_leased or record.get("wake_status") == "leased"
    if (
        not {
            "pending",
            "claimed",
            "delivered",
            "acknowledged",
            "superseded",
            "staged",
            "needs_attention",
        }
        <= statuses
        or not wake_leased
    ):
        raise ValueError("incomplete actual outbox state corpus")
    if phases != {
        "collecting_proposals",
        "collecting_exchange",
        "collecting_convergence_challenge",
        "collecting_synthesis",
        "collecting_representation_check",
        "collecting_synthesis_revision",
        "collecting_revision_check",
        "complete",
        "cancelled",
    }:
        raise ValueError("incomplete actual phase corpus")
    if kinds != {
        "proposal",
        "exchange",
        "convergence_challenge",
        "synthesis",
        "representation_check",
        "synthesis_revision",
        "revision_check",
    }:
        raise ValueError("incomplete actual submission corpus")


def run_case(label, descriptor, corpus, name):
    case = corpus["cases"][name]
    with tempfile.TemporaryDirectory(prefix="c1-reader-") as directory:
        base = Path(directory)
        frozen = base / "frozen"
        shutil.copytree(FIXTURES / label, frozen)
        state = base / "state"
        for path, digest in case["files"].items():
            target = state / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(corpus["objects"][digest])
        response = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(ROOT / "predecessor_worker.py"),
                str(frozen),
                str(state),
            ],
            input=json.dumps(
                {
                    "reader": descriptor,
                    "clock_epoch": corpus["clock_epoch"],
                    "case": name,
                }
            ),
            capture_output=True,
            text=True,
            timeout=15,
        )
        if response.returncode:
            raise AssertionError(response.stderr)
        result = json.loads(response.stdout)
        errors = []
        disposition = case["disposition"]
        if disposition == "constructor_refuses":
            if result["constructor"] != "refused":
                errors.append("expected_constructor_refusal")
        elif result["constructor"] != "ok":
            errors.append("constructor_refused")
        elif disposition != "unsupported":
            if result["relay_ready"]:
                errors.append("relay_resurrected")
            if result["reader_errors"]:
                errors.append("reader_refused")
            if case["expected_phase"] and set(result["manifest_phases"].values()) != {
                case["expected_phase"]
            }:
                errors.append("phase_changed")
            for path, digest in case["files"].items():
                target = state / path
                # Submission bytes/scope/response references and canonical finals
                # are reader-sensitive: parser success cannot discard any of them.
                preserved = (
                    "/submissions/" in path
                    or path.endswith("final.json")
                    or path
                    in ("router.json", "retention.json", "opencode-runtime.json")
                    or path.startswith(".council-lifecycle/")
                )
                if disposition == "delete" and path.startswith(
                    ("dialogues/", "outbox/")
                ):
                    if target.exists():
                        errors.append("deletion_not_completed")
                elif disposition == "orphan_final" and path.endswith("final.json"):
                    if target.exists():
                        errors.append("orphan_final_retained")
                elif preserved and (
                    not target.is_file() or sha(target.read_bytes()) != digest
                ):
                    errors.append("reader_sensitive_bytes_changed")
            # Constructor recovery may settle transport statuses/audits but never
            # changes participant scopes or creates a second logical submission.
            for path in (state / "dialogues").glob("dlg-*/manifest.json"):
                previous = json.loads(
                    corpus["objects"][case["files"][str(path.relative_to(state))]]
                )
                current = json.loads(path.read_text())
                for field in (
                    "participant_scopes",
                    "submissions",
                    "extension_operations",
                    "authorized_rounds",
                    "dialogue_id",
                ):
                    if current.get(field) != previous.get(field):
                        errors.append("logical_state_changed")
            if (
                disposition == "expired_registration"
                and (state / "registrations/alpha.json").exists()
            ):
                errors.append("expired_route_retained")
            if (
                disposition in ("route_error", "relay_tombstone")
                and result["restore_error_count"] == 0
            ):
                errors.append("missing_restore_error")
            if name == "staged-before-commit":
                records = [
                    json.loads(path.read_text())
                    for path in (state / "outbox").glob("*/*.json")
                ]
                if not any(record["status"] == "aborted" for record in records):
                    errors.append("uncommitted_stage_activated")
            if name == "delivered-lost-ack":
                records = [
                    json.loads(path.read_text())
                    for path in (state / "outbox").glob("*/*.json")
                ]
                if any(
                    record["envelope"]["kind"] == "proposal_request"
                    and record["status"] == "delivered"
                    for record in records
                ):
                    errors.append("lost_ack_not_recovered")
        # Unsupported schema/corruption is deliberately not certified even if
        # historical code silently parses it. Record that actual old behavior.
        if name == "pending-audit-intent" and result["constructor"] == "ok":
            manifests = list((state / "dialogues").glob("dlg-*/manifest.json"))
            for path in manifests:
                value = json.loads(path.read_text())
                events = [
                    json.loads(line)
                    for line in (path.parent / "audit.jsonl").read_text().splitlines()
                ]
                if (
                    value.get("pending_audit_events")
                    or sum(item["event"] == "fixture_event" for item in events) != 1
                ):
                    errors.append("audit_intent_not_reconciled_once")
        if name == "extension-lost-ack" and not result.get("duplicate_extension"):
            errors.append("extension_not_idempotent")
        if name == "stale-binding-generation" and not result.get("stale_wake_rejected"):
            errors.append("stale_wake_not_refused")
        if result.get("pin_admitted"):
            errors.append("unavailable_pin_admitted")
        support = (
            result["constructor"] == "ok"
            and disposition not in ("unsupported", "constructor_refuses", "route_error")
            and not errors
        )
        result.update(
            reader_supported=support,
            managed_writer_admission=False,
            oracle_errors=sorted(set(errors)),
        )
        return result


class PredecessorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readers = json.loads((FIXTURES / "readers.json").read_text())["readers"]
        encoded = (FIXTURES / "corpus.json").read_bytes()
        if sha(encoded) != (FIXTURES / "corpus.sha256").read_text().strip():
            raise ValueError("corpus digest mismatch")
        cls.corpus = json.loads(encoded)
        validate_corpus(cls.corpus)
        for label, descriptor in cls.readers.items():
            validate_reader(label, descriptor)

    def test_exact_offline_reader_state_matrix(self):
        observed = {}
        for label, descriptor in self.readers.items():
            observed[label] = {}
            for name in sorted(REQUIRED_CASES):
                with self.subTest(reader=label, state=name):
                    observed[label][name] = run_case(
                        label, descriptor, self.corpus, name
                    )
        # The checked-in support matrix is an explicit per-tuple policy, not an
        # inference that equal schema/version integers imply compatibility.
        expected = json.loads((FIXTURES / "support.json").read_text())
        for label, cases in observed.items():
            for name, result in cases.items():
                self.assertEqual(result, expected[label][name], (label, name, result))

    def test_actual_predecessor_seed_is_read_by_current_without_route_resurrection(
        self,
    ):
        import council

        for label, descriptor in self.readers.items():
            with (
                self.subTest(reader=label),
                tempfile.TemporaryDirectory(prefix="c1-historical-seed-") as directory,
            ):
                base = Path(directory)
                frozen = base / "frozen"
                shutil.copytree(FIXTURES / label, frozen)
                state = base / "state"
                response = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(ROOT / "predecessor_worker.py"),
                        str(frozen),
                        str(state),
                    ],
                    input=json.dumps(
                        {
                            "reader": descriptor,
                            "clock_epoch": self.corpus["clock_epoch"],
                            "mode": "seed",
                        }
                    ),
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(response.returncode, 0, response.stderr)
                result = json.loads(response.stdout)
                self.assertEqual(
                    set(result["manifest_phases"].values()), {"collecting_proposals"}
                )
                with council.CouncilBroker(state) as broker:
                    self.assertEqual(len(broker.status()["dialogues"]), 1)
                    self.assertTrue(
                        all(
                            not route.get("_admitted")
                            for route in broker.registrations.values()
                        )
                    )

    def test_identity_helper_corpus_schema_and_oracle_negative_controls(self):
        for label, descriptor in self.readers.items():
            with tempfile.TemporaryDirectory(prefix="c1-reader-control-") as directory:
                root = Path(directory)
                shutil.copytree(FIXTURES / label, root / label)
                target = root / label / "scripts/council.py"
                target.write_bytes((ROOT / "council.py").read_bytes())
                with self.assertRaises(ValueError):
                    validate_reader(label, descriptor, root)
            altered = copy.deepcopy(descriptor)
            altered["files"]["scripts/council.py"]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                validate_reader(label, altered)
        with tempfile.TemporaryDirectory(prefix="c1-missing-helper-") as directory:
            root = Path(directory)
            shutil.copytree(FIXTURES / "pre-c1", root / "pre-c1")
            (root / "pre-c1/scripts/council_protocol.py").unlink()
            with self.assertRaises((OSError, ValueError)):
                validate_reader("pre-c1", self.readers["pre-c1"], root)
        descriptor = copy.deepcopy(self.readers["pre-c1"])
        descriptor["files"].pop("scripts/council_protocol.py")
        with self.assertRaises(ValueError):
            validate_reader("pre-c1", descriptor)
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"].pop("pending-audit-intent")
        with self.assertRaises(ValueError):
            validate_corpus(corpus)
        corpus = copy.deepcopy(self.corpus)
        corpus["objects"][next(iter(corpus["objects"]))] = "{}"
        with self.assertRaises(ValueError):
            validate_corpus(corpus)
        for label, descriptor in self.readers.items():
            self.assertFalse(
                run_case(label, descriptor, self.corpus, "unknown-dialogue-schema")[
                    "reader_supported"
                ]
            )
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"]["triad-complete"]["expected_phase"] = "collecting_proposals"
        result = run_case("pre-c1", self.readers["pre-c1"], corpus, "triad-complete")
        self.assertIn("phase_changed", result["oracle_errors"])
        self.assertFalse(result["reader_supported"])


if __name__ == "__main__":
    unittest.main()
