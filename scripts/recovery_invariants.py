#!/usr/bin/env python3
"""Reusable artifact-oracle checkers for the broker's documented recovery invariants.

Each checker inspects only durable broker artifacts (manifests, outbox
records, audit logs, tombstones, route files) under a state root and returns
human-readable violation strings tagged with a stable invariant ID. The full
map from documented invariant to oracle lives in docs/verification-map.md;
invariants that are observable only at a live relay boundary (for example
exactly-once EXTERNAL delivery) are deliberately absent here and assigned to
the live recovery matrix instead.

Precondition: the state root must be quiescent and post-recovery — checkers
assert the steady state the docs promise AFTER a clean broker restart, so a
root captured mid-transaction (between stage and activate) legitimately
fails. The crash harness therefore runs them only after constructing a
recovered CouncilBroker.

This module is intentionally standalone (stdlib only, no import of
council.py): an oracle that shared the broker's own parsing and traversal
code could inherit the very defect it is meant to catch.

Standalone use: python3 recovery_invariants.py [state-root]
"""

import hashlib
import json
import stat
import sys
from pathlib import Path

OUTBOX_STATUSES = {
    "staged",
    "pending",
    "claimed",
    "delivered",
    "acknowledged",
    "aborted",
    "orphaned",
    "needs_attention",
    "superseded",
}
# Statuses that can still surface work to a participant.
LIVE_STATUSES = {"staged", "pending", "claimed", "delivered"}
TERMINAL_ENVELOPE_KINDS = {"dialogue_complete", "cancelled"}
MANIFEST_PHASES = {
    "collecting_proposals",
    "collecting_exchange",
    "collecting_convergence_challenge",
    "collecting_synthesis",
    "collecting_representation_check",
    "collecting_synthesis_revision",
    "collecting_revision_check",
    "complete",
    "cancelled",
}
ENVELOPE_REQUIRED_KEYS = ("message_id", "recipient", "dialogue_id", "kind", "round")
TOMBSTONE_REQUIRED_KEYS = (
    "dialogue_id",
    "deleted_at",
    "reason",
    "phase_at_deletion",
    "outbox_records_superseded",
)
REGISTRATION_REQUIRED_KEYS = (
    "participant",
    "runtime",
    "project",
    "capability_hash",
    "lease_expires_epoch",
    "bound_at",
)


def _load_json(path):
    """Parse one JSON artifact; return (value, error_string)."""
    try:
        return json.loads(path.read_bytes().decode("utf-8")), None
    except (OSError, UnicodeDecodeError, ValueError) as error:
        return None, "%s: %s" % (path.name, error)


def _is_hex_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _iter_dialogue_dirs(root):
    dialogues = root / "dialogues"
    if not dialogues.is_dir():
        return
    for path in sorted(dialogues.iterdir()):
        if path.is_dir():
            yield path


def _iter_outbox_records(root):
    outbox = root / "outbox"
    if not outbox.is_dir():
        return
    for participant_dir in sorted(outbox.iterdir()):
        if not participant_dir.is_dir():
            continue
        for path in sorted(participant_dir.glob("*.json")):
            yield path


def _submission_paths(node):
    """Collect every string leaf in a manifest submissions tree."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _submission_paths(value)
    elif isinstance(node, list):
        for value in node:
            yield from _submission_paths(value)


def _final_refs(node, dialogue_id):
    """Yield every final_ref recorded for the dialogue inside a JSON tree."""
    if isinstance(node, dict):
        final_ref = node.get("final_ref")
        if (
            isinstance(final_ref, dict)
            and final_ref.get("dialogue_id") == dialogue_id
        ):
            yield final_ref
        for value in node.values():
            yield from _final_refs(value, dialogue_id)
    elif isinstance(node, list):
        for value in node:
            yield from _final_refs(value, dialogue_id)


def check_outbox_transactions(root):
    """I1 — staged-outbox convergence (protocol.md, Delivery and recovery).

    After recovery no record may remain 'staged': staged records matching the
    committed transition are activated and the rest are marked aborted. Every
    record uses a documented status and carries a well-formed envelope.
    """
    violations = []
    for path in _iter_outbox_records(root):
        record, error = _load_json(path)
        if error:
            violations.append("I1 outbox-transactions: unreadable record %s" % error)
            continue
        if not isinstance(record, dict):
            violations.append(
                "I1 outbox-transactions: %s is not a JSON object" % path.name
            )
            continue
        status = record.get("status")
        if status not in OUTBOX_STATUSES:
            violations.append(
                "I1 outbox-transactions: %s has undocumented status %r"
                % (path.name, status)
            )
        if status == "staged":
            violations.append(
                "I1 outbox-transactions: %s still staged after recovery "
                "(transition %s was neither activated nor aborted)"
                % (path.name, record.get("transition_id"))
            )
        envelope = record.get("envelope")
        if not isinstance(envelope, dict) or any(
            key not in envelope for key in ENVELOPE_REQUIRED_KEYS
        ):
            violations.append(
                "I1 outbox-transactions: %s envelope is missing required keys"
                % path.name
            )
    return violations


def check_audit_intents(root):
    """I2 — durable audit intent drained (protocol.md, Delivery and recovery).

    Restart reconciles remaining intent before advancing, so a recovered
    manifest never retains pending_audit_events.
    """
    violations = []
    for dialogue_dir in _iter_dialogue_dirs(root):
        manifest, error = _load_json(dialogue_dir / "manifest.json")
        if error or not isinstance(manifest, dict):
            continue  # unreadable manifests are I5's finding
        pending = manifest.get("pending_audit_events")
        if pending:
            violations.append(
                "I2 audit-intents: %s retains pending audit events %s after "
                "recovery" % (dialogue_dir.name, sorted(pending))
            )
    return violations


def check_audit_log_wellformed(root):
    """I3 — audit log tail repair (protocol.md, Delivery and recovery).

    After recovery every audit record is a complete, newline-terminated JSON
    object with the documented shape, and no event was double-appended.
    """
    violations = []
    for dialogue_dir in _iter_dialogue_dirs(root):
        audit_path = dialogue_dir / "audit.jsonl"
        if not audit_path.is_file():
            continue
        raw = audit_path.read_bytes()
        if not raw:
            continue
        if not raw.endswith(b"\n"):
            violations.append(
                "I3 audit-log: %s/audit.jsonl is not newline-terminated after "
                "recovery" % dialogue_dir.name
            )
        seen = set()
        for index, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                violations.append(
                    "I3 audit-log: %s/audit.jsonl line %d is not valid JSON"
                    % (dialogue_dir.name, index)
                )
                continue
            if (
                not isinstance(event, dict)
                or not isinstance(event.get("event"), str)
                or "at" not in event
                or "details" not in event
            ):
                violations.append(
                    "I3 audit-log: %s/audit.jsonl line %d lacks the documented "
                    "at/event/details shape" % (dialogue_dir.name, index)
                )
                continue
            if line in seen:
                violations.append(
                    "I3 audit-log: %s/audit.jsonl line %d duplicates an "
                    "earlier event byte-for-byte" % (dialogue_dir.name, index)
                )
            seen.add(line)
    return violations


def check_deletion_bimodality(root):
    """I4 — tombstone bimodality (docs/install.md, Deleting dialogue records).

    A tombstoned dialogue keeps zero content: no dialogue directory, no
    referencing outbox record, and a tombstone with the documented fields.
    """
    violations = []
    tombstone_dir = root / "tombstones"
    tombstoned = set()
    if tombstone_dir.is_dir():
        for path in sorted(tombstone_dir.glob("dlg-*.json")):
            tombstone, error = _load_json(path)
            if error or not isinstance(tombstone, dict):
                violations.append("I4 deletion: unreadable tombstone %s" % path.name)
                continue
            missing = [key for key in TOMBSTONE_REQUIRED_KEYS if key not in tombstone]
            if missing:
                violations.append(
                    "I4 deletion: tombstone %s is missing fields %s"
                    % (path.name, missing)
                )
            dialogue_id = tombstone.get("dialogue_id") or path.stem
            tombstoned.add(dialogue_id)
            if (root / "dialogues" / dialogue_id).exists():
                violations.append(
                    "I4 deletion: %s has both a tombstone and dialogue content"
                    % dialogue_id
                )
    if tombstoned:
        for path in _iter_outbox_records(root):
            record, error = _load_json(path)
            if error or not isinstance(record, dict):
                continue
            envelope = record.get("envelope") or {}
            if envelope.get("dialogue_id") in tombstoned:
                violations.append(
                    "I4 deletion: outbox record %s still references tombstoned "
                    "dialogue %s" % (path.name, envelope.get("dialogue_id"))
                )
    return violations


def check_manifest_consistency(root):
    """I5 — phase and submission consistency (protocol.md, State machine).

    Every manifest parses, uses a documented phase, keeps its round counts
    ordered (current <= authorized <= max, minimum <= max), records a terminal
    timestamp in a terminal phase, owns a final.json exactly when complete,
    and every referenced submission artifact exists and parses.
    """
    violations = []
    for dialogue_dir in _iter_dialogue_dirs(root):
        name = dialogue_dir.name
        manifest, error = _load_json(dialogue_dir / "manifest.json")
        if error:
            violations.append("I5 manifest: unreadable manifest %s" % error)
            continue
        if not isinstance(manifest, dict):
            violations.append("I5 manifest: %s manifest is not a JSON object" % name)
            continue
        phase = manifest.get("phase")
        if phase not in MANIFEST_PHASES:
            violations.append(
                "I5 manifest: %s has undocumented phase %r" % (name, phase)
            )
            continue
        current = manifest.get("current_round")
        authorized = manifest.get("authorized_rounds")
        maximum = manifest.get("max_rounds", authorized)
        minimum = manifest.get("minimum_rounds")
        counts = [current, authorized, maximum]
        if all(isinstance(item, int) for item in counts) and not (
            current <= authorized <= maximum
        ):
            violations.append(
                "I5 manifest: %s round counts are out of order "
                "(current=%s authorized=%s max=%s)"
                % (name, current, authorized, maximum)
            )
        if (
            isinstance(minimum, int)
            and isinstance(maximum, int)
            and minimum > maximum
        ):
            violations.append(
                "I5 manifest: %s minimum_rounds %s exceeds max_rounds %s"
                % (name, minimum, maximum)
            )
        final_exists = (dialogue_dir / "final.json").is_file()
        if phase == "complete":
            if not final_exists:
                violations.append(
                    "I5 manifest: %s is complete but final.json is missing" % name
                )
            if not manifest.get("completed_at"):
                violations.append(
                    "I5 manifest: %s is complete without completed_at" % name
                )
        elif phase == "cancelled":
            if not manifest.get("cancelled_at"):
                violations.append(
                    "I5 manifest: %s is cancelled without cancelled_at" % name
                )
        elif final_exists:
            violations.append(
                "I5 manifest: %s has final.json in non-terminal phase %s"
                % (name, phase)
            )
        for relative in _submission_paths(manifest.get("submissions", {})):
            submission = dialogue_dir / relative
            if not submission.is_file():
                violations.append(
                    "I5 manifest: %s references missing submission %s"
                    % (name, relative)
                )
                continue
            _, sub_error = _load_json(submission)
            if sub_error:
                violations.append(
                    "I5 manifest: %s submission unreadable: %s" % (name, sub_error)
                )
    return violations


def check_terminal_references(root):
    """I6 — terminal digest integrity (protocol.md, State machine ¶terminal).

    The terminal transition records the canonical final.json digest in the
    audit log and in every dialogue_complete envelope; after recovery every
    recorded reference must match the canonical bytes exactly.
    """
    violations = []
    finals = {}
    for dialogue_dir in _iter_dialogue_dirs(root):
        final_path = dialogue_dir / "final.json"
        if not final_path.is_file():
            continue
        raw = final_path.read_bytes()
        finals[dialogue_dir.name] = (hashlib.sha256(raw).hexdigest(), len(raw))
        audit_path = dialogue_dir / "audit.jsonl"
        if not audit_path.is_file():
            continue
        for line in audit_path.read_bytes().splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue  # I3's finding
            for final_ref in _final_refs(event, dialogue_dir.name):
                violations.extend(
                    _check_final_ref(dialogue_dir.name, final_ref, finals)
                )
    for path in _iter_outbox_records(root):
        record, error = _load_json(path)
        if error or not isinstance(record, dict):
            continue
        envelope = record.get("envelope") or {}
        dialogue_id = envelope.get("dialogue_id")
        if dialogue_id in finals and envelope.get("kind") == "dialogue_complete":
            for final_ref in _final_refs(envelope, dialogue_id):
                violations.extend(_check_final_ref(dialogue_id, final_ref, finals))
    return violations


def _check_final_ref(dialogue_id, final_ref, finals):
    digest, size = finals[dialogue_id]
    violations = []
    if final_ref.get("sha256") != digest:
        violations.append(
            "I6 terminal-reference: %s final.json digest %s does not match the "
            "recorded completion reference %s"
            % (dialogue_id, digest, final_ref.get("sha256"))
        )
    recorded_size = final_ref.get("size_bytes")
    if isinstance(recorded_size, int) and recorded_size != size:
        violations.append(
            "I6 terminal-reference: %s final.json is %d bytes but the recorded "
            "completion reference says %d" % (dialogue_id, size, recorded_size)
        )
    return violations


def check_route_files(root):
    """I7 — restart-safe route hygiene (protocol.md, Security).

    Route files persist capability hashes only — never a raw capability —
    and every registration keeps its documented fields.
    """
    violations = []
    registrations = root / "registrations"
    if registrations.is_dir():
        for path in sorted(registrations.glob("*.json")):
            registration, error = _load_json(path)
            if error or not isinstance(registration, dict):
                violations.append("I7 route-files: unreadable registration %s" % path.name)
                continue
            missing = [
                key for key in REGISTRATION_REQUIRED_KEYS if key not in registration
            ]
            if missing:
                violations.append(
                    "I7 route-files: registration %s is missing fields %s"
                    % (path.name, missing)
                )
            violations.extend(_check_capability_fields(path.name, registration))
    for name in ("router.json", "opencode-runtime.json"):
        path = root / name
        if path.is_file():
            record, error = _load_json(path)
            if error or not isinstance(record, dict):
                violations.append("I7 route-files: unreadable %s" % name)
                continue
            violations.extend(_check_capability_fields(name, record))
    return violations


def _check_capability_fields(name, record):
    violations = []
    for key, value in record.items():
        if "capability" not in key:
            continue
        if not key.endswith("_hash"):
            violations.append(
                "I7 route-files: %s persists non-hash capability field %r" % (name, key)
            )
        elif value is not None and not _is_hex_digest(value):
            violations.append(
                "I7 route-files: %s field %r is not a sha256 hash" % (name, key)
            )
    return violations


def check_permission_modes(root):
    """I8 — restrictive modes (protocol.md, Persistent state).

    Files and sockets use mode 0600; directories use 0700.
    """
    violations = []
    for path in sorted(root.rglob("*")):
        try:
            mode = path.lstat().st_mode
        except OSError:
            continue
        permissions = stat.S_IMODE(mode)
        if stat.S_ISDIR(mode):
            if permissions != 0o700:
                violations.append(
                    "I8 permissions: directory %s is %o, expected 700"
                    % (path.relative_to(root), permissions)
                )
        elif stat.S_ISREG(mode) or stat.S_ISSOCK(mode):
            if permissions & 0o077:
                violations.append(
                    "I8 permissions: %s is %o, expected owner-only"
                    % (path.relative_to(root), permissions)
                )
    return violations


REQUEST_TO_SUBMIT_KIND = {
    "proposal_request": "proposal",
    "exchange_request": "exchange",
    "convergence_challenge_request": "convergence_challenge",
    "synthesis_request": "synthesis",
    "representation_check_request": "representation_check",
    "synthesis_revision_request": "synthesis_revision",
    "revision_check_request": "revision_check",
}


def _has_recorded_response(manifest, request_kind, recipient, round_number):
    """True when the manifest records the recipient's answer to this request."""
    submit_kind = REQUEST_TO_SUBMIT_KIND.get(request_kind)
    if submit_kind is None:
        return False
    tree = (manifest.get("submissions") or {}).get(submit_kind)
    if not isinstance(tree, dict):
        return False
    node = tree.get(str(round_number), tree)
    return (isinstance(node, dict) and recipient in node) or recipient in tree


def check_terminal_supersession(root):
    """I9 — terminal supersession (protocol.md, State machine ¶cancelled).

    A terminal transition supersedes every still-live request before its
    terminal notices activate, so after recovery no unanswered non-terminal
    envelope for a terminal dialogue may remain in a live status. A delivered
    or claimed request whose durable response is already recorded is the
    documented safely-handled state awaiting acknowledgement reconciliation
    and is exempt. Dialogues cancelled by brokers that predate the
    supersession machinery can legitimately be flagged; deleting them clears
    the finding.
    """
    violations = []
    terminal_manifests = {}
    for dialogue_dir in _iter_dialogue_dirs(root):
        manifest, error = _load_json(dialogue_dir / "manifest.json")
        if error or not isinstance(manifest, dict):
            continue
        if manifest.get("phase") in ("complete", "cancelled"):
            terminal_manifests[dialogue_dir.name] = manifest
    if not terminal_manifests:
        return violations
    for path in _iter_outbox_records(root):
        record, error = _load_json(path)
        if error or not isinstance(record, dict):
            continue
        envelope = record.get("envelope") or {}
        dialogue_id = envelope.get("dialogue_id")
        manifest = terminal_manifests.get(dialogue_id)
        if manifest is None:
            continue
        kind = envelope.get("kind")
        if kind in TERMINAL_ENVELOPE_KINDS:
            continue
        if record.get("status") not in LIVE_STATUSES:
            continue
        if _has_recorded_response(
            manifest, kind, envelope.get("recipient"), envelope.get("round")
        ):
            continue
        violations.append(
            "I9 supersession: %s dialogue %s is %s but unanswered request %s "
            "(%s) is still %s"
            % (
                path.name,
                dialogue_id,
                manifest.get("phase"),
                envelope.get("message_id"),
                kind,
                record.get("status"),
            )
        )
    return violations


def check_claim_ledger_conservation(root):
    """I10 — ledger conservation (protocol.md, State machine ¶claims).

    At least two active claims from at least two distinct participant origins
    remain in every dialogue that reached synthesis, and every retired
    claim's duplicate_of target still exists somewhere in the record.
    """
    violations = []
    for dialogue_dir in _iter_dialogue_dirs(root):
        manifest, error = _load_json(dialogue_dir / "manifest.json")
        if error or not isinstance(manifest, dict):
            continue
        raw_ledger = manifest.get("raw_claim_ledger")
        if not isinstance(raw_ledger, list) or not raw_ledger:
            continue
        submissions = manifest.get("submissions") or {}
        if not submissions.get("synthesis"):
            continue
        active = [item for item in raw_ledger if isinstance(item, dict)]
        origins = {item.get("origin_participant") for item in active}
        if len(active) < 2 or len(origins - {None}) < 2:
            violations.append(
                "I10 ledger: %s reached synthesis with fewer than two active "
                "claims from two origins" % dialogue_dir.name
            )
        known_ids = {
            item.get("claim_id")
            for source in (raw_ledger, manifest.get("retired_claims") or [])
            for item in source
            if isinstance(item, dict)
        }
        for item in manifest.get("retired_claims") or []:
            if not isinstance(item, dict):
                continue
            target = item.get("duplicate_of")
            if target and target not in known_ids:
                violations.append(
                    "I10 ledger: %s retired claim %s points at unknown "
                    "duplicate target %s"
                    % (dialogue_dir.name, item.get("claim_id"), target)
                )
    return violations


CHECKERS = (
    check_outbox_transactions,
    check_audit_intents,
    check_audit_log_wellformed,
    check_deletion_bimodality,
    check_manifest_consistency,
    check_terminal_references,
    check_route_files,
    check_permission_modes,
    check_terminal_supersession,
    check_claim_ledger_conservation,
)


def check_state_root(root):
    """Run every artifact oracle; returns a list of violations (empty = pass)."""
    root = Path(root).expanduser().resolve()
    violations = []
    for checker in CHECKERS:
        violations.extend(checker(root))
    return violations


def main(argv):
    root = Path(argv[0]) if argv else Path.home() / ".claude" / "peer-consults"
    violations = check_state_root(root)
    for violation in violations:
        print(violation)
    print(
        "%d invariant checker(s), %d violation(s), state root %s"
        % (len(CHECKERS), len(violations), root)
    )
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
