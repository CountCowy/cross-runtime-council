# Invariant coverage map

This map assigns every documented recovery invariant to the tier that
verifies it, per the v0.20 verification plan decided in the
[committed example packet](../examples/v020-verification-depth/decision-packet.md).
An invariant is either checked by an **artifact oracle**
([`scripts/recovery_invariants.py`](../scripts/recovery_invariants.py) —
standalone checkers over durable broker state, run by
`test_recovery_invariants.py` in CI and by the crash harness after every
injected crash), pinned by a **static suite**, or observable only at a live
relay boundary and assigned to a named **live-matrix** row of the release
checklist. Nothing on this map is silently unverified: if a row says
live-matrix, no CI job claims it.

Oracle precondition: the artifact oracles describe the steady state the
documentation promises **after a clean broker restart**. A state root
captured mid-transaction (between stage and activate) legitimately fails
them; the crash harness therefore runs them only after constructing a
recovered broker.

## Artifact-oracle invariants

| ID | Invariant (documented source) | Oracle |
|---|---|---|
| I1 | Staged-outbox convergence: after recovery no envelope record remains `staged` — records matching the committed transition are activated, the rest aborted; every record uses a documented status and a well-formed envelope. (protocol.md, "Delivery and recovery") | `check_outbox_transactions` |
| I2 | Durable audit intent is drained: restart reconciles remaining intent before advancing, so no recovered manifest retains `pending_audit_events`. (protocol.md, "Delivery and recovery") | `check_audit_intents` |
| I3 | Audit-log wellformedness: after tail repair every audit record is a complete, newline-terminated JSON object with the documented `at`/`event`/`details` shape, and no event was double-appended. (protocol.md, "Delivery and recovery") | `check_audit_log_wellformed` |
| I4 | Deletion bimodality: a tombstoned dialogue keeps zero content — no dialogue directory, no referencing outbox record, and a tombstone with exactly the documented fields. (install.md, "Deleting dialogue records") | `check_deletion_bimodality` |
| I5 | Manifest consistency: documented phase values, ordered round counts, terminal timestamps in terminal phases, `final.json` present exactly when complete, and every referenced submission artifact present and parseable. (protocol.md, "State machine") | `check_manifest_consistency` |
| I6 | Terminal reference integrity: every completion reference recorded in the audit log and in `dialogue_complete` envelopes matches the canonical `final.json` digest and size exactly. (protocol.md, terminal transition) | `check_terminal_references` |
| I7 | Route-file hygiene: restart-safe route files persist capability **hashes** only, never a raw capability, with the documented registration fields. (protocol.md, "Security") | `check_route_files` |
| I8 | Restrictive modes: files and sockets 0600, directories 0700, across the entire state root. (protocol.md, "Persistent state") | `check_permission_modes` |
| I9 | Terminal supersession: no **unanswered** non-terminal request for a terminal dialogue remains in a live status. A delivered/claimed request whose durable response is recorded is the documented safely-handled state awaiting acknowledgement reconciliation and is exempt; the reconciliation itself is asserted by `test_restart_reconciles_answered_delivered_record`. (protocol.md, cancellation and extension transitions) | `check_terminal_supersession` |
| I10 | Ledger conservation: at least two active claims from two distinct origins survive to synthesis, and every retired claim's `duplicate_of` target still exists in the record. (protocol.md, claim ledger) | `check_claim_ledger_conservation` |

Known caveat: dialogues cancelled by brokers that predate the supersession
machinery (early v0.18 development) can hold pre-invariant `pending`
leftovers that I9 truthfully reports. Deleting those dialogues clears the
finding; the invariant itself is claimed only for the current broker.

## Statically pinned invariants

| Invariant | Suite |
|---|---|
| Relay envelope preamble and kind allow-list are byte-identical across the broker and both relay implementations | `test_parity.py` (release-blocking) |
| Tool/submit-kind/enum/bound parity across broker, MCP schemas, TypeScript, and prose | `test_parity.py` |
| Corrupt (unparseable) manifest/outbox records cost that record — quarantined, surfaced in health, never the broker; audit-integrity conflicts stay fail-loud | `test_council.py` containment tests |
| Crash-boundary convergence for deletion, recovery, and retention — with the full artifact oracle asserted after every injected crash | `test_deletion_crash.py` (release-blocking) |
| Rendered decision packets: deterministic output, three-state verification labeling, refusal on digest mismatch or tombstone | `test_council.py` RenderTests |

## Live-matrix observations (blocking release-checklist rows)

These are observable only with live sessions on real transports; no CI job
claims them, and per the ratified plan the exact-tree live recovery matrix is
a **blocking** release-checklist row from v0.20 onward.

| ID | Observation | Matrix row |
|---|---|---|
| L1 | Exactly-once EXTERNAL delivery of a durably delivered, unanswered envelope across a broker crash — relay dedup state is memory-only, so no artifact can witness this | G3 |
| L2 | Router wake delivery to an idle Codex task | G1 |
| L3 | Broker-restart barrier recovery with live seats | G2 |
| L4 | Acknowledgement recovery over live transports | G4 (artifact half: I9 exemption + reconciliation test) |
| L5 | Terminal delivery with identical canonical digests at every seat | G5 (artifact half: I6) |

## Planned next (Stage 2 of the ratified plan)

A one-day recovery-window inventory (including an injectable-time-source
check for lease/wake windows), then a ~24–36-row deterministic crash matrix
over six structural transaction classes driven by named failpoints at the
persistence seams, release-gated on killing a mutant corpus implemented as
inverted failpoint behaviors — with at least one held-out mutant. The
oracles above are the assertion layer those rows reuse.
