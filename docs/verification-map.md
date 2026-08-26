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

## Named failpoints (landed with Stage 1)

The persistence primitives (`atomic_json`, `append_jsonl`, `remove_file`,
`remove_empty_dir`) call a test-only hook (`council.FAILPOINT_HOOK`, `None`
in production) with a stable seam name — `atomic_json:manifest`,
`atomic_json:tombstone`, `append_jsonl:audit-log`,
`remove_file:outbox-record`, and so on — immediately before every durable
mutation. A test may raise from the hook to crash at that exact boundary.
`test_recovery_invariants.py` pins that real flows touch every documented
seam and never an unclassified one, and asserts crash-at-seam recovery with
the full oracle; monkeypatching the primitives directly remains the
test-local fallback.

## Recovery-window inventory (Stage 2, step 1)

Every window the broker persists and later compares against the wall clock,
with where it is created and every place its expiry changes behavior.

| ID | Window | Duration | Created | Expiry behavior |
|---|---|---|---|---|
| W1 | Participant binding lease (`lease_expires_epoch`) | `lease_minutes` × 60 (default 120 min, bounds 1–1440) | `bind` | Restart deletes the expired route file; every authorized call raises "binding expired" and frees the seat; `ping` sweeps; bind idempotency and duplicate exact-route checks ignore expired peers; delivery skips an expired recipient (record stays pending) |
| W2 | Envelope claim (`claim_until_epoch`) | `CLAIM_SECONDS` (120 s) | claim in `wait` | An expired claim is re-claimable by the next `wait`; the wake scheduler recovers an expired consumed claim to pending + `retry_pending` (or the safe-acknowledgement path) |
| W3 | Wake notification lease (`wake_lease_until_epoch`) | `WAKE_LEASE_SECONDS` (120 s) | `pending_wakes` | A leased wake is invisible to the router until expiry, then re-leasable; cleared by `wake_ack`, by claim consumption, and by binding-generation rearm |
| W4 | Wake retry back-off (`wake_retry_after_epoch`) | `WAKE_RETRY_SECONDS` (300 s) | `wake_ack(delivered=true)` | A notified record is quiet until the window passes, then re-attempted; `WAKE_MAX_ATTEMPTS` (2) exhausted routes to `needs_attention` |
| W5 | Attention notification lease (`attention_lease_until_epoch`) | `WAKE_LEASE_SECONDS` (120 s) | `pending_wakes` attention branch | Same lease semantics as W3; attention attempts share the cap of 2, then the record waits for a human |
| W6 | Retention cutoff | `days` × 86400 (retention.json, 1–3650) | broker startup sweep only | Terminal dialogues whose manifest terminal timestamp predates `epoch_now() − window` are tombstone-deleted; a missing or malformed timestamp always skips (never delete on an uncertain age) |

Ordering checks that compare two **recorded** epochs (no "now"; deterministic
via the already-mocked `_process_start_epoch` subprocess seam): the OpenCode
pin rejects a process that started before `configured_at_epoch` was recorded,
and relay reuse requires an exact `relay_process_start_epoch` match.

Real-time waits excluded from the crash matrix (bounded, never persisted, no
recovery semantics): the `wait` long-poll deadline (≤ 55 s, 1 s condition-var
slices), the client's 3 s daemon-start spin, the launcher-death watchdog's
1 s poll, and subprocess timeouts. The OpenCode relay's detached-tombstone
TTL reads `Date.now()` in memory only — covered by the Node suite and the L1
live-matrix row, never by artifact oracles.

**Injectable-time-source check: PASS, no production change needed.**
`epoch_now()` is the only wall-clock read in the broker (pinned by
`test_epoch_now_is_the_single_wall_clock_seam`), and every W1–W6 comparison
resolves it at call time, so rebinding `council.epoch_now` time-travels all
six windows deterministically. `InjectableTimeSourceTests` proves each
window crossing end to end (lease → invisible → re-offered; claim → expired
→ re-claimed same message; binding expiry frees the seat; retention deletes
on restart). Backdating the persisted epoch fields remains the equivalent
per-record technique. Useful matrix fact: a +301 s jump crosses W2–W5 while
every default binding lease stays live.

## Planned next (Stage 2, step 2)

A ~24–36-row deterministic crash matrix over six structural transaction
classes driven by the named failpoints above — single-file atomic replace,
audit append, multi-file forward transactions (intent → append → commit),
deletion/tombstone, supersession/outbox fan-out, and window-expiry recovery
transitions (the W-rows) — release-gated on killing a mutant corpus
implemented as inverted failpoint behaviors, with at least one held-out
mutant. The oracles above are the assertion layer those rows reuse.
