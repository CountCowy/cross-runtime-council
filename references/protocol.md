# Council protocol reference

## Contents

1. Participants and transport
2. Persistent state
3. State machine
4. Submission shapes
5. Delivery and recovery
6. Security and cold-review firewall

## Participants and transport

Before sending any participant or router capability, each client verifies that the connected Unix peer is a broker whose live launcher chain terminates at an admitted signed Codex/Claude runtime or the currently pinned OpenCode process. The production broker refuses any other launcher. The same-UID-replaceable lifetime-lock and socket pathnames are coordination artifacts, never authentication anchors. Before participant work, the adapter also requires the broker's exact current version. Broker and Claude-relay handlers impose bounded read timeouts and both servers cap concurrent accepted handlers, so idle connections cannot retain unbounded threads or descriptors.

The local broker listens only on a user-owned Unix socket under `~/.claude/peer-consults/` and holds an exclusive lifetime file lock before creating or unlinking that socket. A broker exits when its authenticated launcher process generation dies; admitted adapters restart it and recover durable state. A dialogue has an immutable ordered set of two or three exact sessions. Codex and Claude bind through the current session's Council MCP child. OpenCode CLI binds through native custom tools whose context supplies the exact `sessionID`; its plugin keeps a broker child under the pinned OpenCode host while one-request Python bridges carry tool operations. The broker requires a bridge child to use its exact Python executable and its parent to satisfy either a Codex/Claude designated requirement whose path CDHash matches the live process CDHash, or the user-approved OpenCode executable path, SHA-256, and macOS code-directory hash. The accepted OpenCode executable is the exact CLI binary configured offline; the digest and code identity pin must change after an upgrade, and the live parent process must have started at or after that pin was recorded. OpenCode Desktop is unsupported until a version-specific live acceptance proves that its sidecar initializes both the plugin and exact-session relay. Process arguments, names, basenames, model names, and matching substrings never authenticate a runtime. This proves runtime origin only, not adapter code, session metadata, or model provider identity; malicious sibling MCP children or plugins inside an admitted runtime remain outside the threat model. Each adapter retains an unguessable capability while the broker persists only its hash.

- A Claude bind must execute inside the exact selected session. The session-spawned MCP adapter reads `CLAUDE_CODE_MESSAGING_SOCKET`, opens a private relay socket, and registers that relay plus a second memory-only relay capability with the broker. One per-child owner nonce is shared across participant-specific relay sockets and persisted only as a hash, preventing one Claude session from occupying multiple Council seats. Merely looking up an unknown participant never creates a relay. The relay authenticates its capability, validates the fixed Council preamble and complete envelope shape/recipient, and de-duplicates message IDs before posting to its parent Claude inbox. On macOS, Claude verifies the live child by process evidence, so no exported token is required. Participant operations never use a Bash/CLI fallback.
- A Codex MCP bind records the task ID supplied by the host to the Council adapter's request metadata. An active task waits through `council_wait`. An idle task is awakened by a dedicated context-isolated router; the planning task itself never runs recurring empty polls. The broker treats that ID as adapter-supplied routing data, not host-signed attestation.
- An OpenCode CLI bind uses native custom-tool `context.sessionID`, never ordinary MCP metadata or session-list guessing. The global plugin owns a private Unix relay and posts validated envelopes through OpenCode's session SDK to that exact session. Concurrent retries for one message join one in-flight post; completed-message dedupe is scoped to exact `sessionID + participant`, survives capability rotation in that session, and preserves a just-settled in-flight tombstone across the unbind/rebind gap until same-session retain, confirmed session move, or bounded expiry. Raw binding and relay capabilities stay memory-only. The offline CLI executable pin authenticates OpenCode runtime origin; a custom model's unknown provider is intentionally irrelevant to transport identity. After broker restart the route is a tombstone until the exact surviving plugin rebinds. Native tools loading in OpenCode Desktop is not sufficient evidence of support: the desktop sidecar failed to initialize the plugin-owned relay in the most recent acceptance attempt.
- The user binds the actual topic-context task that will participate. A setup or coordinator task must not pre-bind a participant intended for another task; exact-task capability isolation deliberately rejects that takeover. The authenticated old task may explicitly unbind (`council_unbind`) so a same-runtime, same-project replacement can recover queued work.
- The MCP child relay sends Claude the documented user-message JSON line and is authenticated by Claude's live-child process evidence. The broker queues Codex envelopes until that exact authenticated task polls.
- The broker never selects a recipient by recency or directory. Every send uses the exact bound participant ID.
- A live participant cannot be renewed or rebound without its prior capability. Capability rotation is retry-safe: the adapter retains a pending new/previous pair across an ambiguous response, and an identical already-applied capability returns idempotent success. Each dialogue persists every participant's runtime/project scope as an authorization tombstone. After termination, a differently scoped binding still cannot access old dialogue or outbox records. One exact task or session cannot hold two live participant identities, and all participants must share one project.
- Every participant operation—start, status, wait, submit, acknowledge, extension, cancellation, retry, and unbind—is authenticated at the broker against the initiating participant's capability. General health is aggregate-only and exposes no participant, project, task, relay, or route identifier.
- The router is configured offline as one Codex task. Bootstrap is accepted only over a Unix connection with a signed Codex runtime origin whose adapter-supplied task ID matches that configuration. A raw shell client or shell-launched copy cannot bootstrap; the malicious-sibling-MCP limitation above still applies. The MCP child retains an initial pending router capability until the broker accepts it; after an ambiguous response it reuses the identical value, which the broker recognizes as an idempotent already-applied bind. Every later rotation requires the prior capability. Only that capability may lease or acknowledge wakes. The router sees only opaque wake metadata: notification ID, message ID, participant, and exact target task ID. It never sees or claims an envelope. It sends only the fixed constant `COUNCIL_WAKE_V1` (or `COUNCIL_NEEDS_ATTENTION_V1` for a durable stall); the planning task obtains all actual content from the broker.

## Persistent state

The physical state root is `~/.claude/peer-consults/`. A Codex-side symlink may expose the same bytes at `~/.codex/peer-consults/`.

```text
peer-consults/
├── broker.sock              # live local IPC; absent after shutdown
├── broker.lock              # exclusive lifetime owner record; no credential
├── broker.log               # broker startup/runtime diagnostics; no credentials
├── router.json              # offline-configured exact router task + router capability hash
├── opencode-runtime.json    # approved OpenCode real path + SHA-256; no credential
├── registrations/*.json     # expiring restart-safe routes + binding capability hashes
├── dialogues/<dialogue-id>/
│   ├── manifest.json        # canonical protocol phase + private claim-ID salt
│   ├── audit.jsonl          # exact egress and state-transition audit
│   ├── submissions/*.json   # proposals, exchanges, synthesis, check
│   └── final.json           # synthesis plus representation check
└── outbox/<participant>/*.json
```

New manifests use dialogue schema v2 with an ordered participant list, one initiator, one or two non-initiators, immutable runtime/project scopes, explicit required submitter sets, and a random per-dialogue claim-ID salt. Existing v1 manifests remain readable and mint the salt lazily if their proposal barrier has not completed. Every participant status view strips the salt; triad status additionally strips peer names, scope records, alias maps, and submission paths. Files use mode `0600`; directories and relay roots use `0700`; live sockets use `0600`. Raw participant and relay capabilities remain memory-only. Codex routes continue across restart; Claude and OpenCode relay routes restore as takeover-blocking tombstones until the exact adapter rebinds.

## State machine

```text
collecting_proposals
  -> collecting_exchange(round 1..authorized_rounds)
  -> collecting_convergence_challenge
  -> collecting_synthesis
  -> collecting_representation_check
  -> [triad material correction: collecting_synthesis_revision
      -> collecting_revision_check]
  -> complete + identical dialogue_complete notice to every participant
```

`cancelled` is terminal from every active phase. Cancellation (`council_cancel`) uses the same committed staged-outbox transaction as other phase transitions and records every live proposal, exchange, challenge, synthesis, or review request for that dialogue as a superseded transition input. The transition supersedes those requests before activating terminal notices, so no later wait, relay retry, or wake can surface stale work. If failure occurs after the cancelled manifest commits but before supersedes or peer notification activation, an identical cancellation retry finishes both idempotently without requiring broker restart.

The broker reveals no proposal until every participant submits. Every exchange round is a strict barrier. Every submission is capped at 16 KiB so worst-case triad exchange and synthesis fan-outs remain below the 256 KiB transport ceiling; the final proposal also preflights every derived exchange request before it becomes immutable. A rejected proposal is not persisted and may be shortened and resubmitted. Proposal claims appear only in the canonical ledger, not duplicated inside public proposal positions. Canonical claim IDs are HMAC-derived from the participant/local ID with a random per-dialogue salt that is never exported, preventing dictionary recovery of participant names and cross-dialogue correlation. Public claims use one persisted randomized order independent of membership and expose only recipient-relative `origin_is_self`; later exchange requests additionally expose that recipient's private prior claim-position map. Requests carry `peer_positions` and all public position collections, including synthesis-revision representation checks, sorted by randomized round alias rather than canonical membership or submission-arrival order; two-party synthesis compatibility fields are selected by canonical role before sorting. A material convergence challenge that reopens exchange carries bounded anonymized challenge artifacts and the union of reopened claim IDs, including when a user extension reopens synthesis. Retirement commits only after the mandatory challenge passes. Triad status and exchange do not disclose peer names or runtime scopes. Public position projections omit submission timestamps, which would otherwise be a stable cross-round correlator. Current-round author linkage is unavailable before that participant's submission is durable; v0.19.0 naturally satisfies the embargo because it sends only completed prior-phase or prior-round positions. Alias anonymization is best-effort bias reduction, not an identity guarantee: in a triad each participant can always eliminate its own alias, leaving a binary guess between its peers, and behavioral signals in the positions themselves may narrow that further.

Round policy is user-owned. `minimum_rounds` is the hard contention floor, `rounds` is the initially authorized exchange count, `max_rounds` is the ceiling for later user-authorized extensions, and `stop_on_convergence` controls early challenge eligibility after the floor. `Run exactly N rounds` maps all three counts to N. `At least N, up to M` maps the floor and initial count to N unless separately stated and the ceiling to M. `Permit/up to N rounds` maps the ceiling to N while preserving a separately stated count or the two-round floor/default. Five is only the default ceiling when the user is silent, not a policy cap. The broker accepts values through 100 and rejects larger values without substitution.

Each adapter records whether round-policy and active-ledger-ceiling arguments were `provided` or filled as an `adapter_default`. These labels prove argument presence only, not user provenance. Every participant compares user-stated values against the proposal request and refuses a mismatch. User silence permits the documented default; explicit values must be exact and source-labelled `provided`.

Every non-initiator independently checks synthesis. In a triad, an inaccurate check or material correction opens exactly one synthesis revision and one recheck by both non-initiators. Each recheck carries the alias-sorted original checks with recipient-relative self markers plus the reviewer-visible active claim ledger and IDs, so a same-scope replacement can recover its recorded corrections without identity disclosure. A second revision is unavailable; remaining corrections stay canonical. The terminal transition commits full `final.json`, the complete phase, the completion audit, and one identical staged `dialogue_complete` envelope per participant. The terminal envelope carries a bounded decision packet plus the canonical file's SHA-256, byte size, dialogue ID, and stable local reference instead of embedding the potentially large artifact. Each participant handles and acknowledges it; acknowledgement recomputes and verifies the canonical reference. Codex uses wait/wake routing; Claude and OpenCode use authenticated session relays.

Every nonterminal request envelope carries a broker-generated `payload.response_contract` with a contract version, exact submit kind and round, JSON payload schema, allowed enums, active claim IDs where relevant, and state-dependent rules. The contract is self-contained so a blank or filesystem-restricted session never needs to guess a submission shape. It is response metadata only, not peer content or authority. Participant-scoped status exposes payload-free barrier progress: required/responded/waiting counts, self-submission state, and last durable activity time.

Each blind proposal contributes 1–8 decision-material claims. Triad raw claims are capped at 24. `active_claim_ceiling` is source-labelled like round policy; silence permits `adapter_default=24`. Overflow is selected by equal round-robin participant allocation preserving originator order, parked visibly, and carried to synthesis. Every exchange assesses every active claim. A later unchanged position must use `concession_basis=unchanged`; a position change requires an evidence-qualified substantive basis. A claim retires immediately only when all participants mark it nonmaterial and name the same valid `duplicate_of` target, or when unanimous nonmaterial assessments contain evidence. Every duplicate target is protected from any retirement in that same batch, including independent evidence-backed nonmaterial retirement, so a retired duplicate never points at a removed target. Evidence-free unanimous nonmaterial requires confirmation in the next consecutive round; the broker then carries a confirmed marker forward through any extra rounds until the challenge commits or later assessments revoke it, so retirement never depends on odd/even round count. At least two active claims from at least two distinct participant origins remain so every participant can still name a peer-origin strongest opposing point. Retired claims and their assessments remain in `final.json`.

The broker does not accept a set of `material_delta:false` booleans as convergence. Early convergence is eligible only at or after `minimum_rounds`, when every participant nominates it, every active claim is assessed by all, positions agree claim-by-claim, no claim remains uncertain, and no structured disagreement survives. Reaching the authorized limit still proceeds to challenge.

Every path to synthesis passes through `collecting_convergence_challenge`. Every participant independently attacks the tentative plan. Any material defect reopens exchange while an authorized round remains; at the limit, synthesis must surface it. Every non-initiator then records decision quality and unresolved claim IDs.

The initiating runtime may apply a user-authorized extension during exchange or at the synthesis gate, up to `max_rounds`. Each extension call carries a memory-retained operation ID which is persisted with the updated round limit; retrying an ambiguous call returns the recorded result and cannot add the same rounds twice. An explicit unbind in the surviving adapter does not erase that ambiguous operation. OpenCode keys pending extension operations by participant plus dialogue, not session ID, so an authenticated same-scope move inside the surviving plugin retains the ID. Only an operation-level rejection that proves no commit clears the pending ID. Not-bound, expired-binding, and exact-session authorization rejections remain ambiguous because a prior response may have been lost; the adapter retains the ID through rebind. Transport loss, invalid response, internal failure, or same-adapter unbind/rebind likewise retains it for identical retry. Before committing a new extension transition, the broker reconciles the manifest's existing committed audit intent, supersedes, and staged outbox records; the new transition therefore cannot overwrite and orphan an earlier committed delivery. The broker supersedes any still-queued synthesis request when an extension reopens exchange. A peer extension request records a reason but changes no round limit. A committed user extension updates the persisted round policy's authorized count and marks its source as `user_extension`.

Extension requests are accepted only during `collecting_exchange` or `collecting_synthesis`. Each participant may record one request per phase and round; an identical retry returns the existing request and a conflicting second reason fails closed. Reasons are limited to 4 KiB, histories to 20 requests, and every manifest to 768 KiB before persistence, keeping participant-scoped status below the 1 MiB transport ceiling.

## Submission shapes

Proposal:

```json
{
  "recommendation": "...",
  "premises": [
    {"source": "user|verified|memory|inference", "claim": "..."}
  ],
  "material_claims": [
    {
      "claim_id": "local-stable-id",
      "claim": "...",
      "importance": "high|medium|low",
      "decision_consequence": "...",
      "evidence": [],
      "falsifier": "..."
    }
  ]
}
```

Adversarial exchange:

```json
{
  "recommendation": "...",
  "changed_position": [],
  "evidence": [],
  "claim_assessments": [
    {
      "claim_id": "claim-canonical-id",
      "position": "accept|reject|uncertain|nonmaterial",
      "concession_basis": "initial_assessment|unchanged|new_evidence|counterexample|corrected_fact|binding_constraint|superior_tradeoff",
      "concession_reason": "...",
      "evidence": [],
      "duplicate_of": "optional-canonical-claim-id"
    }
  ],
  "remaining_disagreements": [
    {
      "claim_id": "claim-canonical-id",
      "decision_consequence": "...",
      "confidence": 0.8,
      "falsifier": "...",
      "resolution_cost": "low|medium|high",
      "new_evidence": []
    }
  ],
  "strongest_opposing_point": {
    "claim_id": "claim-peer-id",
    "rationale": "...",
    "unresolved_risk": "..."
  },
  "falsifiable_tests": [],
  "material_delta": true,
  "convergence_candidate": false
}
```

Convergence challenge:

```json
{
  "strongest_failure_mode": "...",
  "counterexample": "...",
  "premortem": "...",
  "material_issue_found": false,
  "reopen_claim_ids": [],
  "evidence": [],
  "falsifiable_tests": []
}
```

Synthesis:

```json
{
  "executive_summary": "Concise user-facing decision packet (maximum 4,000 Unicode characters)",
  "recommendation": "...",
  "disagreements": [],
  "rejected_alternatives": [],
  "evidence_gaps": [],
  "user_decisions": []
}
```

Representation check:

```json
{
  "accurate": true,
  "corrections": [],
  "decision_quality": {
    "material_disputes_resolved": true,
    "unresolved_claim_ids": [],
    "hidden_assumptions": [],
    "confidence": 0.9
  }
}
```

## Delivery and recovery

Participant authorization and method dispatch execute under the same broker generation lock. An unbind/rebind cannot occur between capability validation and a mutation; `wait` additionally revalidates its captured generation after every condition wake.

Every envelope has a UUID message ID and exact round. Codex polling binds to the capability-authorized registration generation and immutable dialogue scope, revalidates the generation under the broker condition lock before every claim, claims an envelope for 120 seconds, and acknowledges it only after submitting the requested response with that round. Lease expiry, unbind, or rebind invalidates a sleeping old poll before it can claim replacement-session work. If a claimed task dies, claim expiry checks durable state: a safe recorded response is reconciled to acknowledgement, while an unanswered claim returns to pending and reuses the bounded router retry/needs-attention sequence. If either runtime durably submits a required response but loses the explicit acknowledgement, the next authenticated operation for that same participant and runtime/project scope—or broker restart—reconciles the matching `claimed`/`delivered` record to acknowledgement and audits the recovery. A delivered request with no durable response is re-armed on explicit same-scope rebind; an unchanged exact relay deduplicates it and a replacement exact session receives it once. Pending unseen work is never reconciled, and a later explicit acknowledgement is duplicate-safe. The broker itself rejects acknowledgement unless the message was claimed or session-delivered and the matching response is recorded, or the request is provably stale or terminal. Identical submissions for the same participant, kind, and round are idempotent even after the dialogue advances; stale rounds return a no-state-change result; conflicting second submissions fail closed.

Next-phase messages use a durable staged-outbox transaction. The broker writes submission artifacts and `staged` envelopes, commits the new manifest with a transition ID, and only then activates and delivers those envelopes. On restart, staged records matching the manifest's committed transition are activated; uncommitted staged records are marked aborted. Activated `pending` records are independently reconciled: their audit event is appended idempotently and delivery is retried, covering a crash after activation persistence but before audit or send. An identical submission retry also activates any committed staged transition, so recovery does not require a process restart. The same commit-point rule governs the terminal artifact: `final.json` is written before the completing manifest commits, so on restart a `final.json` under a non-terminal manifest is the uncommitted half of a crashed completion transition and is discarded exactly like an uncommitted staged record — resubmission rebuilds it, and `final.json` therefore exists exactly when a dialogue is complete.

The response-free `dialogue_complete` notice is not auto-acknowledged merely because `final.json` exists. A claimed Codex notice that expires before explicit acknowledgement returns to pending and reuses the bounded wake path. Explicit acknowledgement verifies that its carried digest reference and decision packet exactly match the broker's canonical `final.json`; legacy full-artifact notices remain acknowledgement-compatible. Duplicate acknowledgement is safe.

Canonical manifest mutations stage reconstructable audit intent before commit. Each intent has a durable audit ID; phase transitions use their transition ID, and multiple events such as `submission_received` plus `dialogue_completed` may share it. Acknowledgement-recovery audit identity contains only the stable message and participant; the caller-specific recovery reason remains on the outbox record, so restart and participant-operation recovery cannot conflict. Before every append or scan, the broker repairs only an incomplete final JSONL record: a complete record missing its newline is completed, a malformed unterminated fragment is truncated, and malformed internal records fail closed. After commit, the broker appends each event idempotently, verifies the exact event parses back, and clears the intent only after every event is present. Restart and authenticated retry reconcile remaining intent before advancing, so a crash between manifest persistence and audit append cannot omit or duplicate the transition record. A conflicting pre-existing event fails closed rather than satisfying the intent.

Claude and OpenCode delivery write an outbox record before contacting a session-specific authenticated relay. Each registration binds the relay PID and process generation; the broker verifies the connected Unix peer before sending either envelope content or the memory-only relay capability. Each relay then authenticates that capability, verifies the exact fixed envelope preamble (so the untrusted-planning-data framing cannot be replaced by anything holding the capability), validates schema, envelope kind, and exact recipient, deduplicates message IDs, and acknowledges only after posting to the exact parent session. A failed write remains pending and retries only when that participant's exact adapter rebinds. OpenCode binding cleanup is capability-generation-conditional, and plugin disposal times out idle sockets and destroys every accepted connection before awaiting server close.

Relay delivery is serialized with the broker's other operations: envelope posts to a session relay execute while the broker lock is held, so one slow or wedged relay delays unrelated broker operations until its bounded I/O timeouts fire. This is a known, accepted liveness (not correctness) limitation of the current single-broker design.

Codex/Claude MCP tool calls convert expected broker, validation, and local I/O failures into an error result carrying the original JSON-RPC request ID; the adapter loop never silently strands those calls. OpenCode custom tools reject a missing, empty, scalar, or array broker success as an internal transport failure instead of returning an ambiguous empty tool result. `council_submit` directs the model to the exact envelope response contract; broker validation errors enumerate closed-set values such as `concession_basis` rather than requiring schema guessing.

The broker, not the process-global OpenCode binding map, is authoritative for lease expiry and replacement-session admission. Definitive not-bound/expired responses prune stale local bindings. Explicit unbind retains both settled and in-flight delivery tombstones for a bounded window; a same-session rebind joins or deduplicates the prior post instead of emitting a duplicate model turn, while a confirmed move discards the old session's state.

For Codex delivery, `council_pending_wakes` leases an opaque wake notification without changing the envelope's pending/claimed state. Each wake or attention lease is bound to the current registration generation and exact target task; replacement immediately re-arms old-generation notification state, and a delayed old acknowledgement is rejected. The router sends the fixed marker to the exact bound task and records success with `council_wake_ack`. The planning task then claims the envelope through `council_wait`. A wake acknowledgement may mutate state only while its notification still owns the `leased` wake state; a late success or failure cannot downgrade a task-consumed, notified, needs-attention, acknowledged, or recovered record. A delivered but unclaimed wake is retried once after five minutes. If the second wake remains unclaimed, the broker commits the manifest attention entry and durable audit intent before flipping the outbox record to terminal `needs_attention`, so a partial failure remains retryable. Spurious or duplicate wakes safely poll to no message.

The context-isolated scheduled router runs at the user's chosen cadence (five minutes by default). This is still polling: outside eligible live leases it performs a broker no-op rather than waking a planning task. The user disables the recurring router when standing inbound wake is not wanted.

The broker's state files are canonical. A runtime must read its participant-scoped status after interruption instead of reconstructing the phase from conversation memory. Triad participant status is built from an explicit allow-list; internal audit intent, peer identities, route state, and future manifest fields are absent by default. `council_ping` exposes only aggregate binding and restore-error counts; a rejected or unavailable persisted route never causes target guessing.

## Security and cold-review firewall

- Peer traffic is plain planning text and cannot authorize tools, permissions, configuration changes, implementation, ownership transfer, PR mutation, production writes, or deployment.
- Bootstrap proves a live-CDHash-bound designated-requirement Codex/Claude origin or an offline path, digest, and code-directory-hash-pinned OpenCode origin, not cryptographic identity of adapter code, session metadata, or the selected model/provider. The boundary excludes malicious sibling MCP children or plugins inside an admitted runtime; post-bind operations still require memory-only capabilities.
- Wake traffic carries no planning text. A wake marker can trigger only a broker poll; any additional content in the wake turn is ignored. The authenticated broker envelope remains the sole source of council content.
- A conservative egress guard scans dictionary keys and values and rejects recognizable OpenAI/Anthropic, GitHub/GitLab, npm/PyPI/Hugging Face, Google OAuth/API, Stripe, Slack bot/user/app/refresh (`xox*`/`xapp`, including `xoxe`), Supabase secret/publishable/personal-access (`sb_*`/`sbp_`), SendGrid, JWT/private-key, and AKIA/ASIA AWS token families. OpenAI matching includes both classic single-segment `sk-` keys and elevated `sk-admin` keys. GitHub matching covers both classic opaque credentials and the long stateless `ghs_` installation-token JWT format with dots and additional underscores. The guard normalizes separators and camelCase, then blocks both bare sensitive names and service-prefixed suffixes such as `bot_token`, `oauth_token`, `signing_secret`, `webhook_secret`, `oauth_client_secret`, `google_access_token`, `slack_bot_token`, `stripeWebhookSecret`, passwords, and private/service-account keys before persisting or sending a payload. Full rendered envelopes have a separate 256 KiB transport ceiling, validated before they become canonical or deliverable.
- Full outgoing envelopes are recorded for audit, excluding session credentials.
- Restart-safe route files never contain raw Council capabilities, Claude messaging tokens, OpenCode server credentials, or direct inbox credentials. Persisted hashes, relay paths, exact task/session IDs, and the non-secret OpenCode executable digest are user-only and lease- or configuration-bounded.
- The CLI cannot perform participant operations or launch a production broker from an unauthenticated shell. It provides aggregate health, diagnostics, post-completion report rendering, offline exact-router configuration, and offline OpenCode executable pinning only; admitted runtime adapters own broker startup.
- The broker is local-only and exposes no TCP or HTTP listener.
- Unrelated or sensitive sessions are never implicit candidates. The user binds the planning session explicitly.
- A session that receives or sends council content is warm for that topic. Council output never satisfies a cold, independent code review, even when two vendors agree.
