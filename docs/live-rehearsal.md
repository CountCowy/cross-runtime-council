# Live recovery rehearsal contract

Contract: `council-live-rehearsal/v1`. This is the specification for a recorded
rehearsal, not evidence that one ran. The maintainer completes the
[run-record template](../examples/live-rehearsal/run-record.template.json)
against the exact tested artifact set. An assisted runner and validated capture
adapters are subsequent work; this document launches no runtime or intervention.

The [verification map](verification-map.md#live-matrix-observations-blocking-release-checklist-rows)
assigns observations to G1–G5. CI, artifact oracles, and participant
[eval definitions](../evals/evals.json) support preparation but cannot establish
receipt or handling inside a live receiving runtime.

## Claim and verdict rules

The maintainer declares the participating runtimes, transports, cases, targets,
expected counts and observation windows before the run. Every result is limited
to that tuple and window. A successful smoke run supports its stated smoke claim;
it does not qualify recovery, installation, rollback, or an untested runtime.

| Result | Meaning |
|---|---|
| `pass` | All applicable preconditions, required observations and controls are evidenced for the declared case. Any completeness requirement is satisfied. |
| `fail` | Evidence establishes behavior contradicting the declared expectation. A verified duplicate remains a failure even if another source is missing. With established preconditions and a functioning, complete observer, missing the declared recovery deadline is a failure. |
| `unobserved` | Evidence cannot decide the claim: missing provenance, incomplete capture, unvalidated observer, failed harness, unavailable required observation, or a truncated window. A timeout alone does not identify whether the runtime or observer failed. |
| `skipped` | The maintainer deliberately did not attempt the case and records why, including whether it was applicable. It supplies no passing evidence. |

Each gate takes `fail` if any of its required cases fails; otherwise it takes
`unobserved` if a required case is missing or unobserved, then `skipped` if a
required case was skipped, otherwise `pass`. The same precedence applies across
required gates. Optional exploratory cases remain visible and outside that
aggregation; the maintainer may not relabel a required case optional after seeing
its result. Changing the declared plan creates a separately identified attempt.
A qualifying run has a nonempty required-case inventory and at least one
applicable executed case per passing gate; empty arrays cannot establish a pass.

A full five-gate recovery claim requires all five gates to pass. For a topology
without Codex, G1 is inapplicable and recorded as skipped; the maintainer may
report the remaining passing gates individually, explicitly excluding Codex wake
recovery. No required failure, skipped gate or unobserved gate qualifies the full
matrix. Previously recorded compatibility observations remain historical and are
not retroactively certified under this contract.

## Actors, isolation and preflight

The user provisions a dedicated macOS account for disruptive rehearsals and
approves its systems, interventions and retention choices. The maintainer records
that authorization, operates the run, assesses evidence and performs cleanup.
Each participant handles its own envelopes through its ordinary authenticated
adapter. The observer records events without becoming an extra participant.

The maintainer records these preconditions before an intervention:

1. The exact source commit/tree, clean-or-dirty status, release-manifest SHA-256,
   package ID, runtime cohort and per-component artifacts. A dirty source requires
   an immutable captured diff and final artifact hashes; a commit alone is then
   insufficient. A source change during a run starts a new attempt.
2. macOS version/build/architecture; Python version and relevant configuration;
   each participating host's version/build, transport and SDK version where
   applicable; the OpenCode executable/pin identity when used. The private roster
   maps stable redacted seat labels to exact participant/session identifiers.
3. Installed-file/cohort compatibility, loaded component identity observations,
   readiness of each exact authenticated seat, and aggregate restoration health,
   recorded separately with their evidence sources. Unknown observations remain
   unknown. On-disk hashes or a successful broker ping cannot prove every host is
   running those bytes or every seat is ready.
4. The dedicated account and admitted host inventory, with evidence that test
   hosts, sockets, registrations, state and captures belong to that account.
   An environment-only state-root override does not isolate all runtimes; current
   adapters include fixed home-directory paths. The maintainer does not perform
   disruptive recovery tests on the production account or its state root.
5. A private roster and test dialogue with no real secrets or unrelated content;
   the permitted broker/host generations and interventions; declared deadlines,
   configured timers, and required observation sources and controls.

A production-account smoke run permits ordinary authorized operations only and
must be labeled `smoke`, with recovery gates unobserved or skipped as appropriate.
Account isolation is not a claim about independent backend accounts or services;
the maintainer inventories shared services and excludes disruptive effects there.
Unknown identity, unavailable required hosts, missing isolation, or an unvalidated
intervention boundary prevents the disruptive case from proceeding.

## Windows and event identity

Every case records UTC start, intervention, recovery and end times, its deadline,
and any quiet-period end. Capture starts before the first relevant event and
continues through the final declared retry/recovery opportunity. The maintainer
records actual claim, binding and notification leases, retry delay/attempt cap,
router cadence and delivery allowance from the tested configuration. The
[window inventory](verification-map.md#recovery-window-inventory-stage-2-step-1)
is a starting reference, not a substitute for those recorded values.

For an absence or deduplication claim, the window must cover the retry eligibility
boundary and its scheduling/delivery opportunity. A fixed sleep, one router tick,
or the configured retry delay alone is insufficient. A lease expiring, a host
closing, or a capture rotating must be accounted for; an unexplained interruption
makes the relevant absence claim unobserved. Finite observation does not establish
absence beyond the recorded window.

The private identity tuple includes dialogue, envelope/message, recipient seat,
exact receiving session, relay/plugin generation and broker generations as relevant.
A process identifier alone is insufficient generation evidence; use PID plus
trustworthy process-start identity and the supported runtime/broker evidence.
A new source version is not proof that the broker restarted.

Each evidence item has an opaque reference, SHA-256, byte count, collection time
and classification. The private evidence index holds the actual location, source
identity and any transformation. Hashes bind bytes; they do not establish the
truth, completeness or independence of the observation.

## G1 — wake an idle Codex target

**Preconditions:** The maintainer records the configured router, exact idle Codex
seat/session, live binding generation, pending unanswered envelope and starting
wake state. The target remains idle until the ordinary router wake; manual user
steering cannot stand in for it.

**Observation:** The observer correlates the router's leased notification and
send result with the fixed wake marker received by that exact task, then with its
own adapter's successful claim of the intended envelope. Record cadence and the
notification/claim timeline. Router send success alone does not satisfy G1.

**Pass:** All three links identify the declared target and envelope within the
window. The participant claims its work without manual substitution.

**Controls:** The observer must reject evidence from a different task or envelope.
An unrelated/duplicate wake with no matching pending work must not manufacture a
claim. Controls identify whether they exercise captured observer inputs or live
behavior in the isolated account; only the latter claims native behavior.

## G2 — recover a pending barrier after broker restart

**Preconditions:** The maintainer records a partially satisfied proposal/exchange
barrier: dialogue, phase, required roster, accepted durable responses and the
missing participant. Hosts/relays intended to survive the broker interruption
remain available; any necessary authenticated rebind is explicitly recorded.

**Observation:** Capture the admitted old and new broker generations and the
same recovered barrier. It must stay pending while a required response is absent.
After the missing participant submits through its ordinary transport, observe the
expected durable transition and the ensuing participant-facing request. Account
for existing restoration errors instead of hiding them in a readiness boolean.

**Pass:** Recovery retains accepted work and the original required roster, waits
for the missing response and advances once when the barrier is satisfied.

**Controls:** Withhold the last required response and establish that no advance
or premature disclosure occurs. The observer rejects unchanged-generation and
wrong-dialogue evidence. An unavailable seat cannot silently reduce quorum.

## G3 — establish the external arrival count

The maintainer declares the target envelope and expected receiving-session count
in advance. A receiving-runtime arrival is an event actually accepted into that
session. Broker `delivered`/outbox state, a relay attempt, or text visible in a
rendered transcript is not by itself such an event.

Two cases distinguish the guarantees in the [protocol](../references/protocol.md):

- **Surviving relay, same session:** Capture the initial external arrival and a
  durably delivered, unanswered envelope. Interrupt only the broker while the
  relay/plugin generation and its deduplication state survive. Observe a recovery
  delivery attempt of the same envelope and establish that the target session's
  total arrival count remains one across the declared window.
- **Replacement session:** Record the supported expiry/rebind route and the new
  receiving session/generation explicitly. Establish that this replacement
  session's count changes from zero to one for the recovered envelope. Any
  arrival in the original session is reported separately. This does not claim
  global exactly-once delivery across erased relay memory or session replacement.

The maintainer must run every case needed by the advertised recovery claim and
record each receiving runtime separately. A successful surviving-relay case does
not prove replacement-session behavior, or conversely.

**Pass:** Actual arrival counts satisfy the declared case, the observer has the
complete-source qualification below, and delivery-attempt evidence establishes
that recovery exercised the relevant deduplication/delivery path. No attempted
redelivery is not evidence that redelivery would be deduplicated.

**Controls:** A fresh control envelope proves that the receiving path is working.
A capture containing two genuine arrivals must count both and fail an expected-one
case, even when they carry the same envelope ID. Omission controls must withdraw
completeness qualification. A single visible occurrence without complete coverage
is unobserved; a verified additional arrival is a failure.

### Complete-source qualification

The evidence collector must reference a versioned adapter contract and its
validation artifact for the exact receiving-runtime version and source format.
That contract must establish all of the following:

1. An inventory of every relevant source, including primary streams, sibling
   branches, sidechains, queued arrivals, rotated files/databases and paginated
   responses. Record enumeration boundaries, all pages/cursors and exhaustion.
2. Coverage of the entire declared interval, with source rotation, restart and
   concurrent writes accounted for. Parent links, first/last markers, timestamps,
   or pagination tokens alone cannot prove that interior or sibling data is absent.
3. An event definition separating genuine arrivals from quoted messages, UI
   repeats, tool-result projections and local send retries. Different projections
   of one native event may share its stable native event ID; two genuine arrivals
   may not be collapsed merely because their envelope ID or text matches.
4. Exact target/session binding, byte-level capture references and all filtering,
   normalization, joining or omission steps. Unexplained gaps defeat completeness.
5. Validation against real captures, with controls that remove an interior event,
   sibling/sidechain source, queued form, page and rotated segment wherever those
   forms apply. Each incomplete capture must fail completeness qualification;
   inapplicable forms need version-specific evidence, not an empty checklist.

Claude and OpenCode collectors remain candidates until these validations exist.
Unsupported Codex transcript-completeness claims remain unobserved. A checksum,
JSONL parse, visible message count or synthetic fixture alone does not validate a
whole receiving-runtime source. A verified duplicate is never erased by an
incomplete-source classification elsewhere.

## G4 — reconcile a durable response after lost acknowledgement

**Preconditions:** The maintainer records an already claimed/session-delivered
request and its exact durable logical response, while handling acknowledgement is
absent. Evidence must establish the interruption at that boundary; an ordinary
successful submission does not exercise G4. If the submission RPC reply itself
is lost, identify that boundary separately from the later handling acknowledgement.

**Observation:** Correlate the live submit attempt, durable response identity,
before/after outbox state, reconciliation and any retry. Exercise authenticated
operation recovery and broker-restart recovery as separately identified cases.
A later explicit acknowledgement must remain duplicate-safe, without another
logical response or another forward transition.

**Pass:** The original durable response survives and is reconciled once through
the declared live recovery path, without requiring the participant to author a
second logical response. Transient response formatting is not the identity key.

**Controls:** A matching delivered request with no durable response stays
recoverable; an unseen pending request cannot be falsely reconciled. The observer
rejects a mismatched response identity or an additional logical response. Count
raw retry attempts separately from accepted logical responses.

## G5 — every seat handles the same canonical completion

**Preconditions:** The maintainer freezes the required roster and independently
records the completed dialogue's canonical `final.json` SHA-256 and size. Any
interrupted terminal activation has its own evidenced boundary and recovery case.

**Observation:** Every declared seat receives the ordinary-transport completion
notice, resolves the referenced final artifact, checks its digest/size and handles
the packet before acknowledging. Record the per-seat receipt, verification,
handling and acknowledgement. A final file or broker outbox alone cannot witness
what participants actually handled.

**Pass:** All required seats handle the same canonical digest and size within
the window, and subsequent acknowledgements refer to those handled notices.

**Controls:** Wrong-digest and omitted-seat evidence cannot qualify the result.
A completion receipt before handling is not a handling acknowledgement. These
are observer/participant-contract controls; the broker's acknowledgement RPC is
not claimed to cryptographically attest that the participant read the document.

## Record, privacy and retention

The template is editable scaffolding, not a JSON Schema or a validator. The
maintainer sets `record_kind` to `run` only for an actual attempt, assigns a unique
run ID, and completes the following fields without importing historical results:

- `tested_tuple` records immutable code/artifact identities and their observation
  sources; OS/Python/host builds and transports; redacted seats and private roster
  reference. Unknowns are `null` with a corresponding limitation.
- `preflight` separates installed compatibility, loaded identities, exact-seat
  readiness, and aggregate restoration health. `isolation` and `authorization`
  identify the operator's scope and the user's approved account/interventions.
- `declared_plan` names required gate/case/recipient combinations and their expected
  counts, windows, timers and control plan before execution.
- Each `gates` entry has one result and one or more `cases`. Each case records its
  identifier, actor, required/applicable flags, targets, precondition evidence,
  window, interventions/recovery, expected/observed behavior, evidence references,
  observer/completeness qualification, controls, result and rationale. Split cases
  when recipient, generation, expected count or recovery path changes.
- `evidence` is the redacted inventory; `private_evidence_index_ref` joins it to
  actual locations and identity mappings kept outside the repository. `retention`
  and `cleanup` keep export/deletion ownership and outcomes explicit.

Within a run, case IDs and evidence references are unique. Each
`declared_plan.required_cases` item names a gate ID, case ID and target seat refs;
its matching case must exist. Each `interventions` item records `actor_ref`,
`action`, `at_utc`, `boundary_ref` and `evidence_refs`. Each `controls` item records
`control_id`, `actor_ref`, `kind` (`observer_fixture` or `isolated_live`), `expected`,
`observed`, `result` and `evidence_refs`. A control passes only when it demonstrates
the expected detection or rejection; an unrun control cannot support a passing
gate. Count expectations specify the unit and receiving session/generation.

All non-null hashes are SHA-256 of the referenced bytes, sizes are nonnegative
byte counts, and times are absolute UTC instants. Evidence classifications are
`redacted_record` or `private_capture`; the published inventory contains references
and metadata only. Completed run records remove the scaffolding-only
`case_template` and `evidence_item_template` keys. The maintainer verifies these
record constraints manually until a later runner implements validation.

The maintainer creates private evidence directories with `0700` and files with
`0600`. Transcripts, renders, exact-session mappings and other content-bearing
captures stay outside the repository. Exclude credentials, raw capabilities,
raw host configuration/native-get output and unrelated conversation content from
both evidence bundles; collect allowlisted observations instead. Review a
redacted copy before publishing it; an opaque reference must not encode a private
path or session identifier. Public code/version identifiers can remain explicit.

The user chooses retention deadlines and the maintainer records the responsible
actor separately for the redacted record and private captures. No default TTL or
automatic deletion is implied. The maintainer exports intended evidence, verifies
its hashes and references, and records that verification before deleting the test
dialogue. Detached transcripts/renders survive broker dialogue deletion and need
their own recorded cleanup. Preserve evidence needed to explain failures until
its authorized retention deadline or an explicit superseding user decision.

## Release checklist

The maintainer checks that the declared required cases ran on the recorded tuple,
G3 collectors have real-capture qualification, all evidence references resolve,
and controls support the asserted observations. Every required gate must pass for
a full-matrix claim. The maintainer publishes the redacted scope, results and
limitations with the release's compatibility record; missing gates stay visible.

The implementing owner must separately complete lifecycle recovery and
registration prerequisites before activating a managed updater. Passing these
live recovery gates does not supply predecessor-reader, installation transaction,
rollback, or configuration-write evidence. The master maintenance plan remains
in progress after this specification is committed.
