# Example decision packet: v0.20 verification depth

This is the rendered decision packet of a **genuinely run** council dialogue —
not a staged transcript. Three sessions (Claude Code, Codex, OpenCode CLI)
deliberated a real, open engineering question for this project: how deep
v0.20's verification investment should go. The maintainer ran it specifically
for publication; the topic, premises, and every submission are real, and the
outcome feeds actual v0.20 planning.

## Provenance

| | |
|---|---|
| Dialogue | `dlg-3db54d4ebf8b4bb8b4afad03e6c02a56` |
| Completed | 2026-08-24T23:36:34+00:00 |
| Broker | v0.18.7 (the published release) |
| Participants | `claude-example` (initiator), `codex-example`, `opencode-example` |
| Rounds | 3 adversarial exchange rounds (minimum 2, ceiling 4), then the mandatory convergence challenge, synthesis, representation checks, and one challenge-forced synthesis revision |
| Canonical artifact | [`final.json`](final.json) — committed **unmodified** |
| Integrity | `shasum -a 256 -c final.json.sha256` (CI re-verifies this on every push) |

## The question

Choose v0.20's verification investment: **Option A**, a full property-based
state-machine harness over the broker's recovery invariants (highest
defect-finding power, unestimated effort, possible new dependency), versus
**Option B**, an expanded deterministic crash-injection matrix (bounded and
predictable, but only covers sequences a human enumerates) — under a
single-maintainer budget with CI determinism non-negotiable.

## What was decided

The council's canonical executive summary, verbatim from `final.json`:

> DECISION: v0.20 verification depth for the cross-runtime-council broker. All three participants converged on a staged hybrid anchored on Option B, then the mandatory convergence challenge produced two material revisions and one verified confirmation that are folded in below.
>
> PLAN (challenge-revised): Stage 1 (2-4 focused days): extract the documented recovery invariants as reusable checkers scoped strictly to durable broker artifacts; add test-only named failpoints at the persistence seams (~150-line invasiveness cap, test-local wrapper fallback); emit an invariant coverage map assigning every documented invariant to either the artifact oracle or a named relay-level/live-matrix observation - exactly-once EXTERNAL relay delivery is asserted only via the live matrix, never from broker artifacts (unanimously rejected claim, confirmed by code inspection: relay dedup state is memory-only in opencode_delivery_registry.ts). Stage 2: a one-day recovery-window inventory booked as its own line item (including an injectable-time-source check for lease/wake windows), then a ~24-36-row deterministic crash matrix over six structural transaction classes, release-gated on killing the mutant corpus - mutants implemented as inverted failpoint behaviors (priced <=1 day), with at least one held-out mutant not known to the checker author. Stage 3 (max 2 days, after the core): a state-aware seeded stdlib sequencer whose admission gate was REVISED by challenge: the generated distribution must include >=25% protocol-meaningful adversarial operations (identical resubmission, stale-round submission, duplicate ack, conflicting submission, re-poll after expiry) - not merely >=80% valid operations, which would steer generation away from the broker's core recovery surface - plus a replayable trace and >=1 kill of a compound mutant the matrix cannot express; if the adversarial-mix gate cannot be implemented within the 2-day box, stage 3 is deferred without delaying v0.20; zero yield likewise drops it without prejudice. Full Option A (property-based model, possible dependency) is deferred to a v0.21 go/no-go gated on pure-core extraction or a 2-day spike meeting three entry criteria, decided on recorded mutant-corpus evidence.
>
> MATERIAL CHALLENGE FINDINGS SURFACED AT THE ROUND LIMIT: (1) Gate miscalibration - a validity-only sequencer gate under-samples the adversarial operations protocol.md's recovery semantics exist to handle, so a quiet sequencer could be dropped on evidence measuring the wrong distribution; revision above. (2) Cap-arithmetic contradiction - stage upper bounds (2-4 + 5-8 days) exceed the 8-day core cap, and the plan cannot simultaneously treat the cap as a deadline and the coverage claim as complete; the maintainer must pre-commit a rule: if the post-inventory 80th-percentile estimate exceeds 8 days, either extend the budget or explicitly narrow the assurance claim (deferred rows listed, never silently dropped). (3) Assurance substitution risk - reassigning delivery-once to the live matrix is only safe if the live-matrix run becomes a blocking release-checklist row; otherwise the one tier verifying the relay boundary goes silently dark.
>
> SURVIVING DISAGREEMENTS: whether the seeded sequencer captures most of full Option A's marginal value (one reject at 0.9, two uncertain; resolved empirically by the shared mutant-corpus comparison); whether the matrix expansion fits 3-5 vs 5-8 focused days (all uncertain; resolved by the one-day inventory); whether compound-sequence coverage is a v0.20 necessity or a measured experiment (split accept/uncertain; practically resolved by the admission gate). None warrants a fourth round - each resolves only through scheduled work, not deliberation.
>
> DECISION AUTHORITY: the maintainer ratifies the revised gate, the cap rule, the inventory's budget position, and the live-matrix checklist change.

## What to notice

- **Blind proposals.** Each participant committed a position before seeing the
  others'; the ledger in `final.json` tracks every claim from proposal to
  final position with an auditable concession basis for every change.
- **The challenge did real work.** After apparent convergence, the mandatory
  adversarial challenge produced two *material* revisions (a miscalibrated
  acceptance gate and a budget-arithmetic contradiction) and one
  code-inspection-verified confirmation. Agreement was not allowed to stand
  untested.
- **Disagreement survived, usefully.** Three disputes remain in the packet —
  each with named positions, confidence levels, and a concrete empirical
  resolution path. The protocol optimizes for decision-relevant error
  reduction, not consensus.
- **The human decides.** The packet ends by assigning every ratification to
  the maintainer. Council output is planning input, never authority.

## Try it yourself

The shortest live path is a two-session, single-runtime council — see the
[quick start](../../README.md#quick-start).
