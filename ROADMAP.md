# Roadmap

Planned directions, in rough priority order. No dates are promised — this is
a best-effort, single-maintainer project (see README "Support"). Items here
exist so known gaps are visible, not to imply commitments.

## Privacy lifecycle

Dialogue material (manifests, submissions, finals, audit logs) persists under
`~/.claude/peer-consults`. Per-dialogue deletion of terminal dialogues landed
in v0.19 development (the `delete` subcommand — tombstoned, idempotent,
crash-tested), as did optional retention (`configure-retention`, applied at
broker startup through the same primitive); see `docs/install.md`.
`uninstall.sh --purge-state` still deletes everything. An offline HTML
export of a completed dialogue's decision packet landed in v0.20 development
(the `render` subcommand — deterministic, script-free, digest-labeled with an
explicit three-state verification contract; see `docs/install.md`). Planned
next: a redaction path, with the same audit discipline as the rest of the
broker. Deferred by the 2026-08-25 adoption council, in order: outcome
tracking (a user-authored, append-only sidecar keyed to dialogue id plus
final digest — targeted after the verification work), then revisit
(side-by-side comparison of two decision packets, built on the renderer).

## Verification depth

- Clean-room rehearsal of the Codex and Claude registration steps (the
  OpenCode path is rehearsed; the Codex/Claude steps in `docs/install.md`
  are verified against a working installation only).
- CI additions: Python static analysis (ruff), strict TypeScript
  type-checking of the plugin/tools, and cross-representation parity tests
  landed in v0.19 development, as did the targeted deletion-and-recovery
  crash harness (release-blocking, runs in CI). In progress for v0.20: the
  staged verification plan decided in the
  [committed example packet](examples/v020-verification-depth/decision-packet.md)
  — durable-artifact invariant checkers (landed: see the
  [invariant coverage map](docs/verification-map.md); the oracles run in CI
  and inside the crash harness after every injected crash) with test-only
  failpoints, then an
  expanded deterministic crash matrix release-gated on killing a mutant
  corpus, then an optional seeded adversarial sequencer; full property-based
  modeling is deferred to a v0.21 go/no-go decided on recorded mutant-corpus
  evidence. Still planned: a dedicated review of extension semantics after a
  convergence candidate (a parked v0.18 finding whose exact defect needs
  re-derivation before any fix).

## Implementation consolidation

The protocol's shapes are currently expressed in several places (broker
validators, response contracts, MCP schemas, TypeScript, skill text, prose
reference). Planned: a single schema source of truth generating the other
representations, and extraction of the pure protocol/state-machine core from
persistence and transport code. This is a large, review-heavy change and will
be staged carefully rather than rushed.

## Release mechanics

Semantic versioning with cryptographically signed tags from `v0.19.0`
onward; the initial public release tag `v0.18.7` is annotated but unsigned.
