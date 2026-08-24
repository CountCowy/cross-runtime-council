# Roadmap

Planned directions, in rough priority order. No dates are promised — this is
a best-effort, single-maintainer project (see README "Support"). Items here
exist so known gaps are visible, not to imply commitments.

## Privacy lifecycle

Dialogue material (manifests, submissions, finals, audit logs) persists under
`~/.claude/peer-consults` and is currently removed only by
`uninstall.sh --purge-state`, which deletes everything. Planned: first-class
per-dialogue deletion, optional retention limits, and an export/redaction
path, with the same audit discipline as the rest of the broker.

## Verification depth

- Clean-room rehearsal of the Codex and Claude registration steps (the
  OpenCode path is rehearsed; the Codex/Claude steps in `docs/install.md`
  are verified against a working installation only).
- CI additions: Python static analysis, type-checking for the OpenCode
  plugin/tools TypeScript, and property-based state-machine and
  crash-sequence tests for the broker's recovery paths.

## Implementation consolidation

The protocol's shapes are currently expressed in several places (broker
validators, response contracts, MCP schemas, TypeScript, skill text, prose
reference). Planned: a single schema source of truth generating the other
representations, and extraction of the pure protocol/state-machine core from
persistence and transport code. This is a large, review-heavy change and will
be staged carefully rather than rushed.

## Release mechanics

Semantic versioning with signed tags from the next release onward; the
initial public release is tagged `v0.18.7`.
