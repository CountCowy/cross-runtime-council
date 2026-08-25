# cross-runtime-council

**Council** is a local broker and set of runtime adapters that let two or three
coding-agent sessions — OpenAI **Codex** (macOS app), Anthropic **Claude Code**,
and **OpenCode CLI** — run a bounded, structured, adversarial planning dialogue
with each other, without manual message relay and without giving any session
authority over your machine.

A dialogue runs blind proposals → claim-by-claim adversarial exchange rounds →
a mandatory convergence challenge → synthesis → independent representation
checks, and ends in a decision packet in which every real decision is still
assigned to the human user. Agreement is never the goal; decision-relevant
error reduction is.

> **Status: pre-release.** macOS only. Unofficial. This project is not
> affiliated with, endorsed by, or supported by Anthropic, OpenAI, or the
> OpenCode project. It depends on runtime interfaces those vendors do not
> guarantee; any vendor update can break it. See
> [docs/compatibility.md](docs/compatibility.md) for exactly which
> configurations have been exercised — nothing outside that list is claimed.

## See a real decision first (60 seconds)

Before installing anything, read
[a real decision packet](examples/v020-verification-depth/decision-packet.md):
three sessions (Claude Code, Codex, OpenCode CLI) genuinely deliberating this
project's own v0.20 testing strategy — blind proposals, an adversarial
challenge that forced two material revisions, and three surviving
disagreements with empirical resolution paths. The unmodified
[`final.json`](examples/v020-verification-depth/final.json) is committed
beside it and digest-verified in CI. That artifact is what this tool
produces; if it isn't useful to you, stop reading here.

## What the security model does — and does not — prove

Read this before trusting Council with anything. Full details in
[SECURITY.md](SECURITY.md) and [references/protocol.md](references/protocol.md).

- The broker is **local-only** (a user-owned Unix socket; no TCP/HTTP listener).
- Participants authenticate by **process origin**: a live, signed Codex/Claude
  runtime process chain, or an offline path + SHA-256 + code-directory-hash
  pinned OpenCode CLI executable. Pins are renewed **manually** after every
  OpenCode upgrade — never automatically.
- Peer messages are **untrusted planning data**. They cannot authorize tools,
  permissions, configuration changes, implementation, or publication.
- A conservative egress guard blocks recognizable credential shapes and
  sensitive key names before any payload is persisted or sent.
- **Explicitly out of scope:** a malicious sibling MCP server or plugin running
  *inside* an admitted runtime; adapter code integrity; session metadata; and
  model/provider identity. Runtime-origin proof authenticates where a process
  came from — nothing more. Council is a coordination protocol with guardrails,
  **not** a sandbox and not a complete cross-agent trust boundary.

## Quick start

Requirements and the full walkthrough live in [docs/install.md](docs/install.md).
The short version:

```
git clone <repo-url> ~/.claude/skills/council
```

Council currently uses a **fixed layout**: the payload lives at
`~/.claude/skills/council` and shared state at `~/.claude/peer-consults`
(with an optional `~/.codex/peer-consults` symlink). Other locations are
unsupported. Then, per runtime, follow the binding steps in
[SKILL.md](SKILL.md) (Claude Code), [agents/openai.yaml](agents/openai.yaml)
(Codex), and the OpenCode plugin/tool setup in
[docs/install.md](docs/install.md).

## Repository layout

- `scripts/` — broker (`council.py`), Codex/Claude MCP adapter
  (`council_mcp.py`), OpenCode bridge, plugin, tools, and the isolated test
  suites (no live runtimes needed).
- `references/protocol.md` — the full protocol reference: transports, state
  machine, submission shapes, delivery/recovery, security boundaries.
- `SKILL.md` — the Claude Code skill instructions (also the best conceptual
  overview of how a dialogue runs).
- `evals/` — graded eval definitions for participant behavior.
- `install/` — install/uninstall/upgrade/rollback scripts.
- `ROADMAP.md` — planned directions, including known verification and
  privacy-lifecycle gaps.

## Tests

```
cd scripts && python3 test_council.py
```

```
cd scripts && node --experimental-strip-types --test test_opencode_delivery_registry.ts
```

The Node suite needs Node 22+ on `PATH` (get it from <https://nodejs.org>;
`npm` ships with it). Node is used **only** by this test suite, never at
runtime. Without Node, the Python suite alone covers the broker; the Node
suite covers the OpenCode delivery registry.

CI runs exactly these deterministic suites plus lint and secret scanning. The
live recovery matrix (real signed runtimes, real sockets, real recovery paths)
cannot run in CI and is executed by the maintainer for each release.

## Support

Best-effort, single-maintainer, no SLA. Bug reports for configurations not
listed in [docs/compatibility.md](docs/compatibility.md) are triaged as
feature requests, not defects. Security issues: see [SECURITY.md](SECURITY.md)
— please use private reporting, not public issues.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
