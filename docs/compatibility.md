# Compatibility

This table is **tested-set disclosure, not a supported-range promise**. A row
appears here only when a recorded rehearsal artifact exists for it. Anything
not listed is **untested** — it may work, but failures on untested
configurations are triaged as feature requests, not defects, and fail-closed
authentication errors on them are expected behavior.

## Platform

| Component | Requirement | Status |
|---|---|---|
| Operating system | macOS only. Trust anchors use macOS code-signing evidence, process chains, and CDHash checks. | Full install/upgrade/rollback/uninstall lifecycle rehearsed clean-room on macOS 26.5.2 (Apple silicon), Standard (non-admin) account, from the public docs alone. |
| Python | 3.9+ (broker, bridges, tests; stdlib only) | Clean-room rehearsal on 3.9.6 (macOS system Python): full suite green, install preflights verified at and below the minimum. |
| Node | 22+ with `--experimental-strip-types` (Node test suite only; not needed at runtime) | Node suite green in CI on Node 22 (macOS runner). The rehearsal host had no Node: the full runtime lifecycle was verified without it. |
| Linux / Windows / WSL | Not supported. The authentication model is macOS-specific by design. | Out of scope. |

## Runtimes

| Runtime | Transport | Status |
|---|---|---|
| Codex (macOS app) | Session-authenticated MCP adapter (`council_mcp.py`) | **Live dialogue untested pending the maintainer-run recovery matrix.** |
| Claude Code | Session-authenticated MCP adapter + live child relay | **Live dialogue untested pending the maintainer-run recovery matrix.** |
| OpenCode CLI | Native custom tools + plugin-owned relay + offline executable pin | Setup rehearsed clean-room on OpenCode CLI 1.18.21: registration from docs alone, SDK auto-resolution (no npm needed), pin recorded (real path + SHA-256 + CDHash), post-pin restart with all eleven `council_*` tools registered. **Live dialogue untested pending the maintainer-run recovery matrix.** Pin must be manually renewed after every OpenCode upgrade; restart OpenCode after re-pinning. |
| OpenCode Desktop | — | **Unsupported.** The desktop sidecar did not initialize the plugin-owned relay in the most recent live acceptance attempt. Native tools loading there is not evidence of support. |

## Minimal viable configurations

A dialogue needs **two or three participants**. Participants are *sessions*,
not machines: two sessions of the same runtime on one machine is a valid
minimal setup. You do not need all three runtimes installed.

## Filesystem layout (fixed)

| Path | Purpose |
|---|---|
| `~/.claude/skills/council` | Installed payload (`SKILL.md`, `LICENSE`, `NOTICE`, `agents/`, `evals/`, `references/`, `scripts/` — the full repository tree only in a clone-into-place install). Other locations are unsupported — the OpenCode plugin resolves the broker and bridge here by constant. |
| `~/.claude/peer-consults` | Shared state root (sockets, registrations, dialogues, outbox). Created with `0700`/`0600` modes. |
| `~/.codex/peer-consults` | Optional symlink to the state root for Codex-side visibility. |

`COUNCIL_STATE_ROOT` exists in the Python broker for isolated testing only.
It is **unsupported** for real use: the OpenCode plugin does not read it, so
overriding it splits state across two roots.

## Version sensitivity

Runtime authentication is version-sensitive on purpose. Vendor updates
(runtime apps, OpenCode CLI binaries, macOS signing behavior) can invalidate
trust anchors, and Council then **fails closed** until re-pinned or updated.
That refusal is the design working, not a bug.
