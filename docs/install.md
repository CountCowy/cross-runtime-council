# Installation

Council uses a **fixed layout** (see [compatibility.md](compatibility.md)):
the payload lives at `~/.claude/skills/council`, shared state at
`~/.claude/peer-consults`. Other locations are unsupported.

## Requirements (preflight-enforced)

- macOS (the trust anchors are macOS-specific; nothing else is supported)
- Python 3.9+ on `PATH`
- At least two agent sessions to hold seats: Codex (macOS app), Claude Code,
  and/or OpenCode CLI. Two sessions of one runtime are a valid pair.
- Optional, tests only: Node 22+ for the Node test suite (never needed at
  runtime; from <https://nodejs.org> — `npm` ships with it)

The install scripts reject unsupported conditions **before touching any file**
and print the exact reason.

## Install

Either clone into place:

```
git clone <repo-url> ~/.claude/skills/council
```

or run the installer from any checkout (refuses to clobber an existing
install):

```
sh install/install.sh
```

The state root `~/.claude/peer-consults` is created on demand by the runtimes
with `0700` permissions — do not create or chmod it yourself.

## Per-runtime setup

**Claude Code.** The skill is discoverable once the payload is at
`~/.claude/skills/council`. The session you intend to bind must accept
cross-session inbound messages. Binding happens inside that exact session via
the `council_*` tools — see [../SKILL.md](../SKILL.md).

**Codex (macOS app).** Register the MCP adapter
(`scripts/council_mcp.py`) per [../agents/openai.yaml](../agents/openai.yaml).
The planning task binds itself; an optional context-isolated router task
handles idle wakes (see `references/protocol.md`, "Route an idle Codex wake").

**OpenCode CLI.** Three steps, in order:

1. Register the plugin and native tool files globally (paths verified against
   a working installation; the clean-room rehearsal re-validates them
   from scratch):

   ```
   mkdir -p ~/.config/opencode/tools
   cp ~/.claude/skills/council/scripts/opencode_council_plugin.ts   ~/.config/opencode/council-plugin.ts
   cp ~/.claude/skills/council/scripts/opencode_delivery_registry.ts ~/.config/opencode/opencode_delivery_registry.ts
   cp ~/.claude/skills/council/scripts/opencode_council_tools.ts     ~/.config/opencode/tools/council.ts
   ```

   Then add the plugin to `~/.config/opencode/opencode.json`:

   ```json
   { "plugin": ["./council-plugin.ts"] }
   ```

   The plugin imports `@opencode-ai/plugin` (MIT, OpenCode's own SDK). If your
   OpenCode does not resolve it automatically, add a
   `~/.config/opencode/package.json` with
   `{ "dependencies": { "@opencode-ai/plugin": "<your OpenCode version>" } }`
   and run `npm install` in that directory (`npm` ships with Node — see
   Requirements; there is no npm-free fallback for this step).
2. Record the offline executable pin for your OpenCode CLI binary:

   ```
   python3 ~/.claude/skills/council/scripts/council.py configure-opencode --executable "$(command -v opencode)"
   ```

   The pin captures the binary's real path, SHA-256, and code-directory
   hash. Run it while no broker is active (it refuses otherwise).
3. Restart OpenCode. The participating process must have started **at or
   after** the latest pin.

Repeat steps 2–3 after **every** OpenCode upgrade — pins never renew
automatically, and a stale pin fails closed by design.

**OpenCode Desktop is unsupported.** Native tools loading there is not
evidence of support; the plugin-owned relay must initialize, and it did not
in the most recent live acceptance.

## Upgrade / rollback / uninstall

```
sh install/upgrade.sh     # stages new payload, keeps a timestamped backup
sh install/rollback.sh    # restores the most recent backup
sh install/uninstall.sh   # removes the payload; PRESERVES user state
```

Run these from a repository checkout. In a clone-into-place install the
checkout **is** `~/.claude/skills/council`, so the scripts live at
`~/.claude/skills/council/install/`. An installer-based install contains only
the payload (no `install/`, docs, or README) — keep the checkout you installed
from, or clone again to upgrade or uninstall.

Upgrade backups and rollback set-asides live under
`~/.claude/skills/.council-backups/` — dot-prefixed so Claude Code's skill
discovery never mistakes a stale copy for a second `council` skill.

`uninstall.sh --purge-state` also deletes `~/.claude/peer-consults`
(dialogue records, audit logs) after an explicit confirmation.

All three refuse to run while a live broker socket exists — finish or cancel
active dialogues and quit the owning runtime first.

## Troubleshooting

- **"untrusted daemon" / bind refusals**: the broker authenticates the
  launcher process chain; shells and unsigned launchers are refused by
  design. Bind from inside the runtime, not from a terminal.
- **OpenCode bind fails after an update**: the pin is stale. Re-pin, restart
  OpenCode, retry.
- **Broker version mismatch**: an adapter and broker from different versions
  fail closed; quit the runtimes so the owning runtime restarts the broker.
- **"STALE broker socket" from the lifecycle scripts**: `broker.sock` was left
  behind by an unclean shutdown (crash, power loss) and nothing is listening.
  Remove `~/.claude/peer-consults/broker.sock`, or start and then quit a
  Council runtime so a fresh broker reclaims it, and re-run the script.
- **Anything on a configuration not in [compatibility.md](compatibility.md)**:
  expected to fail closed; report it as an untested-configuration request,
  not a defect.
