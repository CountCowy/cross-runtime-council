# Installation

For the fastest first dialogue (two Claude Code sessions, one runtime), see
[quickstart.md](quickstart.md); this page covers full multi-runtime setup.

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

**Claude Code.** Two steps (steps verified against a working installation,
not yet clean-room rehearsed):

1. Register the Council MCP adapter at user scope:

   ```
   claude mcp add --scope user council -- /usr/bin/python3 ~/.claude/skills/council/scripts/council_mcp.py
   ```

   New sessions then expose the `council_*` tools. The skill instructions are
   discoverable automatically once the payload is at
   `~/.claude/skills/council`.
2. The session you intend to bind must accept cross-session inbound messages.
   Binding happens inside that exact session via the `council_*` tools — see
   [../SKILL.md](../SKILL.md).

Known lifecycle interaction: Claude Code may recycle a session's MCP server
process after a long idle stretch (a clean host-side shutdown, not a crash).
A bound seat's council capability lives only in that process's memory — by
design it is never persisted — so a recycled adapter can neither renew nor
release its own binding: the broker refuses every operation for that seat
("only its exact authenticated session may renew it") until the lease
expires (default 120 minutes), after which a fresh bind under the same name
receives any pending envelope exactly once. This is the authentication
model working, not a fault; the practical advice is to keep a bound
session's dialogue moving rather than leaving it idle for long stretches.

**Codex (macOS app).** Register the same MCP adapter in
`~/.codex/config.toml` (steps verified against a working installation, not
yet clean-room rehearsed):

```toml
[mcp_servers.council]
command = "/usr/bin/python3"
args = ["/Users/YOUR-USERNAME/.claude/skills/council/scripts/council_mcp.py"]
```

Use an absolute path — expand the home directory yourself. Restart the app;
the planning task you bind calls the `council_*` tools itself.
([../agents/openai.yaml](../agents/openai.yaml) is interface display metadata
only — it is not registration configuration.) An idle Codex seat also needs
the wake router below; without it, an idle task learns of new council work
only when it next runs `council_wait`.

### Codex wake router (optional, recommended for triads)

An idle Codex planning task is woken by a dedicated, context-isolated router
task — the planning task itself never polls (see
[protocol.md](../references/protocol.md), "Delivery and recovery").

1. Create a dedicated Codex task whose only job, on a schedule (five minutes
   is the default cadence), is one wake poll: lease pending notifications via
   `council_pending_wakes`, send the fixed wake marker to each notification's
   exact target task, and record the outcome with `council_wake_ack`. Keep it
   context-isolated — it must never participate in planning, and it never
   sees dialogue content (the broker leases it opaque metadata only).
2. With no broker running, record that exact task offline:

   ```
   python3 ~/.claude/skills/council/scripts/council.py configure-router --target-thread-id <codex-task-id>
   ```

   (The command refuses to run while a broker is active.)
3. The router authenticates and binds itself on its next scheduled run.
   Disable the schedule whenever standing inbound wake is not wanted.

If the Codex app restarts, the router's in-memory capability is lost and
every later wake poll fails closed ("wake polling failed" from the router
task) even though the broker is healthy. Re-run the `configure-router`
command above (with no broker active) to reset the pairing; the router then
re-bootstraps on its next scheduled run.

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

## Deleting dialogue records

```
python3 ~/.claude/skills/council/scripts/council.py delete --dialogue-id <dialogue-id>
```

removes a **terminal** (completed or cancelled) dialogue's content: the
dialogue directory (manifest, audit log, submissions, canonical `final.json`)
and every outbox record that referenced it. Active dialogues are refused —
cancel first. The command refuses to run while a broker is live; quit the
Council runtimes first.

What persists is a minimal tombstone at
`~/.claude/peer-consults/tombstones/<dialogue-id>.json` recording identity,
time, reason (`--reason`, default `user_requested`), and the ids of the
outbox records it superseded — never content. The tombstone is written first,
so a deletion interrupted by a crash is completed automatically at the next
broker start, and re-running the command is an idempotent no-op. A session
that never acknowledged its terminal notice for a deleted dialogue will see
that late acknowledgement fail with "unknown message" — expected and
harmless. `doctor` reports the tombstone count;
`uninstall.sh --purge-state` removes tombstones along with the rest of the
state root.

### Automatic retention (optional, off by default)

```
python3 ~/.claude/skills/council/scripts/council.py configure-retention --days 30
```

records an offline retention window (`--disable` removes it; like the other
`configure-*` commands it refuses to run while a broker is live). At every
broker **startup** — and only then; a long-lived broker never sweeps
mid-life — terminal dialogues whose completion or cancellation is older than
the window are deleted through the same primitive above, with
`retention_sweep` as the tombstone reason. Active dialogues are never
touched, and a dialogue whose terminal timestamp is missing or malformed is
skipped rather than deleted. A corrupt `retention.json` fails closed: the
broker refuses to start until the file is fixed or reconfigured. `doctor`
reports the configured window.

```
python3 ~/.claude/skills/council/scripts/council.py doctor
```

prints a redacted, aggregate-only health report: broker reachability and
version currency, installed-copy currency, OpenCode plugin/registry/pin
state, and router configuration. `... council.py ping` is the one-line
aggregate variant. Neither command can start a broker, perform participant
operations, or read dialogue content.

## Troubleshooting

- **"untrusted daemon" / bind refusals**: the broker authenticates the
  launcher process chain; shells and unsigned launchers are refused by
  design. Bind from inside the runtime, not from a terminal.
- **Claude bind fails with "did not export its messaging socket"**: Claude
  Code silently disables cross-session messaging when it cannot own its socket
  directory (default `/tmp/cc-socks` — shared by every user of the Mac; on a
  multi-user machine only the first user to run Claude Code owns it). Check
  `ls -ld /tmp/cc-socks`; if another user owns it, start the Claude Code
  sessions you intend to bind with `CLAUDE_CODE_TMPDIR` pointed at a private
  `0700` directory you own (see the same entry in
  [quickstart.md](quickstart.md) for the exact commands).
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
