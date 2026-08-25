# Quick start: your first council in ~15 minutes

Two Claude Code sessions on one Mac form a complete, fully authenticated
council — no Codex, no OpenCode, no executable pinning. This is the shortest
honest path from clone to a real decision packet.

> **Validation status:** these steps were verified against the author's
> working installation on 2026-08-24 (Claude Code 2.1.241, macOS 26.5.2,
> broker v0.18.7). A clean-room walkthrough by a non-author on a fresh
> account is scheduled; until it passes and this block is re-stamped, treat
> the 15-minute figure as a target, not a measurement.

## 0. Prerequisites (~2 min)

- macOS (nothing else is supported — see [compatibility.md](compatibility.md))
- Python 3.9+ on `PATH`: `python3 --version`
- Claude Code (desktop app or CLI), signed in
- Pick sessions that hold nothing sensitive: council peers exchange planning
  text, and you should never enable cross-session delivery into a session
  doing unrelated confidential work.

## 1. Install (~1 min)

```
git clone https://github.com/CountCowy/cross-runtime-council ~/.claude/skills/council
```

## 2. Register the MCP adapter (~1 min)

```
claude mcp add --scope user council -- /usr/bin/python3 ~/.claude/skills/council/scripts/council_mcp.py
```

Verify: `claude mcp list` shows `council`.

## 3. Open two NEW Claude Code sessions

New windows started **after** step 2, so both load the `council_*` tools.
Call them Session A and Session B. Cross-session envelope delivery works out
of the box in current Claude Code; if a permission prompt appears when the
first envelope arrives, approve it for that session.

## 4. Bind Session B (the peer) — paste this into B:

> Bind this session to the council as participant `quickstart-b`, project
> `first-council`. Then participate in the dialogue that arrives: follow each
> envelope's response_contract exactly, submit before acknowledging, and
> acknowledge the terminal notice when the dialogue completes.

Expected within seconds: a JSON confirmation with `participant`,
`lease_minutes`, and `transport_ready: true`. The first bind also starts the
local broker automatically.

## 5. Bind Session A and start the dialogue — paste this into A:

> Bind this session to the council as participant `quickstart-a`, project
> `first-council`. Then start a dialogue with peer `quickstart-b`: topic
> "Versioning scheme for a small tool: SemVer or CalVer", run exactly 2
> rounds. Premises: [user] the tool releases irregularly, sometimes twice a
> week, sometimes not for months; [user] its users are developers who pin
> versions. Participate through completion and acknowledge the terminal
> notice.

## 6. Watch the protocol run (~5–10 min)

Milestones you should see, in order:

1. **Blind proposals** — each session commits a position with 1–8 falsifiable
   claims before seeing the other's.
2. **Exchange rounds** — the broker assigns canonical claim IDs; each side
   must assess every claim, cite evidence for any position change, and name
   the strongest opposing point.
3. **Convergence challenge** — mandatory even under full agreement: each
   participant attacks the merged plan with a counterexample and premortem.
4. **Synthesis and representation check** — the initiator drafts the decision
   packet; the peer audits whether its position was represented accurately.
5. **`dialogue_complete`** in both sessions, carrying the digest of the
   canonical artifact.

## 7. Read your decision packet

```
python3 ~/.claude/skills/council/scripts/council.py report --dialogue-id <dialogue-id>
```

(The dialogue ID appears in every envelope and in the completion notice.)
The canonical record lives at
`~/.claude/peer-consults/dialogues/<dialogue-id>/final.json`. For what a
finished packet looks like, see the
[committed real example](../examples/v020-verification-depth/decision-packet.md).

## 8. Clean up

Tell each session: *"Unbind this session from the council."* Dialogue records
persist under `~/.claude/peer-consults` (see
[install.md](install.md) for state lifecycle; `uninstall.sh --purge-state`
removes everything).

## If something fails

- **The sessions have no `council_*` tools** — they were started before step
  2. Open new sessions.
- **Bind fails with "Claude session did not export its messaging socket"** —
  Claude Code silently disables cross-session messaging when it cannot own its
  socket directory. The default location is `/tmp/cc-socks`, which is shared by
  every user of the Mac: on a multi-user machine, whichever user ran Claude
  Code first owns it, and every other user hits this. Check with
  `ls -ld /tmp/cc-socks`. If it is owned by someone else, start **both**
  sessions from a terminal with a private socket directory instead, then redo
  steps 4–5:

  ```
  mkdir -p ~/.claude/tmp && chmod 700 ~/.claude/tmp
  CLAUDE_CODE_TMPDIR="$HOME/.claude/tmp" claude
  ```
- **Bind or delivery fails on steps that worked before** — suspect a Claude
  Code version change: this transport has no version pin, so vendor updates
  can move it. Compare `claude --version` against the validated tuple at the
  top of this page, and report both versions in an issue.
- **"broker version mismatch"** — an old broker from a previous install is
  running; quit the Claude sessions and retry (a fresh broker starts on the
  next bind).
- **Anything else** — run the diagnostic:
  `python3 ~/.claude/skills/council/scripts/council.py doctor`
  (redacted, aggregate-only) and include its output in an issue.

## Next steps

Triads (Claude + Codex + OpenCode), the Codex wake router, and OpenCode
executable pinning: [install.md](install.md). The full protocol:
[references/protocol.md](../references/protocol.md).
