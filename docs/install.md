# Installation and lifecycle operations

For the fastest first dialogue between two Claude Code sessions, see
[quickstart.md](quickstart.md). This page covers generated releases, the managed
artifact lifecycle, and multi-runtime setup.

Council uses three fixed roots:

| Purpose | Path |
| --- | --- |
| Council state and lifecycle control | `~/.claude/peer-consults` |
| Installed Council payload | `~/.claude/skills/council` |
| OpenCode artifacts | `~/.config/opencode` |

Other roots are unsupported. The lifecycle command validates these paths and
refuses symlinked or otherwise unsafe layouts.

## Requirements

- macOS, because Council's runtime trust anchors are macOS-specific
- Python 3.9 or newer as `python3` on `PATH`
- A generated Council release containing root `release_manifest.json` and
  `payload/scripts/council_lifecycle.py`
- At least two agent sessions to hold Council seats: Codex, Claude Code, and/or
  OpenCode CLI; two sessions of one runtime are a valid pair
- Node 22 or newer only for development tests and OpenCode package setup

Every lifecycle launcher executes the Python entrypoint with isolated mode and
bytecode writes disabled: `python3 -I -B`. Policy, validation, filesystem
mutation, liveness checks, and recovery all remain in the Python implementation.

## Prepare a generated release

Run the release builder from a separate, quiescent source checkout:

```sh
python3 scripts/generate_protocol.py --check
python3 scripts/build_release.py --write
python3 scripts/build_release.py --check
python3 scripts/build_release.py --output /absolute/path/to/council-release
```

The output directory must not already exist and must be outside the checkout.
The generated release contains the complete tracked payload, the four OpenCode
copies, and a manifest that binds the exact artifact closure and hashes. The
lifecycle engine refuses a source checkout or an incomplete, extra, stale, or
modified release tree.

`build_release.py --write` changes tracked source stamps and the committed
manifest. A maintainer performs that step during release preparation; an
operator installing an already generated release does not run it.

## Inspect a plan

Planning is read-only and emits canonical JSON on standard output. From a source
checkout, pass the generated release explicitly:

```sh
python3 -I -B scripts/council_lifecycle.py plan install \
  --release /absolute/path/to/council-release
python3 -I -B scripts/council_lifecycle.py plan upgrade \
  --release /absolute/path/to/council-release
python3 -I -B scripts/council_lifecycle.py plan rollback \
  --receipt <receipt-id>
python3 -I -B scripts/council_lifecycle.py plan uninstall
python3 -I -B scripts/council_lifecycle.py status
```

A plan reports its blockers and required gates. It is deliberately
non-executable: the mutating command repeats ownership and registration checks
while holding the Council writer lease before it publishes an intent.

When the entrypoint is inside `council-release/payload/scripts/`, install and
upgrade may infer that generated release. Source checkouts never qualify for
inference and require `--release`.

## Install

First inspect the plan, finish or cancel Council dialogues, unbind participants,
and quit the Council runtimes that could still hold loaded writers. An initial
install or adoption of unmanaged artifacts also requires an explicit maintenance
window acknowledgement:

```sh
sh install/install.sh \
  --release /absolute/path/to/council-release \
  --maintenance-window-confirmed
```

The copy of the wrapper inside the generated release can infer its enclosing
release, so the equivalent invocation is:

```sh
sh /absolute/path/to/council-release/payload/install/install.sh \
  --maintenance-window-confirmed
```

The engine validates the entire release, current ownership, fixed roots, Council
writer admission, and persisted runtime registrations. Live, unknown, duplicate,
or incompatible registrations block the transaction. A payload containing
`.git` is an ownership stop; clone preservation or relocation is a separate
operator decision and is not automated by the lifecycle command.

On success, the engine installs one coherent five-unit artifact set: the Council
payload plus the OpenCode plugin, protocol, delivery registry, and tool. Existing
external files that merely happen to match release bytes are not silently made
owned. The terminal receipt records exactly which artifacts the lifecycle owns.

## Upgrade

Upgrade requires a receipt-certified managed installation and a generated
release:

```sh
python3 -I -B scripts/council_lifecycle.py plan upgrade \
  --release /absolute/path/to/council-release
sh install/upgrade.sh --release /absolute/path/to/council-release
```

There is no timestamped backup-directory interface. The transaction retains
the exact prior artifact set and provenance under the lifecycle namespace and
publishes an immutable receipt. Local edits, missing owned files, unexpected
payload content, and unowned destination conflicts refuse before intent.

The lifecycle transaction replaces artifact files only. It does not edit MCP
registrations, `opencode.json`, package dependencies, executable pins, or running
host processes. Apply any corresponding runtime configuration change through
that runtime's separately reviewed procedure, then restart it as required.

## Roll back

Rollback accepts exactly one retained receipt ID:

```sh
python3 -I -B scripts/council_lifecycle.py plan rollback \
  --receipt <receipt-id>
sh install/rollback.sh --receipt <receipt-id>
```

The receipt must be a supported, committed lifecycle receipt whose retained
release, provenance, recovery tool, fixed roots, and lock identity still verify.
The engine revalidates current ownership, writer admission, and registrations as
a new transaction. A directory path, a timestamped legacy backup, or an
unsupported predecessor is refused.

## Uninstall

Managed uninstall removes only receipt-owned code artifacts and keeps the state,
lock, lifecycle namespace, receipts, journals, retained recovery material, and
unowned matching external files:

```sh
python3 -I -B scripts/council_lifecycle.py plan uninstall
sh install/uninstall.sh
```

`--purge-state` is intentionally unsupported and is rejected before mutation.
Destructive removal of dialogue state, audit logs, tombstones, receipts, or
retained recovery data requires a separate bounded retention decision. Uninstall
also does not remove runtime registration or configuration entries.

## Recovery after interruption

Before publishing a transaction intent, every mutating lifecycle command writes
an exact `recovery-command` JSON argument vector to standard error and flushes
it. Record that vector. If the lifecycle command is interrupted after intent,
run those exact arguments; the recovery program is an immutable copy retained
outside the replaceable payload and works with the payload absent.

Recovery holds the same fixed `broker.lock`, validates the pending admission,
plan, journal, receipts, root identities, and all five artifact units, then
continues the recorded target outcome. Re-running recovery is safe. `--abort`
may select the validated prior outcome only when the prepared plan advertises
that goal; it cannot reverse a terminal transaction or guess a missing prior
state.

Do not select a recovery tool by timestamp or from a backup directory. Do not
remove `broker.lock`, `.council-lifecycle`, a staged unit, or a pending admission.
Unknown or corrupt recovery content is a fail-closed condition that requires
inspection of the exact retained transaction.

See [lifecycle.md](lifecycle.md) for the record formats, ownership rules, and
crash-boundary model.

## Per-runtime setup

Lifecycle installation places code artifacts at their fixed destinations. The
following registration and host operations remain separate from the artifact
transaction.

### Claude Code

Register the Council MCP adapter at user scope:

```sh
claude mcp add --scope user council -- /usr/bin/python3 \
  ~/.claude/skills/council/scripts/council_mcp.py
```

New sessions then expose the `council_*` tools. The exact session that will bind
must accept cross-session inbound messages. A bound seat's capability exists
only in its adapter process memory. If Claude Code recycles that process, the
replacement cannot renew or release the old binding; wait for its bounded lease
to expire, then bind again under the same name.

### Codex

Register the MCP adapter in `~/.codex/config.toml`, using an absolute path:

```toml
[mcp_servers.council]
command = "/usr/bin/python3"
args = ["/Users/YOUR-USERNAME/.claude/skills/council/scripts/council_mcp.py"]
```

Restart Codex. The planning task calls its `council_*` tools directly. An idle
planning task needs the separately configured, context-isolated wake router to
learn about queued work without a manual poll; see
[protocol.md](../references/protocol.md), "Delivery and recovery".

Configure the exact router task offline while no broker is active:

```sh
python3 ~/.claude/skills/council/scripts/council.py configure-router \
  --target-thread-id <codex-task-id>
```

The router sends only fixed wake markers. It never sees dialogue content and
must never participate in Council planning. Reconfigure it after the Codex app
loses its in-memory router capability.

### OpenCode CLI

The managed lifecycle installs these four files from the generated release:

```text
~/.config/opencode/council-plugin.ts
~/.config/opencode/council_protocol.ts
~/.config/opencode/opencode_delivery_registry.ts
~/.config/opencode/tools/council.ts
```

Separately add `./council-plugin.ts` to the `plugin` array in
`~/.config/opencode/opencode.json`. If OpenCode does not resolve
`@opencode-ai/plugin` itself, declare the matching SDK version in
`~/.config/opencode/package.json` and install that dependency.

Record the exact OpenCode CLI executable while no broker is active, then restart
OpenCode:

```sh
python3 ~/.claude/skills/council/scripts/council.py configure-opencode \
  --executable "$(command -v opencode)"
```

Repeat the pin and restart after every OpenCode upgrade. OpenCode Desktop remains
unsupported until a version-specific live acceptance proves its plugin-owned
relay initializes and passes the exact-session checks.

## Administrative commands

`council.py report --dialogue-id <dialogue-id>` prints the canonical
post-completion decision packet as JSON. `council.py render` writes that packet
as a self-contained HTML file after verifying either the dialogue audit binding
or an explicitly supplied input digest. `doctor` emits a redacted aggregate
diagnostic, and `ping` is its one-line aggregate form. The administrative CLI
cannot perform participant operations or launch a production broker.

Terminal dialogue deletion and optional retention remain explicit administrative
operations:

```sh
python3 ~/.claude/skills/council/scripts/council.py delete \
  --dialogue-id <dialogue-id>
python3 ~/.claude/skills/council/scripts/council.py configure-retention --days 30
```

These operations are distinct from lifecycle uninstall. Deletion writes a
minimal tombstone before removing the selected terminal dialogue and its outbox
records. Retention is off by default and runs only when the broker starts.

## Troubleshooting

- An `untrusted daemon` or bind refusal means the runtime-origin check failed;
  bind from the admitted runtime, not from a terminal-launched broker.
- A maintenance refusal naming registrations means the source transaction did
  not prove every persisted route positively dead and compatible. Resolve the
  named host/session state, then inspect a new plan.
- A lifecycle ownership blocker means the current payload or external artifacts
  differ from the recorded receipt or include unowned content. Preserve the
  paths and inspect the reported unit; do not delete around the blocker.
- A `recovery_required` status means the retained external recovery command owns
  the next step. Do not run install, upgrade, rollback, or uninstall again.
- A release error means the supplied directory is not the exact generated
  manifest closure. Generate a fresh release in a new directory rather than
  repairing release files by hand.
- A broker or adapter version mismatch fails closed until the owning runtime
  restarts on one compatible installed cohort.
- A configuration outside [compatibility.md](compatibility.md) is an
  unqualified configuration request and should be reported as such.
