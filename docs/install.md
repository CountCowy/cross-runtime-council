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
- CPython 3.9 or newer as `python3` on `PATH`
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

If the fixed payload path is the source clone from the README setup, preserve
that entire clone before the first managed install. During the same quiescent
maintenance window, choose a retained path that does not exist and is outside
both the fixed payload path and the generated release, then run:

```sh
retained=/absolute/retained/path/council-source-clone
test ! -e "$retained" || { echo "retained path already exists" >&2; exit 1; }
mv "$HOME/.claude/skills/council" "$retained"
sh /absolute/path/to/council-release/payload/install/install.sh \
  --maintenance-window-confirmed
```

The move keeps the clone's `.git` directory, local edits, and untracked files
together at the operator-selected path. It does not move or rewrite the state
root at `~/.claude/peer-consults` or external runtime configuration. The
lifecycle engine neither claims nor changes the retained clone. It still
refuses an in-place source clone and any differing unowned artifact at a fixed
destination; preserve and resolve each such collision explicitly before
requesting another plan.

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

If the first managed install left hand-copied external files unowned, the plan
reports `unowned_change_requires_adoption` for each of them, because every
release changes those four files. Adopt them deliberately, after reading the
plan:

```sh
python3 -I -B scripts/council_lifecycle.py plan upgrade \
  --release /absolute/path/to/council-release --adopt-unowned
sh install/upgrade.sh --release /absolute/path/to/council-release --adopt-unowned
```

Adoption applies only where the artifact still holds exactly the bytes the
receipt recorded, so it never replaces a later local edit; such an artifact
stays blocked and must be preserved or reverted by hand. `rollback` accepts the
same flag. Once adopted, the artifacts are owned and later operations need it no
longer.

Artifact commands remain artifact-only unless an owned OpenCode registration is
being removed during managed uninstall. Registration itself is a separate,
digest-confirmed lifecycle command. It never installs package dependencies,
changes executable pins, controls a host, or claims the restarted integration is
authenticated and ready.

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
retained recovery data requires a separate bounded retention decision. When the
current receipt owns an unchanged OpenCode Council entry, `plan uninstall`
returns its registration-plan digest and uninstall additionally requires:

```sh
sh install/uninstall.sh --quiescent-edit \
  --confirm-plan <sha256> --invocation-id <fresh-id>
```

The format-2 transaction removes that entry before deleting its backing
artifacts. A matching pre-existing unowned entry is preserved.

## Recovery after interruption

Before publishing a transaction intent, every mutating lifecycle command writes
an exact `recovery-command` JSON argument vector to standard error and flushes
it. Record that vector. If the lifecycle command is interrupted after intent,
run that complete vector without changing its flags, tool path, or state root.
The recovery program is a digest-bound immutable copy retained outside the
replaceable payload and works with the payload absent.

`python3 -I -B scripts/council_lifecycle.py status` has a dedicated read-only
result for a validated `recovery_required` admission. It keeps the normal
top-level `status_format`, `roots`, `management`, `payload_cache_count`, and
`units` fields. Registration formats also add a `registrations` projection whose
`stored_config_result` remains `pending_recovery`, whose `recovery_state` comes
from the validated progress journal, and whose effective scope and authenticated
readiness remain unobserved. The result adds:

```json
{
  "pending_recovery": {
    "transaction_id": "<transaction-id>",
    "plan_sha256": "<plan-sha256>",
    "recovery_command": ["<compatible-python>", "-I", "-B", "<copied-tool>", "recover", "--state-root", "<state-root>"],
    "python_contract": {
      "implementation": "CPython",
      "minimum": [3, 9],
      "required_flags": ["-I", "-B"],
      "recorded_path": "<original-python-path>",
      "recorded_version": [3, 9, 0]
    }
  }
}
```

Status validates the pending admission, exact plan, fixed roots, and copied
recovery-tool identity before returning this command. The command uses the
currently running compatible interpreter and the plan-bound copied tool.
`recorded_path` and `recorded_version` report transaction provenance; recovery
does not require the same executable path or patch release. The executing
interpreter must satisfy the reported contract and the recoverer's required
runtime feature checks. Missing, malformed, cross-root, or digest-mismatched
pending records fail closed instead of producing a recovery command.
For a native format-3 transaction, status verifies every copied closure file by
its fixed name, owner, mode, link count, size, and digest without importing or
executing those bytes.

Recovery holds the same fixed `broker.lock`, validates the pending admission,
plan, journal, receipts, root identities, and all five artifact units, then
continues the recorded target outcome. Re-running recovery is safe. `--abort`
may select the validated prior outcome only when the prepared plan advertises
that goal; it cannot reverse a terminal transaction or guess a missing prior
state.

For a pending registration transaction the printed vector includes
`--quiescent-edit`, `--confirm-plan <sha256>`, and a placeholder for a fresh
invocation ID. Replace only that placeholder after again closing the named host
and confirming no competing configuration writer. The historical confirmation
inside the transaction is not current authority.

Do not select a recovery tool by timestamp or from a backup directory. Do not
remove `broker.lock`, `.council-lifecycle`, a staged unit, or a pending admission.
Unknown or corrupt recovery content is a fail-closed condition that requires
inspection of the exact retained transaction.

## Re-bind after a re-created root or lock

A receipt binds the `(device, inode)` identity of the three fixed roots and of
`broker.lock`. A remount, a restore, a home-directory migration, or a
`broker.lock` that was removed and re-created changes those numbers while the
installation stays byte-identical. `status` then reports `committed` but
uncertified, naming the identity that changed, and every operation refuses.
Re-certify it:

```sh
python3 -I -B scripts/council_lifecycle.py status
python3 -I -B scripts/council_lifecycle.py rebind
```

`rebind` re-verifies the receipt, its provenance, the retained recovery tool,
and all five artifact units under the writer lease before recording the observed
identities. It writes no artifact and refuses an installation whose content
actually changed; such a state is a content blocker, not an identity one, and is
resolved by restoring the artifact. Never delete the lifecycle namespace to
clear an identity mismatch.

See [lifecycle.md](lifecycle.md) for the record formats, ownership rules, and
crash-boundary model.

## Per-runtime setup

Lifecycle installation places code artifacts at their fixed destinations.
OpenCode's strict-JSON plugin entry has a managed registration command below.
Native Claude and Codex mutation remains unavailable until an exact vendor tuple
passes genuine disposable-runner qualification; their manual setup remains the
documented fallback.

### Claude Code

Register the Council MCP adapter at user scope:

```sh
claude mcp add --scope user council -- /usr/bin/python3 \
  ~/.claude/skills/council/scripts/council_mcp.py
```

`plan register --runtime claude` reports `native_behavior_unqualified` unless an
owner-recorded admission binds genuine evidence for the exact binary, closed
config shape, source package, copied recovery closure, and process/network/write
observer. This release ships no such admission, so managed apply refuses before
the writer lease, lifecycle state, configuration, or process effects. CLI help
does not establish idempotence, preservation, or scope behavior; the manual
command above remains the fallback.

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

`plan register --runtime codex` has the same owner-admission gate and normally
reports `native_behavior_unqualified`. Conditional `tomllib` parsing can produce a
read-only/manual-edit comparison under a pinned Python 3.11+ interpreter, but it
does not qualify Codex's whole-map native writer. Managed native apply remains
disabled until that separately reviewed admission exists.

When future evidence satisfies either native gate, execution uses native format
3 under the same C1 writer lease. It records a blocked supervisor generation
before releasing one fixed command, treats missing observer coverage as
`unknown`, and never infers success from exit zero. An `observed_prior` result may
use one fresh, linked recovery sequence; target recovery does not relaunch.
Removal is a new separately admitted inverse transaction. Stored configuration
still does not establish effective scope or authenticated readiness.

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

With OpenCode closed and no competing configuration writer, first obtain the
read-only exact plan:

```sh
python3 -I -B scripts/council_lifecycle.py plan register --runtime opencode
```

Then apply that exact digest with a fresh invocation identifier:

```sh
python3 -I -B scripts/council_lifecycle.py register --runtime opencode \
  --quiescent-edit --confirm-plan <sha256> --invocation-id <fresh-id>
```

This supports exactly one existing strict-JSON `opencode.json` or
`opencode.jsonc`. It preserves unrelated bytes and plugin entries. Multiple
sources, JSONC syntax, aliases, duplicate Council identities, options-bearing
Council entries, ownership loss, or a changed file produce a refusal and an
exact manual edit is then required; the command never experiments on the file and then
undoes it. To remove an owned unchanged entry, use `plan unregister` followed by
the corresponding `unregister` command with the same three confirmation flags.
Matching pre-existing entries are recorded as unowned and are never removed.

If OpenCode does not resolve `@opencode-ai/plugin` itself, declare the matching
SDK version in `~/.config/opencode/package.json` and install that dependency.
Dependency installation remains manual and outside the registration command.

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
