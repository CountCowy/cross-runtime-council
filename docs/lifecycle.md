# Managed artifact lifecycle

Council's lifecycle engine installs, upgrades, rolls back, and uninstalls one
coherent artifact set while sharing the existing Council writer-exclusion and
registration-liveness boundary. It is Python 3.9 standard-library code. The four
shell files in `install/` only select a verb and execute
`scripts/council_lifecycle.py` with `python3 -I -B`.

## Fixed roots and artifact units

The engine accepts no configurable production roots:

| Root | Fixed path |
| --- | --- |
| State and lifecycle control | `~/.claude/peer-consults` |
| Payload | `~/.claude/skills/council` |
| OpenCode configuration root | `~/.config/opencode` |

A transaction covers exactly five units, in this order:

1. `payload`
2. `opencode-plugin`
3. `opencode-protocol`
4. `opencode-registry`
5. `opencode-tool`

The last four map to `council-plugin.ts`, `council_protocol.ts`,
`opencode_delivery_registry.ts`, and `tools/council.ts` under the OpenCode root.
The generated root `release_manifest.json` is provenance input; it is not copied
into the payload as an extra managed unit.

The engine rejects a symlinked root, unsafe ancestor, hard-linked source,
unexpected unit, path escape, manifest collision, or incomplete release closure.
Each file is checked against the generated manifest before a transaction can be
prepared.

## Command contract

All public Python invocations use isolated mode with bytecode writes disabled:

```text
python3 -I -B scripts/council_lifecycle.py status
python3 -I -B scripts/council_lifecycle.py plan install --release <generated-release>
python3 -I -B scripts/council_lifecycle.py plan upgrade --release <generated-release>
python3 -I -B scripts/council_lifecycle.py plan rollback --receipt <receipt-id>
python3 -I -B scripts/council_lifecycle.py plan uninstall
python3 -I -B scripts/council_lifecycle.py plan register --runtime claude|codex|opencode
python3 -I -B scripts/council_lifecycle.py plan unregister --runtime claude|codex|opencode
python3 -I -B scripts/council_lifecycle.py install --release <generated-release> --maintenance-window-confirmed
python3 -I -B scripts/council_lifecycle.py upgrade --release <generated-release>
python3 -I -B scripts/council_lifecycle.py rollback --receipt <receipt-id>
python3 -I -B scripts/council_lifecycle.py uninstall
python3 -I -B scripts/council_lifecycle.py register --runtime opencode --quiescent-edit --confirm-plan <sha256> --invocation-id <id>
python3 -I -B scripts/council_lifecycle.py unregister --runtime opencode --quiescent-edit --confirm-plan <sha256> --invocation-id <id>
```

Install and upgrade infer a release only when the Python entrypoint is inside a
generated layout with root `release_manifest.json` and
`payload/scripts/council_lifecycle.py`. A source checkout requires `--release`.

Successful lifecycle and plan commands write canonical JSON to standard output.
A mutating command writes and flushes its exact recovery argument vector to
standard error before publishing intent. Usage and validation failures exit
without presenting a successful JSON result.

`plan` and `status` read state and artifacts without acquiring a writer lease or
changing them. A plan includes `executable: false`, the current ownership state,
target identities, required gates, blockers, and the five-unit preview. It omits
transaction IDs, proposed receipts, object paths, and other fields that could
turn it into executable intent.

For terminal or unmanaged state, `status` uses the existing ownership
inspection and returns `status_format`, `roots`, `management`,
`payload_cache_count`, and `units`; terminal certification remains
receipt-backed. For a `recovery_required` admission it uses a separate read-only
path: it validates the pending admission, exact plan, fixed roots, and
digest-bound copied recoverer without attempting terminal ownership
certification. The same top-level fields are present, with `management.status`
set to `recovery_required`, and `pending_recovery` adds the validated
`transaction_id`, `plan_sha256`, `recovery_command`, and `python_contract`.
Format-2 and format-3 results also include a `registrations` projection from the
validated plan and progress journal. Its `stored_config_result` is
`pending_recovery`; `recovery_state` reports the recorded operation phase or
native attempt state, while effective scope and authenticated readiness remain
unobserved. Native status verifies the copied closure's fixed filesystem and
digest identities without importing or executing its bytes.

## Admission and operation rules

Normal execution performs an initial ownership and release preflight, then
acquires the existing C1 writer lease on the fixed `broker.lock`. Under that
lease it repeats ownership validation, captures registrations, and refuses live,
unknown, duplicate, or incompatible registered writers. It prepares the complete
transaction and validates the standalone recovery program before changing the
admission marker.

The operation-specific rules are:

| Operation | Required current state | Target input | Additional rule |
| --- | --- | --- | --- |
| Install | Unmanaged or receipt-certified `uninstalled` | Generated release | First adoption requires `--maintenance-window-confirmed` |
| Upgrade | Receipt-certified `committed` | Generated release | Every owned artifact must still match its receipt |
| Rollback | Receipt-certified `committed` | Exact retained receipt ID | Retained release and reader/recovery support must verify again |
| Uninstall | Receipt-certified `committed` | None | Removes only receipt-owned code artifacts |

Registration is a separate explicit operation over a receipt-certified
artifact install. Its read-only plan selects exactly one strict-JSON
`opencode.json` or `opencode.jsonc`, rejects aliases, duplicate identities,
options-bearing Council entries, JSONC syntax, and ambiguous sources, and emits a
digest without writing control or configuration state. Apply requires
`--quiescent-edit`, that exact digest, and a fresh invocation ID. It changes only
the selected `plugin` member through a reversible byte patch.

Claude and Codex use distinct native format 3. The source distribution contains
no qualification admission, so these commands normally report
`native_behavior_unqualified` and refuse before the writer lease, control state,
configuration, or process effects. An eligible path requires an owner-recorded,
operation-specific admission at its fixed lifecycle path. That admission binds
the exact runtime tuple, package/cohort, three-file copied recovery closure,
closed shape policy, observer implementation, genuine case packets, and
independent review. A plan field or matching digest cannot substitute for that
record.

After eligibility, apply still requires the exact plan digest and a fresh
quiescent invocation. The C1 writer lease is held while the copied recoverer
records a blocked supervisor generation, arms its process/network/write
observer, authorizes release, observes the entire process group, classifies the
stored entry, and publishes the immutable receipt. Missing network or write-set
coverage yields `unknown` and leaves recovery required. Native success remains
disabled in this source until the separately controlled genuine evidence and
observer gates are satisfied.

An install does not convert matching pre-existing external files into owned
artifacts. A later uninstall preserves those unowned files. Any changed owned
file, missing owned file, unexpected payload entry, unowned conflict, payload
`.git` entry, or pending recovery is a blocker. The operator resolves the
underlying ownership decision outside the lifecycle engine and requests a fresh
plan; the engine does not select, delete, or relocate the content.

Inspection reports these conditions; it does not refuse them. `status` and
`plan` always describe the state they find, so an installation that drifted from
its receipt reads as `committed` but uncertified with the reason attached, and
the plan lists its blockers. Mutation stays strict: an uncertified installation
is ineligible for install, upgrade, rollback, and uninstall alike.

A receipt also binds the `(device, inode)` identity of the three fixed roots and
of `broker.lock`. A remount, a restore, a migration, or a cleared stale lock
changes those numbers without touching one byte of the installation, which then
reads as uncertified with an identity reason. `rebind` re-certifies exactly that
case. It re-verifies the receipt digest, provenance, recovery tool, and every
artifact under the writer lease, and records the observed identities for that
one receipt. It never writes an artifact, and it refuses an installation whose
content has actually changed. The record is scoped to the receipt it names, so
the next transaction's receipt supersedes it.

Every blocker carries a stable code:

| Code | Meaning |
| --- | --- |
| `managed_installation_present` | Install requires an unmanaged or uninstalled current state |
| `uncertified_lifecycle_marker` | An uninstalled marker has no certifying receipt |
| `certified_installation_required` | Upgrade, rollback, and uninstall require a certified committed install |
| `source_clone` | The payload path contains a `.git` ownership stop |
| `unowned_payload` | Unmanaged payload content cannot be changed or claimed |
| `unowned_collision` | An unmanaged external file differs from the release artifact |
| `unowned_change_requires_adoption` | The release would change a matching pre-existing unowned artifact |

`unowned_change_requires_adoption` is the one blocker with an in-engine remedy,
because every release changes the four external files by construction: their
embedded package identity is derived from the payload. An operator who copied
those files in by hand before the first managed install keeps them unowned, and
the next upgrade reports this blocker for each one. Passing `--adopt-unowned` to
`upgrade` or `rollback` claims them as managed artifacts, and only when each one
still holds exactly the bytes the receipt recorded, so adoption can never
replace content the operator wrote afterwards. Adoption is a one-time decision:
the resulting receipt records the artifacts as owned, and later operations need
no flag. Without the flag, or with a locally changed artifact, the plan stays
blocked and the engine changes nothing.

For the README source-clone layout, the supported first-install migration is an
operator move of the complete fixed-path clone to an explicitly chosen retained
path during the required quiescent maintenance window, followed by generated
release installation. The move preserves `.git`, local edits, and untracked
files while leaving the state root and external runtime configuration in place.
The lifecycle engine does not claim, delete, or rewrite the retained clone, and
continues to refuse an in-place source clone or differing unowned destination
artifacts. [install.md](install.md) gives the exact command sequence.

Rollback uses immutable receipt identity rather than a mutable backup directory.
It is a new transaction against current state, so it repeats liveness and
ownership validation. A legacy timestamp, directory path, guessed predecessor,
or receipt from another fixed-root identity is unsupported.

Uninstall retains the state root, `broker.lock`, lifecycle namespace, receipts,
journals, recovery tools, provenance, and dialogue data. The terminal
`uninstalled` admission continues to block old loaded writers. There is no
`--purge-state` lifecycle operation.

## Durable records

The stable lifecycle discovery path is:

```text
~/.claude/peer-consults/.council-lifecycle/admission.json
```

Artifact-only transactions retain version 1 admission, plan, journal/progress,
receipt, and recovery behavior. OpenCode registration uses strict format 2;
native registration uses distinct format 3 and a constant three-module copied
closure inside the same version-1 namespace. Version 1 continues to reject every
registration/configuration operation, and format 2 accepts only the two fixed
OpenCode operations. Metadata is strict JSON with bounded size, exact keys,
duplicate-key refusal, finite integer rules, and fixed identifier/path
constraints. Unknown versions or operations fail closed.

The namespace retains:

```text
.council-lifecycle/
├── admission.json
└── v1/
    ├── identity-binding.json   (only after a rebind)
    ├── receipts/
    ├── recovery/
    └── transactions/<transaction-id>/
```

Each transaction binds the fixed roots and their physical identities, the
original lock identity, source manifest and reader-support provenance, exact
initial/prior/target states, immutable recovery-tool digest, permitted outcome
goals, proposed receipt, and per-unit object paths. The admission marker is
either terminal (`committed` or `uninstalled`) with a certifying receipt, or
`recovery_required` with the pending transaction identity.

Directory and metadata writes use file and parent-directory synchronization at
the transaction's durability boundaries. A terminal receipt is published and
verified before terminal admission. Receipt existence alone is not a committed
outcome.

## Recovery contract

The standalone recovery implementation is copied into the lifecycle namespace
before intent. It imports only Python 3.9 standard-library modules and does not
depend on the installed payload, Git, Node, a runtime adapter, or the network.
The lifecycle engine verifies both its interface and the prepared plan through:

```text
<python3> -I -B <recoverer> describe
<python3> -I -B <recoverer> check-plan <plan-path>
```

The recovery interface advertises artifact format 1, OpenCode registration
format 2, native registration format 3, the five fixed artifact unit IDs, and the
original required operations:

- `classify-filesystem-v1`
- `preserve-initial-v1`
- `materialize-selected-v1`
- `activate-five-units-v1`
- `verify-receipt-v1`
- `publish-admission-v1`

The mutating CLI writes and flushes its complete recovery argument vector before
intent. A later `status` invocation on the pending transaction returns a
validated `pending_recovery` object with this shape:

```json
{
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
```

Run the complete returned `recovery_command` without editing its flags, copied
tool path, or state root. It uses the currently running compatible interpreter;
the interpreter path and version captured in the plan remain provenance rather
than an exact-path or patch-release requirement. Recovery requires CPython 3.9
or newer, isolated mode, disabled bytecode writes, and the recoverer's closed
runtime feature probes. An incompatible interpreter or incomplete pending
record refuses before recovery mutation.

Format 2 adds `classify-registration-v1`, `replace-registration-v1`, and
`verify-registration-receipt-v1`. Only the fixed OpenCode semantic operations
are executable without native qualification. The registration replacement runs
after coherent artifact activation when adding the plugin, and before artifact
removal when removing an owned plugin. Terminal receipts bind the selected entry
and ownership origin while allowing unrelated later configuration settings; a
new inverse plan recomputes its narrow patch against those current bytes.

Format 3 adds the four fixed Claude/Codex stdio operations. Its prepared receipt
binds a stable attempt-family identity rather than a particular invocation. The
journal retains sequence zero and, only after a complete `observed_prior` result
with confirmed whole-process-group termination, may append one fresh sequence
one. The second sequence binds the canonical terminal digest of sequence zero,
a new execution admission, and a complete fresh quiescent decision. Unknown
evidence never advances; another prior result exhausts the family. Recovery of
an already observed target performs no native relaunch. Abort/removal is a new,
separately qualified inverse transaction and a distinct family.

The recoverer acquires the same `broker.lock`, verifies its physical identity
and every bound record, classifies each destination from hashes, and resumes the
sticky target goal. Mixed intermediate generations and a temporarily absent
payload are expected recoverable states when every observed object matches the
prepared plan.

Recovery can be interrupted and repeated. It verifies all five destinations,
publishes the selected immutable receipt, and only then publishes terminal
admission. If the transaction recorded a validated prior goal, adding `--abort`
selects it durably; repeated recovery continues that selected goal. Abort cannot
change an already terminal transaction and cannot synthesize missing prior data.

A pending format-2 recovery also requires a fresh `--quiescent-edit`, the
recorded registration-plan digest through `--confirm-plan`, and a new
`--invocation-id`, including on `--abort`. Missing or stale confirmation makes no
configuration or progress write: the abort goal is selected in memory and
journalled only after the confirmation validates. A configuration whose bytes
match neither the intended nor the prior digest is refused rather than adopted;
the refusal names the file and all three digests so the operator can restore one
of them exactly. The receipt reports stored configuration,
effective scope, restart requirement, and authenticated readiness separately;
stored success leaves the latter two unobserved until the owning host restarts
and a separately authorized readiness check runs.

A pending format-3 recovery uses the same confirmation fields plus
`--sequence 0|1`. The copied closure verifies constant-named recoverer,
registration, and qualification modules by owner, mode, link count, size, and
hash before executing their already-read bytes. The supervisor receives an
independent descriptor of the C1 `broker.lock` and verifies its identity; it
never holds the lease, so releasing the lease cannot unlock it for a supervisor
that is still alive. It starts blocked, records its PID/PGID/start generation
and attempt-lock identity, and cannot release the fixed vendor argv until the
progress journal has durably recorded `release_authorized`. A supervisor that
outlives its wait is signalled and reaped before the recoverer unwinds. An
unavailable or incomplete process/network/write observer leaves the transaction
pending.

A missing or corrupt plan, receipt, provenance record, recovery file, staged
object, retained prior object, or unexpected destination fails closed. Do not
repair a pending transaction by removing its namespace, changing its lock, or
choosing a similarly named backup.

## Crash-boundary guarantee

The recovery suite interrupts install, upgrade, rollback, uninstall, and allowed
abort paths before and after durability operations. It covers namespace and
intent publication, immutable record writes, each per-unit preservation,
materialization and activation, progress updates, receipt publication, admission
publication, and cleanup of owned staging.

At any covered boundary, recovery must reach one complete outcome permitted by
the prepared plan. It may not certify a mixed five-unit set. Tests also remove
the normal payload and source checkout, poison imports, repeat recovery, and
interrupt the recoverer itself.

These checks establish software ordering and recovery behavior on disposable
filesystems. They do not claim physical-device power-loss qualification or live
host adoption. Live installation, runtime shutdown, registration changes,
OpenCode pin renewal, and clean-room acceptance remain separately authorized
operator work.

## Development verification

The focused source checks are:

```sh
sh -n install/install.sh
sh -n install/upgrade.sh
sh -n install/rollback.sh
sh -n install/uninstall.sh
python3 scripts/test_lifecycle.py
python3 scripts/test_lifecycle_recovery.py
python3 -m unittest discover -s scripts -p 'test_registration*.py' -v
python3 scripts/test_admission.py
python3 scripts/test_predecessors.py
python3 scripts/build_release.py --check
```

The tests use temporary roots and generated fixture releases. They do not touch
the fixed production roots. See [development.md](development.md) for the full
repository verification set and [install.md](install.md) for operator-facing
commands.
