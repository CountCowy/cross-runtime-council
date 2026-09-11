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
python3 -I -B scripts/council_lifecycle.py install --release <generated-release> --maintenance-window-confirmed
python3 -I -B scripts/council_lifecycle.py upgrade --release <generated-release>
python3 -I -B scripts/council_lifecycle.py rollback --receipt <receipt-id>
python3 -I -B scripts/council_lifecycle.py uninstall
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

An install does not convert matching pre-existing external files into owned
artifacts. A later uninstall preserves those unowned files. Any changed owned
file, missing owned file, unexpected payload entry, unowned conflict, payload
`.git` entry, or pending recovery is a blocker. The operator resolves the
underlying ownership decision outside the lifecycle engine and requests a fresh
plan; the engine does not select, delete, or relocate the content.

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

Version 1 lifecycle records include admission, plan, journal/progress, receipt,
and recovery formats. Metadata is strict JSON with bounded size, exact keys,
duplicate-key refusal, finite integer rules, and fixed identifier/path
constraints. Unknown versions or operations fail closed.

The namespace retains:

```text
.council-lifecycle/
├── admission.json
└── v1/
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

The recovery interface advertises admission, plan, journal, and receipt format
1; the five fixed unit IDs; and these required operations:

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
python3 scripts/test_admission.py
python3 scripts/test_predecessors.py
python3 scripts/build_release.py --check
```

The tests use temporary roots and generated fixture releases. They do not touch
the fixed production roots. See [development.md](development.md) for the full
repository verification set and [install.md](install.md) for operator-facing
commands.
