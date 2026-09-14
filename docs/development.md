# Definitions, release provenance, and lifecycle development

Maintainers edit `scripts/council_protocol.py` for shared enums, bounds, and
static tool arguments. The broker imports those values, the MCP adapter requests
independent schema copies, and both OpenCode entrypoints use the generated
`openCodeToolArgs` builder. Descriptions and execution remain with their
adapters. The broker still owns authentication, phase and role checks, relational
bounds, ledger validation, persistence, and acknowledgements.

After changing definitions, run:

```sh
python3 scripts/generate_protocol.py
```

The output is committed TypeScript. Generation requires Python 3.9 or newer and
no new Python dependency. The generator emits explicit SDK expressions; there is
no installed generic schema interpreter. It does not insert defaults. Omitted
round-policy arguments must remain distinguishable from explicit default-valued
arguments and `false`. Adapters apply defaults and forward independent
`*_provided` flags; the broker persists source labels.

The static tool-schema continuation shares definitions between eleven OpenCode
tool shapes and the MCP surface. MCP's explicit runtime selector, wake-router
tools, nullable status argument, and peer-selection schema remain intentional
differences. Literal fixtures exercise argument acceptance and actual adapter
forwarding separately from generated-output parity.

Independent payload fixtures cover all seven submission kinds, the concession
matrix, dynamic ledger overlays, copy isolation, and exact UTF-8 byte versus
character bounds. `scripts/fixtures/payloads.json` and
`payload_contracts.json` contain literal expectations independent of production
definitions. They preserve advertised-schema versus broker-validation
differences, including arbitrary correction-list items and nullable
`duplicate_of`.

The six synthesis-required field names share the immutable Python
`SYNTHESIS_REQUIRED_FIELDS` tuple; the advertised contract and both synthesis
request builders return list copies. Broader payload-schema extraction remains
gated on a demonstrated maintenance benefit. Generic adapter payload interfaces
and dynamic broker validation remain unchanged.

## Offline release preparation

Use a separate, quiescent development checkout. Stage every intended new input
so Git includes it, then run:

```sh
python3 scripts/generate_protocol.py --check
python3 scripts/build_release.py --write
python3 scripts/build_release.py --check
```

`--write` refreshes embedded identity literals and `release_manifest.json`.
Commit those outputs with their source change. The builder reads the working
bytes of every Git-tracked input; staging includes a new path but does not freeze
its content. Untracked files are excluded. Missing runtime inputs, missing
tracked files, symlink inputs, and attempts to stamp the installed payload are
errors.

Emit a standalone release into a new directory outside the checkout:

```sh
python3 scripts/build_release.py --output /tmp/council-release
```

The directory contains root `release_manifest.json`, a complete `payload/`
snapshot, and `opencode/` copies for the plugin, protocol, delivery registry, and
tool. The manifest binds every final path and byte hash. The builder preserves
only source executable bits; other release files use deterministic
non-executable modes. It does not install, inspect or mutate a live Council
runtime.

Inspect the emitted artifact without copying its manifest:

```sh
python3 -B scripts/council_inspect.py \
  --state-root /tmp/council-release-empty-state \
  --release-root /tmp/council-release
```

Package identity covers all tracked release inputs, including documentation and
tests. Runtime cohort identity covers the explicit executed-source inventory in
`build_release.py`. Each identity hashes sorted path/digest pairs after
normalizing identity literals, which avoids a self-referential digest. The
manifest is outside its own preimage and records final hashes after stamping.
Adding an executed component requires updating the explicit runtime inventory
and every corresponding loaded-source check.

Every runtime component carries its own package and cohort literals. Python
entrypoints compare loaded helpers; OpenCode compares loaded definitions and the
delivery registry; the tool wrapper validates its private versioned plugin
registration. These are loaded-code consistency checks within Council's trust
model, not executable attestation.

## Lifecycle architecture

`scripts/council_lifecycle.py` owns release validation, deterministic ownership
planning, C1 admission and registration revalidation, transaction preparation,
and normal execution handoff. It loads its required local Python helpers from
verified single-linked source bytes and runs with bytecode writes disabled.

`scripts/council_recover.py` owns strict lifecycle formats, path classification,
durability primitives, five-unit artifact transitions, immutable receipts, and
recovery. Its retained external copy uses Python 3.9 standard-library modules
only and remains executable when the installed payload and source checkout are
absent.

The shell launchers contain no lifecycle policy. Each resolves its adjacent
`scripts/council_lifecycle.py` path and uses `exec python3 -I -B` with one fixed
verb. Add validation, policy, generation, socket/liveness inspection, recovery
selection, or filesystem mutation to Python rather than a shell wrapper.

The lifecycle entrypoint has fixed production roots and exposes this parser
contract:

```text
status
plan install --release <generated-release>
plan upgrade --release <generated-release>
plan rollback --receipt <receipt-id>
plan uninstall
install --release <generated-release> --maintenance-window-confirmed
upgrade --release <generated-release>
rollback --receipt <receipt-id>
uninstall
```

Only a generated entrypoint may infer its enclosing release. Source checkouts
require `--release`. Mutating commands publish their exact external recovery
argument vector on standard error before intent and canonical JSON on standard
output after success.

The planner remains non-executable and read-only. Execution revalidates under
the existing `broker.lock` writer lease, refuses blocked registrations, verifies
the independently staged recovery program with both `describe` and `check-plan`,
and only then publishes `recovery_required`. Recovery publishes and verifies a
receipt for all five units before terminal admission.

The lifecycle namespace, lock, receipts, journals, provenance, and recovery
tools survive ordinary uninstall. `--purge-state`, timestamped backup rollback,
clone relocation, native runtime registration, OpenCode configuration edits,
pin renewal, and host restarts are outside this engine.

See [lifecycle.md](lifecycle.md) for the operation, record, and recovery
contracts. See [maintenance-admission.md](maintenance-admission.md) for writer
lifetime, exact frozen readers, and the C1/C2 boundary.

## Test boundaries

Lifecycle and recovery tests use disposable roots, generated fixture releases,
and subprocesses. They must never access the fixed production roots. The
recovery suite exercises normal and optimized Python, an absent payload, poisoned
imports, repeated recovery, and interruption before and after durable boundaries.
Its independent filesystem oracle accepts only coherent outcomes recorded by the
prepared plan.

Reader-support evidence is split into three claims: state-reader compatibility,
managed-writer admission, and external-recoverer plan support. A release must
carry positive evidence for each; one result does not substitute for another.
Frozen predecessor sources and their digests remain immutable. Add a new
candidate and regenerate corpus metadata rather than changing an existing
candidate's bytes.

The source crash matrix proves software ordering against disposable filesystems.
It does not qualify physical-device power loss, a private installed artifact,
running host shutdown, native registration changes, or live adoption. Record
those results only after their separate, explicitly authorized rehearsal.

## Verification

Run focused lifecycle checks while iterating:

```sh
sh -n install/install.sh
sh -n install/upgrade.sh
sh -n install/rollback.sh
sh -n install/uninstall.sh
python3 scripts/test_lifecycle.py
python3 scripts/test_lifecycle_recovery.py
python3 scripts/test_admission.py
python3 scripts/test_predecessors.py
```

Before release handoff, run generation, release, Python, and Node gates from the
repository root:

```sh
python3 -m ruff check .
python3 scripts/generate_protocol.py --check
python3 scripts/build_release.py --check
python3 scripts/test_council.py
python3 scripts/test_parity.py
python3 scripts/test_deletion_crash.py
python3 scripts/test_recovery_invariants.py
python3 scripts/test_crash_matrix.py
python3 scripts/test_admission.py
python3 scripts/test_predecessors.py
python3 scripts/test_lifecycle.py
python3 scripts/test_lifecycle_recovery.py
npx tsc --noEmit
node --experimental-strip-types --test scripts/test_opencode_delivery_registry.ts
node --experimental-transform-types --test scripts/test_protocol.ts
env -u SOURCE_DATE_EPOCH python3 scripts/test_release.py
SOURCE_DATE_EPOCH=1700000000 python3 scripts/test_release.py
```

CI supplies the pinned development dependencies and runs the lifecycle recovery
suite on its supported macOS/Python matrix. Preserve committed example digest and
render checks when changing the release inventory.
