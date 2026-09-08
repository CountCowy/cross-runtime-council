# Definitions and release provenance

Maintainers edit `scripts/council_protocol.py` for shared enums, bounds and
static tool arguments. The broker imports these values, the MCP adapter requests
independent schema copies, and both OpenCode entrypoints use the generated
`openCodeToolArgs` builder. Descriptions and execution remain with their adapters.
The broker still owns authentication, phase/role checks, relational bounds,
ledger validation, persistence and acknowledgements.

After changing definitions, the maintainer runs:

```sh
python3 scripts/generate_protocol.py
```

The output is committed TypeScript. Generation requires Python 3.9+, with no Node
runtime or new Python dependency. The generator emits explicit SDK expressions;
there is no installed generic schema interpreter. It does not insert defaults.
In particular, omitted round-policy arguments must remain distinguishable from
explicit default-valued arguments and `false`. The adapters apply defaults and
forward their independent `*_provided` flags; the broker persists source labels.

The static tool-schema continuation is included: eleven OpenCode tool shapes now
share one definition with the MCP surface. MCP's explicit runtime selector,
wake-router tools, nullable status argument and peer-selection schema remain
intentional differences. Independent literal fixtures exercise argument
acceptance and actual adapter forwarding, separately from generated-output parity.

Shared payload-schema generation remains the next gated continuation. Before
extracting the broker's advertised payload schemas, the maintainer must establish
independent accepted/rejected fixtures for all seven submission kinds, concession
transitions, dynamic ledger overlays and byte-versus-character bounds. Existing
broker behavior and tests remain authoritative until that gate is met.

## Offline release preparation

A maintainer works in a separate development checkout, stages the intended files
so Git includes new inputs, and runs:

```sh
python3 scripts/generate_protocol.py --check
python3 scripts/build_release.py --write
python3 scripts/build_release.py --check
```

`--write` refreshes embedded identity literals and `release_manifest.json`; the
maintainer commits those outputs with the source change. It refuses the supported
installed-payload location. The builder reads the working bytes of Git-tracked
files, so staging does not freeze their content. The maintainer uses a quiescent
checkout for release preparation. Untracked files are excluded; missing runtime
inputs, missing tracked files and symlink inputs are errors.

For a new offline release directory, the maintainer runs:

```sh
python3 scripts/build_release.py --output /tmp/council-release
```

The destination must not exist and must be outside the source checkout. It
contains `payload/` with the tracked source snapshot, `opencode/` with the exact
external copy layout, and a manifest binding each final artifact's bytes. It does
not install, restart hosts, mutate registration or touch broker state. The current
shell installer remains a separate legacy operation; a managed transaction cannot
be enabled until its complete external recovery path is implemented.

Package identity covers tracked release inputs, including documentation/tests.
Runtime cohort identity covers the eight executed source components listed in
`build_release.py`; standalone documentation/test changes preserve that cohort.
Each identity hashes sorted path/digest pairs with identity literal fields
normalized, avoiding self-referential hashes. The manifest itself is excluded
from the identity preimage and records final hashes after stamping. Adding an
executed component requires updating the explicit runtime inventory and its
entry/helper checks.

Every runtime component carries its own literal cohort. Python entrypoints
compare it with loaded helpers; OpenCode compares loaded definitions/registry,
and the tool wrapper validates a private versioned plugin registration before
execution. These checks describe loaded code, rather than re-hashing a source
path that may have been replaced since import. Broker `ping` includes the loaded
package and cohort identities. Documentation-only package differences do not
reject a compatible runtime cohort.

This is compatibility checking within Council's existing trust model. It is not
attestation, proof of predecessor state-reader support, authenticated cross-process
cohort admission, proof that hosts restarted, or a recoverable updater. Those
lifecycle and broker-route gates remain subsequent work. Doctor's external-copy
checks describe files on disk; they do not establish loaded-host readiness.

## Verification

CI checks committed generation and release stamps, all existing Python/Node
suites, and the additional semantic/provenance suites:

```sh
python3 scripts/test_parity.py
node --experimental-transform-types --test scripts/test_protocol.ts
python3 scripts/test_release.py
```

Tests require the pinned development dependencies from `.github/workflows/ci.yml`.
The adapter test uses real generated SDK argument schemas, the actual wrapper and
plugin, a temporary home-directory probe and a stubbed transport. The release
suite covers independent final hashes, repeatability, docs-only changes, loaded
source replacement, mixed helper generations, the actual external directory
layout, and non-destructive refusal cases. These offline fixtures do not satisfy
the signed-runtime live recovery gates.

The [live rehearsal contract](live-rehearsal.md) specifies the separate G1–G5
release observations and links an unexecuted run-record template. The maintainer
records real recipient evidence before making a live compatibility claim; the
assisted runner and complete-source capture adapters remain subsequent work.
