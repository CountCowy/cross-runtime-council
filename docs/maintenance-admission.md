# Maintenance admission (source preparation)

C1 supplies inspection and writer admission. It does not install, update, adopt,
roll back, uninstall, recover a lifecycle transaction, or certify an existing
installation. C2 must supply the complete external recoverer, actual receipt and
journal formats, artifact ownership and crash evidence before managed activation.
The operator still owns the initial maintenance window and live adoption.

## Read-only evidence

The operator can run `python3 -B scripts/council_inspect.py`. The inspector neither
imports `council` nor constructs a broker, connects to a socket, expires a route,
repairs JSONL, quarantines a file, creates a missing root or writes a report file.
Explicit test roots are available through `--state-root`, `--payload-root` and
`--opencode-root`; production layout remains fixed. `council.py doctor` now uses
this offline inspection instead of ping. Its `local_runtime_ready` and broker
reachability are null, and authenticated readiness is explicitly unobserved.

The report separates the observed release-manifest hashes/cohort, admission
metadata/receipt binding, registration liveness, structural artifact errors and
aggregate restoration limitations. A valid admission envelope does not establish
artifact integrity, reader compatibility, coherent recovery or participant
readiness. A source checkout without installed provenance stays unmanaged.
Package identity is diagnostic; runtime cohort equality determines compatibility
within the existing trust model. It is not attestation or authority.

Inspection covers dialogue manifests, submissions, final packets and durable
`audit.jsonl`; outbox and registration records; router, retention and OpenCode
pin configuration; and tombstones. It observes the manifest's payload artifacts
and all four external OpenCode copies. Ephemeral relay sockets, `broker.log`, MCP
output, host transcripts and rendered exports are outside the retained-reader and
replacement sets. Inspection does not lock or claim to freeze those outputs.

Each inventory is bounded to 10,000 entries, 4 MiB per file and 64 MiB of file
content. Admission envelopes and receipt bytes have a separate 1 MiB limit.
Failed enumeration, symlinks, malformed/unsupported state and incomplete
inventories remain explicit errors, never empty-state evidence. The public
report omits capability hashes, relay owners, relay paths and dialogue content.
The private registration snapshot records the complete name set, exact bytes,
filesystem identities and original metadata; missing generations remain missing.

Liveness uses at most one signal-zero check and one two-second `ps` probe per
distinct holder PID, cached within an inspection. The probe budget stops starting
new probes after ten seconds (a last in-flight probe may add two seconds).
Only ESRCH proves absence. Permission errors, timeouts and unsupported or
noncomparable identity observations remain unknown. A matching legacy
second-resolution `ps` identity is conservatively live; a different timestamp
never proves death. Legacy Codex has no trustworthy holder metadata and stays
unknown until valid expiry. Expired and positively dead routes may stop blocking
solely on liveness; their compatibility/restoration problems remain visible and
their files remain unchanged. Dormant phase alone is not a blocker.

C2 must acquire the lease and call `revalidate_under_lease(snapshot, lease, now,
probe)` immediately before intent. The operation repeats exact inventory and
identity checks and re-probes liveness. New/disappeared/replaced records, changed
bytes, a displaced root/lock, unknown identities and malformed records invalidate
admission. A pre-lock report is informational and cannot authorize intent.

## Writer lifetime and transport

`acquire_writer_lease(root)` owns the existing `broker.lock` inode using exclusive
nonblocking flock. A failed contender cannot truncate its diagnostic record or
change reader-sensitive state. The lease binds the canonical root, descriptor,
lock inode and acquiring process. A forked child cannot borrow or unlock its
parent's lease. The owner must close the lease; nested operations borrow without
re-locking or releasing it. Lock order is OS lease before broker RLock.

`CouncilBroker(root)` owns a lease until `close()` or context exit. Direct callers
must close before reconstructing a broker for the same root. A caller can pass
`lease=lease` explicitly; closing that broker does not close the borrowed lease.
The owning close waits for active operations. Private file helpers are internal
implementation details, not independent supported writer APIs.

Daemon startup, restoration, expiry, retention, binding, configuration, dialogue
transactions, delivery and acknowledgement/recovery all run under that lifetime
lease. Offline delete and all configuration paths, including retention disable,
use the same exclusion instead of a socket probe. Runtime admission is reread
under the lease before constructor/configuration writes. The daemon stops
acceptance and joins accepted bounded handlers before releasing the lease; it
never joins while holding the broker RLock. Ordinary request cohort checks are
local comparisons. They add no network call, process inventory or retry fan-out.
No performance improvement is claimed.

Clients construct top-level `runtime_cohort` metadata privately. The broker
checks existing signed-runtime/capability and exact-scope authority first, then
checks request and admitted-route cohorts before dispatch. A matching cohort
cannot grant authority. Rejected incompatible requests do not expire routes.
Persisted matching-cohort routes retain their prior authorization after restart;
participant operations still prove their retained capability and current request
cohort. Authenticated router claim/ack checks its retained capability and both
stored/request cohorts on every call, so a surviving router needs no bootstrap
RPC after a compatible restart. Compatible idle Codex recipients remain wakeable.
Legacy or incompatible route cohorts remain tombstones until ordinary
authenticated bind/rebind. Restored Claude/OpenCode relay secrets and transport
readiness remain absent until exact-session relay reauthentication; automatic
delivery skips those transports and all incompatible recipients. Package-only changes remain compatible when
the runtime cohort is unchanged.

The OpenCode plugin puts its executed cohort in bridge stdin. A newly launched
bridge verifies that origin and preserves it to the broker; it cannot replace an
old plugin's origin with its own newly loaded stamp. Known version/maintenance
failures do not trigger startup loops. Pending binding/router rotations survive
failed retries, including a failure after a lost acknowledgement. Pending
extensions retain their logical ID across version, maintenance, authorization,
transport, malformed and unknown errors, expiry and same-scope rebind. Only an
established `extension_precommit_rejected` releases an extension ID for changed
arguments. Successful unbind remains an explicit termination of that binding.

Runtime Python entrypoints set `sys.dont_write_bytecode` before custom imports.
This prevents incidental payload writes; it does not make stale caches safe.
Loaded-helper cohort checks and optimized stale-cache rejection remain release
gates. Source generators are offline developer operations.

## Inert lifecycle envelope

The stable discovery path is `$STATE/.council-lifecycle/admission.json`.
Namespace absence means unmanaged. Any other namespace form fails closed unless
its strict v1 envelope and receipt binding verify. JSON duplicate keys,
nonregular/symlink metadata, unknown fields/versions/status, malformed IDs/hashes,
unreadable paths, mismatched canonical roots and missing/mismatched receipts
refuse ordinary writers. IDs match `[A-Za-z0-9][A-Za-z0-9_-]{0,95}`.

The envelope has exactly `format: 1`, `namespace_version: 1`, canonical `roots`
(`state`, `payload`, `opencode`), `status`, `transaction_id` and `committed`.
Only `committed` with a null transaction and a matching committed cohort admits
an ordinary writer. Its summary contains `receipt_id`, `receipt_sha256`,
`package_id` and `runtime_cohort`; the digest binds exact bytes at
`v1/receipts/<receipt_id>.json`. `recovery_required` requires a transaction ID;
`uninstalled` has no active transaction. Both refuse writers. C1 reads receipt
bytes opaquely and makes no claim about their internal format or recoverability.
C1 creates these records only inside disposable test fixtures.

All four legacy scripts refuse namespace existence before clone/no-op, backup,
replacement and purge paths, including dangling links and guard failure. This
is a refusal fence, not an atomic adoption transaction. Historic unfenced copies
and already loaded pre-C1 writers still require the operator's initial window.
The operator must use C2's compatible managed engine/recoverer after activation;
neither deleting the marker nor deleting/replacing `broker.lock` is a recovery
step. C2 must retain the root, lock inode and recovery/control namespace after
managed uninstall/purge, and preserve source clones and unowned/local edits.

## Frozen-reader evidence

`python3 scripts/test_predecessors.py` runs offline, including in a shallow
checkout. The committed fixture manifest pins actual source import closures,
licenses, Git commit/blob identities and SHA-256 bytes for:

- Immediate predecessor `a3f35b07207e85af1aafbd21933182aa87570e1b` (broker plus
  protocol helper).
- Public v0.19 candidate `f376101e1ee2092fe01152232f48c306b4a1ba21` (self-contained
  broker). These are not the user's separately modified installed 0.19 bytes.

Each reader runs in a separate isolated subprocess on copied corpus state with
bytecode disabled. Its actual constructor, status/submission/final readers and
recovery code execute unmodified, with only a declared clock and transport trap.
The oracle checks preserved submission/final/configuration bytes, participant
scope, logical responses/extension IDs, phase reconstruction, unavailable relay
restoration, staged work, audit intents, deletion and retention. Corpus coverage
is checked from real files, independently of tags. The support matrix records
actual outcomes; unknown schemas and malformed state are explicit refusals even
when an old parser silently accepts them. Public v0.19 retains an orphan final
that pre-C1 recovers, so that reader/state tuple is refused. Neither predecessor
supports managed writer admission; reader success alone never authorizes managed
rollback. C2 must add its real receipt/journal/recovery corpora before claiming
support for those formats.
