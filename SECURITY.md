# Security Policy

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting** on this repository
("Report a vulnerability" under the Security tab). Do not open public issues
for suspected vulnerabilities.

This is a best-effort, single-maintainer project with **no response SLA**.
Reports are read and triaged as capacity allows. Coordinated disclosure is
appreciated; if you receive no response within 30 days, you may disclose
publicly.

## Supported versions

Only the **latest tagged release** receives security fixes. Older tags are not
patched. Configurations outside [docs/compatibility.md](docs/compatibility.md)
are untested and out of scope.

## Threat model (summary)

Council coordinates planning dialogues between coding-agent sessions on **one
machine, for one user**. Its guarantees are deliberately narrow.

**What it defends against:**

- An arbitrary local process (shell script, unsigned binary) impersonating a
  participant: binding requires a live launcher process chain terminating at a
  signed Codex/Claude runtime, or the offline path/SHA-256/code-directory-hash
  pinned OpenCode CLI executable.
- Replay, duplication, cross-session takeover, and stale-route delivery:
  memory-only capabilities, per-child owner nonces, capability-generation
  checks, message-ID dedupe, and lease-bounded registrations.
- Credential exfiltration through dialogue payloads: a conservative egress
  guard rejects recognizable token families and sensitive key names before
  persistence or send.
- Peer-driven privilege escalation: peer messages are data; the protocol
  grants them no authority, and wake markers carry no content.

**What it explicitly does NOT defend against (out of scope by design):**

- A malicious sibling MCP server, plugin, or extension running **inside** an
  admitted runtime. Origin proof authenticates the runtime, not its children.
- Compromise or modification of the adapter code itself on disk.
- A hostile or compromised model/provider. Model identity is metadata, never
  authentication.
- Anything cross-machine or cross-user. The broker binds a user-owned Unix
  socket with `0600`/`0700` modes and exposes no network listener.
- Stale OpenCode pins the user chooses to re-approve without verifying the
  binary they are pinning.

**Trust anchors are macOS-specific** (code-signing evidence, process chains,
CDHash checks) and version-sensitive: vendor updates can invalidate them, in
which case Council fails closed until re-pinned or updated. Failing closed on
an untested configuration is expected behavior, not a vulnerability.

## Disclosure boundaries

Reports demonstrating a violation of the defended properties above are in
scope. Reports that reduce to the documented exclusions (sibling-process
attacks inside an admitted runtime, adapter tampering, unsupported platforms
or versions) will be acknowledged and documented but are not treated as
vulnerabilities.
