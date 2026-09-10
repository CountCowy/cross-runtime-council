import {
  ENVELOPE_PREAMBLE, RELAY_ENVELOPE_KINDS as PROTOCOL_RELAY_KINDS,
  DEFAULT_LEASE_MINUTES, DEFAULT_ROUNDS, DEFAULT_MINIMUM_ROUNDS,
  DEFAULT_MAX_ROUNDS, DEFAULT_ACTIVE_CLAIM_CEILING, openCodeToolArgs,
  BIND_COMMIT_STATUSES,
  MAX_LEASE_MINUTES, MAX_TEXT_BYTES, RUNTIME_COHORT as PROTOCOL_COHORT,
  SAFE_NAME_PATTERN,
} from "./council_protocol.ts"
import { type Plugin, tool } from "@opencode-ai/plugin"
import { randomBytes } from "node:crypto"
import { chmodSync, mkdirSync, unlinkSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { createServer, type Socket } from "node:net"
import {
  bindingGenerationMatches,
  normalizeErrorReason,
  normalizedBrokerPeer,
  OpenCodeDeliveryRegistry,
  PendingExtensionRegistry,
  prepareRelaySocket,
  rejectOversizedRelayBuffer,
  safeRelayEnd,
  shouldDropLocalBinding,
  type ErrorReason,
  RUNTIME_COHORT as REGISTRY_COHORT,
  TOOL_REGISTRY_KEY,
  type ToolRegistration,
} from "./opencode_delivery_registry.ts"

type BridgeResponse = {
  ok: boolean
  result?: unknown
  error?: string
  error_kind?: "rejected" | "error" | "internal"
  reason?: unknown
  commit_status?: unknown
}

type DaemonStartupStatus = {
  ok: boolean
  reason: ErrorReason | null
  retryable: boolean
}

const PACKAGE_ID = "68ce315f8d4f8b32516b2feeafb629a44a130a83ce3d1ec09fe352ec323da258"
const RUNTIME_COHORT = "8181ae63906b42e4af670df1613dede4d194c48991594e3b8ea9b961877831b5"
const DAEMON_STARTUP_TIMEOUT_MS = 3000
const MAX_DAEMON_STARTUP_STATUS_BYTES = 1024
const MAX_PENDING_BINDING_ROTATIONS = 32
if (RUNTIME_COHORT !== PROTOCOL_COHORT || RUNTIME_COHORT !== REGISTRY_COHORT) {
  throw new Error("Council plugin/helper cohort mismatch; refresh the complete runtime set")
}
const RELAY_ENVELOPE_KINDS = new Set<string>(PROTOCOL_RELAY_KINDS)
const toolArgs = openCodeToolArgs(tool.schema)

type Binding = {
  participant: string
  sessionID: string
  capability: string
  relayCapability: string
}

type PendingRotation = {
  capability: string
  previousCapability?: string
  relayCapability: string
  inFlight: number
  uncertain: boolean
  deliveryStateWasPresent?: boolean
}

class BridgeError extends Error {
  readonly reason: ErrorReason

  constructor(
    message: string,
    readonly kind?: string,
    reason?: unknown,
    readonly commitStatus?: typeof BIND_COMMIT_STATUSES[number],
  ) {
    super(message)
    this.reason = normalizeErrorReason(reason)
  }
}

const stateRoot = join(homedir(), ".claude", "peer-consults")
const bridgePath = join(
  homedir(),
  ".claude",
  "skills",
  "council",
  "scripts",
  "council_opencode.py",
)
const brokerPath = join(
  homedir(),
  ".claude",
  "skills",
  "council",
  "scripts",
  "council.py",
)

const bindings = new Map<string, Binding>()
const pendingRotations = new Map<string, PendingRotation>()
const deliveryRegistry = new OpenCodeDeliveryRegistry()
const pendingExtensions = new PendingExtensionRegistry()

const submitDescription =
  "Submit the response requested by a Council envelope. Use payload.response_contract from that exact envelope as the authoritative kind, round, payload schema, enum, and active-claim contract; never guess an omitted field or enum."

function key(sessionID: string, participant: string) {
  return `${sessionID}\u0000${participant}`
}

function capability() {
  return randomBytes(48).toString("base64url")
}

const safeNamePattern = new RegExp(`^(?:${SAFE_NAME_PATTERN})$`)

function validateBindInputs(
  args: {
    participant: string
    label: string
    project: string
    lease_minutes?: number
  },
  sessionID: string,
) {
  for (const [field, value] of [
    ["participant", args.participant],
    ["target_session_id", sessionID],
  ] as const) {
    if (typeof value !== "string" || !safeNamePattern.test(value)) {
      throw new BridgeError(
        `${field} must match [A-Za-z0-9][A-Za-z0-9_.-]{0,79}`,
        "error",
        "invalid_request",
      )
    }
  }
  for (const [field, value] of [
    ["label", args.label],
    ["project", args.project],
  ] as const) {
    if (typeof value !== "string" || !value.trim()) {
      throw new BridgeError(`${field} must not be empty`, "error", "invalid_request")
    }
    if (new TextEncoder().encode(value).byteLength > MAX_TEXT_BYTES) {
      throw new BridgeError(
        `${field} exceeds ${MAX_TEXT_BYTES} bytes`,
        "error",
        "invalid_request",
      )
    }
  }
  const leaseMinutes = args.lease_minutes ?? DEFAULT_LEASE_MINUTES
  if (!Number.isInteger(leaseMinutes) || leaseMinutes < 1 || leaseMinutes > MAX_LEASE_MINUTES) {
    throw new BridgeError(
      `lease_minutes must be between 1 and ${MAX_LEASE_MINUTES}`,
      "error",
      "invalid_request",
    )
  }
}

async function rawBridge(action: string, args: Record<string, unknown>) {
  let child: CouncilBunSubprocess
  try {
    child = Bun.spawn(["python3", bridgePath], {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    })
  } catch {
    throw new BridgeError(
      "OpenCode Council bridge child was not created",
      "internal",
      "broker_unavailable",
      "precommit",
    )
  }
  try {
    child.stdin.write(JSON.stringify(
      { action, arguments: args, runtime_cohort: RUNTIME_COHORT },
    ) + "\n")
    child.stdin.end()
  } catch (error) {
    try {
      child.kill()
    } catch {}
    throw error
  }
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  let response: BridgeResponse
  try {
    response = JSON.parse(stdout.trim()) as BridgeResponse
  } catch {
    throw new BridgeError(
      `OpenCode Council bridge returned invalid JSON${stderr ? `: ${stderr.trim()}` : ""}`,
      "internal",
      "malformed_response",
    )
  }
  if (!response || typeof response !== "object" || Array.isArray(response) || typeof response.ok !== "boolean") {
    throw new BridgeError("OpenCode Council bridge returned an invalid response", "internal", "malformed_response")
  }
  if (response.ok === false) {
    throw new BridgeError(
      typeof response.error === "string" ? response.error : `bridge exited ${exitCode}`,
      response.error_kind,
      response.reason,
      response.commit_status === "precommit" ? "precommit" : undefined,
    )
  }
  if (response.result === null || typeof response.result !== "object" || Array.isArray(response.result)) {
    throw new BridgeError("OpenCode Council bridge returned no broker JSON object", "internal", "malformed_response")
  }
  return response.result
}

let brokerStartup: Promise<void> | undefined

async function readDaemonStartupStatus(
  stream: ReadableStream<Uint8Array>,
  deadline: number,
): Promise<DaemonStartupStatus> {
  const reader = stream.getReader()
  let timedOut = false
  let encoded = new Uint8Array()
  const timeout = setTimeout(() => {
    timedOut = true
    void reader.cancel()
  }, Math.max(0, deadline - performance.now()))
  try {
    while (encoded.byteLength <= MAX_DAEMON_STARTUP_STATUS_BYTES) {
      const { value, done } = await reader.read()
      if (done) break
      if (value) {
        const combined = new Uint8Array(encoded.byteLength + value.byteLength)
        combined.set(encoded)
        combined.set(value, encoded.byteLength)
        encoded = combined
      }
      if (encoded.byteLength > MAX_DAEMON_STARTUP_STATUS_BYTES) {
        throw new BridgeError("Council broker returned oversized startup status", "internal", "malformed_response")
      }
      const newline = encoded.indexOf(10)
      if (newline >= 0) {
        let status: unknown
        try {
          status = JSON.parse(new TextDecoder().decode(encoded.slice(0, newline)))
        } catch {
          throw new BridgeError("Council broker returned malformed startup status", "internal", "malformed_response")
        }
        if (
          !status || typeof status !== "object" || Array.isArray(status)
          || typeof (status as { ok?: unknown }).ok !== "boolean"
          || typeof (status as { retryable?: unknown }).retryable !== "boolean"
        ) {
          throw new BridgeError("Council broker returned invalid startup status", "internal", "malformed_response")
        }
        const rawReason = (status as { reason?: unknown }).reason
        if ((status as { ok: boolean }).ok && (rawReason !== null || (status as { retryable: boolean }).retryable)) {
          throw new BridgeError("Council broker returned invalid startup status", "internal", "malformed_response")
        }
        if (!(status as { ok: boolean }).ok && (typeof rawReason !== "string" || normalizeErrorReason(rawReason) !== rawReason)) {
          throw new BridgeError("Council broker returned invalid startup status", "internal", "malformed_response")
        }
        return {
          ok: (status as { ok: boolean }).ok,
          reason: rawReason === null ? null : normalizeErrorReason(rawReason),
          retryable: (status as { retryable: boolean }).retryable,
        }
      }
    }
  } finally {
    clearTimeout(timeout)
    await reader.cancel().catch(() => {})
    reader.releaseLock()
  }
  throw new BridgeError(
    timedOut ? "Council broker startup status timed out" : "Council broker startup status ended early",
    "internal",
    "broker_unavailable",
  )
}

async function waitForDaemonStartupExit(exited: Promise<number>, deadline: number): Promise<number> {
  let timeout: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      exited,
      new Promise<number>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new BridgeError(
            "Council broker startup child did not exit after refusal",
            "internal",
            "broker_unavailable",
          )),
          Math.max(0, deadline - performance.now()),
        )
      }),
    ])
  } finally {
    if (timeout) clearTimeout(timeout)
  }
}

async function ensureBroker() {
  try {
    await rawBridge("ping", {})
    return
  } catch (error) {
    if (!(error instanceof BridgeError) || !["broker_unavailable", "transport_lost"].includes(error.reason)) throw error
  }
  if (!brokerStartup) {
    brokerStartup = (async () => {
      const startupDeadline = performance.now() + DAEMON_STARTUP_TIMEOUT_MS
      const daemon = Bun.spawn(
        ["python3", brokerPath, "daemon", "--state-root", stateRoot, "--startup-report"],
        { stdin: "ignore", stdout: "pipe", stderr: "ignore" },
      )
      let status: DaemonStartupStatus
      try {
        status = await readDaemonStartupStatus(
          daemon.stdout as ReadableStream<Uint8Array>,
          startupDeadline,
        )
      } catch (error) {
        if (error instanceof BridgeError && error.reason === "malformed_response") {
          daemon.kill()
          try {
            await waitForDaemonStartupExit(daemon.exited, performance.now() + 1000)
          } catch {
            // The bounded startup error remains authoritative.
          }
        }
        throw error
      }
      if (!status.ok) {
        const exitCode = await waitForDaemonStartupExit(daemon.exited, startupDeadline)
        if (exitCode === 0) {
          throw new BridgeError(
            "Council broker startup child reported refusal with a successful exit",
            "internal",
            "malformed_response",
          )
        }
        if (!status.retryable) {
          throw new BridgeError(
            `Council broker startup failed: ${status.reason}`,
            "rejected",
            status.reason,
          )
        }
        let lastError: unknown
        while (performance.now() < startupDeadline) {
          await new Promise<void>((resolve) => setTimeout(resolve, 50))
          try {
            await rawBridge("ping", {})
            return
          } catch (error) {
            if (!(error instanceof BridgeError) || !["broker_unavailable", "transport_lost"].includes(error.reason)) throw error
            lastError = error
          }
        }
        throw lastError instanceof Error
          ? lastError
          : new BridgeError("Council broker startup race did not become ready", "internal", "broker_unavailable")
      }
      await rawBridge("ping", {})
    })().finally(() => {
      brokerStartup = undefined
    })
  }
  await brokerStartup
}

async function bridge(action: string, args: Record<string, unknown>) {
  await ensureBroker()
  return rawBridge(action, args)
}

function bindingFor(sessionID: string, participant: string) {
  const binding = bindings.get(key(sessionID, participant))
  if (!binding) {
    throw new BridgeError(
      `this OpenCode session has no Council capability for ${participant}; bind it first`,
    )
  }
  return binding
}

function safeResult(value: unknown) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BridgeError("OpenCode Council bridge returned no broker JSON object", "internal", "malformed_response")
  }
  const encoded = JSON.stringify(value, null, 2)
  if (!encoded.trim()) {
    throw new BridgeError("OpenCode Council bridge returned an empty broker result", "internal", "malformed_response")
  }
  return encoded
}

function relayBinding(participant: string, relayCapability: string) {
  for (const item of bindings.values()) {
    if (item.participant === participant && item.relayCapability === relayCapability) return item
  }
  for (const [identity, pending] of pendingRotations) {
    const separator = identity.indexOf("\u0000")
    if (identity.slice(separator + 1) !== participant) continue
    if (pending.relayCapability !== relayCapability) continue
    return {
      participant,
      sessionID: identity.slice(0, separator),
      capability: pending.capability,
      relayCapability: pending.relayCapability,
    }
  }
}

export const CouncilPlugin: Plugin = async ({ client }) => {
  const relayDir = join(stateRoot, "relays")
  mkdirSync(relayDir, { recursive: true, mode: 0o700 })
  chmodSync(relayDir, 0o700)
  const relayPath = join(
    relayDir,
    `opencode-${process.pid}-${randomBytes(8).toString("hex")}.sock`,
  )

  const relaySockets = new Set<Socket>()
  const server = createServer((socket: Socket) => {
    relaySockets.add(socket)
    socket.once("close", () => relaySockets.delete(socket))
    socket.setTimeout(5000, () => socket.destroy())
    let buffer = ""
    prepareRelaySocket(socket)
    socket.setEncoding("utf8")
    socket.on("data", (chunk) => {
      buffer += chunk
      if (rejectOversizedRelayBuffer(socket, buffer.length)) return
      if (!buffer.includes("\n")) return
      const line = buffer.slice(0, buffer.indexOf("\n"))
      void (async () => {
        try {
          const request = JSON.parse(line) as {
            type?: string
            content?: string
            relay_capability?: string
          }
          if (request.type !== "deliver" || typeof request.content !== "string") {
            throw new Error("unsupported relay request")
          }
          const content = request.content
          if (!content.startsWith(ENVELOPE_PREAMBLE)) {
            throw new Error("OpenCode relay accepts only Council envelopes")
          }
          const envelope = JSON.parse(content.slice(ENVELOPE_PREAMBLE.length)) as {
            schema_version?: number
            message_id?: string
            recipient?: string
            kind?: string
            payload?: unknown
          }
          if (
            envelope.schema_version !== 1 ||
            typeof envelope.message_id !== "string" ||
            typeof envelope.recipient !== "string" ||
            typeof envelope.kind !== "string" ||
            !RELAY_ENVELOPE_KINDS.has(envelope.kind) ||
            typeof envelope.payload !== "object" ||
            !request.relay_capability
          ) {
            throw new Error("OpenCode relay envelope is invalid")
          }
          const binding = relayBinding(envelope.recipient, request.relay_capability)
          if (!binding) throw new Error("OpenCode relay authentication failed")
          const messageID = envelope.message_id
          const result = await deliveryRegistry.deliver(
            binding.sessionID,
            envelope.recipient,
            messageID,
            async () => {
              const posted = await client.session.promptAsync({
                path: { id: binding.sessionID },
                body: { parts: [{ type: "text", text: content }] },
              })
              if (posted.error) throw new Error("OpenCode rejected Council session delivery")
            },
          )
          safeRelayEnd(
            socket,
            JSON.stringify({ ok: true, duplicate: result.duplicate }) + "\n",
          )
        } catch (error) {
          safeRelayEnd(
            socket,
            JSON.stringify({
              ok: false,
              error: error instanceof Error ? error.message : String(error),
            }) + "\n",
          )
        }
      })()
    })
  })
  server.on("error", () => {})

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject)
    server.listen(relayPath, () => {
      server.off("error", reject)
      chmodSync(relayPath, 0o600)
      resolve()
    })
  })

  async function authenticated(
    sessionID: string,
    participant: string,
    action: string,
    args: Record<string, unknown>,
  ) {
    const identity = key(sessionID, participant)
    const binding = bindingFor(sessionID, participant)
    try {
      return await bridge(action, { ...args, _auth_capability: binding.capability })
    } catch (error) {
      if (
        error instanceof BridgeError &&
        error.kind === "rejected" &&
        shouldDropLocalBinding(error.reason)
      ) {
        if (
          bindingGenerationMatches(
            bindings.get(identity)?.capability,
            binding.capability,
          )
        ) {
          bindings.delete(identity)
          // Expiry does not disprove an earlier pending rotation commit.
          deliveryRegistry.clear(sessionID, participant)
        }
      }
      throw error
    }
  }

  function releaseUncommittedRotation(
    identity: string,
    sessionID: string,
    participant: string,
    pending: PendingRotation,
  ) {
    if (
      pendingRotations.get(identity) !== pending
      || pending.uncertain
      || pending.inFlight !== 0
    ) return
    pendingRotations.delete(identity)
    if (pending.previousCapability) return
    if (pending.deliveryStateWasPresent) {
      deliveryRegistry.clear(sessionID, participant)
    } else if (pending.deliveryStateWasPresent === false) {
      deliveryRegistry.discard(sessionID, participant)
    }
  }

  const hooks = {
    dispose: async () => {
      for (const socket of relaySockets) socket.destroy()
      await new Promise<void>((resolve) => server.close(() => resolve()))
      bindings.clear()
      pendingRotations.clear()
      deliveryRegistry.dispose()
      try {
        unlinkSync(relayPath)
      } catch {}
    },
    tool: {
      council_ping: tool({
        description: "Read the local Council broker version and aggregate health.",
        args: toolArgs.council_ping,
        async execute() {
          return safeResult(await bridge("ping", {}))
        },
      }),
      council_bind: tool({
        description:
          "Bind this exact OpenCode session as an expiring Council participant. The model provider is not treated as the transport identity.",
        args: toolArgs.council_bind,
        async execute(args, context) {
          validateBindInputs(args, context.sessionID)
          const identity = key(context.sessionID, args.participant)
          let pending = pendingRotations.get(identity)
          if (!pending) {
            const confirmed = bindings.get(identity)
            if (
              pendingRotations.size >= MAX_PENDING_BINDING_ROTATIONS
              && !confirmed
            ) {
              throw new BridgeError(
                "too many pending Council binding rotations; retry an existing identity",
                "error",
                "invalid_request",
              )
            }
            pending = {
              capability: capability(),
              previousCapability: confirmed?.capability,
              relayCapability: capability(),
              inFlight: 0,
              uncertain: false,
            }
            pendingRotations.set(identity, pending)
          }
          pending.inFlight += 1
          let precommitFailure = false
          try {
            try {
              await ensureBroker()
            } catch (error) {
              precommitFailure = true
              throw error
            }
            const deliveryStateWasPresent = deliveryRegistry.retain(
              context.sessionID, args.participant,
            )
            if (pending.deliveryStateWasPresent === undefined) {
              pending.deliveryStateWasPresent = deliveryStateWasPresent
            }
            const result = await rawBridge("bind", {
              runtime: "opencode",
              participant: args.participant,
              label: args.label,
              project: args.project,
              lease_minutes: args.lease_minutes ?? DEFAULT_LEASE_MINUTES,
              target_session_id: context.sessionID,
              relay_path: relayPath,
              relay_capability: pending.relayCapability,
              relay_pid: process.pid,
              binding_capability: pending.capability,
              previous_capability: pending.previousCapability,
            })
            if (pendingRotations.get(identity) === pending) {
              for (const [existingIdentity, existing] of bindings) {
                if (
                  existingIdentity !== identity &&
                  existing.participant === args.participant
                ) {
                  bindings.delete(existingIdentity)
                  pendingRotations.delete(existingIdentity)
                  deliveryRegistry.discard(existing.sessionID, existing.participant)
                }
              }
              for (const pendingIdentity of pendingRotations.keys()) {
                const separator = pendingIdentity.indexOf("\u0000")
                if (
                  pendingIdentity !== identity &&
                  pendingIdentity.slice(separator + 1) === args.participant
                ) {
                  pendingRotations.delete(pendingIdentity)
                }
              }
              bindings.set(identity, {
                participant: args.participant,
                sessionID: context.sessionID,
                capability: pending.capability,
                relayCapability: pending.relayCapability,
              })
              pendingRotations.delete(identity)
            }
            return safeResult(result)
          } catch (error) {
            if (!precommitFailure) {
              precommitFailure = (
                error instanceof BridgeError
                && error.commitStatus === "precommit"
              )
            }
            if (!precommitFailure) pending.uncertain = true
            throw error
          } finally {
            pending.inFlight -= 1
            if (precommitFailure) {
              releaseUncommittedRotation(
                identity, context.sessionID, args.participant, pending,
              )
            }
          }
        },
      }),
      council_unbind: tool({
        description: "Unbind this exact OpenCode Council participant.",
        args: toolArgs.council_unbind,
        async execute(args, context) {
          const identity = key(context.sessionID, args.participant)
          const capabilityAtStart = bindingFor(
            context.sessionID,
            args.participant,
          ).capability
          const result = await authenticated(context.sessionID, args.participant, "unbind", {
            participant: args.participant,
          })
          if (
            bindingGenerationMatches(
              bindings.get(identity)?.capability,
              capabilityAtStart,
            )
          ) {
            bindings.delete(identity)
            const pending = pendingRotations.get(identity)
            if (pending?.inFlight) {
              const deliveryStateWasPresent = deliveryRegistry.retain(
                context.sessionID, args.participant,
              )
              if (pending.deliveryStateWasPresent === undefined) {
                pending.deliveryStateWasPresent = deliveryStateWasPresent
              }
              pending.previousCapability = undefined
            } else {
              pendingRotations.delete(identity)
              deliveryRegistry.clear(context.sessionID, args.participant)
            }
          }
          return safeResult(result)
        },
      }),
      council_start: tool({
        description:
          "Start a two- or three-participant Council. Explicit round and ledger values are binding.",
        args: toolArgs.council_start,
        async execute(args, context) {
          if ((args.peer ? 1 : 0) + (args.peers ? 1 : 0) !== 1) {
            throw new BridgeError("provide peer or peers, not both")
          }
          const binding = bindingFor(context.sessionID, args.initiator)
          const rounds = args.rounds ?? DEFAULT_ROUNDS
          return safeResult(
            await bridge("start", {
              initiator: args.initiator,
              peer: normalizedBrokerPeer(args.peer),
              peers: args.peers,
              topic: args.topic,
              brief: args.brief,
              premises: args.premises,
              minimum_rounds: args.minimum_rounds ?? Math.min(DEFAULT_MINIMUM_ROUNDS, rounds),
              rounds,
              max_rounds: args.max_rounds ?? DEFAULT_MAX_ROUNDS,
              stop_on_convergence: args.stop_on_convergence ?? true,
              active_claim_ceiling: args.active_claim_ceiling ?? DEFAULT_ACTIVE_CLAIM_CEILING,
              rounds_provided: args.rounds !== undefined,
              minimum_rounds_provided: args.minimum_rounds !== undefined,
              max_rounds_provided: args.max_rounds !== undefined,
              stop_on_convergence_provided: args.stop_on_convergence !== undefined,
              active_claim_ceiling_provided: args.active_claim_ceiling !== undefined,
              _auth_capability: binding.capability,
            }),
          )
        },
      }),
      council_submit: tool({
        description: submitDescription,
        args: toolArgs.council_submit,
        async execute(args, context) {
          return safeResult(
            await authenticated(context.sessionID, args.participant, "submit", args),
          )
        },
      }),
      council_wait: tool({
        description: "Claim the next Council envelope for this exact OpenCode participant.",
        args: toolArgs.council_wait,
        async execute(args, context) {
          return safeResult(
            await authenticated(context.sessionID, args.participant, "wait", {
              participant: args.participant,
              timeout_seconds: args.timeout_seconds ?? 0,
            }),
          )
        },
      }),
      council_ack: tool({
        description: "Acknowledge a handled Council envelope after its response is durable.",
        args: toolArgs.council_ack,
        async execute(args, context) {
          return safeResult(await authenticated(context.sessionID, args.participant, "ack", args))
        },
      }),
      council_status: tool({
        description: "Read participant-scoped durable Council state.",
        args: toolArgs.council_status,
        async execute(args, context) {
          return safeResult(
            await authenticated(context.sessionID, args.participant, "status", args),
          )
        },
      }),
      council_extend: tool({
        description: "Apply user-authorized additional Council rounds.",
        args: toolArgs.council_extend,
        async execute(args, context) {
          const pending = pendingExtensions.begin(
            args.participant,
            args.dialogue_id,
            args.additional_rounds,
            () => `ext-${randomBytes(16).toString("hex")}`,
          )
          try {
            const result = await authenticated(
              context.sessionID,
              args.participant,
              "extend",
              { ...args, extension_id: pending.extensionID },
            )
            const rendered = safeResult(result)
            if (!pendingExtensions.complete(args.participant, args.dialogue_id, pending, result)) {
              throw new BridgeError("broker returned an invalid extension result", "error", "malformed_response")
            }
            return rendered
          } catch (error) {
            if (error instanceof BridgeError) {
              pendingExtensions.reject(
                args.participant, args.dialogue_id, pending, error.kind, error.reason,
              )
            }
            throw error
          }
        },
      }),
      council_request_extension: tool({
        description: "Record a reason for more rounds without authorizing them.",
        args: toolArgs.council_request_extension,
        async execute(args, context) {
          return safeResult(
            await authenticated(context.sessionID, args.participant, "request_extension", args),
          )
        },
      }),
      council_cancel: tool({
        description: "Cancel a Council dialogue and notify every other participant.",
        args: toolArgs.council_cancel,
        async execute(args, context) {
          return safeResult(
            await authenticated(context.sessionID, args.participant, "cancel", args),
          )
        },
      }),
    },
  }
  ;(globalThis as Record<symbol, unknown>)[
    TOOL_REGISTRY_KEY
  ] = { format: 1, cohort: RUNTIME_COHORT, tools: hooks.tool } satisfies ToolRegistration
  return { dispose: hooks.dispose }
}
