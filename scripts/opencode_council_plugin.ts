import {
  ENVELOPE_PREAMBLE, RELAY_ENVELOPE_KINDS as PROTOCOL_RELAY_KINDS,
  DEFAULT_LEASE_MINUTES, DEFAULT_ROUNDS, DEFAULT_MINIMUM_ROUNDS,
  DEFAULT_MAX_ROUNDS, DEFAULT_ACTIVE_CLAIM_CEILING, openCodeToolArgs,
  RUNTIME_COHORT as PROTOCOL_COHORT,
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
}

const PACKAGE_ID = "5b191cf1770d560f2898b9220f2420f454dab7b47fee07e54c341657183ed661"
const RUNTIME_COHORT = "5f0deaae436f790f960a08f2ec51d6e112379f6b73b6d6084aa5928f2179950a"
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
}

class BridgeError extends Error {
  readonly reason: ErrorReason

  constructor(message: string, readonly kind?: string, reason?: unknown) {
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

async function rawBridge(action: string, args: Record<string, unknown>) {
  const child = Bun.spawn(["python3", bridgePath], {
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  })
  child.stdin.write(JSON.stringify({ action, arguments: args }) + "\n")
  child.stdin.end()
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
      response.error_kind, response.reason,
    )
  }
  if (response.result === null || typeof response.result !== "object" || Array.isArray(response.result)) {
    throw new BridgeError("OpenCode Council bridge returned no broker JSON object", "internal", "malformed_response")
  }
  return response.result
}

let brokerStartup: Promise<void> | undefined

async function ensureBroker() {
  try {
    await rawBridge("ping", {})
    return
  } catch {}
  if (!brokerStartup) {
    brokerStartup = (async () => {
      Bun.spawn(
        ["python3", brokerPath, "daemon", "--state-root", stateRoot],
        { stdin: "ignore", stdout: "ignore", stderr: "ignore" },
      )
      let lastError: unknown
      for (let attempt = 0; attempt < 60; attempt += 1) {
        await new Promise<void>((resolve) => setTimeout(resolve, 50))
        try {
          await rawBridge("ping", {})
          return
        } catch (error) {
          lastError = error
        }
      }
      throw lastError instanceof Error
        ? lastError
        : new BridgeError("Council broker failed to start", "internal")
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
          pendingRotations.delete(identity)
          deliveryRegistry.clear(sessionID, participant)
        }
      }
      throw error
    }
  }

  const hooks = {
    dispose: async () => {
      for (const socket of relaySockets) socket.destroy()
      await new Promise<void>((resolve) => server.close(() => resolve()))
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
          const identity = key(context.sessionID, args.participant)
          const hadBinding = bindings.has(identity)
          let pending = pendingRotations.get(identity)
          if (!pending) {
            pending = {
              capability: capability(),
              previousCapability: bindings.get(identity)?.capability,
              relayCapability: capability(),
            }
            pendingRotations.set(identity, pending)
          }
          deliveryRegistry.retain(context.sessionID, args.participant)
          try {
            const result = await bridge("bind", {
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
            return safeResult(result)
          } catch (error) {
            if (error instanceof BridgeError && error.kind === "rejected") {
              pendingRotations.delete(identity)
              if (!hadBinding) {
                deliveryRegistry.clear(context.sessionID, args.participant)
              }
            }
            throw error
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
            pendingRotations.delete(identity)
            deliveryRegistry.clear(context.sessionID, args.participant)
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
