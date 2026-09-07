import { ERROR_REASONS, MAX_LINE_BYTES, RUNTIME_COHORT as PROTOCOL_COHORT } from "./council_protocol.ts"
import type { ToolDefinition } from "@opencode-ai/plugin"

export const PACKAGE_ID = "2d7458236799dbf14d6266f31a525bd29b06aec6e8e664789b530045fd057de1"
export const RUNTIME_COHORT = "5f0deaae436f790f960a08f2ec51d6e112379f6b73b6d6084aa5928f2179950a"
if (RUNTIME_COHORT !== PROTOCOL_COHORT) {
  throw new Error("Council registry/definitions cohort mismatch; refresh the complete runtime set")
}

export const TOOL_REGISTRY_KEY = Symbol.for("council.opencode.tool-definitions.v1")
export type ToolRegistration = {
  format: 1
  cohort: string
  tools: Record<string, ToolDefinition>
}

export function registeredTools(value: unknown, cohort: string): Record<string, ToolDefinition> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Council OpenCode plugin is not initialized; restart with the complete runtime set")
  }
  const record = value as Partial<ToolRegistration>
  if (record.format !== 1 || record.cohort !== cohort || record.tools === null ||
      typeof record.tools !== "object" || Array.isArray(record.tools) ||
      Object.values(record.tools).some((entry) => !entry || typeof entry.execute !== "function")) {
    throw new Error("Council wrapper/plugin cohort or registry mismatch; refresh copies and restart OpenCode")
  }
  return record.tools
}

type DeliveryState = {
  delivered: Set<string>
  inFlight: Map<string, Promise<void>>
  clearWhenIdle: boolean
  expiresAt?: number
  expiryTimer?: ReturnType<typeof setTimeout>
}

const DETACHED_TOMBSTONE_TTL_MS = 5 * 60 * 1000

type RelaySocket = {
  destroyed: boolean
  destroy: () => void
  end: (payload: string) => void
  on: (event: "error", listener: () => void) => unknown
}

export function normalizedBrokerPeer(peer: string | undefined) {
  return peer ?? null
}

export { ERROR_REASONS } from "./council_protocol.ts"
export type ErrorReason = typeof ERROR_REASONS[number]

export function normalizeErrorReason(value: unknown): ErrorReason {
  return typeof value === "string" && (ERROR_REASONS as readonly string[]).includes(value)
    ? value as ErrorReason
    : "unknown"
}

export function shouldDropLocalBinding(reason: unknown) {
  return reason === "not_bound" || reason === "binding_expired"
}

export function shouldRetainPendingExtension(reason: unknown) {
  return reason !== "extension_precommit_rejected"
}

export function extensionOperationKey(participant: string, dialogueID: string) {
  return `${participant}\u0000${dialogueID}`
}

type PendingExtension = { extensionID: string; additionalRounds: number }

export class PendingExtensionRegistry {
  private readonly operations = new Map<string, PendingExtension>()

  begin(participant: string, dialogueID: string, additionalRounds: number, newID: () => string) {
    const key = extensionOperationKey(participant, dialogueID)
    let pending = this.operations.get(key)
    if (pending && pending.additionalRounds !== additionalRounds) {
      throw new Error("a prior extension attempt is ambiguous; retry its original round count")
    }
    if (!pending) {
      pending = { extensionID: newID(), additionalRounds }
      this.operations.set(key, pending)
    }
    return pending
  }

  private clear(participant: string, dialogueID: string, pending: PendingExtension) {
    const key = extensionOperationKey(participant, dialogueID)
    if (this.operations.get(key) === pending) this.operations.delete(key)
  }

  reject(participant: string, dialogueID: string, pending: PendingExtension, kind: unknown, reason: unknown) {
    if (kind === "rejected" && !shouldRetainPendingExtension(reason)) {
      this.clear(participant, dialogueID, pending)
    }
  }

  complete(participant: string, dialogueID: string, pending: PendingExtension, result: unknown) {
    if (result === null || typeof result !== "object" || Array.isArray(result)) return false
    const value = result as Record<string, unknown>
    if (
      value.dialogue_id !== dialogueID || typeof value.phase !== "string" || !value.phase ||
      typeof value.authorized_rounds !== "number" || !Number.isInteger(value.authorized_rounds) ||
      value.authorized_rounds < 1 || typeof value.current_round !== "number" ||
      !Number.isInteger(value.current_round) || value.current_round < 0
    ) return false
    this.clear(participant, dialogueID, pending)
    return true
  }
}

export function bindingGenerationMatches(
  currentCapability: string | undefined,
  capturedCapability: string,
) {
  return currentCapability === capturedCapability
}

export function prepareRelaySocket(socket: RelaySocket) {
  socket.on("error", () => {})
}

export function rejectOversizedRelayBuffer(
  socket: RelaySocket,
  length: number,
  maximum = MAX_LINE_BYTES,
) {
  if (length <= maximum) return false
  socket.destroy()
  return true
}

export function safeRelayEnd(socket: RelaySocket, payload: string) {
  if (!socket.destroyed) socket.end(payload)
}

export class OpenCodeDeliveryRegistry {
  private readonly states = new Map<string, DeliveryState>()

  private key(sessionID: string, participant: string) {
    return `${sessionID}\u0000${participant}`
  }

  private state(sessionID: string, participant: string) {
    const identity = this.key(sessionID, participant)
    let state = this.states.get(identity)
    if (
      state?.clearWhenIdle &&
      state.inFlight.size === 0 &&
      state.expiresAt !== undefined &&
      state.expiresAt <= Date.now()
    ) {
      if (state.expiryTimer) clearTimeout(state.expiryTimer)
      this.states.delete(identity)
      state = undefined
    }
    if (!state) {
      state = {
        delivered: new Set<string>(),
        inFlight: new Map<string, Promise<void>>(),
        clearWhenIdle: false,
      }
      this.states.set(identity, state)
    }
    return state
  }

  private expireDetached(identity: string, state: DeliveryState) {
    if (this.states.get(identity) !== state || !state.clearWhenIdle) return
    if (state.expiryTimer) clearTimeout(state.expiryTimer)
    state.expiresAt = Date.now() + DETACHED_TOMBSTONE_TTL_MS
    state.expiryTimer = setTimeout(() => {
      if (
        this.states.get(identity) === state &&
        state.clearWhenIdle &&
        state.inFlight.size === 0
      ) {
        this.states.delete(identity)
      }
    }, DETACHED_TOMBSTONE_TTL_MS)
    state.expiryTimer.unref?.()
  }

  async deliver(
    sessionID: string,
    participant: string,
    messageID: string,
    post: () => Promise<void>,
  ) {
    const identity = this.key(sessionID, participant)
    const state = this.state(sessionID, participant)
    if (state.delivered.has(messageID)) return { duplicate: true }

    let delivery = state.inFlight.get(messageID)
    const joinedInFlight = Boolean(delivery)
    if (!delivery) {
      delivery = (async () => {
        await post()
        state.delivered.add(messageID)
      })()
      state.inFlight.set(messageID, delivery)
    }
    try {
      await delivery
    } finally {
      if (state.inFlight.get(messageID) === delivery) {
        state.inFlight.delete(messageID)
      }
      if (state.clearWhenIdle && state.inFlight.size === 0) {
        this.expireDetached(identity, state)
      }
    }
    return { duplicate: joinedInFlight }
  }

  clear(sessionID: string, participant: string) {
    const identity = this.key(sessionID, participant)
    const state = this.states.get(identity)
    if (!state) return
    state.clearWhenIdle = true
    if (state.inFlight.size === 0) {
      this.expireDetached(identity, state)
    }
  }

  retain(sessionID: string, participant: string) {
    const state = this.state(sessionID, participant)
    if (state.expiryTimer) clearTimeout(state.expiryTimer)
    state.expiryTimer = undefined
    state.expiresAt = undefined
    state.clearWhenIdle = false
  }

  discard(sessionID: string, participant: string) {
    const identity = this.key(sessionID, participant)
    const state = this.states.get(identity)
    if (state?.expiryTimer) clearTimeout(state.expiryTimer)
    this.states.delete(identity)
  }
}
