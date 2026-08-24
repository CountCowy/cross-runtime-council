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

export function shouldDropLocalBinding(error: string) {
  return (
    error.includes("participant is not bound") ||
    error.includes("participant binding expired")
  )
}

export function shouldRetainPendingExtension(error: string) {
  return (
    error.includes("participant is not bound:") ||
    error.includes("participant binding expired:") ||
    error.includes("this exact session is not authorized for participant")
  )
}

export function extensionOperationKey(participant: string, dialogueID: string) {
  return `${participant}\u0000${dialogueID}`
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
  maximum = 1024 * 1024,
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
