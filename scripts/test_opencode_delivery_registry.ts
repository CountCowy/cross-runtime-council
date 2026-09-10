import assert from "node:assert/strict"
import test from "node:test"

import {
  bindingGenerationMatches,
  ERROR_REASONS,
  extensionOperationKey,
  normalizeErrorReason,
  normalizedBrokerPeer,
  OpenCodeDeliveryRegistry,
  PendingExtensionRegistry,
  prepareRelaySocket,
  rejectOversizedRelayBuffer,
  safeRelayEnd,
  shouldDropLocalBinding,
  shouldRetainPendingExtension,
} from "./opencode_delivery_registry.ts"

test("concurrent retries join one in-flight delivery", async () => {
  const registry = new OpenCodeDeliveryRegistry()
  let posts = 0
  let release!: () => void
  const barrier = new Promise<void>((resolve) => {
    release = resolve
  })
  const post = async () => {
    posts += 1
    await barrier
  }

  const first = registry.deliver("session-a", "gamma", "msg-1", post)
  await new Promise<void>((resolve) => setImmediate(resolve))
  const second = registry.deliver("session-a", "gamma", "msg-1", post)
  release()
  const results = await Promise.all([first, second])

  assert.equal(posts, 1)
  assert.deepEqual(results, [{ duplicate: false }, { duplicate: true }])
  assert.deepEqual(
    await registry.deliver("session-a", "gamma", "msg-1", post),
    { duplicate: true },
  )
  assert.equal(posts, 1)
})

test("dedupe survives same-session rotation but not explicit session move", async () => {
  const registry = new OpenCodeDeliveryRegistry()
  let posts = 0
  const post = async () => {
    posts += 1
  }

  assert.deepEqual(
    await registry.deliver("session-a", "gamma", "msg-1", post),
    { duplicate: false },
  )
  assert.deepEqual(
    await registry.deliver("session-a", "gamma", "msg-1", post),
    { duplicate: true },
  )
  registry.clear("session-a", "gamma")
  assert.deepEqual(
    await registry.deliver("session-b", "gamma", "msg-1", post),
    { duplicate: false },
  )
  assert.equal(posts, 2)
})

test("triad peer normalization serializes an explicit null", () => {
  assert.equal(normalizedBrokerPeer(undefined), null)
  assert.equal(normalizedBrokerPeer("beta"), "beta")
})

test("relay socket safety absorbs errors, stops oversized parsing, and avoids closed writes", () => {
  const events: string[] = []
  const writes: string[] = []
  const socket = {
    destroyed: false,
    destroy() {
      this.destroyed = true
    },
    end(payload: string) {
      writes.push(payload)
    },
    on(event: "error", _listener: () => void) {
      events.push(event)
    },
  }
  prepareRelaySocket(socket)
  assert.deepEqual(events, ["error"])
  assert.equal(rejectOversizedRelayBuffer(socket, 1024), false)
  safeRelayEnd(socket, "ok")
  assert.deepEqual(writes, ["ok"])
  assert.equal(rejectOversizedRelayBuffer(socket, 1024 * 1024 + 1), true)
  safeRelayEnd(socket, "late")
  assert.deepEqual(writes, ["ok"])
})

test("broker expiry and not-bound rejections prune stale local bindings", () => {
  for (const reason of ERROR_REASONS) {
    assert.equal(shouldDropLocalBinding(reason), ["not_bound", "binding_expired"].includes(reason))
  }
  for (const reason of [undefined, null, [], {}, 1, "future_reason", "participant is not bound: gamma"]) {
    assert.equal(shouldDropLocalBinding(reason), false)
    assert.equal(normalizeErrorReason(reason), "unknown")
  }
  assert.equal(normalizeErrorReason("binding_expired"), "binding_expired")
})

test("only the explicit precommit reason can release an extension id", () => {
  for (const reason of ERROR_REASONS) {
    assert.equal(shouldRetainPendingExtension(reason), reason !== "extension_precommit_rejected")
  }
  for (const reason of [undefined, null, [], {}, 1, "future_reason", "extension exceeds max_rounds=3"]) {
    assert.equal(shouldRetainPendingExtension(reason), true)
  }
})

const extensionResult = {
  dialogue_id: "dlg-1", phase: "collecting_exchange", current_round: 1, authorized_rounds: 2,
}

test("pending extension state survives all ambiguous failures and caller retries", () => {
  const registry = new PendingExtensionRegistry()
  let allocated = 0
  const newID = () => `ext-${++allocated}`
  const pending = registry.begin("gamma", "dlg-1", 1, newID)
  for (const reason of [...ERROR_REASONS, undefined, null, [], "future_reason"]) {
    if (reason === "extension_precommit_rejected") continue
    registry.reject("gamma", "dlg-1", pending, "rejected", reason)
    assert.equal(registry.begin("gamma", "dlg-1", 1, newID), pending)
  }
  registry.reject("gamma", "dlg-1", pending, "internal", "extension_precommit_rejected")
  assert.equal(registry.begin("gamma", "dlg-1", 1, newID), pending)
  assert.throws(() => registry.begin("gamma", "dlg-1", 2, newID), /original round count/)
  assert.equal(allocated, 1)
  assert.notEqual(registry.begin("other", "dlg-1", 1, newID), pending)
  assert.notEqual(registry.begin("gamma", "dlg-2", 1, newID), pending)
  registry.reject("gamma", "dlg-1", pending, "rejected", "extension_precommit_rejected")
  assert.notEqual(registry.begin("gamma", "dlg-1", 2, newID), pending)
})

test("only a validated extension response clears its pending state", () => {
  const registry = new PendingExtensionRegistry()
  const pending = registry.begin("gamma", "dlg-1", 1, () => "ext-first")
  const malformed = [
    undefined, null, [], {}, 1,
    { ...extensionResult, dialogue_id: "dlg-other" },
    { ...extensionResult, phase: "" },
    { ...extensionResult, authorized_rounds: true },
    { ...extensionResult, current_round: -1 },
  ]
  for (const value of malformed) {
    assert.equal(registry.complete("gamma", "dlg-1", pending, value), false)
    assert.equal(registry.begin("gamma", "dlg-1", 1, () => "ext-wrong"), pending)
  }
  assert.equal(registry.complete("gamma", "dlg-1", pending, extensionResult), true)
  assert.notEqual(registry.begin("gamma", "dlg-1", 2, () => "ext-next"), pending)
})

test("late success or rejection cannot clear a replacement extension", () => {
  const registry = new PendingExtensionRegistry()
  const first = registry.begin("gamma", "dlg-1", 1, () => "ext-first")
  assert.equal(registry.complete("gamma", "dlg-1", first, extensionResult), true)
  const next = registry.begin("gamma", "dlg-1", 2, () => "ext-next")
  registry.reject("gamma", "dlg-1", first, "rejected", "extension_precommit_rejected")
  registry.complete("gamma", "dlg-1", first, extensionResult)
  assert.equal(registry.begin("gamma", "dlg-1", 2, () => "ext-wrong"), next)
})

test("extension operation identity survives an authenticated session move", () => {
  assert.equal(
    extensionOperationKey("gamma", "dlg-1"),
    extensionOperationKey("gamma", "dlg-1"),
  )
  assert.notEqual(
    extensionOperationKey("gamma", "dlg-1"),
    extensionOperationKey("gamma", "dlg-2"),
  )
  assert.notEqual(
    extensionOperationKey("gamma", "dlg-1"),
    extensionOperationKey("other", "dlg-1"),
  )
})

test("stale cleanup cannot delete a replacement binding generation", () => {
  assert.equal(bindingGenerationMatches("cap-a", "cap-a"), true)
  assert.equal(bindingGenerationMatches("cap-b", "cap-a"), false)
  assert.equal(bindingGenerationMatches(undefined, "cap-a"), false)
})

test("unbind during in-flight delivery retains tombstone through same-session rebind", async () => {
  const registry = new OpenCodeDeliveryRegistry()
  let posts = 0
  let release!: () => void
  const barrier = new Promise<void>((resolve) => {
    release = resolve
  })
  const post = async () => {
    posts += 1
    await barrier
  }

  const first = registry.deliver("session-a", "gamma", "msg-race", post)
  await new Promise<void>((resolve) => setImmediate(resolve))
  registry.clear("session-a", "gamma")
  registry.retain("session-a", "gamma")
  const retry = registry.deliver("session-a", "gamma", "msg-race", post)
  release()
  await Promise.all([first, retry])

  assert.equal(posts, 1)
  assert.deepEqual(
    await registry.deliver("session-a", "gamma", "msg-race", post),
    { duplicate: true },
  )
})

test("settled delivery tombstone survives the clear-to-retain gap", async () => {
  const registry = new OpenCodeDeliveryRegistry()
  let posts = 0
  let release!: () => void
  const barrier = new Promise<void>((resolve) => {
    release = resolve
  })
  const post = async () => {
    posts += 1
    await barrier
  }

  const first = registry.deliver("session-a", "gamma", "msg-gap", post)
  await new Promise<void>((resolve) => setImmediate(resolve))
  registry.clear("session-a", "gamma")
  release()
  await first
  registry.retain("session-a", "gamma")

  assert.deepEqual(
    await registry.deliver("session-a", "gamma", "msg-gap", post),
    { duplicate: true },
  )
  assert.equal(posts, 1)
})

test("settled tombstone survives explicit unbind and same-session rebind", async () => {
  const registry = new OpenCodeDeliveryRegistry()
  let posts = 0
  const post = async () => {
    posts += 1
  }

  await registry.deliver("session-a", "gamma", "msg-settled", post)
  registry.clear("session-a", "gamma")
  registry.retain("session-a", "gamma")

  assert.deepEqual(
    await registry.deliver("session-a", "gamma", "msg-settled", post),
    { duplicate: true },
  )
  assert.equal(posts, 1)
})

test("disposing the registry clears retained delivery state", async () => {
  const registry = new OpenCodeDeliveryRegistry()
  let posts = 0
  const post = async () => {
    posts += 1
  }

  await registry.deliver("session-a", "gamma", "msg-dispose", post)
  registry.clear("session-a", "gamma")
  registry.dispose()

  assert.deepEqual(
    await registry.deliver("session-a", "gamma", "msg-dispose", post),
    { duplicate: false },
  )
  assert.equal(posts, 2)
})
