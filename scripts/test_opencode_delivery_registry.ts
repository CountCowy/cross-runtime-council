import assert from "node:assert/strict"
import test from "node:test"

import {
  bindingGenerationMatches,
  extensionOperationKey,
  normalizedBrokerPeer,
  OpenCodeDeliveryRegistry,
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
  assert.equal(shouldDropLocalBinding("participant is not bound: gamma"), true)
  assert.equal(shouldDropLocalBinding("participant binding expired: gamma"), true)
  assert.equal(shouldDropLocalBinding("different exact session"), false)
})

test("extension auth rejection preserves its ambiguous operation id", () => {
  assert.equal(shouldRetainPendingExtension("participant is not bound: gamma"), true)
  assert.equal(shouldRetainPendingExtension("participant binding expired: gamma"), true)
  assert.equal(
    shouldRetainPendingExtension("this exact session is not authorized for participant gamma"),
    true,
  )
  assert.equal(shouldRetainPendingExtension("extension exceeds max_rounds=3"), false)
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
