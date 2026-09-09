import assert from "node:assert/strict"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { syncBuiltinESMExports } from "node:module"
import os from "node:os"
import test, { mock } from "node:test"
import { tool } from "@opencode-ai/plugin"
import { BROKER_VERSION, openCodeToolArgs, SUBMIT_KINDS, RUNTIME_COHORT } from "./council_protocol.ts"
import { registeredTools, TOOL_REGISTRY_KEY } from "./opencode_delivery_registry.ts"
import * as wrapper from "./tools/council.ts"

const shapes = openCodeToolArgs(tool.schema)
const policyCases = JSON.parse(readFileSync(new URL("./fixtures/start_policy.json", import.meta.url), "utf8")) as Array<{
  name: string
  input: Record<string, unknown>
  values: Record<string, unknown>
  provided: Record<string, boolean>
}>
const startBase = { initiator: "alpha", peer: "beta", topic: "fixture", brief: "policy", premises: [] }

test("literal tool inventory and intentional OpenCode input surface", () => {
  assert.deepEqual(Object.keys(wrapper).sort(), ["ack", "bind", "cancel", "extend", "ping", "request_extension", "start", "status", "submit", "unbind", "wait"].sort())
  assert.deepEqual([...SUBMIT_KINDS], ["proposal", "exchange", "convergence_challenge", "synthesis", "representation_check", "synthesis_revision", "revision_check"])
  assert.equal("runtime" in shapes.council_bind, false)
  assert.equal("council_pending_wakes" in shapes, false)
  assert.equal("council_wake_ack" in shapes, false)
  const status = tool.schema.object(shapes.council_status)
  assert.deepEqual(status.parse({ participant: "alpha" }), { participant: "alpha" })
  assert.equal(status.safeParse({ participant: "alpha", dialogue_id: null }).success, false)
})

test("schemas preserve omission, explicit defaults and false; reject invalid types and bounds", () => {
  const start = tool.schema.object(shapes.council_start)
  for (const fixture of policyCases) {
    assert.deepEqual(start.parse({ ...startBase, ...fixture.input }), { ...startBase, ...fixture.input }, fixture.name)
  }
  for (const invalid of [0, 101, true, null, "6", 1.5]) {
    assert.equal(start.safeParse({ ...startBase, rounds: invalid }).success, false)
  }
  for (const [name, values] of Object.entries({ minimum_rounds: [0, 101], max_rounds: [0, 101], active_claim_ceiling: [1, 25] })) {
    for (const value of values) assert.equal(start.safeParse({ ...startBase, [name]: value }).success, false)
  }
  assert.equal(tool.schema.object(shapes.council_bind).safeParse({ participant: "p", label: "p", project: "p", lease_minutes: 1441 }).success, false)
  assert.equal(tool.schema.object(shapes.council_wait).safeParse({ participant: "p", timeout_seconds: 56 }).success, false)
  assert.equal(tool.schema.object(shapes.council_submit).safeParse({ participant: "p", dialogue_id: "d", kind: "other", round_number: 1, payload: {} }).success, false)
})

test("wrapper requires a typed matching loaded plugin before any delegation", async () => {
  let executions = 0
  const tools = { council_start: { execute: async () => { executions++; return "ok" } } }
  const invalid = [undefined, null, [], tools, { format: 1, cohort: "other", tools },
    { format: 2, cohort: RUNTIME_COHORT, tools }, { format: 1, cohort: RUNTIME_COHORT, tools: null },
    { format: 1, cohort: RUNTIME_COHORT, tools: { council_start: {} } }]
  const globals = globalThis as Record<symbol, unknown>
  try {
    for (const value of invalid) {
      globals[TOOL_REGISTRY_KEY] = value
      await assert.rejects(wrapper.start.execute(startBase, {} as never), /Council/)
    }
    assert.equal(executions, 0)
    globals[TOOL_REGISTRY_KEY] = { format: 1, cohort: RUNTIME_COHORT, tools }
    assert.equal(await wrapper.start.execute(startBase, {} as never), "ok")
    assert.equal(executions, 1)
    assert.throws(() => registeredTools(globals[TOOL_REGISTRY_KEY], "stale-wrapper"), /mismatch/)
  } finally {
    delete globals[TOOL_REGISTRY_KEY]
  }
})

test("real plugin and wrapper preserve every policy value and provided flag", async () => {
  const directory = mkdtempSync("/tmp/cpl-")
  const homedir = mock.method(os, "homedir", () => directory)
  syncBuiltinESMExports()
  const globals = globalThis as unknown as Record<string | symbol, unknown>
  const priorBun = globals.Bun
  const requests: Array<{ action: string; arguments: Record<string, unknown> }> = []
  globals.Bun = {
    spawn: () => {
      let request: { action: string; arguments: Record<string, unknown> }
      return {
        stdin: { write: (line: string) => { request = JSON.parse(line); requests.push(request) }, end: () => {} },
        get stdout() { return new Blob([JSON.stringify({ ok: true, result: request.action === "ping" ? { broker_version: "0.19.0" } : {} })]).stream() },
        get stderr() { return new Blob([]).stream() },
        exited: Promise.resolve(0),
      }
    },
  }
  let hooks: Awaited<ReturnType<typeof import("./opencode_council_plugin.ts").CouncilPlugin>> | undefined
  try {
    const { CouncilPlugin } = await import("./opencode_council_plugin.ts")
    hooks = await CouncilPlugin({ client: {} } as never)
    const context = { sessionID: "fixture-session" } as never
    await wrapper.bind.execute({ participant: "alpha", label: "Alpha", project: "test" }, context)
    for (const fixture of policyCases) {
      const parsed = tool.schema.object(wrapper.start.args).parse({ ...startBase, ...fixture.input })
      await wrapper.start.execute(parsed, context)
      const captured = requests.filter((request) => request.action === "start").at(-1)!.arguments
      assert.deepEqual(Object.fromEntries(Object.keys(fixture.values).map((key) => [key, captured[key]])), fixture.values, fixture.name)
      assert.deepEqual(Object.fromEntries(Object.keys(fixture.provided).map((key) => [key, captured[key + "_provided"]])), fixture.provided, fixture.name)
    }
    const count = requests.length
    await assert.rejects(wrapper.start.execute({ ...startBase, peers: ["beta"] }, context), /peer or peers/)
    assert.equal(requests.length, count)
    const registration = globals[TOOL_REGISTRY_KEY] as { tools: Record<string, { args: Parameters<typeof tool.schema.object>[0] }> }
    for (const [name, definition] of Object.entries(wrapper)) {
      const wrapped = tool.schema.object(definition.args)
      const native = tool.schema.object(registration.tools["council_" + name].args)
      for (const candidate of [{}, { participant: "alpha" }, startBase, { ...startBase, rounds: 0 },
        { participant: "alpha", dialogue_id: "dlg-fixture", additional_rounds: 6 },
        { participant: "alpha", dialogue_id: null }, { participant: 42 }]) {
        const left = wrapped.safeParse(candidate)
        const right = native.safeParse(candidate)
        assert.equal(left.success, right.success, name)
        if (left.success && right.success) assert.deepEqual(left.data, right.data, name)
      }
    }
  } finally {
    await hooks?.dispose?.()
    delete globals[TOOL_REGISTRY_KEY]
    if (priorBun === undefined) delete globals.Bun
    else globals.Bun = priorBun
    homedir.mock.restore()
    syncBuiltinESMExports()
    rmSync(directory, { recursive: true, force: true })
  }
})

test("loaded plugin origin, bounded mismatch startup and pending operation conservation", async () => {
  const directory = mkdtempSync("/tmp/cpa-")
  const homedir = mock.method(os, "homedir", () => directory)
  syncBuiltinESMExports()
  const globals = globalThis as unknown as Record<string | symbol, unknown>
  const priorBun = globals.Bun
  type Request = { action: string; runtime_cohort: string; arguments: Record<string, unknown> }
  const requests: Request[] = []
  let failAction = "bind"
  let reason = "transport_lost"
  let daemonSpawns = 0
  globals.Bun = {
    spawn: (command: string[]) => {
      if (command.includes("daemon")) { daemonSpawns += 1; throw new Error("unexpected daemon spawn") }
      let request: Request
      return {
        stdin: { write: (line: string) => { request = JSON.parse(line); requests.push(request) }, end: () => {} },
        get stdout() {
          const response = request.action === failAction
            ? { ok: false, error: "fixture failure", error_kind: "rejected", reason }
            : { ok: true, result: request.action === "extend"
                ? { dialogue_id: "dlg-pending", phase: "collecting_exchange", authorized_rounds: 2, current_round: 1, duplicate: true }
                : {} }
          return new Blob([JSON.stringify(response)]).stream()
        },
        get stderr() { return new Blob([]).stream() },
        exited: Promise.resolve(0),
      }
    },
  }
  let hooks: Awaited<ReturnType<typeof import("./opencode_council_plugin.ts").CouncilPlugin>> | undefined
  try {
    const { CouncilPlugin } = await import(new URL("./opencode_council_plugin.ts?admission-fixture", import.meta.url).href)
    hooks = await CouncilPlugin({ client: {} } as never)
    const context = { sessionID: "pending-session" } as never
    const binding = { participant: "alpha", label: "Alpha", project: "test" }
    for (const failure of ["transport_lost", "version_mismatch", "maintenance_required", "not_authorized", "unknown"]) {
      reason = failure
      await assert.rejects(wrapper.bind.execute(binding, context), /fixture failure/)
    }
    const rotations = requests.filter((request) => request.action === "bind")
    assert.equal(new Set(rotations.map((request) => request.arguments.binding_capability)).size, 1)
    assert.equal(new Set(rotations.map((request) => request.arguments.relay_capability)).size, 1)
    failAction = ""
    await wrapper.bind.execute(binding, context)
    assert.equal(requests.filter((request) => request.action === "bind").at(-1)!.arguments.binding_capability, rotations[0].arguments.binding_capability)
    failAction = "extend"
    const extension = { participant: "alpha", dialogue_id: "dlg-pending", additional_rounds: 1 }
    for (const failure of ["transport_lost", "version_mismatch", "maintenance_required", "not_authorized", "unknown", "binding_expired"]) {
      reason = failure
      await assert.rejects(wrapper.extend.execute(extension, context), /fixture failure/)
    }
    const ids = requests.filter((request) => request.action === "extend").map((request) => request.arguments.extension_id)
    assert.equal(new Set(ids).size, 1)
    failAction = ""
    await wrapper.bind.execute(binding, context)
    await assert.rejects(wrapper.extend.execute({ ...extension, additional_rounds: 2 }, context), /original round count/)
    await wrapper.extend.execute(extension, context)
    assert.equal(requests.filter((request) => request.action === "extend").at(-1)!.arguments.extension_id, ids[0])
    for (const request of requests) assert.equal(request.runtime_cohort, RUNTIME_COHORT)
    failAction = "ping"
    reason = "version_mismatch"
    const before = requests.length
    await assert.rejects(wrapper.ping.execute({}, context), /fixture failure/)
    assert.equal(requests.length, before + 1)
    assert.equal(daemonSpawns, 0)
  } finally {
    await hooks?.dispose?.()
    delete globals[TOOL_REGISTRY_KEY]
    if (priorBun === undefined) delete globals.Bun
    else globals.Bun = priorBun
    homedir.mock.restore()
    syncBuiltinESMExports()
    rmSync(directory, { recursive: true, force: true })
  }
})

test("OpenCode startup reports bounded failures and observes a competing winner", async () => {
  const directory = mkdtempSync("/tmp/cps-")
  const homedir = mock.method(os, "homedir", () => directory)
  syncBuiltinESMExports()
  const globals = globalThis as unknown as Record<string | symbol, unknown>
  const priorBun = globals.Bun
  type Mode = "maintenance" | "malformed" | "oversized" | "timeout" | "race"
  const modes: Mode[] = ["maintenance", "malformed", "oversized", "timeout", "race"]
  let brokerAvailable = false
  let daemonSpawns = 0
  let bridgeSpawns = 0
  let killedStartupChildren = 0
  globals.Bun = {
    spawn: (command: string[]) => {
      if (command.includes("daemon")) {
        daemonSpawns += 1
        const mode = modes.shift()!
        if (mode === "race") setTimeout(() => { brokerAvailable = true }, 100)
        const body = mode === "maintenance"
          ? '{"ok":false,"reason":"maintenance_required","retryable":false}\n'
          : mode === "malformed"
            ? "not-json\n"
            : mode === "oversized"
              ? "x".repeat(1025)
              : mode === "race"
                ? '{"ok":false,"reason":"broker_unavailable","retryable":true}\n'
                : null
        return {
          stdout: body === null
            ? new ReadableStream<Uint8Array>({ start() {} })
            : new Blob([body]).stream(),
          exited: mode === "timeout"
            ? new Promise<number>(() => {})
            : Promise.resolve(2),
          kill: () => { killedStartupChildren += 1 },
        }
      }
      bridgeSpawns += 1
      let request: { action: string }
      return {
        stdin: { write: (line: string) => { request = JSON.parse(line) }, end: () => {} },
        get stdout() {
          const response = request.action === "ping" && !brokerAvailable
            ? { ok: false, error: "fixture unavailable", error_kind: "error", reason: "broker_unavailable" }
            : { ok: true, result: request.action === "ping"
                ? { broker_version: BROKER_VERSION, runtime_cohort: RUNTIME_COHORT }
                : {} }
          return new Blob([JSON.stringify(response)]).stream()
        },
        get stderr() { return new Blob(["raw daemon details must not propagate"]).stream() },
        exited: Promise.resolve(brokerAvailable ? 0 : 2),
      }
    },
  }
  let hooks: Awaited<ReturnType<typeof import("./opencode_council_plugin.ts").CouncilPlugin>> | undefined
  let wallClock: ReturnType<typeof mock.method> | undefined
  try {
    const { CouncilPlugin } = await import(new URL("./opencode_council_plugin.ts?startup-status", import.meta.url).href)
    hooks = await CouncilPlugin({ client: {} } as never)
    wallClock = mock.method(Date, "now", () => {
      throw new Error("wall clock changed during monotonic startup deadline")
    })
    const registry = globals[TOOL_REGISTRY_KEY] as {
      tools: Record<string, { execute: (args: unknown, context: unknown) => Promise<unknown> }>
    }
    const bind = () => registry.tools.council_bind.execute(
      { participant: "alpha", label: "Alpha", project: "fixture" },
      { sessionID: "startup-session" },
    )
    for (const expected of [
      "maintenance_required",
      "malformed_response",
      "malformed_response",
      "broker_unavailable",
    ]) {
      brokerAvailable = false
      await assert.rejects(bind(), (error: unknown) => (
        typeof error === "object" && error !== null
        && "reason" in error && (error as { reason: unknown }).reason === expected
        && !(error instanceof Error && error.message.includes("raw daemon details"))
      ))
    }
    brokerAvailable = true
    assert.equal(await bind(), "{}")
    assert.equal(daemonSpawns, 4)
    brokerAvailable = false
    assert.equal(await bind(), "{}")
    assert.equal(daemonSpawns, 5)
    assert.equal(killedStartupChildren, 2)
    assert.ok(bridgeSpawns < 15, `unexpected bridge startup probes: ${bridgeSpawns}`)
    assert.equal(modes.length, 0)
  } finally {
    wallClock?.mock.restore()
    await hooks?.dispose?.()
    delete globals[TOOL_REGISTRY_KEY]
    if (priorBun === undefined) delete globals.Bun
    else globals.Bun = priorBun
    homedir.mock.restore()
    syncBuiltinESMExports()
    rmSync(directory, { recursive: true, force: true })
  }
})
