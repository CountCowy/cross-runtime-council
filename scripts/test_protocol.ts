import assert from "node:assert/strict"
import { mkdtempSync, readFileSync, rmSync } from "node:fs"
import { syncBuiltinESMExports } from "node:module"
import os from "node:os"
import test, { mock } from "node:test"
import { tool } from "@opencode-ai/plugin"
import { openCodeToolArgs, SUBMIT_KINDS, RUNTIME_COHORT } from "./council_protocol.ts"
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
