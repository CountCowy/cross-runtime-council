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
  let errorKind = "rejected"
  let commitStatus: "precommit" | undefined
  let reason = "transport_lost"
  let failBindSpawn = false
  let failNextSpawn = false
  let writeFailureAction = ""
  let daemonSpawns = 0
  globals.Bun = {
    spawn: (command: string[]) => {
      if (command.includes("daemon")) { daemonSpawns += 1; throw new Error("unexpected daemon spawn") }
      if (failNextSpawn) {
        failNextSpawn = false
        throw new Error("fixture spawn failure")
      }
      let request: Request
      return {
        stdin: {
          write: (line: string) => {
            request = JSON.parse(line)
            requests.push(request)
            if (request.action === writeFailureAction) {
              throw new Error("fixture write failure")
            }
          },
          end: () => {},
        },
        get stdout() {
          if (request.action === "ping" && failBindSpawn) failNextSpawn = true
          const response = request.action === failAction
            ? {
                ok: false,
                error: "fixture failure",
                error_kind: errorKind,
                reason,
                ...(commitStatus ? { commit_status: commitStatus } : {}),
              }
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
    const confirmedCapability = requests.filter(
      (request) => request.action === "bind",
    ).at(-1)!.arguments.binding_capability
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

    const bindRequests = () => requests.filter((request) => request.action === "bind")
    failAction = ""
    failBindSpawn = true
    for (let index = 0; index < 40; index += 1) {
      await assert.rejects(
        wrapper.bind.execute(
          { participant: `spawn-${index}`, label: "Spawn", project: "fixture" },
          { sessionID: `spawn-session-${index}` } as never,
        ),
        /child was not created/,
      )
    }
    failBindSpawn = false
    await wrapper.bind.execute(
      { participant: "after-spawn", label: "After", project: "fixture" },
      { sessionID: "after-spawn-session" } as never,
    )

    failAction = "ping"
    errorKind = "error"
    reason = "version_mismatch"
    for (let index = 0; index < 40; index += 1) {
      await assert.rejects(
        wrapper.bind.execute(
          { participant: `presend-${index}`, label: "Presend", project: "fixture" },
          { sessionID: `presend-session-${index}` } as never,
        ),
        /fixture failure/,
      )
    }
    failAction = ""
    await wrapper.bind.execute(
      { participant: "after-presend", label: "After", project: "fixture" },
      { sessionID: "after-presend-session" } as never,
    )

    failAction = "bind"
    errorKind = "rejected"
    commitStatus = "precommit"
    reason = "invalid_request"
    for (let index = 0; index < 40; index += 1) {
      await assert.rejects(
        wrapper.bind.execute(
          { participant: `definite-${index}`, label: "Definite", project: "fixture" },
          { sessionID: "pending-session" } as never,
        ),
        /fixture failure/,
      )
    }
    failAction = ""
    commitStatus = undefined
    await wrapper.bind.execute(
      { participant: "after-definite", label: "After", project: "fixture" },
      { sessionID: "after-definite-session" } as never,
    )

    failAction = "bind"
    errorKind = "error"
    reason = "transport_lost"
    for (let index = 0; index < 32; index += 1) {
      await assert.rejects(
        wrapper.bind.execute(
          { participant: `pending-${index}`, label: "Pending", project: "fixture" },
          { sessionID: `pending-session-${index}` } as never,
        ),
        /fixture failure/,
      )
    }
    const atCapacity = bindRequests().length
    await assert.rejects(
      wrapper.bind.execute(
        { participant: "overflow", label: "Overflow", project: "fixture" },
        { sessionID: "overflow-session" } as never,
      ),
      /too many pending Council binding rotations/,
    )
    assert.equal(bindRequests().length, atCapacity)

    await assert.rejects(
      wrapper.bind.execute(
        { participant: "pending-0", label: "Pending", project: "fixture" },
        { sessionID: "pending-session-0" } as never,
      ),
      /fixture failure/,
    )
    const pendingRetries = bindRequests().filter(
      (request) => request.arguments.participant === "pending-0",
    )
    assert.equal(new Set(pendingRetries.map(
      (request) => request.arguments.binding_capability,
    )).size, 1)

    commitStatus = undefined
    reason = "transport_lost"
    writeFailureAction = "bind"
    await assert.rejects(wrapper.bind.execute(binding, context), /fixture write failure/)
    writeFailureAction = ""
    const ambiguousRenewal = bindRequests().at(-1)!
    errorKind = "rejected"
    commitStatus = "precommit"
    reason = "invalid_request"
    await assert.rejects(wrapper.bind.execute(binding, context), /fixture failure/)
    const definiteRenewal = bindRequests().at(-1)!
    assert.equal(
      definiteRenewal.arguments.binding_capability,
      ambiguousRenewal.arguments.binding_capability,
    )
    assert.equal(
      definiteRenewal.arguments.previous_capability,
      confirmedCapability,
    )
    const beforePresendRetry = bindRequests().length
    failAction = "ping"
    errorKind = "error"
    commitStatus = undefined
    reason = "version_mismatch"
    await assert.rejects(wrapper.bind.execute(binding, context), /fixture failure/)
    assert.equal(bindRequests().length, beforePresendRetry)
    failAction = "bind"
    errorKind = "rejected"
    commitStatus = "precommit"
    reason = "invalid_request"
    await assert.rejects(wrapper.bind.execute(binding, context), /fixture failure/)
    assert.equal(
      bindRequests().at(-1)!.arguments.binding_capability,
      ambiguousRenewal.arguments.binding_capability,
    )
    commitStatus = undefined

    const beforeInvalid = bindRequests().length
    for (const [candidate, message] of [
      [{ participant: "invalid/name", label: "Invalid", project: "fixture" }, /participant must match/],
      [{ participant: "valid", label: " ", project: "fixture" }, /label must not be empty/],
      [{ participant: "valid", label: "Valid", project: "é".repeat(32_769) }, /project exceeds/],
    ] as const) {
      await assert.rejects(
        wrapper.bind.execute(candidate, { sessionID: "invalid-session" } as never),
        message,
      )
    }
    await assert.rejects(
      wrapper.bind.execute(
        { participant: "valid", label: "Valid", project: "fixture" },
        { sessionID: "invalid/session" } as never,
      ),
      /target_session_id must match/,
    )
    assert.equal(bindRequests().length, beforeInvalid)

    failAction = "bind"
    await wrapper.unbind.execute({ participant: "alpha" }, context)
    await assert.rejects(
      wrapper.bind.execute(binding, context),
      /too many pending Council binding rotations/,
    )

    await hooks?.dispose?.()
    hooks = undefined
    const { CouncilPlugin: RestartedCouncilPlugin } = await import(
      new URL("./opencode_council_plugin.ts?admission-fixture", import.meta.url).href
    )
    hooks = await RestartedCouncilPlugin({ client: {} } as never)
    const beforeRestart = bindRequests().length
    await assert.rejects(
      wrapper.bind.execute(
        { participant: "after-dispose", label: "After", project: "fixture" },
        { sessionID: "after-dispose-session" } as never,
      ),
      /fixture failure/,
    )
    assert.equal(bindRequests().length, beforeRestart + 1)
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

test("OpenCode bind cleanup is attempt-aware across concurrency and extension state", async () => {
  const directory = mkdtempSync("/tmp/cpc-")
  const homedir = mock.method(os, "homedir", () => directory)
  syncBuiltinESMExports()
  const globals = globalThis as unknown as Record<string | symbol, unknown>
  const priorBun = globals.Bun
  type Request = { action: string; arguments: Record<string, unknown> }
  type Response = {
    ok: boolean
    result?: Record<string, unknown>
    error?: string
    error_kind?: string
    reason?: string
    commit_status?: string
  }
  const requests: Request[] = []
  const deferred = () => {
    let resolve!: (value: Response) => void
    const promise = new Promise<Response>((done) => {
      resolve = done
    })
    return { promise, resolve }
  }
  const sharedFirst = deferred()
  const sharedSecond = deferred()
  const replacementOld = deferred()
  const replacementSuccess = deferred()
  const replacementRenewal = deferred()
  const staleSuccessFirst = deferred()
  const staleSuccessRenewal = deferred()
  const unbindRaceRenewal = deferred()
  let sharedOrdinal = 0
  let replacementOrdinal = 0
  let staleSuccessBrokerCapability: unknown
  let unbindRaceOrdinal = 0
  let unbindRaceBrokerCapability: unknown
  const rejected = (
    reason: string,
    commitStatus?: "precommit",
  ): Response => ({
    ok: false,
    error: "fixture failure",
    error_kind: commitStatus ? "rejected" : "error",
    reason,
    ...(commitStatus ? { commit_status: commitStatus } : {}),
  })
  const responseFor = (request: Request): Response | Promise<Response> => {
    if (request.action === "ping") return { ok: true, result: {} }
    if (request.action === "extend") return rejected("transport_lost")
    if (
      request.action === "unbind"
      && request.arguments.participant === "unbind-race"
    ) {
      assert.equal(
        request.arguments._auth_capability,
        unbindRaceBrokerCapability,
      )
      unbindRaceBrokerCapability = undefined
      return { ok: true, result: {} }
    }
    if (request.action !== "bind") return { ok: true, result: {} }
    const participant = request.arguments.participant
    if (participant === "owner" || participant === "unrelated") {
      return { ok: true, result: {} }
    }
    if (participant === "unused") return rejected("invalid_request", "precommit")
    if (participant === "shared") {
      sharedOrdinal += 1
      if (sharedOrdinal === 1) return sharedFirst.promise
      if (sharedOrdinal === 2) return sharedSecond.promise
      return rejected("invalid_request", "precommit")
    }
    if (participant === "replacement") {
      replacementOrdinal += 1
      if (replacementOrdinal === 1) return replacementOld.promise
      if (replacementOrdinal === 2) return replacementSuccess.promise
      if (replacementOrdinal === 3) return replacementRenewal.promise
      return rejected("invalid_request", "precommit")
    }
    if (participant === "stale-success") {
      const capability = request.arguments.binding_capability
      const previous = request.arguments.previous_capability
      if (staleSuccessBrokerCapability === undefined) {
        staleSuccessBrokerCapability = capability
        return staleSuccessFirst.promise
      }
      if (capability === staleSuccessBrokerCapability) {
        return { ok: true, result: {} }
      }
      if (previous === staleSuccessBrokerCapability) {
        staleSuccessBrokerCapability = capability
        return staleSuccessRenewal.promise
      }
      return rejected("not_authorized", "precommit")
    }
    if (participant === "unbind-race") {
      unbindRaceOrdinal += 1
      const capability = request.arguments.binding_capability
      const previous = request.arguments.previous_capability
      if (unbindRaceOrdinal === 2) {
        return unbindRaceRenewal.promise.then((response) => {
          assert.equal(unbindRaceBrokerCapability, undefined)
          unbindRaceBrokerCapability = capability
          return response
        })
      }
      if (unbindRaceBrokerCapability === undefined) {
        unbindRaceBrokerCapability = capability
        return { ok: true, result: {} }
      }
      if (previous === unbindRaceBrokerCapability) {
        unbindRaceBrokerCapability = capability
        return { ok: true, result: {} }
      }
      return rejected("not_authorized", "precommit")
    }
    throw new Error(`unexpected bind participant: ${String(participant)}`)
  }
  const stream = (response: Response | Promise<Response>) => (
    new ReadableStream<Uint8Array>({
      async start(controller) {
        const body = JSON.stringify(await response)
        controller.enqueue(new TextEncoder().encode(body))
        controller.close()
      },
    })
  )
  globals.Bun = {
    spawn: (command: string[]) => {
      if (command.includes("daemon")) throw new Error("unexpected daemon spawn")
      let request: Request
      return {
        stdin: {
          write: (line: string) => {
            request = JSON.parse(line)
            requests.push(request)
          },
          end: () => {},
        },
        get stdout() {
          return stream(responseFor(request))
        },
        get stderr() {
          return new Blob([]).stream()
        },
        exited: Promise.resolve(0),
      }
    },
  }
  const bindRequests = (participant: string) => requests.filter(
    (request) => request.action === "bind"
      && request.arguments.participant === participant,
  )
  const waitForBindCount = async (participant: string, count: number) => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      if (bindRequests(participant).length >= count) return
      await new Promise<void>((resolve) => setImmediate(resolve))
    }
    assert.fail(`timed out waiting for ${participant} bind ${count}`)
  }
  let hooks: Awaited<
    ReturnType<typeof import("./opencode_council_plugin.ts").CouncilPlugin>
  > | undefined
  try {
    const { CouncilPlugin } = await import(
      new URL("./opencode_council_plugin.ts?bind-precommit-concurrency", import.meta.url).href
    )
    hooks = await CouncilPlugin({ client: {} } as never)
    const ownerContext = { sessionID: "owner-session" } as never
    await wrapper.bind.execute(
      { participant: "owner", label: "Owner", project: "fixture" },
      ownerContext,
    )
    const extension = {
      participant: "owner",
      dialogue_id: "dlg-pending",
      additional_rounds: 1,
    }
    await assert.rejects(
      wrapper.extend.execute(extension, ownerContext),
      /fixture failure/,
    )
    await assert.rejects(
      wrapper.bind.execute(
        { participant: "unused", label: "Unused", project: "fixture" },
        { sessionID: "unused-session" } as never,
      ),
      /fixture failure/,
    )
    await wrapper.bind.execute(
      { participant: "unrelated", label: "Unrelated", project: "fixture" },
      { sessionID: "unrelated-session" } as never,
    )
    await assert.rejects(
      wrapper.extend.execute(
        { ...extension, additional_rounds: 2 },
        ownerContext,
      ),
      /original round count/,
    )

    const sharedBinding = {
      participant: "shared",
      label: "Shared",
      project: "fixture",
    }
    const sharedContext = { sessionID: "shared-session" } as never
    const first = wrapper.bind.execute(sharedBinding, sharedContext)
    await waitForBindCount("shared", 1)
    const second = wrapper.bind.execute(sharedBinding, sharedContext)
    await waitForBindCount("shared", 2)
    const sharedCapability = bindRequests("shared")[0].arguments.binding_capability
    assert.equal(
      bindRequests("shared")[1].arguments.binding_capability,
      sharedCapability,
    )
    sharedFirst.resolve(rejected("invalid_request", "precommit"))
    await assert.rejects(first, /fixture failure/)
    await assert.rejects(
      wrapper.bind.execute(sharedBinding, sharedContext),
      /fixture failure/,
    )
    assert.equal(
      bindRequests("shared")[2].arguments.binding_capability,
      sharedCapability,
    )
    sharedSecond.resolve(rejected("transport_lost"))
    await assert.rejects(second, /fixture failure/)
    await assert.rejects(
      wrapper.bind.execute(sharedBinding, sharedContext),
      /fixture failure/,
    )
    await assert.rejects(
      wrapper.bind.execute(sharedBinding, sharedContext),
      /fixture failure/,
    )
    assert.equal(
      new Set(bindRequests("shared").map(
        (request) => request.arguments.binding_capability,
      )).size,
      1,
    )

    const replacementBinding = {
      participant: "replacement",
      label: "Replacement",
      project: "fixture",
    }
    const replacementContext = { sessionID: "replacement-session" } as never
    const old = wrapper.bind.execute(replacementBinding, replacementContext)
    await waitForBindCount("replacement", 1)
    const winner = wrapper.bind.execute(replacementBinding, replacementContext)
    await waitForBindCount("replacement", 2)
    const oldCapability = bindRequests("replacement")[0].arguments.binding_capability
    replacementSuccess.resolve({ ok: true, result: {} })
    await winner
    const renewal = wrapper.bind.execute(replacementBinding, replacementContext)
    await waitForBindCount("replacement", 3)
    const renewalCapability = bindRequests("replacement")[2].arguments.binding_capability
    assert.notEqual(renewalCapability, oldCapability)
    replacementOld.resolve(rejected("invalid_request", "precommit"))
    await assert.rejects(old, /fixture failure/)
    await assert.rejects(
      wrapper.bind.execute(replacementBinding, replacementContext),
      /fixture failure/,
    )
    assert.equal(
      bindRequests("replacement")[3].arguments.binding_capability,
      renewalCapability,
    )
    replacementRenewal.resolve(rejected("transport_lost"))
    await assert.rejects(renewal, /fixture failure/)
    await assert.rejects(
      wrapper.bind.execute(replacementBinding, replacementContext),
      /fixture failure/,
    )
    assert.equal(
      bindRequests("replacement").at(-1)!.arguments.binding_capability,
      renewalCapability,
    )

    const staleSuccessBinding = {
      participant: "stale-success",
      label: "Stale success",
      project: "fixture",
    }
    const staleSuccessContext = { sessionID: "stale-success-session" } as never
    const staleFirst = wrapper.bind.execute(
      staleSuccessBinding, staleSuccessContext,
    )
    await waitForBindCount("stale-success", 1)
    const staleWinner = wrapper.bind.execute(
      staleSuccessBinding, staleSuccessContext,
    )
    await waitForBindCount("stale-success", 2)
    await staleWinner
    const staleP1 = bindRequests(
      "stale-success",
    )[0].arguments.binding_capability
    assert.equal(
      bindRequests("stale-success")[1].arguments.binding_capability,
      staleP1,
    )
    const staleRenewal = wrapper.bind.execute(
      staleSuccessBinding, staleSuccessContext,
    )
    await waitForBindCount("stale-success", 3)
    const staleP2 = bindRequests(
      "stale-success",
    )[2].arguments.binding_capability
    assert.notEqual(staleP2, staleP1)
    assert.equal(staleSuccessBrokerCapability, staleP2)
    staleSuccessFirst.resolve({ ok: true, result: {} })
    await staleFirst
    staleSuccessRenewal.resolve(rejected("transport_lost"))
    await assert.rejects(staleRenewal, /fixture failure/)
    await wrapper.bind.execute(staleSuccessBinding, staleSuccessContext)
    assert.equal(
      bindRequests("stale-success")[3].arguments.binding_capability,
      staleP2,
    )

    const unbindRaceBinding = {
      participant: "unbind-race",
      label: "Unbind race",
      project: "fixture",
    }
    const unbindRaceContext = { sessionID: "unbind-race-session" } as never
    await wrapper.bind.execute(unbindRaceBinding, unbindRaceContext)
    const unbindRaceP1 = bindRequests(
      "unbind-race",
    )[0].arguments.binding_capability
    assert.equal(unbindRaceBrokerCapability, unbindRaceP1)
    const unbindRace = wrapper.bind.execute(
      unbindRaceBinding, unbindRaceContext,
    )
    await waitForBindCount("unbind-race", 2)
    const unbindRaceP2 = bindRequests(
      "unbind-race",
    )[1].arguments.binding_capability
    assert.equal(
      bindRequests("unbind-race")[1].arguments.previous_capability,
      unbindRaceP1,
    )
    await wrapper.unbind.execute(
      { participant: "unbind-race" }, unbindRaceContext,
    )
    assert.equal(unbindRaceBrokerCapability, undefined)
    unbindRaceRenewal.resolve({ ok: true, result: {} })
    await unbindRace
    assert.equal(unbindRaceBrokerCapability, unbindRaceP2)
    await wrapper.bind.execute(unbindRaceBinding, unbindRaceContext)
    assert.equal(
      bindRequests("unbind-race")[2].arguments.previous_capability,
      unbindRaceP2,
    )
  } finally {
    sharedFirst.resolve(rejected("transport_lost"))
    sharedSecond.resolve(rejected("transport_lost"))
    replacementOld.resolve(rejected("transport_lost"))
    replacementSuccess.resolve(rejected("transport_lost"))
    replacementRenewal.resolve(rejected("transport_lost"))
    staleSuccessFirst.resolve(rejected("transport_lost"))
    staleSuccessRenewal.resolve(rejected("transport_lost"))
    unbindRaceRenewal.resolve(rejected("transport_lost"))
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
