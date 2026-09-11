import { openCodeToolArgs, RUNTIME_COHORT as PROTOCOL_COHORT } from "../council_protocol.ts"
import { registeredTools, TOOL_REGISTRY_KEY, RUNTIME_COHORT as REGISTRY_COHORT } from "../opencode_delivery_registry.ts"
import { tool, type ToolDefinition } from "@opencode-ai/plugin"

const PACKAGE_ID = "b71ebbdbd71ea50e2b156fb581b7956b8bf516df4eb873a3549dbe6930a0a9df"
const RUNTIME_COHORT = "8181ae63906b42e4af670df1613dede4d194c48991594e3b8ea9b961877831b5"
if (RUNTIME_COHORT !== PROTOCOL_COHORT || RUNTIME_COHORT !== REGISTRY_COHORT) {
  throw new Error("Council wrapper/helper cohort mismatch; refresh the complete runtime set")
}

type ToolMap = Record<string, ToolDefinition>

const submitDescription =
  "Submit the response requested by a Council envelope. Use payload.response_contract from that exact envelope as the authoritative kind, round, payload schema, enum, and active-claim contract; never guess an omitted field or enum."

function runtimeTools(): ToolMap {
  return registeredTools((globalThis as Record<symbol, unknown>)[TOOL_REGISTRY_KEY], RUNTIME_COHORT)
}

function delegate(
  name: string,
  description: string,
  args: Parameters<typeof tool>[0]["args"],
) {
  return tool({
    description,
    args,
    async execute(values, context) {
      const selected = runtimeTools()[name]
      if (!selected) throw new Error(`Council runtime tool is unavailable: ${name}`)
      return selected.execute(values, context)
    },
  })
}

const toolArgs = openCodeToolArgs(tool.schema)

export const ping = delegate("council_ping", "Read local Council broker health.", toolArgs.council_ping)

export const bind = delegate("council_bind", "Bind this exact OpenCode session as an expiring Council participant.", toolArgs.council_bind)

export const unbind = delegate("council_unbind", "Unbind this exact OpenCode Council participant.", toolArgs.council_unbind)

export const start = delegate("council_start", "Start a bounded two- or three-participant Council with exact user policy values.", toolArgs.council_start)

export const submit = delegate("council_submit", submitDescription, toolArgs.council_submit)

export const wait = delegate("council_wait", "Claim the next Council envelope for this exact OpenCode participant.", toolArgs.council_wait)

export const ack = delegate("council_ack", "Acknowledge a handled Council envelope after its response is durable.", toolArgs.council_ack)

export const status = delegate("council_status", "Read participant-scoped durable Council state.", toolArgs.council_status)

export const extend = delegate("council_extend", "Apply user-authorized additional Council rounds.", toolArgs.council_extend)

export const request_extension = delegate("council_request_extension", "Record a reason for more rounds without authorizing them.", toolArgs.council_request_extension)

export const cancel = delegate("council_cancel", "Cancel a Council dialogue and notify every other participant.", toolArgs.council_cancel)
