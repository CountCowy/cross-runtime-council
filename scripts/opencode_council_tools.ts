import { tool, type ToolDefinition } from "@opencode-ai/plugin"

type ToolMap = Record<string, ToolDefinition>

const submitDescription =
  "Submit the response requested by a Council envelope. Use payload.response_contract from that exact envelope as the authoritative kind, round, payload schema, enum, and active-claim contract; never guess an omitted field or enum."

function runtimeTools(): ToolMap {
  const tools = (globalThis as Record<symbol, unknown>)[
    Symbol.for("council.opencode.tool-definitions")
  ] as ToolMap | undefined
  if (!tools) {
    throw new Error(
      "Council OpenCode plugin is not initialized; restart OpenCode with the Council plugin enabled",
    )
  }
  return tools
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

const z = tool.schema
const participant = { participant: z.string() }
const dialogueParticipant = {
  dialogue_id: z.string(),
  participant: z.string(),
}

export const ping = delegate("council_ping", "Read local Council broker health.", {})

export const bind = delegate(
  "council_bind",
  "Bind this exact OpenCode session as an expiring Council participant.",
  {
    participant: z.string(),
    label: z.string(),
    project: z.string(),
    lease_minutes: z.number().int().min(1).max(1440).optional(),
  },
)

export const unbind = delegate(
  "council_unbind",
  "Unbind this exact OpenCode Council participant.",
  participant,
)

export const start = delegate(
  "council_start",
  "Start a bounded two- or three-participant Council with exact user policy values.",
  {
    initiator: z.string(),
    peer: z.string().optional(),
    peers: z.array(z.string()).min(1).max(2).optional(),
    topic: z.string(),
    brief: z.string(),
    premises: z.array(z.any()),
    minimum_rounds: z.number().int().min(1).max(100).optional(),
    rounds: z.number().int().min(1).max(100).optional(),
    max_rounds: z.number().int().min(1).max(100).optional(),
    stop_on_convergence: z.boolean().optional(),
    active_claim_ceiling: z.number().int().min(2).max(24).optional(),
  },
)

export const submit = delegate(
  "council_submit",
  submitDescription,
  {
    ...dialogueParticipant,
    kind: z.enum([
      "proposal",
      "exchange",
      "convergence_challenge",
      "synthesis",
      "representation_check",
      "synthesis_revision",
      "revision_check",
    ]),
    round_number: z.number().int().min(0),
    payload: z.record(z.string(), z.any()),
  },
)

export const wait = delegate(
  "council_wait",
  "Claim the next Council envelope for this exact OpenCode participant.",
  {
    ...participant,
    timeout_seconds: z.number().int().min(0).max(55).optional(),
  },
)

export const ack = delegate(
  "council_ack",
  "Acknowledge a handled Council envelope after its response is durable.",
  { ...participant, message_id: z.string() },
)

export const status = delegate(
  "council_status",
  "Read participant-scoped durable Council state.",
  { ...participant, dialogue_id: z.string().optional() },
)

export const extend = delegate(
  "council_extend",
  "Apply user-authorized additional Council rounds.",
  {
    ...dialogueParticipant,
    additional_rounds: z.number().int().min(1).max(100),
  },
)

export const request_extension = delegate(
  "council_request_extension",
  "Record a reason for more rounds without authorizing them.",
  { ...dialogueParticipant, reason: z.string() },
)

export const cancel = delegate(
  "council_cancel",
  "Cancel a Council dialogue and notify every other participant.",
  { ...dialogueParticipant, reason: z.string() },
)
