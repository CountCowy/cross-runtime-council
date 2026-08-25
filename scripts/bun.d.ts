// Type-check-only ambient declarations. OpenCode executes the plugin under
// the Bun runtime, whose globals @types/node does not cover. Only the members
// this codebase actually uses are declared; this file is never loaded at
// runtime.
interface CouncilBunSubprocess {
  stdin: { write(chunk: string): unknown; end(): unknown }
  stdout: ReadableStream<Uint8Array>
  stderr: ReadableStream<Uint8Array>
  exited: Promise<number>
}

declare const Bun: {
  spawn(
    command: string[],
    options?: {
      stdin?: "pipe" | "ignore"
      stdout?: "pipe" | "ignore"
      stderr?: "pipe" | "ignore"
    },
  ): CouncilBunSubprocess
}
