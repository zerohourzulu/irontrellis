/** Errors raised inside the engine. `code` is stable and machine-readable; the message is for humans. */
export class EngineError extends Error {
  readonly code: string;
  readonly detail: unknown;
  constructor(code: string, message?: string, detail?: unknown) {
    super(message ?? code);
    this.name = "EngineError";
    this.code = code;
    this.detail = detail;
  }
}
