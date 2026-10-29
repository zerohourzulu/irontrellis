/**
 * Strict JSON: validates raw bytes before any parser can silently discard a
 * duplicate key, and bounds size, depth and node count with an explicit stack
 * so deeply nested input never depends on the JS call stack.
 */
export class StrictJsonError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "StrictJsonError";
    this.code = code;
  }
}
export type StrictJsonLimits = Readonly<{ maxBytes?: number; maxDepth?: number; maxNodes?: number }>;
type Frame = { kind: "object"; state: string; keys: Set<string> } | { kind: "array"; state: string };

export function parseStrictJson(bytes: Uint8Array, { maxBytes = 2 * 1024 * 1024, maxDepth = 64, maxNodes = 100000 }: StrictJsonLimits = {}): unknown {
  if (bytes.byteLength > maxBytes) throw new StrictJsonError("JSON_BYTES_EXCEEDED");
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new StrictJsonError("INVALID_UTF8");
  }
  let at = 0, nodes = 0;
  const stack: Frame[] = [];
  const bad = (): never => { throw new StrictJsonError("INVALID_JSON"); };
  const space = (): void => { while (/[\x20\t\r\n]/.test(source[at] ?? "\0")) at++; };
  const string = (): string => {
    const start = at++;
    while (at < source.length) {
      const c = source.charCodeAt(at++);
      if (c === 34) {
        try { return JSON.parse(source.slice(start, at)) as string; } catch { return bad(); }
      }
      if (c < 32) bad();
      if (c === 92) {
        const escape = source[at++];
        if (escape === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(at, at + 4))) bad();
          at += 4;
        } else if (!['"', "\\", "/", "b", "f", "n", "r", "t"].includes(escape ?? "")) bad();
      }
    }
    return bad();
  };
  const value = (): void => {
    if (++nodes > maxNodes) throw new StrictJsonError("JSON_NODES_EXCEEDED");
    space();
    const c = source[at];
    if (c === "{") { at++; stack.push({ kind: "object", state: "keyOrEnd", keys: new Set() }); }
    else if (c === "[") { at++; stack.push({ kind: "array", state: "valueOrEnd" }); }
    else if (c === '"') string();
    else {
      const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(source.slice(at));
      if (!token) bad();
      at += token![0].length;
    }
    if (stack.length > maxDepth) throw new StrictJsonError("JSON_DEPTH_EXCEEDED");
  };
  value();
  while (stack.length) {
    space();
    const frame = stack[stack.length - 1]!, c = source[at];
    if (frame.kind === "object") {
      if (frame.state === "keyOrEnd" && c === "}") { at++; stack.pop(); }
      else if (frame.state === "key" || frame.state === "keyOrEnd") {
        if (c !== '"') bad();
        const key = string();
        if (frame.keys.has(key)) throw new StrictJsonError("DUPLICATE_KEY");
        frame.keys.add(key);
        frame.state = "colon";
      } else if (frame.state === "colon") { if (c !== ":") bad(); at++; frame.state = "value"; }
      else if (frame.state === "value") { frame.state = "commaOrEnd"; value(); }
      else if (c === "}") { at++; stack.pop(); }
      else if (c === ",") { at++; frame.state = "key"; }
      else bad();
    } else {
      if (frame.state === "valueOrEnd" && c === "]") { at++; stack.pop(); }
      else if (frame.state === "value" || frame.state === "valueOrEnd") { frame.state = "commaOrEnd"; value(); }
      else if (c === "]") { at++; stack.pop(); }
      else if (c === ",") { at++; frame.state = "value"; }
      else bad();
    }
  }
  space();
  if (at !== source.length) bad();
  try {
    return JSON.parse(source, (_key, item: unknown) => {
      if (typeof item === "number" && !Number.isFinite(item)) throw new StrictJsonError("INVALID_JSON_NUMBER");
      return item;
    });
  } catch (error) {
    if (error instanceof StrictJsonError) throw error;
    return bad();
  }
}
