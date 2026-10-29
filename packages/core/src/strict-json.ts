/**
 * Strict parsing of format-2 JSON texts (addendum A-34, as modified by the G2 ruling; A-49 for the string rules).
 *
 * A format-2 JSON text MUST be well-formed UTF-8 without a BOM and without a lone surrogate (a literal one or a
 * `\uD800`–`\uDFFF` escape outside a valid pair); objects MUST NOT contain a duplicate key; numbers MUST match
 * `0|-?[1-9][0-9]*` (no fraction, no exponent, no `-0`) and lie in `-(2^53−1) … 2^53−1`. Key order and the whitespace
 * between tokens stay tolerated (HF1 §3). The platform parser alone does not satisfy these rules (C-29): this module
 * validates the text first, with an explicit stack (no recursion on the JS call stack), and only then hands it to
 * `JSON.parse` — which never revives markers (A-7). Used for format-2 store lines (store.ts → `INVALID_HISTORY
 * {position}`), the snapshot (snapshot.ts → `SNAPSHOT_STALE` + `FULL_REPLAY`) and format-2 adapter inputs
 * (`INVALID_INPUT`). Legacy and format-1 readers keep the format-1 tolerance (A-28).
 */
export class StrictJsonError extends Error {
  readonly code: "BOM" | "LONE_SURROGATE" | "DUPLICATE_KEY" | "INVALID_NUMBER" | "INVALID_JSON" | "DEPTH_EXCEEDED";
  constructor(code: StrictJsonError["code"], message: string) {
    super(message);
    this.name = "StrictJsonError";
    this.code = code;
  }
}
type Frame = { kind: "object"; state: "keyOrEnd" | "key" | "colon" | "value" | "commaOrEnd"; keys: Set<string> } | { kind: "array"; state: "valueOrEnd" | "value" | "commaOrEnd" };
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
/** The maximum container depth of a format-2 text (canonical text allows 32; a store line wraps the event in one record). */
export const STRICT_JSON_MAX_DEPTH = 40;

/** A lone surrogate in a decoded string (`String.prototype.isWellFormed`, with a fallback scan). */
const wellFormed = (value: string): boolean => {
  const native = (value as { isWellFormed?: () => boolean }).isWellFormed;
  if (typeof native === "function") return native.call(value);
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const d = value.charCodeAt(i + 1); if (!(d >= 0xdc00 && d <= 0xdfff)) return false; i += 1; }
    else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
};

/** Validates `text` against the A-34 grammar; returns `undefined` or the first problem. */
export function strictJsonProblem(text: string, maxDepth: number = STRICT_JSON_MAX_DEPTH): StrictJsonError | undefined {
  try { validate(text, maxDepth); return undefined; } catch (error) {
    if (error instanceof StrictJsonError) return error;
    throw error;
  }
}
/** `JSON.parse(text)` after the A-34 validation; throws `StrictJsonError`. */
export function parseStrictJson(text: string, maxDepth: number = STRICT_JSON_MAX_DEPTH): unknown {
  validate(text, maxDepth);
  return JSON.parse(text) as unknown;
}

function validate(source: string, maxDepth: number): void {
  if (source.charCodeAt(0) === 0xfeff) throw new StrictJsonError("BOM", "a byte order mark is not allowed");
  let at = 0;
  const stack: Frame[] = [];
  const bad = (what: string): never => { throw new StrictJsonError("INVALID_JSON", `${what} at offset ${at}`); };
  const space = (): void => { for (let c = source.charCodeAt(at); c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d; c = source.charCodeAt(++at)); };
  const string = (): string => {
    const start = at++;
    // `plain`: no escape and no surrogate code unit seen, so the text between the quotes IS the decoded string and is
    // well-formed (what JSON.parse of the slice would return); anything else is decoded and checked as it always was.
    let plain = true;
    while (at < source.length) {
      const c = source.charCodeAt(at++);
      if (c === 0x22) {
        if (plain) return source.slice(start + 1, at - 1);
        let decoded: string;
        try { decoded = JSON.parse(source.slice(start, at)) as string; } catch { return bad("invalid string"); }
        if (!wellFormed(decoded)) throw new StrictJsonError("LONE_SURROGATE", `a lone surrogate in a string at offset ${start}`);
        return decoded;
      }
      if (c < 0x20) bad("an unescaped control character in a string");
      if (c >= 0xd800 && c <= 0xdfff) plain = false;
      if (c === 0x5c) {
        plain = false;
        const escape = source[at++];
        if (escape === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(at, at + 4))) bad("invalid \\u escape");
          at += 4;
        } else if (escape === undefined || !"\"\\/bfnrt".includes(escape)) bad("invalid escape");
      }
    }
    return bad("unterminated string");
  };
  // A literal, or a number token matching -?(0|[1-9][0-9]*) within the next 40 characters (the window the token
  // grammar was always read through), scanned by character code instead of a slice and two regular expressions.
  const scalar = (): void => {
    if (source.startsWith("true", at) || source.startsWith("null", at)) { at += 4; return; }
    if (source.startsWith("false", at)) { at += 5; return; }
    const limit = Math.min(source.length, at + 40);
    let end = at;
    if (end < limit && source.charCodeAt(end) === 0x2d) end += 1;
    const digits = end;
    const first = end < limit ? source.charCodeAt(end) : -1;
    if (first === 0x30) end += 1;
    else if (first >= 0x31 && first <= 0x39) { end += 1; while (end < limit && source.charCodeAt(end) >= 0x30 && source.charCodeAt(end) <= 0x39) end += 1; }
    else return void bad("unexpected token");
    const next = source[end];
    if (next === "." || next === "e" || next === "E" || (next !== undefined && next >= "0" && next <= "9")) throw new StrictJsonError("INVALID_NUMBER", `a number with a fraction, an exponent or a leading zero at offset ${at}`);
    if (end - at === 2 && first === 0x30 && digits === at + 1) throw new StrictJsonError("INVALID_NUMBER", `-0 at offset ${at}`);
    if (end - digits > 16 || Math.abs(Number(source.slice(at, end))) > MAX_SAFE) throw new StrictJsonError("INVALID_NUMBER", `a number outside ±(2^53−1) at offset ${at}`);
    at = end;
  };
  const value = (): void => {
    space();
    const c = source[at];
    if (c === "{") { at += 1; stack.push({ kind: "object", state: "keyOrEnd", keys: new Set() }); }
    else if (c === "[") { at += 1; stack.push({ kind: "array", state: "valueOrEnd" }); }
    else if (c === "\"") string();
    else scalar();
    if (stack.length > maxDepth) throw new StrictJsonError("DEPTH_EXCEEDED", `nesting deeper than ${maxDepth}`);
  };
  value();
  while (stack.length > 0) {
    space();
    const frame = stack[stack.length - 1]!, c = source[at];
    if (frame.kind === "object") {
      if (frame.state === "keyOrEnd" && c === "}") { at += 1; stack.pop(); }
      else if (frame.state === "key" || frame.state === "keyOrEnd") {
        if (c !== "\"") bad("expected a key");
        const key = string();
        if (frame.keys.has(key)) throw new StrictJsonError("DUPLICATE_KEY", `duplicate key ${JSON.stringify(key)}`);
        frame.keys.add(key);
        frame.state = "colon";
      } else if (frame.state === "colon") { if (c !== ":") bad("expected ':'"); at += 1; frame.state = "value"; }
      else if (frame.state === "value") { frame.state = "commaOrEnd"; value(); }
      else if (c === "}") { at += 1; stack.pop(); }
      else if (c === ",") { at += 1; frame.state = "key"; }
      else bad("expected ',' or '}'");
    } else {
      if (frame.state === "valueOrEnd" && c === "]") { at += 1; stack.pop(); }
      else if (frame.state === "value" || frame.state === "valueOrEnd") { frame.state = "commaOrEnd"; value(); }
      else if (c === "]") { at += 1; stack.pop(); }
      else if (c === ",") { at += 1; frame.state = "value"; }
      else bad("expected ',' or ']'");
    }
  }
  space();
  if (at !== source.length) bad("trailing text");
}
