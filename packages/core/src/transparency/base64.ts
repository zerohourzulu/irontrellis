/**
 * Standard base64 with padding (RFC 4648 §4), strict: the decoder accepts only
 * the canonical spelling (alphabet, padding and zero trailing bits), so every
 * byte string has exactly one accepted text form.
 */
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function encodeBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
}

/** The decoded bytes, or `undefined` when `text` is not canonical padded base64. */
export function decodeBase64(text: unknown): Uint8Array | undefined {
  if (typeof text !== "string" || !BASE64.test(text)) return undefined;
  const bytes = new Uint8Array(Buffer.from(text, "base64"));
  return encodeBase64(bytes) === text ? bytes : undefined;
}
