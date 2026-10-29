// Identifier shape/checksum only; this does not verify a Tezos block or consensus.
import { createHash } from 'node:crypto';
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const prefixes = Object.freeze({
  block: { bytes: [1, 52], length: 32 }, operation: { bytes: [5, 116], length: 32 },
  chain: { bytes: [87, 82, 0], length: 4 }, protocol: { bytes: [2, 170], length: 32 },
  rollup: { bytes: [6, 124, 117], length: 20 },
  commitment: { bytes: [17, 165, 134, 138], length: 32 },
  state: { bytes: [17, 165, 235, 240], length: 32 },
});
const hash = (b: Uint8Array): Buffer => createHash('sha256').update(b).digest();
function decode58(text: unknown): Buffer {
  if (typeof text !== 'string' || text.length < 1 || text.length > 60) throw new Error('TEZOS_IDENTIFIER_LENGTH');
  let value = 0n;
  for (const c of text) { const digit = alphabet.indexOf(c); if (digit < 0) throw new Error('TEZOS_IDENTIFIER_ALPHABET'); value = value * 58n + BigInt(digit); }
  let hex = value.toString(16); if (hex.length % 2) hex = '0' + hex;
  const nonzero = value === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  const zeros = /^1*/.exec(text)![0]!.length;
  return Buffer.concat([Buffer.alloc(zeros), nonzero]);
}
function encode58(bytes: Uint8Array): string {
  let n = bytes.length ? BigInt('0x' + Buffer.from(bytes).toString('hex')) : 0n, out = '';
  while (n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; out = '1' + out; }
  return out;
}
export function validateTezosIdentifier(text: unknown, kind: keyof typeof prefixes): Buffer {
  const profile = prefixes[kind]; if (!profile) throw new Error('TEZOS_IDENTIFIER_KIND');
  const bytes = decode58(text), prefix = Buffer.from(profile.bytes);
  if (bytes.length !== prefix.length + profile.length + 4 || !bytes.subarray(0, prefix.length).equals(prefix)) throw new Error('TEZOS_IDENTIFIER_PREFIX');
  const payload = bytes.subarray(0, -4), checksum = hash(hash(payload)).subarray(0, 4);
  if (!bytes.subarray(-4).equals(checksum) || encode58(bytes) !== text) throw new Error('TEZOS_IDENTIFIER_CHECKSUM');
  return Buffer.from(payload.subarray(prefix.length));
}

export function encodeTezosIdentifier(payload: Uint8Array, kind: keyof typeof prefixes): string {
  const profile = prefixes[kind];
  if (!profile || !(payload instanceof Uint8Array) || payload.length !== profile.length) throw new Error('TEZOS_IDENTIFIER_PAYLOAD');
  const body = Buffer.concat([Buffer.from(profile.bytes), Buffer.from(payload)]);
  return encode58(Buffer.concat([body, hash(hash(body)).subarray(0, 4)]));
}
