// r4 §3.1 / inherited HF1 §2. No host JSON normalization or marker revival.
import { createHash } from 'node:crypto';
export const MAX_U53 = 9007199254740991;
export const LIMITS = Object.freeze({ bytes: 16777216, depth: 32, keys: 256, members: 4096, stringBytes: 4096 });
export class InputError extends Error { constructor(reason) { super(reason); this.name = 'InputError'; this.code = 'INVALID_INPUT'; } }
const fail = reason => { throw new InputError(reason); };
export function wellFormed(s) {
  if (typeof s !== 'string') fail('string required');
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const d = s.charCodeAt(++i); if (!(d >= 0xdc00 && d <= 0xdfff)) fail('lone surrogate'); }
    else if (c >= 0xdc00 && c <= 0xdfff) fail('lone surrogate');
  }
  return s;
}
function boundedString(s) { wellFormed(s); if (Buffer.byteLength(s) > LIMITS.stringBytes) fail('string byte limit'); return s; }
export function quote(s) {
  boundedString(s);
  let out = '"';
  for (const c of s) { const n = c.codePointAt(0); out += c === '"' ? '\\"' : c === '\\' ? '\\\\' : n < 32 ? '\\u' + n.toString(16).padStart(4, '0') : c; }
  return out + '"';
}
export function canonical(value) {
  const active = new Set(); let size = 0; const parts = [];
  const add = s => { size += Buffer.byteLength(s); if (size > LIMITS.bytes) fail('canonical byte limit'); parts.push(s); };
  function visit(v, depth) {
    if (v === null) return add('null');
    if (typeof v === 'string') return add(quote(v));
    if (typeof v === 'boolean') return add(v ? 'true' : 'false');
    if (typeof v === 'number') { if (!Number.isSafeInteger(v) || Object.is(v, -0)) fail('integer grammar'); return add(String(v)); }
    if (typeof v !== 'object') fail('unsupported value');
    if (depth >= LIMITS.depth || active.has(v)) fail('depth or cycle');
    active.add(v);
    const keys = Reflect.ownKeys(v);
    if (keys.some(k => typeof k !== 'string')) fail('symbol key');
    if (Array.isArray(v)) {
      if (v.length > LIMITS.members || keys.length !== v.length + 1) fail('array shape/limit');
      add('[');
      for (let i = 0; i < v.length; i++) { const d = Object.getOwnPropertyDescriptor(v, String(i)); if (!d || !('value' in d) || !d.enumerable) fail('sparse/accessor array'); if (i) add(','); visit(d.value, depth + 1); }
      add(']');
    } else {
      const proto = Object.getPrototypeOf(v); if (proto !== null && proto !== Object.prototype) fail('nonplain record');
      if (keys.length > LIMITS.keys) fail('key limit');
      for (const k of keys) { boundedString(k); if (k.startsWith('$continuity.')) fail('reserved key'); }
      keys.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
      add('{'); let first = true;
      for (const k of keys) { const d = Object.getOwnPropertyDescriptor(v, k); if (!d || !('value' in d) || !d.enumerable) fail('accessor/nonenumerable'); if (!first) add(','); first = false; add(quote(k) + ':'); visit(d.value, depth + 1); }
      add('}');
    }
    active.delete(v);
  }
  visit(value, 0); return parts.join('');
}
export function hashCanonical(value) { return '0x' + createHash('sha256').update(canonical(value), 'utf8').digest('hex'); }
function parseJSON(input, limits, reserved, checkCanonical) {
  let s;
  if (typeof input === 'string') { wellFormed(input); s = input; }
  else if (input instanceof Uint8Array) { try { s = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input); } catch { fail('invalid UTF8'); } }
  else fail('JSON text or bytes required');
  if (Buffer.byteLength(s) > limits.bytes) fail('input byte limit');
  if (s.charCodeAt(0) === 0xfeff) fail('BOM');
  let p = 0;
  const ws = () => { while (p < s.length && ' \t\r\n'.includes(s[p])) p++; };
  function string() {
    if (s[p++] !== '"') fail('string expected'); let out = '';
    while (p < s.length) {
      let c = s[p++];
      if (c === '"') { wellFormed(out); if (Buffer.byteLength(out) > limits.stringBytes) fail('string byte limit'); return out; }
      if (c.charCodeAt(0) < 32) fail('raw control');
      if (c === '\\') {
        c = s[p++];
        const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        if (Object.hasOwn(simple, c)) out += simple[c];
        else if (c === 'u') { const h = s.slice(p, p + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) fail('unicode escape'); out += String.fromCharCode(parseInt(h, 16)); p += 4; }
        else fail('escape');
      } else out += c;
    }
    fail('unterminated string');
  }
  function value(depth) {
    ws(); const c = s[p];
    if (c === '"') return string();
    if (c === '{' || c === '[') {
      if (depth >= limits.depth) fail('depth limit'); p++; ws();
      const array = c === '['; const result = array ? [] : Object.create(null); const end = array ? ']' : '}'; let count = 0;
      if (s[p] === end) { p++; return Object.freeze(result); }
      while (true) {
        if (++count > (array ? limits.members : limits.keys)) fail('container limit');
        if (array) result.push(value(depth + 1));
        else { ws(); const key = string(); if (reserved && key.startsWith('$continuity.')) fail('reserved key'); if (Object.hasOwn(result, key)) fail('duplicate key'); ws(); if (s[p++] !== ':') fail('colon'); result[key] = value(depth + 1); }
        ws(); if (s[p] === end) { p++; return Object.freeze(result); } if (s[p++] !== ',') fail('comma');
      }
    }
    for (const [t, v] of [['true', true], ['false', false], ['null', null]]) if (s.startsWith(t, p)) { p += t.length; return v; }
    const m = /^(?:0|-?[1-9][0-9]*)/.exec(s.slice(p));
    if (!m) fail('value/number grammar'); p += m[0].length; const n = Number(m[0]); if (!Number.isSafeInteger(n)) fail('integer range'); return n;
  }
  const result = value(0); ws(); if (p !== s.length) fail('trailing data/number grammar'); if (checkCanonical) canonical(result); return result;
}

export function parseStrict(input) { return parseJSON(input, LIMITS, true, true); }
export const EVIDENCE_LIMITS = Object.freeze({ maxBytes: 16777216, maxDepth: 64, maxStringBytes: 2097152, maxMembers: 4096, maxKeys: 256 });
// Separate external-evidence transport: same strict JSON grammar, NOT an r4 value/canonicalization claim.
export function parseEvidenceJson(input, options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) || ![null, Object.prototype].includes(Object.getPrototypeOf(options))) fail('evidence limits');
  const ceilings = { maxBytes: 67108864, maxDepth: 256, maxStringBytes: 67108864, maxMembers: 65536, maxKeys: 4096 };
  for (const k of Reflect.ownKeys(options)) {
    const d = Object.getOwnPropertyDescriptor(options, k);
    if (typeof k !== 'string' || !Object.hasOwn(ceilings, k) || !d || !('value' in d) || !d.enumerable || !Number.isSafeInteger(d.value) || d.value < 1 || d.value > ceilings[k]) fail('evidence limits');
  }
  const c = { ...EVIDENCE_LIMITS, ...options };
  return parseJSON(input, { bytes: c.maxBytes, depth: c.maxDepth, stringBytes: c.maxStringBytes, members: c.maxMembers, keys: c.maxKeys }, false, false);
}
