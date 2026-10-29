/**
 * Structure-aware mutation of plain JSON values (the wire form: bigints as
 * `{"$continuity.bigint":"…"}` markers), and text / byte / line mutation for
 * files, notes and HTTP bodies. Everything is driven by an `Rng`, so a
 * mutation is reproducible from its seed. Mutators never mutate their input.
 */

// structuredClone, not a JSON round trip: inputs may hold -0, which JSON.stringify writes as 0.
export const clone = (value) => (value === undefined ? undefined : structuredClone(value));

const isRecord = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
/** Adds a key as an own data property: `obj.__proto__ = v` would set the prototype instead (an input no JSON text can
 * produce, which TypeScript saw through inheritance while its JSON form, stored and sent to Python, lost the key). */
export const put = (obj, key, value) => {
  if (key === '__proto__') Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
  else obj[key] = value;
};

/** Every path (array of keys/indices) to a node below the root, depth-first. */
export function paths(value, limit = 5000) {
  const out = [];
  const walk = (node, prefix) => {
    if (out.length >= limit) return;
    if (Array.isArray(node)) node.forEach((child, i) => { out.push([...prefix, i]); walk(child, [...prefix, i]); });
    else if (isRecord(node)) for (const key of Object.keys(node)) { out.push([...prefix, key]); walk(node[key], [...prefix, key]); }
  };
  walk(value, []);
  return out;
}
export const getAt = (value, path) => path.reduce((node, key) => (node == null ? undefined : node[key]), value);
const parentOf = (value, path) => getAt(value, path.slice(0, -1));

// ---------------------------------------------------------------- dictionary

/** Tokens harvested from the seeds: realistic ids, hashes, signatures, keys and whole subtrees to splice. */
export class Dictionary {
  constructor() {
    this.strings = new Set();
    this.keys = new Set();
    this.numbers = new Set([0, 1]);
    this.subtrees = [];
  }
  add(value, depth = 0) {
    if (typeof value === 'string') { if (value.length <= 600) this.strings.add(value); return; }
    if (typeof value === 'number') { this.numbers.add(value); return; }
    if (Array.isArray(value)) {
      if (depth > 0 && this.subtrees.length < 4000 && value.length > 0) this.subtrees.push(value);
      for (const child of value) this.add(child, depth + 1);
      return;
    }
    if (isRecord(value)) {
      if (depth > 0 && this.subtrees.length < 4000) this.subtrees.push(value);
      for (const [key, child] of Object.entries(value)) { this.keys.add(key); this.add(child, depth + 1); }
    }
  }
  freeze() {
    this.stringList = [...this.strings];
    this.keyList = [...this.keys];
    this.numberList = [...this.numbers];
    return this;
  }
  string(rng) { return this.stringList.length ? rng.pick(this.stringList) : 'x'; }
  key(rng) { return this.keyList.length ? rng.pick(this.keyList) : 'k'; }
  number(rng) { return rng.pick(this.numberList); }
  subtree(rng) { return this.subtrees.length ? clone(rng.pick(this.subtrees)) : {}; }
}

// ---------------------------------------------------------------- interesting values

const MARKER = '$continuity.bigint';
const MAX256 = ((1n << 256n) - 1n).toString();

export function interestingString(rng) {
  return rng.pick([
    '', 'x', ' ', '\n', '\u0000', '\u001f', '\u007f', '\u0085', '\u00a0', '\u2028', '\ufeff', '\ud800', '\udfff', '\ud83d\ude00', 'é', '—',
    'a'.repeat(128), 'a'.repeat(129), 'a'.repeat(256), 'a'.repeat(257), 'é'.repeat(2048), 'é'.repeat(2049), 'a'.repeat(4096), 'a'.repeat(4097),
    '$continuity.bigint', '$continuity.x', '__proto__', 'constructor', 'toString', 'hasOwnProperty',
    `0x${'0'.repeat(64)}`, `0x${'f'.repeat(64)}`, `0x${'F'.repeat(64)}`, `0x${'0'.repeat(63)}`, `0x${'0'.repeat(65)}`, `0x${'ab'.repeat(64)}`, `0x${'ab'.repeat(65)}1b`,
    '0x', '0', '-0', '1e3', '01', 'NaN', 'Infinity', 'null', 'true', '1.0', ':', '+', '/', '=', 'A===', 'AAAA', '..', '../x', 'C:\\x', 'owner:1',
  ]);
}
export function interestingNumber(rng, current) {
  const base = typeof current === 'number' ? current : 0;
  return rng.pick([
    0, 1, -1, 2, 7, 255, 256, 1023, 1024, 4095, 4096, 4097, 65535, 65536, 2 ** 31 - 1, 2 ** 31, 2 ** 32, 2 ** 53 - 1, -(2 ** 53 - 1), 2 ** 53, 2 ** 64,
    0.5, 1.5, -0.5, 1e21, 1e300, base + 1, base - 1, base * 2, -base, Math.floor(base / 2), base + 1000,
  ]);
}
export function interestingMarker(rng) {
  return rng.pick([
    { [MARKER]: '0' }, { [MARKER]: '1' }, { [MARKER]: '-1' }, { [MARKER]: '01' }, { [MARKER]: '-0' }, { [MARKER]: MAX256 }, { [MARKER]: `-${MAX256}` },
    { [MARKER]: (1n << 256n).toString() }, { [MARKER]: '' }, { [MARKER]: 'abc' }, { [MARKER]: 1 }, { [MARKER]: '1', extra: 1 }, { '$continuity.x': '1' },
    { [MARKER]: '1'.repeat(80) }, { [MARKER]: ' 1' },
  ]);
}
export function interestingContainer(rng) {
  const deep = (n, leaf) => { let v = leaf; for (let i = 0; i < n; i += 1) v = [v]; return v; };
  const wide = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${String(i).padStart(4, '0')}`, i]));
  return rng.pick([[], {}, [null], [[]], { '': 1 }, deep(28, 0), deep(29, 0), deep(33, 0), deep(200, 0), wide(256), wide(257),
    Array.from({ length: 4097 }, () => 0), Array.from({ length: 33 }, (_, i) => `id:${i}`), Array.from({ length: 257 }, (_, i) => `id:${i}`)]);
}
export function interestingValue(rng, current, dict) {
  switch (rng.int(9)) {
    case 0: return interestingString(rng);
    case 1: return interestingNumber(rng, current);
    case 2: return interestingMarker(rng);
    case 3: return rng.pick([null, true, false]);
    case 4: return interestingContainer(rng);
    case 5: return dict ? dict.string(rng) : 'x';
    case 6: return dict ? dict.number(rng) : 0;
    case 7: return dict ? dict.subtree(rng) : {};
    default: return typeof current === 'string' ? mutateString(rng, current) : interestingString(rng);
  }
}

// ---------------------------------------------------------------- strings

const HEX = '0123456789abcdef';
export function mutateString(rng, text) {
  if (text.length === 0) return interestingString(rng);
  const at = rng.int(text.length);
  switch (rng.int(10)) {
    case 0: return text.slice(0, at) + text.slice(at + 1);
    case 1: return text.slice(0, at) + rng.pick(['a', '0', 'F', ' ', '\u0000', '\ud800', 'é', ':', '"', '\\', '\n']) + text.slice(at);
    case 2: { // flip one hex digit (hashes, signatures, credentials keep their shape)
      const hexAt = [...text].map((c, i) => (HEX.includes(c.toLowerCase()) && i > 1 ? i : -1)).filter((i) => i >= 0);
      if (hexAt.length === 0) return text + 'x';
      const i = rng.pick(hexAt);
      const c = text[i].toLowerCase();
      return text.slice(0, i) + HEX[(HEX.indexOf(c) + 1 + rng.int(15)) % 16] + text.slice(i + 1);
    }
    case 3: return text.toUpperCase();
    case 4: return text.slice(0, at);
    case 5: return text + text.slice(at);
    case 6: return text + rng.pick(['x', '0', '\u0000', ' ']);
    case 7: return ` ${text}`;
    case 8: return text.slice(0, at) + String.fromCharCode(text.charCodeAt(at) ^ (1 << rng.int(7))) + text.slice(at + 1);
    default: return interestingString(rng);
  }
}

// ---------------------------------------------------------------- JSON values

/** One structural mutation of `value` in place (value must be a container); returns a description. */
function mutateOnce(rng, value, dict) {
  const all = paths(value);
  if (all.length === 0) {
    if (Array.isArray(value)) value.push(interestingValue(rng, undefined, dict));
    else if (isRecord(value)) put(value, dict ? dict.key(rng) : 'k', interestingValue(rng, undefined, dict));
    return 'grow-empty';
  }
  const path = rng.pick(all);
  const parent = parentOf(value, path);
  const key = path.at(-1);
  const current = parent[key];
  switch (rng.weighted([[30, 'replace'], [10, 'delete'], [8, 'insert'], [10, 'string'], [6, 'number'], [6, 'dup'], [5, 'swap'], [6, 'splice'], [4, 'rename'], [3, 'wrap'], [3, 'type'], [4, 'marker']])) {
    case 'replace':
      parent[key] = interestingValue(rng, current, dict);
      return `replace ${path.join('.')}`;
    case 'delete':
      if (Array.isArray(parent)) parent.splice(key, 1); else delete parent[key];
      return `delete ${path.join('.')}`;
    case 'insert':
      if (Array.isArray(parent)) parent.splice(rng.int(parent.length + 1), 0, rng.chance(0.5) ? clone(current) : interestingValue(rng, current, dict));
      else put(parent, rng.chance(0.7) && dict ? dict.key(rng) : interestingString(rng), interestingValue(rng, undefined, dict));
      return `insert ${path.join('.')}`;
    case 'string':
      parent[key] = typeof current === 'string' ? mutateString(rng, current) : (dict ? dict.string(rng) : interestingString(rng));
      return `string ${path.join('.')}`;
    case 'number':
      parent[key] = interestingNumber(rng, current);
      return `number ${path.join('.')}`;
    case 'dup':
      if (Array.isArray(parent)) parent.splice(key, 0, clone(current));
      else put(parent, dict ? dict.key(rng) : `${key}2`, clone(current));
      return `dup ${path.join('.')}`;
    case 'swap':
      if (Array.isArray(parent) && parent.length > 1) {
        const j = rng.int(parent.length);
        [parent[key], parent[j]] = [parent[j], parent[key]];
      } else if (isRecord(parent)) {
        const keys = Object.keys(parent);
        const other = rng.pick(keys);
        [parent[key], parent[other]] = [parent[other], parent[key]];
      }
      return `swap ${path.join('.')}`;
    case 'splice':
      parent[key] = dict ? dict.subtree(rng) : {};
      return `splice ${path.join('.')}`;
    case 'rename':
      if (isRecord(parent)) {
        const to = dict && rng.chance(0.8) ? dict.key(rng) : interestingString(rng);
        delete parent[key];
        put(parent, to, current);
      }
      return `rename ${path.join('.')}`;
    case 'wrap':
      parent[key] = rng.chance(0.5) ? [current] : { [dict ? dict.key(rng) : 'k']: current };
      return `wrap ${path.join('.')}`;
    case 'type':
      parent[key] = typeof current === 'number' ? String(current) : typeof current === 'string' && /^-?\d+$/.test(current) ? Number(current)
        : typeof current === 'boolean' ? Number(current) : Array.isArray(current) ? Object.assign({}, current) : current === null ? {} : null;
      return `type ${path.join('.')}`;
    default:
      parent[key] = typeof current === 'number' && Number.isSafeInteger(current) && current >= 0 && rng.chance(0.5) ? { [MARKER]: String(current) } : interestingMarker(rng);
      return `marker ${path.join('.')}`;
  }
}

/** A mutated deep copy of a JSON value (1..`max` structural mutations). */
export function mutateValue(rng, value, dict, max = 3) {
  if (value === null || typeof value !== 'object') return interestingValue(rng, value, dict);
  const copy = clone(value);
  const count = 1 + rng.small(max - 1);
  for (let i = 0; i < count; i += 1) mutateOnce(rng, copy, dict);
  return copy;
}

// ---------------------------------------------------------------- text

const NUMBER_TOKEN = /(?<=[:[,])(-?)(\d+)(?=[,\]}])/g;
/** Respell one integer token of a JSON text: 5 → 5.0, 5e0, 50e-1, 05, -0, 5.5, 1e400 … */
export function respellNumber(rng, text) {
  const matches = [...text.matchAll(NUMBER_TOKEN)];
  if (matches.length === 0) return text;
  const m = rng.pick(matches);
  const n = m[2];
  const spelled = rng.pick([`${m[1]}${n}.0`, `${m[1]}${n}e0`, `${m[1]}${n}E+0`, `${m[1]}${n}0e-1`, `${m[1]}0${n}`, n === '0' ? '-0' : `-${n}`, '-0', '-0.0', '0.0', `${m[1]}${n}.5`,
    '1e400', '-1e400', `${m[1]}${n}.000000000000000001`, '9007199254740993', '9007199254740992', '9007199254740991', `${m[1]}${n}${n}`, '1E2', '0e5']);
  return text.slice(0, m.index) + spelled + text.slice(m.index + m[0].length);
}

const SPECIAL_CHARS = ['\u0000', '\t', '\n', '\r', ' ', '"', '\\', '{', '}', '[', ']', ',', ':', '\u007f', '\u00a0', '\u2028', '\ufeff', '\ud800', 'é', '—', 'A', '0', '=', '+', '/', 'x'];

/** One text-level mutation (chars, chunks, numbers, whitespace, escapes, duplicate keys). */
export function mutateTextOnce(rng, text) {
  const at = rng.int(text.length + 1);
  switch (rng.weighted([[12, 'char'], [8, 'delete'], [6, 'insert'], [6, 'chunk-del'], [5, 'chunk-dup'], [8, 'number'], [4, 'ws'], [4, 'escape'], [4, 'dupkey'], [3, 'truncate'], [3, 'case'], [3, 'swapchunk']])) {
    case 'char': return text.length === 0 ? rng.pick(SPECIAL_CHARS) : text.slice(0, Math.min(at, text.length - 1)) + rng.pick(SPECIAL_CHARS) + text.slice(Math.min(at, text.length - 1) + 1);
    case 'delete': return text.slice(0, at) + text.slice(at + 1);
    case 'insert': return text.slice(0, at) + rng.pick(SPECIAL_CHARS) + text.slice(at);
    case 'chunk-del': { const len = 1 + rng.int(Math.min(64, text.length + 1)); return text.slice(0, at) + text.slice(at + len); }
    case 'chunk-dup': { const len = 1 + rng.int(Math.min(64, text.length + 1)); return text.slice(0, at + len) + text.slice(at, at + len) + text.slice(at + len); }
    case 'number': return respellNumber(rng, text);
    case 'ws': {
      const spots = [...text.matchAll(/[,:{}[\]]/g)];
      if (spots.length === 0) return text;
      const s = rng.pick(spots);
      return text.slice(0, s.index + 1) + rng.pick([' ', '\t', '\r', '\n', '\r\n', '\u00a0', '\u2028', '  ']) + text.slice(s.index + 1);
    }
    case 'escape': { // respell one ASCII letter inside a string as \u00xx (same string, other bytes)
      const letters = [...text.matchAll(/(?<=")[A-Za-z]/g)];
      if (letters.length === 0) return text;
      const l = rng.pick(letters);
      const code = l[0].charCodeAt(0).toString(16).padStart(4, '0');
      return text.slice(0, l.index) + `\\u${rng.chance(0.5) ? code : code.toUpperCase()}` + text.slice(l.index + 1);
    }
    case 'dupkey': { // duplicate a "key":scalar member right after the opening brace
      const members = [...text.matchAll(/"([^"\\]{1,40})":("[^"\\]{0,80}"|-?\d+|true|false|null)/g)];
      if (members.length === 0) return text;
      const m = rng.pick(members);
      const open = text.lastIndexOf('{', m.index);
      if (open < 0) return text;
      const dup = `"${m[1]}":${rng.chance(0.5) ? m[2] : '"x"'},`;
      return text.slice(0, open + 1) + dup + text.slice(open + 1);
    }
    case 'truncate': return text.slice(0, at);
    case 'case': { const len = 1 + rng.int(16); return text.slice(0, at) + text.slice(at, at + len).toUpperCase() + text.slice(at + len); }
    default: { // swap two chunks
      const len = 1 + rng.int(32);
      const b = rng.int(text.length + 1);
      const [x, y] = at < b ? [at, b] : [b, at];
      if (y - x < len) return text;
      return text.slice(0, x) + text.slice(y, y + len) + text.slice(x + len, y) + text.slice(x, x + len) + text.slice(y + len);
    }
  }
}
export function mutateText(rng, text, max = 3) {
  let out = text;
  const count = 1 + rng.small(max - 1);
  for (let i = 0; i < count; i += 1) out = mutateTextOnce(rng, out);
  return out;
}

/** Line-level mutation of a newline-terminated text (JSONL files, notes). */
export function mutateLines(rng, text) {
  const trailing = text.endsWith('\n');
  const lines = (trailing ? text.slice(0, -1) : text).split('\n');
  const i = rng.int(lines.length), j = rng.int(lines.length);
  switch (rng.int(10)) {
    case 0: lines.splice(i, 1); break;
    case 1: lines.splice(i, 0, lines[i]); break;
    case 2: [lines[i], lines[j]] = [lines[j], lines[i]]; break;
    case 3: lines.splice(i + 1); break;
    case 4: lines.splice(i, 0, ''); break;
    case 5: lines.reverse(); break;
    case 6: return lines.join('\r\n') + (trailing ? '\r\n' : '');
    case 7: return (trailing ? text.slice(0, -1) : `${text}\n`);
    case 8: return `\ufeff${text}`;
    default: { const [line] = lines.splice(i, 1); lines.splice(j, 0, line); break; }
  }
  return lines.join('\n') + (trailing ? '\n' : '');
}

// ---------------------------------------------------------------- bytes

export function mutateBytes(rng, bytes) {
  const out = Buffer.from(bytes);
  if (out.length === 0) return Buffer.from([rng.int(256)]);
  const at = rng.int(out.length);
  switch (rng.int(7)) {
    case 0: out[at] ^= 1 << rng.int(8); return out;
    case 1: out[at] = rng.pick([0x00, 0x0a, 0x0d, 0x22, 0x5c, 0x7f, 0x80, 0xbf, 0xc0, 0xc3, 0xed, 0xef, 0xf4, 0xf8, 0xff]); return out;
    case 2: return Buffer.concat([out.subarray(0, at), Buffer.from(rng.pick([[0xef, 0xbb, 0xbf], [0xc3], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xc0, 0xaf], [0xff], [0x00]])), out.subarray(at)]);
    case 3: return Buffer.concat([out.subarray(0, at), out.subarray(Math.min(out.length, at + 1 + rng.int(8)))]);
    case 4: return out.subarray(0, at);
    case 5: { const len = 1 + rng.int(Math.min(64, out.length - at)); return Buffer.concat([out.subarray(0, at + len), out.subarray(at, at + len), out.subarray(at + len)]); }
    default: return Buffer.concat([out, Buffer.from(rng.pick(['\n', '{}\n', ' ', '\r\n', '\u0000']))]);
  }
}
