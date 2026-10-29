// Adapted from the contributed source resolver. Only bytes are accepted; no
// executable store/caller snapshot is trusted. No store writer is imported.
import { openSync, closeSync, fstatSync, readSync, realpathSync, constants } from 'node:fs';
import { resolve, relative, isAbsolute, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { hashCanonical, immutableProtocolValue } from '../packages/core-0.2/src/core/index.ts';
import { parseStrictJson } from '../integrations/retained-evidence-mcp/src/strict-json.mjs';
import { LIMITS, ReaderError, fail, record, closed, OPERATIONS } from './reader-contract.mjs';

export function readBoundedFile(path, maxBytes = LIMITS.history) {
  let fd;
  try {
    // Reject final symlinks, FIFOs/devices and hardlinks. Ancestor races require
    // a trusted local administrator: this is not a hostile-filesystem sandbox.
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1) fail('SOURCE_NOT_REGULAR');
    if (before.size > maxBytes) fail('SOURCE_BYTES_EXCEEDED');
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const n = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!n) fail('SOURCE_CHANGED');
      offset += n;
    }
    const after = fstatSync(fd);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) fail('SOURCE_CHANGED');
    return bytes;
  } catch (error) { if (error instanceof ReaderError) throw error; fail('SOURCE_UNAVAILABLE'); }
  finally { if (fd !== undefined) closeSync(fd); }
}

// Exact local-store tagged encoding, adapted from PortableFileEventStore. The
// captured bytes are decoded once; parity/integrity tests cover this adapter.
const FORMAT = 'continuity-portable-file-store/0.2';
function encodeTagged(v) {
  if (v === null) return ['null'];
  if (typeof v === 'bigint') return ['bigint', v.toString()];
  if (Array.isArray(v)) return ['array', v.map(encodeTagged)];
  if (typeof v === 'object') return ['object', Object.entries(v).map(([k, x]) => [k, encodeTagged(x)])];
  return [typeof v, v];
}
function decodeTagged(v, depth = 0) {
  if (depth > 64 || !Array.isArray(v)) fail('HISTORY_MALFORMED');
  const [tag, body] = v;
  if (tag === 'null' && v.length === 1) return null;
  if (v.length !== 2) fail('HISTORY_MALFORMED');
  if (tag === 'bigint' && typeof body === 'string' && /^(0|[1-9][0-9]*)$/.test(body) && body.length <= 78) return BigInt(body);
  if (tag === 'string' && typeof body === 'string') return body;
  if (tag === 'number' && Number.isSafeInteger(body) && body >= 0 && !Object.is(body, -0)) return body;
  if (tag === 'boolean' && typeof body === 'boolean') return body;
  if (tag === 'array' && Array.isArray(body)) return body.map(x => decodeTagged(x, depth + 1));
  if (tag === 'object' && Array.isArray(body)) {
    const out = Object.create(null);
    for (const pair of body) {
      if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== 'string' || Object.hasOwn(out, pair[0])) fail('HISTORY_MALFORMED');
      out[pair[0]] = decodeTagged(pair[1], depth + 1);
    }
    return out;
  }
  fail('HISTORY_MALFORMED');
}
function reviveMarkers(value) {
  if (Array.isArray(value)) return value.map(reviveMarkers);
  if (!record(value)) return value;
  if (Object.hasOwn(value, '$continuity.bigint')) {
    const str = value['$continuity.bigint'];
    if (Object.keys(value).length !== 1 || typeof str !== 'string' || str.length > 79 || !/^(0|-?[1-9][0-9]*)$/.test(str)) fail('HISTORY_MALFORMED');
    const n = BigInt(str), max = (1n << 256n) - 1n;
    if (n < -max || n > max) fail('HISTORY_MALFORMED');
    return n;
  }
  const out = Object.create(null);
  for (const [k, v] of Object.entries(value)) out[k] = reviveMarkers(v);
  return out;
}
export function decodeHistory(bytes) {
  if (bytes.length > LIMITS.history) fail('SOURCE_BYTES_EXCEEDED');
  let events;
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.trimStart().startsWith('{')) {
      try { const selected = parseStrictJson(bytes); if (record(selected) && typeof selected.version === 'string' && (selected.version.startsWith('continuity-history-') || selected.version === 'continuity-migrated-file/1')) fail('UNSUPPORTED_HISTORY_PROFILE'); }
      catch (error) { if (error instanceof ReaderError) throw error; }
    }
    if (text.trimStart().startsWith('[')) events = reviveMarkers(parseStrictJson(bytes));
    else {
      if (!text.endsWith('\n')) fail('HISTORY_MALFORMED');
      const lines = text.slice(0, -1).split('\n');
      if (lines.length > LIMITS.events) fail('EVENT_LIMIT_EXCEEDED');
      let previousHash = null;
      events = lines.map(line => {
        const r = parseStrictJson(Buffer.from(line));
        if (record(r) && ['continuity-history-source-fence/1','continuity-history-binding/1','continuity-history-manifest/1'].includes(r.version)) fail('UNSUPPORTED_HISTORY_PROFILE');
        if (!record(r) || Object.keys(r).sort().join(',') !== 'event,previousHash,recordHash,version' || r.version !== FORMAT || r.previousHash !== previousHash) fail('HISTORY_INTEGRITY');
        const event = decodeTagged(r.event);
        if (JSON.stringify(encodeTagged(event)) !== JSON.stringify(r.event)) fail('HISTORY_MALFORMED');
        const digest = hashCanonical({ version: FORMAT, previousHash, event });
        if (r.recordHash !== digest) fail('HISTORY_INTEGRITY');
        previousHash = digest;
        return event;
      });
    }
    if (!Array.isArray(events) || events.length === 0) fail('HISTORY_EMPTY');
    if (events.length > LIMITS.events) fail('EVENT_LIMIT_EXCEEDED');
    return immutableProtocolValue(events);
  } catch (error) {
    if (error instanceof ReaderError) throw error;
    fail(error.code?.startsWith('JSON_') || error.code === 'DUPLICATE_KEY' || error.code === 'INVALID_UTF8' ? error.code : 'HISTORY_MALFORMED');
  }
}

const NAME = /^[a-z][a-z0-9-]{0,31}$/;
export function sourcePath(root, file) {
  if (typeof file !== 'string' || !file || isAbsolute(file) || file.includes('\\') || file.split('/').some(p => !p || p === '..' || p === '.')) fail('SOURCE_PATH_DENIED');
  const path = resolve(root, file);
  let real;
  try { real = realpathSync(path); } catch { fail('SOURCE_UNAVAILABLE'); }
  const rel = relative(root, real);
  if (real !== path || rel.startsWith('../') || isAbsolute(rel)) fail('SOURCE_PATH_DENIED');
  return path;
}
export function loadSourceConfig(path) {
  const bytes = readBoundedFile(resolve(path), LIMITS.config);
  try {
    const data = parseStrictJson(bytes, { maxBytes: LIMITS.config, maxDepth: 8, maxNodes: 2048 });
    closed(data, ['version', 'root', 'sources'], ['version', 'root', 'sources']);
    if (data.version !== 'continuity-reader-config/1' || typeof data.root !== 'string' || !record(data.sources) || Object.keys(data.sources).length > 32) fail('CONFIG_INVALID');
    const root = realpathSync(resolve(dirname(path), data.root));
    const sources = Object.create(null);
    for (const [name, spec] of Object.entries(data.sources)) {
      if (!NAME.test(name)) fail('CONFIG_INVALID');
      if (spec?.historyProfile !== undefined || spec?.historyBinding !== undefined) fail('UNSUPPORTED_HISTORY_PROFILE');
      closed(spec, ['file', 'disclosure', 'operations'], ['file', 'disclosure', 'operations']);
      if (!['summary', 'evidence'].includes(spec.disclosure) || !Array.isArray(spec.operations) || spec.operations.length === 0 || spec.operations.some(x => !OPERATIONS.includes(x)) || new Set(spec.operations).size !== spec.operations.length) fail('CONFIG_INVALID');
      sourcePath(root, spec.file);
      sources[name] = { ...spec };
    }
    return immutableProtocolValue({ root, sources, configHash: createHash('sha256').update(bytes).digest('hex') });
  } catch (error) { if (error instanceof ReaderError && ['SOURCE_PATH_DENIED', 'SOURCE_UNAVAILABLE', 'UNSUPPORTED_HISTORY_PROFILE'].includes(error.code)) throw error; fail('CONFIG_INVALID'); }
}
export function selectSource(config, name, operation) {
  if (typeof name !== 'string' || !NAME.test(name) || !Object.hasOwn(config.sources, name)) fail('SOURCE_DENIED');
  const spec = config.sources[name];
  if (!spec.operations.includes(operation)) fail('OPERATION_DENIED');
  return { path: sourcePath(config.root, spec.file), source: name, disclosure: spec.disclosure, configHash: config.configHash };
}
