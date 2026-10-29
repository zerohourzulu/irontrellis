import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { supplementForSummary } from './review-supplement-format.mjs';

const FIELDS = ['caseId', 'domain', 'adapterProfile', 'head', 'packet', 'review',
  'stage', 'admission', 'duty', 'predecessorEpoch'];
const INVALID_UNICODE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u;

function invalid() {
  const error = new TypeError('REVIEW_CASE_VERSION_INVALID');
  error.code = 'REVIEW_CASE_VERSION_INVALID';
  throw error;
}

function plain(value) {
  if (value === null || typeof value !== 'object' || types.isProxy(value)) invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid();
}

function ownData(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) invalid();
  return descriptor.value;
}

function validString(value) {
  if (INVALID_UNICODE.test(value) || Buffer.byteLength(value, 'utf8') > 65_536) invalid();
}

/** Local reviewed-context identity only; does not decide current authority. */
export function reviewedCaseVersion(summary) {
  plain(summary);
  let supplement;
  try { supplement = supplementForSummary(summary); } catch { invalid(); }
  const source = Object.create(null);
  source.schemaVersion = supplement === null ? 'continuity-reviewed-case/1' : 'continuity-reviewed-case/2';
  for (const key of FIELDS) source[key] = ownData(summary, key);
  if (supplement !== null) source.reviewSupplement = supplement;
  let nodes = 0, encodedBytes = 0;
  function account(text) {
    encodedBytes += Buffer.byteLength(text, 'utf8');
    if (encodedBytes > 262_144) invalid();
  }
  const ancestors = new Set();
  function capture(value, depth) {
    if (++nodes > 16_384 || depth > 32) invalid();
    if (value === null || typeof value === 'boolean') { account(JSON.stringify(value)); return value; }
    if (typeof value === 'string') { validString(value); account(JSON.stringify(value)); return value; }
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || Object.is(value, -0)) invalid();
      account(JSON.stringify(value));
      return value;
    }
    if (typeof value !== 'object' || types.isProxy(value) || ancestors.has(value)) invalid();
    ancestors.add(value);
    let captured;
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || value.length > 256 ||
          Reflect.ownKeys(value).length !== value.length + 1) invalid();
      account('[]' + ','.repeat(Math.max(0, value.length - 1)));
      captured = [];
      for (let index = 0; index < value.length; index++) captured.push(capture(ownData(value, String(index)), depth + 1));
    } else {
      plain(value);
      const keys = Reflect.ownKeys(value);
      if (keys.length > 128 || keys.some(key => typeof key !== 'string')) invalid();
      account('{}' + ','.repeat(Math.max(0, keys.length - 1)));
      captured = Object.create(null);
      for (const key of keys.sort()) {
        validString(key);
        account(JSON.stringify(key) + ':');
        captured[key] = capture(ownData(value, key), depth + 1);
      }
    }
    ancestors.delete(value);
    return captured;
  }
  const captured = capture(source, 0);
  // Serialize captured data directly: never consult a source toJSON method.
  function encode(value) {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(encode).join(',')}]`;
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${encode(value[key])}`).join(',')}}`;
  }
  const encoded = encode(captured);
  if (Buffer.byteLength(encoded, 'utf8') > 262_144) invalid();
  return `rcv${supplement === null ? '1' : '2'}:${createHash('sha256').update(encoded, 'utf8').digest('hex')}`;
}

export function validateExpectedCaseVersion(value) {
  if (typeof value !== 'string' || value.length !== 69 || !/^rcv[12]:[0-9a-f]{64}$/.test(value)) {
    const error = new TypeError('REVIEW_EXPECTED_VERSION_INVALID');
    error.code = 'REVIEW_EXPECTED_VERSION_INVALID';
    throw error;
  }
  return value;
}
