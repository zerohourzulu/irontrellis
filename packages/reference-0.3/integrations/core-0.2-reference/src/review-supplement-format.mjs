// Pure application evidence format. No filesystem, Core, signer or authority decision.
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { validateReviewSnapshotId } from './review-snapshot-location.mjs';

export const SUPPLEMENT_SUMMARY_SCHEMA = 'continuity-local-intake-summary/0.2+review-supplement.1';
export const SUPPLEMENT_EXPORT_SCHEMA = 'continuity-local-intake-export/0.2+review-supplement.1';
export const SIGNED_CONTEXT_SUMMARY_SCHEMA = 'continuity-local-intake-summary/0.2+signed-context.1';
export const SIGNED_CONTEXT_EXPORT_SCHEMA = 'continuity-local-intake-export/0.2+signed-context.1';
export const SUPPLEMENT_SOURCE_SCOPE = 'OPERATOR_SELECTED_SYNTHETIC_UNVERIFIED_SOURCE';
export const SUPPLEMENT_EVIDENCE_SCOPE = 'ORIGINAL_OPERATOR_IMPORTED_SYNTHETIC_SUPPLEMENT_UNVERIFIED_SOURCE';
const RECORD_SCHEMA = 'continuity-review-supplement/1';
const REFERENCE_SCHEMA = 'continuity-review-supplement-reference/1';
const DIGEST = /^[0-9a-f]{64}$(?![\s\S])/;
const HASH = /^0x[0-9a-f]{64}$(?![\s\S])/;
const FILE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,75}\.log$(?![\s\S])/;
const INVALID_UNICODE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u;
const CONTROLS = /[\u0000-\u001f\u007f-\u009f]/u;
const RECORD_FIELDS = ['schemaVersion', 'caseId', 'supplementId', 'fileName', 'bytes', 'sha256', 'sourceLabel',
  'sourceScope', 'importedAt', 'observedHistoryHead', 'basePacketManifestSha256'];
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function fail() { const error = new TypeError('REVIEW_SUPPLEMENT_INVALID'); error.code = error.message; throw error; }
function check(value) { if (!value) fail(); }
function plain(value) {
  check(value !== null && typeof value === 'object' && !types.isProxy(value));
  check([Object.prototype, null].includes(Object.getPrototypeOf(value)));
}
function data(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  check(descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable);
  return descriptor.value;
}
function closed(value, names) {
  plain(value);
  const keys = Reflect.ownKeys(value);
  check(keys.length === names.length && keys.every(key => typeof key === 'string' && names.includes(key)));
  const result = Object.create(null);
  for (const name of names) result[name] = data(value, name);
  return result;
}
function slug(value) { try { return validateReviewSnapshotId(value); } catch { fail(); } }
function matches(value, regex) { check(typeof value === 'string' && regex.test(value)); return value; }
function positive(value, maximum) { check(Number.isSafeInteger(value) && value > 0 && value <= maximum); return value; }
function natural(value) { check(Number.isSafeInteger(value) && !Object.is(value, -0) && value >= 0); return value; }
function label(value) {
  check(typeof value === 'string' && value.length > 0 && value.length <= 160 && !INVALID_UNICODE.test(value) &&
    !CONTROLS.test(value) && Buffer.byteLength(value, 'utf8') <= 160);
  return value;
}
function importedAt(value) {
  check(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$(?![\s\S])/.test(value));
  const time = Date.parse(value);
  check(Number.isFinite(time) && new Date(time).toISOString() === value);
  return value;
}
function head(value) {
  const h = closed(value, ['hash', 'position', 'canonicalTime']);
  return Object.freeze({ hash: matches(h.hash, HASH), position: natural(h.position), canonicalTime: natural(h.canonicalTime) });
}
export function parseSupplementRequest(value) {
  const r = closed(value, ['supplementId', 'fileName', 'sourceLabel', 'expectedSha256']);
  return Object.freeze({ supplementId: slug(r.supplementId), fileName: matches(r.fileName, FILE),
    sourceLabel: label(r.sourceLabel), expectedSha256: matches(r.expectedSha256, DIGEST) });
}
export function validateSupplementRecord(value) {
  const r = closed(value, RECORD_FIELDS);
  check(r.schemaVersion === RECORD_SCHEMA && r.sourceScope === SUPPLEMENT_SOURCE_SCOPE);
  return Object.freeze({ schemaVersion: RECORD_SCHEMA, caseId: slug(r.caseId), supplementId: slug(r.supplementId),
    fileName: matches(r.fileName, FILE), bytes: positive(r.bytes, 16384), sha256: matches(r.sha256, DIGEST),
    sourceLabel: label(r.sourceLabel), sourceScope: SUPPLEMENT_SOURCE_SCOPE, importedAt: importedAt(r.importedAt),
    observedHistoryHead: head(r.observedHistoryHead), basePacketManifestSha256: matches(r.basePacketManifestSha256, DIGEST) });
}
export function encodeSupplementRecord(value) {
  const bytes = Buffer.from(JSON.stringify(validateSupplementRecord(value), null, 2) + '\n', 'utf8');
  check(bytes.length <= 4096);
  return bytes;
}
export function createSupplementReference(value) {
  const record = validateSupplementRecord(value);
  return Object.freeze({ schemaVersion: REFERENCE_SCHEMA, manifestSha256: sha(encodeSupplementRecord(record)), record });
}
export function validateSupplementReference(value) {
  const r = closed(value, ['schemaVersion', 'manifestSha256', 'record']);
  check(r.schemaVersion === REFERENCE_SCHEMA);
  const reference = createSupplementReference(r.record);
  check(matches(r.manifestSha256, DIGEST) === reference.manifestSha256);
  return reference;
}
export function supplementForSummary(value) {
  plain(value);
  const schema = data(value, 'schemaVersion');
  if (schema === 'continuity-local-intake-summary/0.2') {
    check(!Object.hasOwn(value, 'reviewSupplement'));
    return null;
  }
  if (schema === SIGNED_CONTEXT_SUMMARY_SCHEMA) {
    return Object.hasOwn(value, 'reviewSupplement') ? validateSupplementReference(data(value, 'reviewSupplement')) : null;
  }
  check(schema === SUPPLEMENT_SUMMARY_SCHEMA);
  return validateSupplementReference(data(value, 'reviewSupplement'));
}
