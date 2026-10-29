import { types } from 'node:util';
import { createHash } from 'node:crypto';

const SCHEMA = 'continuity-review-progress/1';
const CONTEXT_SCHEMA = 'continuity-review-progress/2';
const SLUG = /^[a-z][a-z0-9-]{0,31}$/;
const FILE_NAME = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;
const CONTROLS = /[\u0000-\u001f\u007f-\u009f]/u;
const NOTE_CONTROLS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/u;
const UNPAIRED_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u;
const utf8 = new TextEncoder();
const ENTRY_KEYS = ['schemaVersion', 'caseId', 'sequence', 'noteId', 'actorId', 'runtimeSessionId',
  'controlEpoch', 'roleTenureId', 'historyHead', 'packetManifestSha256', 'fileName', 'fileSha256',
  'note', 'status', 'previousRecordHash', 'authorizationProofHash', 'signature'];

function invalid(field) {
  const error = new TypeError(`Invalid review progress: ${field}`);
  error.code = 'REVIEW_PROGRESS_INVALID';
  throw error;
}

function record(value, keys, label) {
  if (value === null || typeof value !== 'object' || types.isProxy(value)) invalid(label);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid(label);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || !keys.every(key => ownKeys.includes(key))) invalid(`${label} fields`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) invalid(`${label}.${key}`);
  }
}

function array(value, maximum, label, minimum = 0) {
  if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype ||
      value.length < minimum || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) invalid(label);
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) invalid(`${label}[${index}]`);
  }
}

function text(value, label, pattern) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 160 ||
      CONTROLS.test(value) || UNPAIRED_SURROGATE.test(value) || (pattern && !pattern.test(value))) invalid(label);
}

function integer(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) invalid(label);
}

/** Shape validation only: no signature, chain, history or authority verification. */
export function validateProgressEntry(entry) {
  if (entry === null || typeof entry !== 'object' || types.isProxy(entry)) invalid('entry');
  const schema = Object.getOwnPropertyDescriptor(entry, 'schemaVersion');
  if (!schema || !Object.hasOwn(schema, 'value') || !schema.enumerable) invalid('schemaVersion');
  const contextBound = schema.value === CONTEXT_SCHEMA;
  record(entry, contextBound ? [...ENTRY_KEYS, 'reviewedContext'] : ENTRY_KEYS, 'entry');
  if ((!contextBound && entry.schemaVersion !== SCHEMA) || entry.status !== 'REVIEWED') invalid('schemaVersion/status');
  if (contextBound) validateReviewedContext(entry.reviewedContext);
  text(entry.caseId, 'caseId', SLUG);
  integer(entry.sequence, 1, 32, 'sequence');
  text(entry.noteId, 'noteId', SLUG);
  for (const key of ['actorId', 'runtimeSessionId', 'roleTenureId']) text(entry[key], key);
  integer(entry.controlEpoch, 1, Number.MAX_SAFE_INTEGER, 'controlEpoch');
  record(entry.historyHead, ['canonicalTime', 'hash', 'position'], 'historyHead');
  integer(entry.historyHead.canonicalTime, 0, Number.MAX_SAFE_INTEGER, 'historyHead.canonicalTime');
  integer(entry.historyHead.position, 0, Number.MAX_SAFE_INTEGER, 'historyHead.position');
  text(entry.historyHead.hash, 'historyHead.hash', HASH);
  text(entry.packetManifestSha256, 'packetManifestSha256', SHA256);
  text(entry.fileName, 'fileName', FILE_NAME);
  text(entry.fileSha256, 'fileSha256', SHA256);
  if (typeof entry.note !== 'string' || entry.note.length > 1000 || utf8.encode(entry.note).length > 1000 ||
      NOTE_CONTROLS.test(entry.note) || UNPAIRED_SURROGATE.test(entry.note)) invalid('note');
  if (entry.previousRecordHash !== null) text(entry.previousRecordHash, 'previousRecordHash', HASH);
  text(entry.authorizationProofHash, 'authorizationProofHash', HASH);
  text(entry.signature, 'signature', SIGNATURE);
  return entry;
}

/** Closed v2 byte binding only; no approval, source truth or signature assertion. */
export function validateReviewedContext(value) {
  record(value, ['schemaVersion', 'expectedCaseVersion', 'snapshotManifestSha256', 'proposalSha256', 'proposalUtf8'], 'reviewedContext');
  if (value.schemaVersion !== 'continuity-signed-reviewed-context/1') invalid('reviewedContext.schemaVersion');
  text(value.expectedCaseVersion, 'reviewedContext.expectedCaseVersion', /^rcv[12]:[0-9a-f]{64}$/);
  text(value.snapshotManifestSha256, 'reviewedContext.snapshotManifestSha256', SHA256);
  text(value.proposalSha256, 'reviewedContext.proposalSha256', SHA256);
  const proposal = value.proposalUtf8;
  if (typeof proposal !== 'string' || proposal.length === 0 || proposal.length > 4096 ||
      utf8.encode(proposal).length > 4096 || proposal.startsWith('\ufeff') ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(proposal) || UNPAIRED_SURROGATE.test(proposal)) invalid('reviewedContext.proposalUtf8');
  if (createHash('sha256').update(proposal, 'utf8').digest('hex') !== value.proposalSha256) invalid('reviewedContext.proposalSha256 binding');
  return value;
}

/** Projects caller-authenticated application work; never grants authority or resolves an incident. */
export function summarizeProgress(selection, entries) {
  array(selection, 8, 'selection', 1);
  const selected = new Map();
  let totalBytes = 0;
  for (const item of selection) {
    record(item, ['name', 'bytes', 'sha256'], 'selected file');
    text(item.name, 'selected file.name', FILE_NAME);
    text(item.sha256, 'selected file.sha256', SHA256);
    integer(item.bytes, 0, 65_536, 'selected file.bytes');
    totalBytes += item.bytes;
    if (totalBytes > 262_144 || selected.has(item.name)) invalid('selection limit/duplicate');
    selected.set(item.name, item);
  }
  array(entries, 32, 'entries');
  const noteIds = new Set(), latest = new Map();
  let caseId, packetManifestSha256;
  for (let index = 0; index < entries.length; index++) {
    const entry = validateProgressEntry(entries[index]);
    if (entry.sequence !== index + 1 || noteIds.has(entry.noteId)) invalid('entry sequence/duplicate noteId');
    if (index === 0) { caseId = entry.caseId; packetManifestSha256 = entry.packetManifestSha256; }
    else if (entry.caseId !== caseId || entry.packetManifestSha256 !== packetManifestSha256) invalid('mixed case/packet');
    const file = selected.get(entry.fileName);
    if (!file || file.sha256 !== entry.fileSha256) invalid('entry file binding');
    noteIds.add(entry.noteId);
    latest.set(entry.fileName, entry);
  }
  const files = selection.map(item => {
    const entry = latest.get(item.name);
    return { name: item.name, sha256: item.sha256, bytes: item.bytes, reviewed: entry !== undefined,
      latestNoteId: entry?.noteId ?? null, latestActorId: entry?.actorId ?? null, latestNote: entry?.note ?? null };
  });
  return {
    scope: 'APPLICATION_RECORDED_WORK', recordCount: entries.length, reviewedCount: latest.size,
    totalFiles: selection.length, remainingFiles: files.filter(file => !file.reviewed).map(file => file.name),
    files, incidentResolution: 'NOT_PROVEN',
  };
}
