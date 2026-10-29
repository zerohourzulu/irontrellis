import {
  constants, openSync, closeSync, readSync, writeFileSync, fsyncSync,
  lstatSync, fstatSync, opendirSync, mkdirSync,
} from 'node:fs';
import { resolve, parse, join, sep, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { derivePortableAdapterIdentity } from '../../../packages/core-0.2/src/core/portable-integration.ts';
import { hashCanonical, immutableProtocolInput } from '../../../packages/core-0.2/src/core/canonical.ts';
import { approvedPortableAdapterProfile, LOCAL_EVIDENCE_PACKET_ADAPTER_ID, createPortableAdapterAcknowledgment, portableAdapterAcknowledgmentEvidence, validatePortableAdapterAcknowledgment } from '../../../packages/core-0.2/src/core/portable-adapter-engine.ts';

const VERSION = '0.2';
const ATTEMPT = `continuity-local-packet-attempt/${VERSION}`;
const MANIFEST = `continuity-local-packet-manifest/${VERSION}`;
const ACK = `continuity-local-packet-ack/${VERSION}`;
const NAME = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const FILE_BYTES = 65_536;
const TOTAL_BYTES = 262_144;
const RECORD_BYTES = 16_384;
const fail = message => { throw new Error(message); };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const equal = (a, b) => hashCanonical(a) === hashCanonical(b);
const jsonBytes = value => Buffer.from(JSON.stringify(value) + '\n');
const freeze = value => {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
};
const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

function lexicalDirectory(path) {
  if (typeof path !== 'string' || !path || path.includes('\0') || path.split(sep).includes('..')) fail('Invalid directory path');
  return resolve(path);
}

// Trusted local filesystem, with explicit path/link checks; not hostile-host isolation.
function directory(path) {
  const absolute = lexicalDirectory(path), root = parse(absolute).root;
  let current = root;
  for (const component of absolute.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, component);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) fail('Directory path must not contain a symlink or non-directory');
  }
  return absolute;
}

function entries(path, maximum) {
  directory(path);
  const handle = opendirSync(path), result = [];
  try {
    for (let entry; (entry = handle.readSync()) !== null;) {
      result.push(entry.name);
      if (result.length > maximum) fail('Too many directory entries');
    }
  } finally { handle.closeSync(); }
  return result.sort();
}

function readRegular(path, maximum) {
  directory(dirname(path));
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maximum) fail('Expected bounded regular non-linked file');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino || opened.size > maximum) fail('File identity changed');
    const buffer = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(fd), named = lstatSync(path);
    if (length > maximum || length !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs ||
        after.ctimeMs !== opened.ctimeMs || after.nlink !== 1 || named.isSymbolicLink() || named.dev !== opened.dev || named.ino !== opened.ino) fail('File changed during bounded read');
    return buffer.subarray(0, length);
  } finally { closeSync(fd); }
}

function selectionValue(value) {
  const stable = immutableProtocolInput(value);
  if (!Array.isArray(stable) || stable.length < 1 || stable.length > 8) fail('Select between one and eight files');
  let total = 0, previous;
  for (const item of stable) {
    if (!exactKeys(item, ['name', 'bytes', 'sha256']) || typeof item.name !== 'string' || !NAME.test(item.name) ||
        !Number.isSafeInteger(item.bytes) || Object.is(item.bytes, -0) || item.bytes < 0 || item.bytes > FILE_BYTES ||
        typeof item.sha256 !== 'string' || !DIGEST.test(item.sha256) || (previous !== undefined && previous >= item.name)) fail('Invalid ordered file selection');
    previous = item.name;
    total += item.bytes;
  }
  if (total > TOTAL_BYTES) fail('Selected files exceed aggregate byte limit');
  return freeze(stable);
}

export function selectInput(inputDirectory) {
  const root = directory(inputDirectory), names = entries(root, 8);
  const selected = names.map(name => {
    if (!NAME.test(name)) fail('Invalid selected basename');
    const bytes = readRegular(join(root, name), FILE_BYTES);
    return { name, bytes: bytes.length, sha256: sha256(bytes) };
  });
  return selectionValue(selected);
}

function syncDirectory(path) {
  directory(path);
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function writeExclusive(path, bytes) {
  directory(dirname(path));
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  syncDirectory(dirname(path));
}

function readRecord(path) {
  const bytes = readRegular(path, RECORD_BYTES);
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  // Our retained JSON spelling is exact: duplicate keys/trailing material are invalid.
  if (!bytes.equals(jsonBytes(value))) fail('Non-exact retained record encoding');
  return { value, bytes };
}

export function createPacketExecutor({ inputDirectory, outputDirectory, selection, termsCommitment, resource, domain, intentId: configuredIntentId }) {
  const adapterProfile = approvedPortableAdapterProfile(LOCAL_EVIDENCE_PACKET_ADAPTER_ID);
  const expectedDomain = immutableProtocolInput(domain);
  if (!expectedDomain || expectedDomain.version !== VERSION || typeof configuredIntentId !== 'string' || !configuredIntentId) fail('Missing fixed executor domain/intent');
  // Retained packet inspection must not depend on mutable original inputs.
  // selectInput/first submit performs the actual input directory/link checks.
  const input = lexicalDirectory(inputDirectory), output = directory(outputDirectory);
  if (input === output || input.startsWith(output + sep) || output.startsWith(input + sep)) fail('Input and output directories must be disjoint');
  const selected = selectionValue(selection);
  if (typeof termsCommitment !== 'string' || !HASH.test(termsCommitment) || typeof resource !== 'string' ||
      resource.length < 1 || resource.length > 256 || Buffer.byteLength(resource) > 256 || /[\u0000-\u001f\u007f]/u.test(resource)) fail('Invalid executor terms or resource');
  const packet = join(output, 'packet'), files = join(packet, 'files');
  const record = (schemaVersion, identity, intentId) => ({ schemaVersion, idempotencyKey: identity.idempotencyKey,
    submissionFingerprint: identity.submissionFingerprint, intentId, selection: selected, termsCommitment, resource, adapterIdentity: identity });
  const acknowledgment = (identity, digest) => createPortableAdapterAcknowledgment(identity, `0x${digest}`);
  const evidence = (identity, ack) => portableAdapterAcknowledgmentEvidence(identity, ack);
  const unknown = (reason, identity) => freeze(identity
    ? { status: 'OUTCOME_UNKNOWN', idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }
    : { status: 'OUTCOME_UNKNOWN', reason });

  function retainedAttempt() {
    const { value } = readRecord(join(output, 'attempt.json'));
    if (!exactKeys(value, ['schemaVersion', 'idempotencyKey', 'submissionFingerprint', 'intentId', 'selection', 'termsCommitment', 'resource', 'adapterIdentity']) ||
        value.schemaVersion !== ATTEMPT || typeof value.idempotencyKey !== 'string' || !HASH.test(value.idempotencyKey) ||
        typeof value.submissionFingerprint !== 'string' || !HASH.test(value.submissionFingerprint) ||
        typeof value.intentId !== 'string' || value.intentId.length < 1 || Buffer.byteLength(value.intentId) > 256 ||
        !equal(value, record(ATTEMPT, value.adapterIdentity, value.intentId)) ||
        value.intentId !== configuredIntentId || value.adapterIdentity.intentId !== configuredIntentId || !equal(value.adapterIdentity.domain, expectedDomain) || !equal(value.adapterIdentity.adapterProfile, adapterProfile)) fail('Attempt identity/configuration mismatch');
    return value;
  }

  function inspect() {
    try {
      if (!equal(entries(output, 3), ['ack.json', 'attempt.json', 'packet'])) fail('Missing or unexpected output entries');
      const attempt = retainedAttempt();
      if (!equal(entries(packet, 2), ['files', 'manifest.json']) || !equal(entries(files, 8), selected.map(item => item.name))) fail('Packet file membership mismatch');
      const { value: manifest, bytes: manifestBytes } = readRecord(join(packet, 'manifest.json'));
      if (!equal(manifest, record(MANIFEST, attempt.adapterIdentity, attempt.intentId))) fail('Manifest does not bind the retained attempt');
      for (const item of selected) {
        const bytes = readRegular(join(files, item.name), FILE_BYTES);
        if (bytes.length !== item.bytes || sha256(bytes) !== item.sha256) fail('Packet file hash mismatch');
      }
      const manifestSha256 = sha256(manifestBytes);
      const { value: ack } = readRecord(join(output, 'ack.json'));
      const typed = acknowledgment(attempt.adapterIdentity, manifestSha256);
      if (!validatePortableAdapterAcknowledgment(typed, attempt.adapterIdentity) || !equal(ack, { schemaVersion: ACK, idempotencyKey: attempt.idempotencyKey,
        submissionFingerprint: attempt.submissionFingerprint, manifestSha256, acknowledgment: typed, evidence: evidence(attempt.adapterIdentity, typed) })) fail('Acknowledgment mismatch');
      return freeze({ status: 'PACKET_VERIFIED', manifestSha256, manifest, files: selected, acknowledgment: typed });
    } catch (error) { return unknown(error instanceof Error ? error.message : 'Retained packet unavailable'); }
  }

  function captureSubmission(submission) {
    const stable = immutableProtocolInput(submission);
    const identity = derivePortableAdapterIdentity(stable);
    if (!equal(identity.adapterProfile, adapterProfile) || !equal(identity.domain, expectedDomain) || identity.intentId !== configuredIntentId) fail('Submission differs from fixed executor profile/domain/intent');
    const request = stable.admissionEvent.data.authorizationProof.request;
    if (request.action !== 'collect-evidence-packet' || request.resource !== resource || request.termsCommitment !== termsCommitment) fail('Admitted request does not match the configured executor');
    return { stable, identity };
  }

  function retained(identity, intentId) {
    let attempt;
    try { attempt = retainedAttempt(); } catch { return unknown('Original attempt unavailable or inconsistent', identity); }
    if (attempt.idempotencyKey !== identity.idempotencyKey) return unknown('Output belongs to a different original attempt', identity);
    if (attempt.submissionFingerprint !== identity.submissionFingerprint) return freeze({ status: 'IDEMPOTENCY_FINGERPRINT_CONFLICT',
      idempotencyKey: identity.idempotencyKey, retainedFingerprint: attempt.submissionFingerprint, suppliedFingerprint: identity.submissionFingerprint });
    if (attempt.intentId !== intentId) return unknown('Original intent mismatch', identity);
    const result = inspect();
    return result.status === 'PACKET_VERIFIED' ? freeze({ status: 'RETRY', idempotencyKey: identity.idempotencyKey,
      submissionFingerprint: identity.submissionFingerprint, acknowledgment: result.acknowledgment, retainedEvidence: evidence(identity, result.acknowledgment) }) : unknown(result.reason, identity);
  }

  function reconcile(submission) {
    const { stable, identity } = captureSubmission(submission);
    return retained(identity, stable.intentId);
  }

  // Deliberately not async: all bounded reads/writes finish before the Promise
  // is returned, while the caller's synchronous serialized entry still holds.
  function submit(submission) {
    let identity;
    try {
      const captured = captureSubmission(submission);
      identity = captured.identity;
      const { stable } = captured;
      if (entries(output, 3).length !== 0) return Promise.resolve(retained(identity, stable.intentId));
      if (!equal(selectInput(input), selected)) return Promise.resolve(unknown('Selected inputs changed before intake', identity));
      writeExclusive(join(output, 'attempt.json'), jsonBytes(record(ATTEMPT, identity, stable.intentId)));
      mkdirSync(packet, { mode: 0o700 }); syncDirectory(output);
      mkdirSync(files, { mode: 0o700 }); syncDirectory(packet);
      for (const item of selected) {
        const bytes = readRegular(join(input, item.name), FILE_BYTES);
        if (bytes.length !== item.bytes || sha256(bytes) !== item.sha256) fail('Selected input changed during intake');
        writeExclusive(join(files, item.name), bytes);
      }
      const manifest = record(MANIFEST, identity, stable.intentId), bytes = jsonBytes(manifest), manifestSha256 = sha256(bytes);
      writeExclusive(join(packet, 'manifest.json'), bytes);
      const typed = acknowledgment(identity, manifestSha256);
      writeExclusive(join(output, 'ack.json'), jsonBytes({ schemaVersion: ACK, idempotencyKey: identity.idempotencyKey,
        submissionFingerprint: identity.submissionFingerprint, manifestSha256, acknowledgment: typed, evidence: evidence(identity, typed) }));
      const verified = inspect();
      if (verified.status !== 'PACKET_VERIFIED') return Promise.resolve(unknown(verified.reason, identity));
      return Promise.resolve(freeze({ status: 'SUBMITTED', idempotencyKey: identity.idempotencyKey,
        submissionFingerprint: identity.submissionFingerprint, acknowledgment: typed, evidence: evidence(identity, typed) }));
    } catch (error) { return Promise.resolve(unknown(error instanceof Error ? error.message : 'Packet creation uncertain', identity)); }
  }

  return Object.freeze({ adapterProfile, submit, reconcile, inspect });
}
