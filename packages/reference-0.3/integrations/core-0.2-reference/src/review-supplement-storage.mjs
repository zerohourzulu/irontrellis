// One immutable operator-selected supplement on a cooperative local filesystem.
// No application, history, signer or Core authority is imported here.
import {
  constants, lstatSync, fstatSync, realpathSync, openSync, closeSync, readSync,
  opendirSync, mkdirSync, fsyncSync,
} from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { writeNew } from './io.mjs';
import { validateSupplementRecord, encodeSupplementRecord, createSupplementReference } from './review-supplement-format.mjs';

const SOURCE_LIMIT = 16384, MANIFEST_LIMIT = 4096;
const MEMBERS = Object.freeze(['MANIFEST.json', 'SOURCE.log']);
const STATS = Object.freeze({ bigint: true });
const DIGEST = /^[0-9a-f]{64}$(?![\s\S])/;
const INVALID_UNICODE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const backingBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function fail(reason) {
  const error = new Error(`REVIEW_SUPPLEMENT_${reason}`);
  error.code = error.message; throw error;
}
function check(condition, reason) { if (!condition) fail(reason); }
function io(reason, operation) { try { return operation(); } catch { fail(reason); } }
function absolute(value) {
  check(typeof value === 'string' && value.length > 0 && value.length <= 4096 &&
    Buffer.byteLength(value, 'utf8') <= 4096 && !value.includes('\0') && !INVALID_UNICODE.test(value) &&
    isAbsolute(value) && resolve(value) === value, 'INVALID');
  return value;
}
function locations(caseDirectory) {
  const root = absolute(caseDirectory), directory = absolute(join(root, 'review-supplement'));
  return { root, directory, sourcePath: absolute(join(directory, 'SOURCE.log')),
    manifestPath: absolute(join(directory, 'MANIFEST.json')) };
}
function sameIdentity(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.mode === b.mode && a.nlink === b.nlink &&
    a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}
function ancestry(directory, reason) {
  const result = [];
  let path = parse(directory).root;
  const capture = () => {
    const identity = io(reason, () => lstatSync(path, STATS));
    check(identity.isDirectory() && !identity.isSymbolicLink(), reason);
    result.push({ path, identity });
  };
  capture();
  for (const part of directory.slice(path.length).split(sep).filter(Boolean)) {
    path = join(path, part); capture();
  }
  check(io(reason, () => realpathSync(directory)) === directory, reason);
  return result;
}
function verifyAncestry(identities, reason, completeLast = false) {
  for (let i = 0; i < identities.length; i++) {
    const { path, identity } = identities[i];
    const current = io(reason, () => lstatSync(path, STATS));
    check(current.isDirectory() && !current.isSymbolicLink() && current.dev === identity.dev &&
      current.ino === identity.ino && current.mode === identity.mode, reason);
    // Ancestor sibling activity is unrelated; selected-slot membership is not.
    if (completeLast && i === identities.length - 1) check(sameIdentity(identity, current), reason);
  }
  const last = identities[identities.length - 1].path;
  check(io(reason, () => realpathSync(last)) === last, reason);
}
function fileIdentity(path, maximum, reason) {
  const value = io(reason, () => lstatSync(path, STATS));
  check(value.isFile() && !value.isSymbolicLink() && value.nlink === 1n &&
    value.size > 0n && value.size <= BigInt(maximum), reason);
  return value;
}
function readRegular(path, maximum, before, unavailable, changed) {
  const fd = io(unavailable, () => openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK));
  try {
    const opened = io(changed, () => fstatSync(fd, STATS));
    check(opened.isFile() && opened.nlink === 1n && sameIdentity(before, opened), changed);
    const buffer = Buffer.alloc(Number(opened.size) + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = io(changed, () => readSync(fd, buffer, length, buffer.length - length, length));
      if (count === 0) break;
      length += count;
    }
    const after = io(changed, () => fstatSync(fd, STATS));
    const named = fileIdentity(path, maximum, changed);
    check(length === Number(opened.size) && after.isFile() && sameIdentity(opened, after) &&
      sameIdentity(opened, named), changed);
    return Buffer.from(buffer.subarray(0, length));
  } finally { io(changed, () => closeSync(fd)); }
}
function utf8(bytes, reason) {
  return io(reason, () => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
}
function members(directory, reason) {
  const handle = io(reason, () => opendirSync(directory));
  const names = [];
  try {
    for (;;) {
      const entry = io(reason, () => handle.readSync());
      if (entry === null) break;
      names.push(entry.name);
      check(names.length <= MEMBERS.length, reason);
    }
  } finally { io(reason, () => handle.closeSync()); }
  names.sort();
  check(names.length === MEMBERS.length && names.every((name, i) => name === MEMBERS[i]), reason);
}
function syncDirectory(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function captureBuffer(value) {
  check(value !== null && typeof value === 'object' && !types.isProxy(value) && Buffer.isBuffer(value) &&
    Object.getPrototypeOf(value) === Buffer.prototype, 'INVALID');
  const length = io('INVALID', () => byteLength.call(value));
  check(length > 0 && length <= SOURCE_LIMIT && !types.isSharedArrayBuffer(backingBuffer.call(value)), 'INVALID');
  const keys = Reflect.ownKeys(value);
  check(keys.length === length && keys.every((key, i) => key === String(i)), 'INVALID');
  // The native typed-array operation reads bytes without valueOf/iterator/getters.
  const captured = Buffer.alloc(length);
  io('INVALID', () => Uint8Array.prototype.set.call(captured, value));
  utf8(captured, 'INVALID');
  return captured;
}

export function captureSupplementInput(inputPath, expectedSha256) {
  const path = absolute(inputPath);
  check(typeof expectedSha256 === 'string' && DIGEST.test(expectedSha256), 'INVALID');
  const directories = ancestry(dirname(path), 'INPUT_UNAVAILABLE');
  const before = fileIdentity(path, SOURCE_LIMIT, 'INPUT_UNAVAILABLE');
  const source = readRegular(path, SOURCE_LIMIT, before, 'INPUT_UNAVAILABLE', 'INPUT_CHANGED');
  verifyAncestry(directories, 'INPUT_CHANGED');
  utf8(source, 'INPUT_UNAVAILABLE');
  check(sha(source) === expectedSha256, 'DIGEST_MISMATCH');
  return source;
}

export function readReviewSupplement(caseDirectory) {
  const { root, directory, manifestPath, sourcePath } = locations(caseDirectory);
  const directories = ancestry(root, 'INCOMPLETE');
  let slot;
  try { slot = lstatSync(directory, STATS); }
  catch (error) {
    if (error.code !== 'ENOENT') fail('INCOMPLETE');
    verifyAncestry(directories, 'INCOMPLETE');
    return null;
  }
  check(slot.isDirectory() && !slot.isSymbolicLink(), 'INCOMPLETE');
  directories.push({ path: directory, identity: slot });
  check(io('INCOMPLETE', () => realpathSync(directory)) === directory, 'INCOMPLETE');
  members(directory, 'INCOMPLETE');
  // Capture every member before opening either; recheck every member at the end.
  const manifestIdentity = fileIdentity(manifestPath, MANIFEST_LIMIT, 'INCOMPLETE');
  const sourceIdentity = fileIdentity(sourcePath, SOURCE_LIMIT, 'INCOMPLETE');
  const manifestBytes = readRegular(manifestPath, MANIFEST_LIMIT, manifestIdentity, 'INCOMPLETE', 'INCOMPLETE');
  const sourceBytes = readRegular(sourcePath, SOURCE_LIMIT, sourceIdentity, 'INCOMPLETE', 'INCOMPLETE');
  const record = io('INCOMPLETE', () => validateSupplementRecord(JSON.parse(utf8(manifestBytes, 'INCOMPLETE'))));
  const canonical = io('INCOMPLETE', () => encodeSupplementRecord(record));
  check(manifestBytes.equals(canonical) && sourceBytes.length === record.bytes && sha(sourceBytes) === record.sha256, 'INCOMPLETE');
  utf8(sourceBytes, 'INCOMPLETE');
  const reference = io('INCOMPLETE', () => createSupplementReference(record));
  check(sameIdentity(manifestIdentity, fileIdentity(manifestPath, MANIFEST_LIMIT, 'INCOMPLETE')) &&
    sameIdentity(sourceIdentity, fileIdentity(sourcePath, SOURCE_LIMIT, 'INCOMPLETE')), 'INCOMPLETE');
  members(directory, 'INCOMPLETE');
  verifyAncestry(directories, 'INCOMPLETE', true);
  return Object.freeze({ reference, sourceBytes, manifestBytes });
}

export function writeReviewSupplement(caseDirectory, record, sourceBytes) {
  const { root, directory, sourcePath, manifestPath } = locations(caseDirectory);
  // Capture and validate all caller data before reserving the single slot.
  const capturedRecord = validateSupplementRecord(record);
  const source = captureBuffer(sourceBytes);
  check(source.length === capturedRecord.bytes && sha(source) === capturedRecord.sha256, 'INVALID');
  const manifest = encodeSupplementRecord(capturedRecord);
  const directories = ancestry(root, 'INCOMPLETE');
  try { mkdirSync(directory, { mode: 0o700 }); }
  catch (error) {
    if (error.code === 'EEXIST') fail('EXISTS');
    fail('WRITE_UNCERTAIN');
  }
  // From reservation onward every failure is uncertain. Preserve all state;
  // even failure after both writes never authorizes rollback or a retry.
  return io('WRITE_UNCERTAIN', () => {
    verifyAncestry(directories, 'WRITE_UNCERTAIN');
    const reserved = ancestry(directory, 'WRITE_UNCERTAIN');
    syncDirectory(root);
    writeNew(sourcePath, source);
    verifyAncestry(reserved, 'WRITE_UNCERTAIN');
    writeNew(manifestPath, manifest);
    verifyAncestry(reserved, 'WRITE_UNCERTAIN');
    const result = readReviewSupplement(root);
    check(result !== null && result.sourceBytes.equals(source) && result.manifestBytes.equals(manifest), 'WRITE_UNCERTAIN');
    return result;
  });
}
