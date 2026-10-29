// Pure selected-context binding. It never grants authority, signs or performs I/O.
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalEncode, hashEventHistory } from '../../../packages/core-0.2/src/core/canonical.ts';
import { decodeProposal } from '../../agent-work-proposal/src/proposal.mjs';
import { isReviewSnapshotBundle } from '../../agent-gateway/src/review-snapshot-bytes.mjs';
import { reviewedCaseVersion, validateExpectedCaseVersion } from './reviewed-case-version.mjs';
import { validateReviewedContext } from './review-progress.mjs';

const SLUG = /^[a-z][a-z0-9-]{0,31}$(?![\s\S])/;
const HEX = /^[0-9a-f]{64}$(?![\s\S])/;
const BAD_UNICODE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u;
const BAD_CONTROLS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u;
const fail = code => { const error = new TypeError(code); error.code = code; throw error; };
const check = (ok, code) => { if (!ok) fail(code); };
function ownRecord(input, names, code = 'CONTEXT_INPUT_INVALID') {
  check(input !== null && typeof input === 'object' && !types.isProxy(input), code);
  const proto = Object.getPrototypeOf(input);
  check(proto === Object.prototype || proto === null, code);
  const keys = Reflect.ownKeys(input);
  check(keys.length === names.length && names.every(name => keys.includes(name)), code);
  const result = Object.create(null);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    check(descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable, code);
    result[name] = descriptor.value;
  }
  return result;
}
function proposalText(value) {
  check(typeof value === 'string' && value.length > 0 && value.length <= 4096 &&
    Buffer.byteLength(value, 'utf8') <= 4096 && !value.startsWith('\ufeff') &&
    !BAD_UNICODE.test(value) && !BAD_CONTROLS.test(value), 'CONTEXT_PROPOSAL_INVALID');
  return value;
}
function version(value) {
  try { return validateExpectedCaseVersion(value); } catch { fail('CONTEXT_INPUT_INVALID'); }
}
function equalData(actual, expected, code) {
  try { check(canonicalEncode(actual) === canonicalEncode(expected), code); }
  catch { fail(code); }
}
export function captureContextBoundInput(input) {
  check(arguments.length === 1, 'CONTEXT_INPUT_INVALID');
  const record = ownRecord(input, ['snapshotId', 'snapshotManifestSha256', 'expectedCaseVersion', 'proposalUtf8']);
  check(typeof record.snapshotId === 'string' && SLUG.test(record.snapshotId), 'CONTEXT_INPUT_INVALID');
  check(typeof record.snapshotManifestSha256 === 'string' && HEX.test(record.snapshotManifestSha256), 'CONTEXT_INPUT_INVALID');
  return Object.freeze({ snapshotId: record.snapshotId, snapshotManifestSha256: record.snapshotManifestSha256,
    expectedCaseVersion: version(record.expectedCaseVersion), proposalUtf8: proposalText(record.proposalUtf8) });
}
export function verifyContextBinding(options) {
  check(arguments.length === 1, 'CONTEXT_INPUT_INVALID');
  const config = ownRecord(options, ['caseId', 'actorId', 'expectedCaseVersion', 'snapshotManifestSha256',
    'proposalUtf8', 'bundle', 'history', 'priorEntries']);
  check(typeof config.caseId === 'string' && SLUG.test(config.caseId), 'CONTEXT_INPUT_INVALID');
  const who = config.actorId === `a:${config.caseId}` ? 'a' : config.actorId === `b:${config.caseId}` ? 'b' : null;
  check(who !== null, 'CONTEXT_PROPOSAL_MISMATCH');
  const expectedCaseVersion = version(config.expectedCaseVersion);
  check(typeof config.snapshotManifestSha256 === 'string' && HEX.test(config.snapshotManifestSha256), 'CONTEXT_INPUT_INVALID');
  const proposalUtf8 = proposalText(config.proposalUtf8), proposalBytes = Buffer.from(proposalUtf8, 'utf8');
  check(isReviewSnapshotBundle(config.bundle), 'CONTEXT_SNAPSHOT_MISMATCH');
  const { snapshot, history: snapshotHistory, notes } = config.bundle;
  check(snapshot.catalog.caseId === config.caseId && snapshot.statusSource.caseId === config.caseId &&
    snapshot.catalog.source.manifestSha256 === config.snapshotManifestSha256, 'CONTEXT_SNAPSHOT_MISMATCH');
  check(!types.isProxy(config.history) && Array.isArray(config.history) && config.history.length > 0 &&
    !types.isProxy(snapshotHistory) && Array.isArray(snapshotHistory), 'CONTEXT_HISTORY_MISMATCH');
  equalData(snapshotHistory, config.history, 'CONTEXT_HISTORY_MISMATCH');
  equalData(notes, config.priorEntries, 'CONTEXT_PRIOR_NOTES_MISMATCH');
  // Callers separately validate replay/authority; recompute the exact supplied
  // prefix commitment here so a captured summary cannot substitute its head.
  const expectedHead = { hash: hashEventHistory(config.history), position: config.history.length - 1,
    canonicalTime: config.history[config.history.length - 1].timestamp };
  equalData(snapshot.statusSource.head, expectedHead, 'CONTEXT_HISTORY_MISMATCH');
  equalData(snapshot.catalog.source.head, expectedHead, 'CONTEXT_HISTORY_MISMATCH');
  let snapshotVersion;
  try { snapshotVersion = reviewedCaseVersion(snapshot.statusSource); } catch { fail('CONTEXT_SNAPSHOT_MISMATCH'); }
  check(snapshotVersion === expectedCaseVersion, 'CONTEXT_VERSION_CHANGED');
  let decoded;
  try { decoded = decodeProposal(proposalBytes, { caseId: config.caseId, actor: who, snapshot }); }
  catch { fail('CONTEXT_PROPOSAL_INVALID'); }
  const proposalSha256 = createHash('sha256').update(proposalBytes).digest('hex');
  check(decoded.proposalSha256 === proposalSha256, 'CONTEXT_PROPOSAL_MISMATCH');
  const reviewedContext = Object.freeze({ schemaVersion: 'continuity-signed-reviewed-context/1', expectedCaseVersion,
    snapshotManifestSha256: config.snapshotManifestSha256, proposalSha256, proposalUtf8 });
  validateReviewedContext(reviewedContext);
  const { fileName, noteId, note } = decoded.proposal.action;
  return Object.freeze({ reviewedContext, action: Object.freeze({ fileName, noteId, note }) });
}
