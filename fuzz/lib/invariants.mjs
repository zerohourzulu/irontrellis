/**
 * Invariant helpers shared by the targets.
 *
 *  - typed rejections: every rejection the engine gives is a result object or
 *    one of its own error classes; anything else (TypeError, RangeError, …)
 *    thrown from a public entry point is an untyped crash;
 *  - signed content: an accepted history never carries an owner signature
 *    that was made over different content. For every control signature
 *    (`controlAuthorization`, `nextKeyAuthorizations`) that also occurs in a
 *    seed history, the challenge it signs (domain, event id, type, time,
 *    previous head, effect hash) is recomputed on the accepted history and
 *    must equal the challenge the seed signed. For other signatures the whole
 *    event (minus its owner signatures) must equal the seed event. Head
 *    attestations are judged the same way against the heads they attest.
 */
import { core, plain } from './env.mjs';

const TYPED = new Set(['EngineError', 'IronTrellisError', 'CanonicalError', 'NoteError', 'StoreConflictError', 'AdministrativeProducerError', 'DataError', 'ConfigError', 'UsageError', 'InputError', 'CliError']);

/** True when `error` is one of the engine's own error classes with a string code (or a documented SyntaxError where the API says so). */
export function isTypedError(error, { syntaxOk = false } = {}) {
  if (error === null || typeof error !== 'object') return false;
  if (syntaxOk && error instanceof SyntaxError) return true;
  return TYPED.has(error.name) && (error.name === 'CanonicalError' || error.name === 'NoteError' || typeof error.code === 'string');
}

export function crashFailure(where, error) {
  const top = String(error?.stack ?? '').split('\n').slice(1, 3).map((line) => line.trim().replace(/\(.*[\\/]/, '(').replace(/:\d+:\d+\)/, ')')).join(' | ');
  return { invariant: 'UNTYPED_CRASH', key: `CRASH:${where}:${error?.name ?? typeof error}:${top}`, message: `${where}: ${error?.name ?? typeof error}: ${String(error?.message ?? error).slice(0, 300)}`, detail: { stack: String(error?.stack ?? '').split('\n').slice(0, 6) } };
}

// ---------------------------------------------------------------- signatures in histories

const SIGNATURE = /^0x(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{130})$/;

/** [{signature, path}] for every signature-shaped string in an event's data, with where it sits. */
function signaturesOf(event) {
  const out = [];
  const walk = (node, path) => {
    if (typeof node === 'string') { if (SIGNATURE.test(node)) out.push({ signature: node.toLowerCase(), path }); return; }
    if (Array.isArray(node)) node.forEach((child, i) => walk(child, [...path, i]));
    else if (node !== null && typeof node === 'object') for (const [key, child] of Object.entries(node)) walk(child, [...path, key]);
  };
  walk(event?.data, []);
  return out;
}
const isOwnerSignaturePath = (path) => (path[0] === 'controlAuthorization' && path[1] === 'signature' && path.length === 2) ||
  (path[0] === 'nextKeyAuthorizations' && path.length === 3 && path[2] === 'signature');

const stripOwner = (event) => {
  const { controlAuthorization: _a, nextKeyAuthorizations: _b, ...data } = event.data ?? {};
  return { id: event.id, type: event.type, timestamp: event.timestamp, data };
};
const canonical = (value) => { try { return core.canonicalEncode(core.jsonParseWithBigints(JSON.stringify(value))); } catch { return undefined; } };

/** The control challenge an owner signature at `position` of an accepted history signs. */
function challengeOf(event, position, domain, hashes, algorithm) {
  try {
    const revived = core.jsonParseWithBigints(JSON.stringify(event));
    return core.controlAuthorizationHash({
      domain, eventId: revived.id, eventType: revived.type, timestamp: revived.timestamp,
      previousHead: position === 0 ? null : { hash: hashes[position - 1], position: position - 1 }, effectHash: core.controlEffectHash(revived, algorithm),
    }, algorithm);
  } catch {
    return undefined;
  }
}

/**
 * Index of every signature in the seed histories: signature → {challenge (owner signatures), canonical event (others)}.
 * `histories`: [{ events (wire) }] of ACCEPTED seed histories.
 */
export function signatureIndex(histories) {
  const index = new Map();
  for (const { events } of histories) {
    const result = core.replay(core.jsonParseWithBigints(JSON.stringify(events)));
    if (result.status !== 'ACCEPTED') continue;
    const state = result.state;
    events.forEach((event, position) => {
      for (const { signature, path } of signaturesOf(event)) {
        if (index.has(signature)) continue;
        index.set(signature, isOwnerSignaturePath(path)
          ? { owner: true, challenge: challengeOf(event, position, state.genesis.domain, state.eventHistoryHashes, state.hashAlgorithm) }
          : { owner: false, event: canonical(stripOwner(event)) });
      }
    });
  }
  return index;
}

/** Failures for an ACCEPTED replay `state` whose events reuse a seed signature over other content. */
export function signedContentFailures(index, state, label = 'history') {
  const failures = [];
  const events = state.events.map((event) => plain(event));
  events.forEach((event, position) => {
    for (const { signature, path } of signaturesOf(event)) {
      const known = index.get(signature);
      if (known === undefined) continue;
      if (isOwnerSignaturePath(path) && known.owner) {
        const challenge = challengeOf(event, position, state.genesis.domain, state.eventHistoryHashes, state.hashAlgorithm);
        if (challenge !== known.challenge) {
          failures.push({ invariant: 'SIGNED_CONTENT_ALTERED', key: `SIGNED_CONTENT_ALTERED:${label}:${event.type}:${path.join('.')}`,
            message: `${label}: accepted ${event.type} at position ${position} carries an owner signature (${path.join('.')}) made over another challenge` });
        }
      } else if (!isOwnerSignaturePath(path) && !known.owner && path.at(-1) === 'signature') {
        if (canonical(stripOwner(event)) !== known.event) {
          failures.push({ invariant: 'SIGNED_CONTENT_ALTERED', key: `SIGNED_CONTENT_ALTERED:${label}:${event.type}:${path.join('.')}`,
            message: `${label}: accepted ${event.type} at position ${position} carries a runtime signature (${path.join('.')}) from a seed event with other content` });
        }
      }
    }
  });
  return failures;
}

/** Head-attestation index: signature → attested head {hash, position} (from pins and anchor logs of the seeds). */
export function attestationIndex(attestations) {
  const index = new Map();
  for (const a of attestations) if (a && typeof a.signature === 'string') index.set(a.signature.toLowerCase(), { hash: a.head?.hash, position: a.head?.position, canonicalTime: a.head?.canonicalTime });
  return index;
}

/** A seed attestation reused in an accepted store must still attest the head it was made for, and that head must be a prefix. */
export function attestationFailures(index, attestation, state, label) {
  if (attestation === null || typeof attestation !== 'object' || typeof attestation.signature !== 'string') return [];
  const known = index.get(attestation.signature.toLowerCase());
  if (known === undefined) return [];
  const head = attestation.head ?? {};
  const failures = [];
  if (head.hash !== known.hash || head.position !== known.position || head.canonicalTime !== known.canonicalTime) {
    failures.push({ invariant: 'SIGNED_CONTENT_ALTERED', key: `ATTESTATION_ALTERED:${label}`, message: `${label}: an accepted store carries a seed head attestation over another head` });
  } else if (state.eventHistoryHashes[known.position] !== known.hash) {
    failures.push({ invariant: 'ATTESTED_PREFIX_LOST', key: `ATTESTED_PREFIX_LOST:${label}`, message: `${label}: an accepted store does not contain the head its owner attestation names (position ${known.position})` });
  }
  return failures;
}
