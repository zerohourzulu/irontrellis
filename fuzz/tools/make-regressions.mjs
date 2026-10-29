#!/usr/bin/env node
/**
 * Writes the regression vectors for the defects the fuzzer (and the reviews of
 * its findings) found before the first release (fuzz/regressions/<target>/<id>.json), deterministically from the
 * conformance histories and the transparency vectors: running it again
 * rewrites the same bytes (`--check` fails when a file would change).
 *
 * A vector is `{ id, target, description, rootCause, fix, found, input, expect? }`.
 * `fuzz/run.mjs --regressions` (and the smoke tests) run the target's check on
 * `input` (every invariant must hold: no crash, TS/Python agreement, …) and
 * compare the declared `expect` projection with the target's outcome.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { REGRESSIONS, ROOT, core, plain, revive, signerLib } from '../lib/env.mjs';
import { keyRegistry } from '../lib/seeds.mjs';
import { stringifyFaithful } from '../lib/python.mjs';
import { encodeHistory, parseHistory, pinFor } from '../lib/storefile.mjs';

const check = process.argv.includes('--check');
const vectors = [];
const add = (vector) => vectors.push(vector);
const FOUND = 'pre-release fuzzing, 2026-09-26';

// ---------------------------------------------------------------- canonical

add({
  id: 'deep-nesting-json-parse', target: 'canonical', found: `${FOUND} (canonical target, seed 1)`,
  description: 'Valid JSON nested 20,000 levels deep: jsonParseWithBigints must parse it (depth is the canonical layer\'s to refuse) and Python must refuse it with a typed error.',
  rootCause: 'TypeScript: jsonParseWithBigints decoded markers with a JSON.parse reviver, whose recursion in V8 overflows the call stack (RangeError) on deep but valid JSON, although JSON.parse itself is iterative. Python: json.loads and from_plain raise RecursionError, which no caller caught (python -m irontrellis verify printed a traceback on such a store line).',
  fix: 'canonical.ts: markers are decoded by an explicit-stack walk in document order (also ~4x faster on store lines). Python canonical.json_loads / json_loads_with_bigints turn RecursionError into CanonicalError (limit); the store reader and load_events use them.',
  input: { text: `${'['.repeat(20_000)}0${']'.repeat(20_000)}` },
  expect: { ts: { ok: false, stage: 'encode' } },
});
add({
  id: 'negative-zero-literal', target: 'canonical', found: `${FOUND} (canonical target, seed 1)`,
  description: 'The JSON number literal -0 is JavaScript negative zero, which the canonical form rejects; Python must reject it too.',
  rootCause: 'Python json.loads reads the literal -0 as the integer 0 (Python ints have no negative zero), so the Python canonical encoder accepted what the TypeScript one rejects (docs/HISTORY-FORMAT.md §2: -0 is rejected).',
  fix: 'python canonical.json_loads parses the literal -0 as the float -0.0 (which every protocol check rejects, like the TypeScript -0); used for store lines, .json histories and json_loads_with_bigints.',
  input: { text: '{"id":"x","timestamp":-0}' },
  expect: { ts: { ok: false, stage: 'encode' } },
});

// ---------------------------------------------------------------- events

add({
  id: 'control-event-marker-shaped-data', target: 'events', found: `${FOUND} (events target, seed 2)`,
  description: 'A format-1 control event whose data is a bigint-marker-shaped record (it captures to a bigint, not a record) is EVENT_DATA_INVALID in both engines.',
  rootCause: 'Python events.control_effect / signed_control_effect tested `"controlAuthorization" in data` on the captured data, a BigInt here: TypeError from validate_event and so from replay() on un-revived wire events (the TypeScript controlEffect returns a non-record as it is and the closed schema rejects it).',
  fix: 'python events.py: control_effect and signed_control_effect return a non-dict as it is.',
  input: { event: { id: 'agent:x', type: 'AGENT_CREATED', timestamp: 5, data: { '$continuity.bigint': '1' } }, format: core.TRELLIS_FORMAT, position: 3 },
  expect: { ts: { ok: false, code: 'EVENT_DATA_INVALID' } },
});

// ---------------------------------------------------------------- replay

{
  const v1 = JSON.parse(readFileSync(join(ROOT, 'conformance/v1/vectors.json'), 'utf8'));
  const vector = v1.find((v) => v.id === 'replay/v1/rejects-ed25519-session-in-migrated-prefix');
  add({
    id: 'ed25519-session-in-migrated-prefix', target: 'replay', found: `${FOUND} (replay target, initial campaign seed 11, iteration 12939)`,
    description: 'An owner-signed ed25519 runtime session admission inside a migrated legacy prefix is rejected (EVENT_DATA_INVALID at its position) by both engines (also conformance vector replay/v1/rejects-ed25519-session-in-migrated-prefix).',
    rootCause: 'Inside a migrated prefix (docs/HISTORY-FORMAT.md §11) events are validated with the format-1 schema (ed25519 credentials allowed) but applied to the legacy shadow view, whose sessionCredential reads credentialAddress: TypeError in the TypeScript replay, KeyError in the Python one, i.e. a crash of replay() and of every reader on such a history.',
    fix: 'events.ts sessionData / events.py _session_data: in the shadow (a migrated legacy prefix) a session admission must have credentialScheme eip191-personal-sign-keccak256 (legacy admissions always carry an Ethereum address).',
    input: { events: vector.events, evaluate: 1 },
    expect: { ts: { status: 'REJECTED', code: 'EVENT_DATA_INVALID', position: vector.rejection.position } },
  });
}

// ---------------------------------------------------------------- store (files derived from conformance/v1/histories/rotation-v1.jsonl)

const rotationText = readFileSync(join(ROOT, 'conformance/v1/histories/rotation-v1.jsonl'), 'utf8');
const { format, events } = parseHistory(rotationText);
const state = core.replay(revive(events)).state;
const last = events.length - 1;
const signerAt = (p) => keyRegistry().get(core.ownerKeysAt(state, p)[0].credential.toLowerCase());
const headAt = (p) => ({ hash: state.eventHistoryHashes[p], position: p, canonicalTime: state.events[p].timestamp });
const attestation = plain(signerLib.attestHeadSync(signerAt(last), state.genesis.domain, headAt(last), 'sha256'));
const store = (files) => ({ seed: 'conformance/v1/rotation-v1', witness: 'off', files: Object.fromEntries(Object.entries(files).map(([k, v]) => [k, { text: v }])) });

add({
  id: 'pin-attestation-null', target: 'store', found: `${FOUND} (store target, seed 1)`,
  description: 'A pin file whose attestation is JSON null: the strict open refuses it (PIN_ATTESTATION_INVALID) and verify() reports it instead of throwing.',
  rootCause: 'store.ts verify() called attestationCovers(pin.attestation, …), which read `.head` of the attestation after checking only `!== undefined`; the pin file is public and its optional fields were never shape-checked (repin/acceptRollback had the same defect in attestsExactly). TypeError from HistoryStore.verify / verifyHistory (masked as READ_UNAVAILABLE by the owner API).',
  fix: 'store.ts: attestationCovers and attestsExactly treat a non-record attestation as no valid attestation.',
  input: store({ 'history.jsonl': rotationText, 'history.jsonl.head': `${JSON.stringify({ ...pinFor(format, events, last), attestation: null })}\n` }),
  expect: { strict: { ok: false, code: 'ROLLBACK_DETECTED', reason: 'PIN_ATTESTATION_INVALID' } },
});
add({
  id: 'pin-previous-pin-null', target: 'store', found: `${FOUND} (review of the pin-attestation-null root cause)`,
  description: 'An owner-attested pin that records an accepted rollback with previousPin: null opens, and verify() notes "no readable previous pin" instead of throwing.',
  rootCause: 'store.ts verify() read pin.previousPin.position after checking only `!== undefined` (same class as pin-attestation-null: an unchecked optional pin field).',
  fix: 'store.ts: a previousPin that is not a record reads as absent.',
  input: store({ 'history.jsonl': rotationText, 'history.jsonl.head': `${JSON.stringify({ ...pinFor(format, events, last, { attestation }), rollbackAcceptedAt: 1, previousPin: null })}\n` }),
  expect: { strict: { ok: true } },
});
{
  const moved = structuredClone(events);
  moved[3].id = moved[2].id; // EVENT_ID_DUPLICATE at position 3 (checked before the signature)
  const lines = encodeHistory(format, moved).split('\n');
  lines[5] = '{"version":"irontrellis-portable-file-store/1"'; // a record defect after it
  add({
    id: 'first-defect-in-file-order', target: 'store', requires: 'python', found: `${FOUND} (store target, seed 1)`,
    description: 'A store whose event 3 is rejected by replay and whose line 6 is unparsable: both readers report the replay rejection at position 3 (the first defect in file order).',
    rootCause: 'The Python CLI read the whole file (every record check) before replaying, so it reported the later record defect (status ERROR, line 6) where the TypeScript store, reading line by line as docs/HISTORY-FORMAT.md §3 specifies, reports EVENT_ID_DUPLICATE at 3.',
    fix: 'python store.replay_history(_bytes): record checks and replay line by line, with the file\'s line format; python -m irontrellis verify uses it.',
    input: store({ 'history.jsonl': lines.join('\n') }),
    expect: { reader: { layer: 'replay', status: 'REJECTED', code: 'EVENT_ID_DUPLICATE', position: 3 } },
  });
}
{
  const legacy = JSON.parse(readFileSync(join(ROOT, 'packages/reference-0.2/tests/fixtures/handover-history.json'), 'utf8'));
  add({
    id: 'legacy-history-in-format-1-file', target: 'store', requires: 'python', found: `${FOUND} (review of the first-defect-in-file-order root cause)`,
    description: 'A format-1 store file (irontrellis-portable-file-store/1 lines, sha256 record hashes) carrying the legacy reference history is rejected at position 0 by both readers.',
    rootCause: 'The Python CLI replayed a store file with the format detected from its genesis instead of the file\'s line format, so it ACCEPTED a format-1 file holding a legacy history (no owner signatures at all) that the TypeScript store rejects (the genesis lacks ownerKeys).',
    fix: 'python store.replay_history_bytes replays with the line format of the file, as the TypeScript store does.',
    input: store({ 'history.jsonl': encodeHistory(core.TRELLIS_FORMAT, legacy) }),
    expect: { reader: { layer: 'replay', status: 'REJECTED', code: 'EVENT_DATA_INVALID', position: 0 } },
  });
}
add({
  id: 'negative-zero-in-store-line', target: 'store', requires: 'python', found: `${FOUND} (canonical target finding, reproduced on a store)`,
  description: 'A format-1 store line whose number 0 is respelled -0 (record hash unchanged) is not canonical: rejected by both readers at the record layer.',
  rootCause: 'Python json.loads read -0 as the integer 0, so the record hash matched and Python accepted a file the TypeScript store rejects (the canonical form refuses negative zero).',
  fix: 'python canonical.json_loads (see negative-zero-literal), used by the store reader.',
  input: store({ 'history.jsonl': rotationText.replace('"maxDelegationDepth":0', '"maxDelegationDepth":-0') }),
  expect: { reader: { layer: 'store' }, strict: { ok: false, code: 'INVALID_HISTORY' } },
});

{
  const legacyText = readFileSync(join(ROOT, 'packages/reference-0.2/tests/fixtures/handover-history.jsonl'), 'utf8');
  if (!legacyText.includes('["number",24]')) throw new Error('fixture changed: no ["number",24] to respell');
  add({
    id: 'legacy-tagged-number-exponent', target: 'store', requires: 'python', found: `${FOUND} (store target, initial campaign seed 11, iteration 214)`,
    description: 'A legacy line whose tagged number 24 is spelled 24E+0 (record hash unchanged) is the JavaScript number 24: both readers accept the history, as the reference reader (JSON.parse) does.',
    rootCause: 'python store.decode_tagged accepted only Python ints for ["number", n]; json.loads reads 24E+0 (and 24.0) as a float, so the Python reader rejected ("invalid stored encoding") a file the TypeScript store and the Continuity 0.2 reference accept.',
    fix: 'python store.decode_tagged: an integral non-negative float within 2^53-1 is the number (negative zero stays rejected).',
    input: { seed: 'reference-0.2/handover-history.jsonl', witness: 'off', files: { 'history.jsonl': { text: legacyText.replace('["number",24]', '["number",24E+0]') } } },
    expect: { reader: { layer: 'replay', status: 'ACCEPTED' }, strict: { ok: true } },
  });
}

// ---------------------------------------------------------------- transparency

const V = JSON.parse(readFileSync(join(ROOT, 'conformance/transparency/vectors.json'), 'utf8'));
const answer = V.latestNotes.verify[0];
add({
  id: 'latest-note-null-expectation', target: 'transparency', found: `${FOUND} (transparency target, seed 4)`,
  description: 'verifyLatestNote with a null expectation never throws: it fails closed with EXPECTATION_INVALID in both cores.',
  rootCause: 'transparency/latest.ts defaulted `expect` only for undefined and then read expect.origin: TypeError from a function documented to never throw. Reading a non-record expectation as "expect nothing" would fail open: a Map, an array or a Python MappingProxyType carrying the nonce would skip every check.',
  fix: 'latest.ts and transparency.py: the expectation must be a plain object/dict whose fields are exactly historyId, nonce and optionally origin, each well-formed; anything else is EXPECTATION_INVALID, checked first.',
  input: { kind: 'latestVerify', note: answer.note, keys: answer.trustedVerifierKeys, expect: null },
  expect: { ts: { ok: false, reason: 'EXPECTATION_INVALID' } },
});
add({
  id: 'latest-note-null-nonce-expected', target: 'transparency', requires: 'python', found: `${FOUND} (transparency target, seed 3)`,
  description: 'An expected nonce that is null fails closed in both cores with EXPECTATION_INVALID.',
  rootCause: 'Python verify_latest_note skipped an expectation whose value was None (`expect.get("nonce") is not None`), where TypeScript checks any expectation that is present (`!== undefined`): a caller whose nonce was unexpectedly None accepted an unbound (replayable) answer.',
  fix: 'latest.ts and transparency.py type-check every expectation field (nonce: canonical base64url of 16..64 bytes, required).',
  input: { kind: 'latestVerify', note: answer.note, keys: answer.trustedVerifierKeys, expect: { ...answer.expect, nonce: null } },
  expect: { ts: { ok: false, reason: 'EXPECTATION_INVALID' } },
});
add({
  id: 'latest-note-array-expectation', target: 'transparency', requires: 'python', found: 'pre-release review of the latest-note expectation, 2026-09',
  description: 'An expectation that is not a plain object (here an array; likewise a Map, a MappingProxyType or a UserDict carrying a wrong nonce) fails closed with EXPECTATION_INVALID in both cores.',
  rootCause: 'Both verifiers treated a non-record expectation as "expect nothing", so a replayed answer to another nonce was accepted when the caller passed its nonce in any container other than a plain object/dict.',
  fix: 'latest.ts and transparency.py: EXPECTATION_INVALID for any expectation that is not a plain object/dict with exactly historyId, nonce and optionally origin.',
  input: { kind: 'latestVerify', note: answer.note, keys: answer.trustedVerifierKeys, expect: [answer.expect.origin, answer.expect.historyId, 'A'.repeat(43)] },
  expect: { ts: { ok: false, reason: 'EXPECTATION_INVALID' } },
});

{
  const head0 = V.receipts.find((v) => v.receipt.entry.kind === 'HEAD' && v.receipt.entry.signedStatement.statement.head.position === 0 && v.expect?.ok !== false);
  const receipt = structuredClone(head0.receipt);
  receipt.entry.signedStatement.statement.head.position = -0; // the JSON text says -0 (written faithfully below)
  add({
    id: 'receipt-negative-zero-position', target: 'transparency', found: `${FOUND} (transparency target, initial campaign seed 11; first seen as a harness transport artifact)`,
    description: 'A receipt whose entry states head position -0 is ENTRY_MALFORMED in both cores when read from JSON text (JSON.parse keeps -0, and a U53 is never negative zero).',
    rootCause: 'python -m irontrellis verify-receipt read the file with json.load, which turns -0 into the integer 0, so it reported VALID where the TypeScript verifier, reading the same text, reports ENTRY_MALFORMED. (The fuzz harness itself had the same blind spot: JSON.stringify writes -0 as 0, so its Python side saw another number than its TypeScript side.)',
    fix: 'python __main__ verify-receipt reads the file with canonical.json_loads; the harness sends and stores -0 faithfully (fuzz/lib/python.mjs stringifyFaithful).',
    input: { kind: 'receipt', receipt, keys: head0.trustedVerifierKeys },
    expect: { ts: { ok: false, reason: 'ENTRY_MALFORMED' } },
  });
}

// ---------------------------------------------------------------- cli-args

for (const [id, argv, where] of [['survives-unpaired-surrogate', ['survives', 'a\ud800', '--json'], 'the observation query (survivesState)'], ['revoke-unpaired-surrogate', ['revoke', 'g\ud800:1', '--json'], 'the owner write (event capture)']]) {
  add({
    id, target: 'cli-args', found: `${FOUND} (cli-args target, initial campaign seed 11)`,
    description: `irontrellis ${argv[0]} with an identifier holding an unpaired surrogate is a USAGE-level INVALID_INPUT, not the unclassified FAILED (possible on Windows, where argv is UTF-16).`,
    rootCause: `The CLI's checkIdentifier and the owner API's identifier() (packages/core/src/input.ts) checked length and control characters but not well-formedness, so the id reached ${where}, whose canonical capture threw a raw CanonicalError: the CLI printed error FAILED and the owner API broke its "errors are IronTrellisError" contract.`,
    fix: 'input.ts identifier() requires a well-formed ProtocolString (INVALID_INPUT); the CLI checkIdentifier rejects it first with a message naming the argument.',
    input: { argv, json: true },
    expect: { code: 1, error: 'INVALID_INPUT' },
  });
}

add({
  id: 'session-key-file-unwritable', target: 'cli-args', found: `${FOUND} (cli-args target, initial campaign seed 11)`,
  description: 'irontrellis session admit --new-key into a directory that does not exist is FILE_UNWRITABLE (nothing admitted), not the unclassified FAILED.',
  rootCause: 'commands.ts turned only EEXIST from creating the key file into a CLI error and rethrew every other file-system error (ENOENT, EACCES, ENAMETOOLONG…) as is: the CLI printed error FAILED with the raw errno message.',
  fix: 'commands.ts: any other failure to create the key file is CliError FILE_UNWRITABLE (message in messages.ts); nothing was written or admitted.',
  input: { argv: ['session', 'admit', 's:unwritable', '--agent', 'bea', '--epoch', '1', '--key', 'k:unwritable', '--expires', '+1h', '--new-key', '{dir}/no-such-directory/key.json', '--json'], json: true },
  expect: { code: 1, error: 'FILE_UNWRITABLE' },
});

// ---------------------------------------------------------------- write

let changed = 0;
for (const vector of vectors) {
  const dir = join(REGRESSIONS, vector.target);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${vector.id}.json`);
  const text = `${stringifyFaithful(vector, 1)}\n`;
  if (existsSync(file) && readFileSync(file, 'utf8') === text) continue;
  changed += 1;
  if (check) console.log(`would change: ${file}`);
  else writeFileSync(file, text);
}
console.log(`${vectors.length} regression vectors, ${changed} ${check ? 'differ' : 'written'}`);
process.exitCode = check && changed > 0 ? 1 : 0;
