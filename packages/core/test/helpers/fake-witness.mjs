// An in-test witness server that implements the irontrellis-witness/1 HTTP contract (docs/WITNESS.md §9: acceptance
// rules, key events, wire format, log entries) on top of the core transparency libraries: a
// real RFC 6962 Merkle tree, real C2SP signed-note checkpoints, real receipts, real head-statement verification against
// owner key epochs (ownerKeysAt / verifyRotationEvent). It exists so the client can be tested without the server
// package (core cannot depend on it); packages/witness/test/differential.test.mjs drives this fake and the real server
// with the same random request sequences and requires identical answers. Test knobs: `down`, `tamper`, `splitView()`,
// `wrongKey()`, `statements` (every signed statement received, accepted or not), `requests`. Like the server, a `nonce`
// query parameter on the history routes adds the signed `latestNote` (docs/reference/witness-protocol.md §9.8) to every reply that carries
// log state, and EQUIVOCATION evidence is capped (one entry per position, 64 per history).
import { createServer } from "node:http";

const transparency = await import("../../src/transparency/index.ts");
const { ownerKeysAt, verifyRotationEvent } = await import("../../src/owner-keys.ts");
const { validateEvent } = await import("../../src/events.ts");
const { historyIdOfGenesis } = await import("../../src/hash.ts");
const { canonicalEncode } = await import("../../src/canonical.ts");

const {
  MerkleTree, entryLeafHash, validateSignedHeadStatement, verifySignedHeadStatement, buildReceipt, signNote, formatCheckpoint, noteSignerFromSeed, verifierKey,
  encodeBase64, parseSignerKey, WITNESS_ENTRY_VERSION, formatLatestNote, isValidNonce, validateKeyEventBundle,
} = transparency;

const canonical = (value) => canonicalEncode(value);
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hasExactKeys = (value, keys) => Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const isHeadRef = (value) => isRecord(value) && hasExactKeys(value, ["hash", "position"]) && typeof value.hash === "string" && /^0x[0-9a-f]{64}$/.test(value.hash) && Number.isSafeInteger(value.position) && value.position >= 0;
const sameRef = (a, b) => a !== null && a !== undefined && b !== undefined && a.hash === b.hash && a.position === b.position;
/** Equivocation evidence cap (like the server): one entry per position, at most this many per history. */
const MAX_EQUIVOCATIONS_PER_HISTORY = 64;
const refKey = (ref) => `${ref.position}:${ref.hash}`;
/** Epochs as the wire carries them (like the server's epochsWire): keys, and the next-key commitment when known. */
const wireEpochs = (epochs) => epochs.map((epoch) => ({
  fromPosition: epoch.fromPosition, keys: epoch.keys.map((key) => ({ keyId: key.keyId, scheme: key.scheme, credential: key.credential })),
  ...(epoch.nextKeyDigests === undefined ? {} : { nextKeyDigests: [...epoch.nextKeyDigests] }),
}));
const seedOf = (n) => { const seed = new Uint8Array(32); seed[0] = n & 0xff; seed[1] = (n >> 8) & 0xff; seed[31] = 7; return seed; };

/**
 * startFakeWitness({ name, seed, signerKey, token, now }) → { url, verifierKey, origin, close(), ... }.
 * `token`: registration needs `Authorization: Bearer <token>` (default: open). `signerKey`: a C2SP signer key string
 * (e.g. the `privateKey` of an irontrellis-witness data dir) instead of the seeded test key.
 */
export async function startFakeWitness(options = {}) {
  let signer = options.signerKey === undefined ? undefined : parseSignerKey(options.signerKey);
  const name = signer?.name ?? options.name ?? "fake-witness";
  signer ??= noteSignerFromSeed(name, seedOf(options.seed ?? 1));
  const origin = options.origin ?? `irontrellis-witness/${name}`;
  const vkey = verifierKey(name, signer.publicKey);
  const clock = options.now ?? (() => Date.now());
  let tree = new MerkleTree();
  const entries = [];
  const histories = new Map();
  const state = {
    down: false, tamper: undefined, statements: [], keyEventsReceived: [], requests: [], registrations: 0, alternate: undefined, cappedEquivocations: 0,
    /** Answer every nonce with this latest note instead ("strip": leave it out; a function: (history, nonce) => note text). */
    latestNote: undefined,
  };

  const append = (entry) => {
    const index = tree.append(entryLeafHash(entry));
    entries.push(entry);
    return index;
  };
  const checkpointOf = (size) => signNote(formatCheckpoint(origin, size, tree.root(size)), signer);
  const receiptOf = (index) => {
    const size = tree.size;
    let receipt = buildReceipt({ origin, verifierKey: vkey, entry: entries[index], index, checkpoint: checkpointOf(size), inclusionProof: tree.inclusionProof(index, size) });
    receipt = JSON.parse(JSON.stringify(receipt));
    if (state.tamper === "proof" && receipt.inclusionProof.length > 0) receipt.inclusionProof[0] = encodeBase64(new Uint8Array(32).fill(9));
    if (state.tamper === "entry" && receipt.entry.kind === "HEAD") receipt.entry.receivedAt += 1;
    return receipt;
  };
  const headOf = (history, position) => {
    const held = history.heads.get(position);
    const statement = entries[held.index].signedStatement.statement;
    return { hash: statement.head.hash, position: statement.head.position, canonicalTime: statement.head.canonicalTime };
  };
  const latestOf = (history) => (history.latest === undefined ? null : { head: headOf(history, history.latest.position), receipt: receiptOf(history.latest.index) });
  /** Like the server: one top-level `checkpoint` (the note every receipt of the reply uses) on replies that reference log state. */
  const withCheckpoint = (body) => ({ ...body, checkpoint: checkpointOf(tree.size) });
  /** The signed latest note over `nonce`: the history's latest head (or none) at the reply's tree size. */
  const latestNoteOf = (history, nonce) => {
    if (state.latestNote === "strip") return undefined;
    if (typeof state.latestNote === "function") return state.latestNote(history, nonce);
    const latest = history.latest;
    return signNote(formatLatestNote({
      origin, historyId: history.historyId, nonce, treeSize: tree.size, equivocations: history.equivocations, supersedes: history.supersedes,
      latest: latest === undefined ? null : { position: latest.position, hash: history.heads.get(latest.position).hash, index: latest.index },
    }), signer);
  };
  /** `withCheckpoint`, plus the latest note when the request carried a nonce. */
  const noted = (body, history, nonce) => {
    const out = withCheckpoint(body);
    if (nonce === undefined || history === undefined) return out;
    const note = latestNoteOf(history, nonce);
    return note === undefined ? out : { ...out, latestNote: note };
  };
  const knownKeyIds = (epochs) => new Set(epochs.flatMap((epoch) => epoch.keys.map((key) => key.keyId)));
  const error = (status, code, message, extra = {}, hint) => ({ status, body: { error: { code, message, ...(hint === undefined ? {} : { hint }) }, ...extra } });
  const logError = (history, nonce, status, code, message, extra = {}) => ({ status, body: noted({ error: { code, message }, ...extra }, history, nonce) });

  const register = (body, headers, nonce) => {
    const genesis = body?.genesis;
    // A format-2 genesis registers under recordHash(0), a format-1 one under its prefix hash (SPEC §7.4, WITNESS §9.1).
    const format = genesis?.data?.versions?.eventSchemaVersion === "irontrellis-event/2" ? "irontrellis-event/2" : "irontrellis-event/1";
    const validation = validateEvent(genesis, format, 0);
    if (!validation.ok || genesis.type !== "DEPLOYMENT_INITIALIZED") return error(400, "INVALID_GENESIS", validation.ok ? "not a genesis" : validation.reason);
    const historyId = historyIdOfGenesis(genesis);
    const known = histories.get(historyId);
    if (known !== undefined) return { status: 200, body: noted({ historyId, receipt: receiptOf(known.registeredIndex) }, known, nonce) };
    const entry = { version: WITNESS_ENTRY_VERSION, kind: "REGISTERED", historyId, genesis, receivedAt: clock() };
    const index = append(entry);
    state.registrations += 1;
    histories.set(historyId, {
      historyId, domain: genesis.data.domain, registeredIndex: index, epochs: [{
        fromPosition: 0, keys: genesis.data.ownerKeys.map((key) => ({ keyId: key.keyId, scheme: key.scheme, credential: key.credential })),
        ...(genesis.data.nextKeyDigests === undefined ? {} : { nextKeyDigests: [...genesis.data.nextKeyDigests] }),
      }],
      latest: undefined, heads: new Map(), equivocations: 0, lastEquivocationIndex: undefined, equivocationsByPosition: new Map(),
      keyEvents: new Map(), superseded: new Map(), supersedes: 0, lastSupersedeIndex: undefined, supersededEpochs: new Set(),
    });
    return { status: 201, body: noted({ historyId, receipt: receiptOf(index) }, histories.get(historyId), nonce) };
  };

  const submitHead = (history, signed, nonce) => {
    state.statements.push(signed);
    const malformed = validateSignedHeadStatement(signed);
    if (malformed !== null) return error(400, "INVALID_STATEMENT", malformed);
    const { statement } = signed;
    if (statement.historyId !== history.historyId) return error(400, "INVALID_STATEMENT", "another history");
    if (canonical(statement.domain) !== canonical(history.domain)) return error(400, "INVALID_STATEMENT", "another domain");
    const { head, previous } = statement;
    const held = history.heads.get(head.position);
    const identical = held !== undefined && held.hash === head.hash && canonical(entries[held.index].signedStatement) === canonical(signed);
    if (!identical) {
      const verdict = verifySignedHeadStatement(signed, (position) => ownerKeysAt(history.epochs, position));
      if (!verdict.ok) {
        if (verdict.reason === "UNKNOWN_KEY") {
          const unknown = !knownKeyIds(history.epochs).has(signed.keyId);
          return error(400, "SIGNATURE_INVALID", unknown ? `owner key ${signed.keyId} is unknown; post the rotation first` : `owner key ${signed.keyId} is not in force at ${head.position}`, {}, unknown ? "ROTATION_REQUIRED" : undefined);
        }
        return error(400, verdict.reason === "SIGNATURE_INVALID" ? "SIGNATURE_INVALID" : "INVALID_STATEMENT", "the statement does not verify");
      }
    }
    // A superseded head never counts again, and nothing extends it (docs/reference/witness-operations.md §7.4).
    const supersededPrevious = previous !== null && history.superseded.has(refKey(previous));
    if (supersededPrevious || history.superseded.has(refKey(head))) {
      return logError(history, nonce, 409, "SUPERSEDED", "the statement states or extends a superseded head", { latest: latestOf(history) });
    }
    const latest = history.latest;
    const appendHead = () => {
      appendHeadEntry(history, signed);
      const index = history.latest.index;
      return { status: 201, body: noted({ status: "APPENDED", receipt: receiptOf(index), latest: latestOf(history) }, history, nonce) };
    };
    if (latest === undefined) {
      if (previous === null) return appendHead();
      return logError(history, nonce, 409, "STALE_PREVIOUS", "the witness holds no head yet", { latest: null });
    }
    const latestRef = { hash: history.heads.get(latest.position).hash, position: latest.position };
    // §9.1 rule 2: extends the latest.
    if (sameRef(previous, latestRef)) {
      if (head.hash === latestRef.hash && head.position === latest.position) return { status: 200, body: noted({ status: "ALREADY_WITNESSED", receipt: receiptOf(latest.index), latest: latestOf(history) }, history, nonce) };
      if (head.position > latest.position) return appendHead();
      return error(400, "INVALID_STATEMENT", "the head must be ahead of previous");
    }
    // §9.1 rule 3: a different head at a held position is evidence (one entry per position, at most 64 per history); the history stays open.
    if (held !== undefined && held.hash !== head.hash) {
      let index = history.equivocationsByPosition.get(head.position);
      if (index !== undefined) {
        if (canonical(entries[index].second) !== canonical(signed)) state.cappedEquivocations += 1;
      } else if (history.equivocations >= MAX_EQUIVOCATIONS_PER_HISTORY) {
        index = history.lastEquivocationIndex;
        state.cappedEquivocations += 1;
      } else {
        index = append({ version: WITNESS_ENTRY_VERSION, kind: "EQUIVOCATION", historyId: history.historyId, first: entries[held.index].signedStatement, second: signed, receivedAt: clock() });
        history.equivocations += 1;
        history.lastEquivocationIndex = index;
        history.equivocationsByPosition.set(head.position, index);
      }
      return logError(history, nonce, 409, "EQUIVOCATION", "the owner key signed a different head at a position the witness holds; recorded as evidence", { receipt: receiptOf(index), latest: latestOf(history) });
    }
    // §9.1 rule 4.
    if (held !== undefined) return { status: 200, body: noted({ status: "ALREADY_WITNESSED", receipt: receiptOf(held.index), latest: latestOf(history) }, history, nonce) };
    return logError(history, nonce, 409, "STALE_PREVIOUS", `previous is not the latest (position ${latest.position})`, { latest: latestOf(history) });
  };

  /** Appends a HEAD entry for `signed` and makes it the latest (a head held again is no longer superseded). */
  const appendHeadEntry = (history, signed) => {
    const head = signed.statement.head;
    const index = append({ version: WITNESS_ENTRY_VERSION, kind: "HEAD", historyId: history.historyId, signedStatement: signed, receivedAt: clock() });
    history.heads.set(head.position, { hash: head.hash, index });
    history.latest = { position: head.position, index };
    history.superseded.delete(refKey(head));
    return index;
  };
  const latestRef = (history) => (history.latest === undefined ? undefined : { hash: history.heads.get(history.latest.position).hash, position: history.latest.position });
  /** Like the server's statementProblem: null, or the rejection of a statement delivered with a key event. */
  const statementProblem = (history, signed, head, name) => {
    const malformed = validateSignedHeadStatement(signed);
    if (malformed !== null) return error(400, "INVALID_STATEMENT", `${name}: ${malformed}`);
    const { statement } = signed;
    if (statement.historyId !== history.historyId) return error(400, "INVALID_STATEMENT", `${name} is for another history`);
    if (canonical(statement.domain) !== canonical(history.domain)) return error(400, "INVALID_STATEMENT", `${name}: another domain`);
    if (statement.head.hash !== head.hash || statement.head.position !== head.position) return error(400, "INVALID_STATEMENT", `${name} must state the key event head`);
    const verdict = verifySignedHeadStatement(signed, (position) => ownerKeysAt(history.epochs, position));
    if (!verdict.ok) return error(400, verdict.reason === "MALFORMED" ? "INVALID_STATEMENT" : "SIGNATURE_INVALID", `${name} does not verify`);
    return null;
  };

  /** `POST …/key-events` and the admin bundle import (docs/reference/witness-operations.md §7.3, §9.2), exactly like the server. */
  const keyEvent = (history, body, nonce, route) => {
    const INVALID = "KEY_EVENT_INVALID";
    const UNKNOWN = "KEY_EVENT_HEAD_UNKNOWN";
    let request;
    if (route === "admin") {
      const problem = validateKeyEventBundle(body);
      if (problem !== null) return error(400, "INVALID_REQUEST", `not a key-event bundle: ${problem}`);
      if (body.historyId !== history.historyId) return error(400, "INVALID_REQUEST", "the bundle is for another history");
      if (typeof body.event.id !== "string") return error(400, "KEY_EVENT_INVALID", "the event has no id");
      request = { event: body.event, previousHead: body.previousHead, eventHead: body.eventHead, statement: body.statement, ...(body.chain === undefined ? {} : { chain: body.chain }) };
    } else {
      const keys = isRecord(body) ? Object.keys(body) : [];
      if (!isRecord(body) || !["event", "previousHead", "eventHead"].every((key) => keys.includes(key)) || keys.some((key) => !["event", "previousHead", "eventHead", "statement", "chain"].includes(key))) {
        return error(400, "INVALID_REQUEST", "the body must be { event, previousHead, eventHead, statement?, chain? }");
      }
      if (!isHeadRef(body.previousHead) || !isHeadRef(body.eventHead)) return error(400, "INVALID_REQUEST", "previousHead and eventHead must be { hash, position }");
      if (!isRecord(body.event) || typeof body.event.id !== "string") return error(400, "KEY_EVENT_INVALID", "event must be a key event");
      request = { event: body.event, previousHead: body.previousHead, eventHead: body.eventHead, ...(body.statement === undefined ? {} : { statement: body.statement }), ...(body.chain === undefined ? {} : { chain: body.chain }) };
    }
    const { event, previousHead, eventHead } = request;
    if (event.type !== "OWNER_KEYS_ROTATED") return error(400, INVALID, "not a key event");
    const replyOf = (index, extra = {}) => noted({ receipt: receiptOf(index), epochs: wireEpochs(history.epochs), latest: latestOf(history), ...extra }, history, nonce);
    const existing = history.keyEvents.get(event.id);
    if (existing !== undefined) {
      const entry = entries[existing.index];
      const [recorded, recordedHead] = [entry.rotation, entry.rotationHead];
      if (canonical(recorded) === canonical(event) && sameRef(recordedHead, eventHead) && sameRef(entry.previousHead, previousHead)) return { status: 200, body: replyOf(existing.index) };
      return error(400, INVALID, `a different key event with event id ${event.id} is already recorded`);
    }
    if (eventHead.position !== previousHead.position + 1) return error(400, INVALID, "the event head must follow previousHead");
    const current = history.epochs.at(-1);
    if (eventHead.position < current.fromPosition) return error(400, INVALID, "key event out of order");
    const verdict = verifyRotationEvent(event, { domain: history.domain, previousHead, epochs: history.epochs, algorithm: "sha256" });
    if (!verdict.ok) return error(400, INVALID, verdict.reason);
    const recordKeyEvent = () => {
      const at = (head) => ({ hash: head.hash, position: head.position });
      const index = append({ version: WITNESS_ENTRY_VERSION, kind: "ROTATED", historyId: history.historyId, rotation: event, previousHead: at(previousHead), rotationHead: at(eventHead), receivedAt: clock() });
      history.epochs = verdict.epochs.map((epoch) => ({ fromPosition: epoch.fromPosition, keys: epoch.keys.map((key) => ({ keyId: key.keyId, scheme: key.scheme, credential: key.credential })), ...(epoch.nextKeyDigests === undefined ? {} : { nextKeyDigests: [...epoch.nextKeyDigests] }) }));
      history.keyEvents.set(event.id, { index });
      return index;
    };
    const latest = latestRef(history);
    const held = history.heads.get(eventHead.position);
    const holdsEventHead = held !== undefined && held.hash === eventHead.hash;
    if (holdsEventHead && (request.chain === undefined || sameRef(eventHead, latest))) return { status: 201, body: replyOf(recordKeyEvent()) };
    if (!holdsEventHead) {
      for (const [name, signed] of [["statement", request.statement], ["chain", request.chain]]) {
        if (signed === undefined) continue;
        const problem = statementProblem(history, signed, eventHead, name);
        if (problem !== null) return problem;
        const previous = signed.statement.previous;
        if (latest === undefined ? previous === null : sameRef(previous, latest) && eventHead.position > latest.position) {
          appendHeadEntry(history, signed);
          return { status: 201, body: replyOf(recordKeyEvent()) };
        }
      }
    }
    if (request.chain === undefined || latest === undefined) {
      if (request.statement !== undefined) return logError(history, nonce, 409, "STALE_PREVIOUS", "the delivered statement does not extend the latest head", { latest: latestOf(history) });
      return error(409, UNKNOWN, "submit the statement for the key event head first");
    }
    // Supersede (docs/reference/witness-operations.md §7.4).
    const chain = request.chain;
    const problem = statementProblem(history, chain, eventHead, "chain");
    if (problem !== null) return problem;
    const last = chain.statement.previous;
    if (last === null) return error(400, "INVALID_STATEMENT", "chain.previous must name the last good head");
    if (last.position > previousHead.position) return error(400, "INVALID_STATEMENT", "chain.previous must not be after the head before the rotation");
    if (!verdict.preRotated) return error(409, "SUPERSEDE_REFUSED", "only a pre-rotated rotation can supersede heads");
    const lastHeld = history.heads.get(last.position);
    if (lastHeld === undefined || lastHeld.hash !== last.hash) return logError(history, nonce, 409, "SUPERSEDE_REFUSED", "chain.previous is not a head this witness holds", { latest: latestOf(history) });
    if (history.supersededEpochs.has(current.fromPosition)) return logError(history, nonce, 409, "SUPERSEDE_REFUSED", "at most one supersede per owner key rotation", { latest: latestOf(history) });
    const superseded = [...history.heads.entries()].filter(([position]) => position > last.position).map(([position, value]) => ({ position, hash: value.hash, index: value.index })).sort((a, b) => a.index - b.index);
    if (superseded.length === 0) return logError(history, nonce, 409, "SUPERSEDE_REFUSED", "nothing to supersede", { latest: latestOf(history) });
    const at = (head) => ({ hash: head.hash, position: head.position });
    // Like the server: the entry describes the range (L's leaf, this entry's leaf), not each head (third review, F1).
    const latestHead = history.heads.get(history.latest.position);
    const supersededIndex = append({
      version: WITNESS_ENTRY_VERSION, kind: "SUPERSEDED", historyId: history.historyId, rotation: event, previousHead: at(previousHead), rotationHead: at(eventHead), chain,
      supersededFromIndex: lastHeld.index, supersededToIndex: tree.size,
      supersededLatest: { position: history.latest.position, hash: latestHead.hash, index: history.latest.index }, supersededCount: superseded.length, receivedAt: clock(),
    });
    for (const head of superseded) {
      history.heads.delete(head.position);
      history.superseded.set(refKey(head), head.index);
    }
    history.latest = { position: last.position, index: lastHeld.index };
    history.supersedes += 1;
    history.lastSupersedeIndex = supersededIndex;
    history.supersededEpochs.add(current.fromPosition);
    appendHeadEntry(history, chain);
    return { status: 201, body: replyOf(recordKeyEvent(), { superseded: receiptOf(supersededIndex) }) };
  };

  /** Like the server: the optional nonce is one canonical base64url value of 16..64 bytes (checked after registration auth, before the history lookup). */
  const nonceOf = (query) => {
    const values = query.getAll("nonce");
    if (values.length === 0) return { nonce: undefined };
    if (values.length > 1 || !isValidNonce(values[0])) return { refused: error(400, "INVALID_REQUEST", "nonce must be one canonical unpadded base64url value of 16..64 bytes") };
    return { nonce: values[0] };
  };

  const route = (method, path, query, body, headers) => {
    if (method === "GET" && path === "/healthz") return { status: 200, body: { ok: true } };
    if (method === "GET" && path === "/v1/witness") return { status: 200, body: { version: "irontrellis-witness/1", origin, verifierKey: vkey, software: "fake-witness 0" } };
    if (method === "GET" && path === "/v1/checkpoint") return { status: 200, text: checkpointOf(tree.size) };
    if (method === "POST" && path === "/v1/admin/key-events") {
      if (options.token !== undefined && headers.authorization !== `Bearer ${options.token}`) return error(401, "UNAUTHORIZED", "importing a key-event bundle needs the admin token");
      const { nonce, refused } = nonceOf(query);
      if (refused !== undefined) return refused;
      const history = histories.get(body?.historyId);
      if (typeof body?.historyId !== "string" || !/^0x[0-9a-f]{64}$/.test(body.historyId)) return error(400, "INVALID_REQUEST", "not a key-event bundle");
      if (history === undefined) return error(404, "NOT_REGISTERED", "history not registered");
      return keyEvent(history, body, nonce, "admin");
    }
    if (method === "POST" && path === "/v1/histories") {
      if (options.token !== undefined && headers.authorization !== `Bearer ${options.token}`) return error(401, "UNAUTHORIZED", "registration needs the admin token");
      const { nonce, refused } = nonceOf(query);
      return refused ?? register(body, headers, nonce);
    }
    if (method === "GET" && path === "/v1/proofs/consistency") {
      const from = Number(query.get("from")), to = Number(query.get("to"));
      if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || from > to || to > tree.size) return error(400, "INVALID_REQUEST", "from ≤ to ≤ size");
      return { status: 200, body: { from, to, proof: (from === 0 || from === to ? [] : tree.consistencyProof(from, to)).map(encodeBase64) } };
    }
    if (method === "GET" && path === "/v1/proofs/inclusion") {
      const index = Number(query.get("index")), size = Number(query.get("size"));
      if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index >= size || size > tree.size) return error(400, "INVALID_REQUEST", "index < size ≤ tree size");
      return { status: 200, body: { index, size, proof: tree.inclusionProof(index, size).map(encodeBase64) } };
    }
    if (method === "GET" && path === "/v1/entries") {
      const start = Number(query.get("start")), end = Math.min(Number(query.get("end")), tree.size, Number(query.get("start")) + 1000);
      return { status: 200, body: { start, entries: entries.slice(start, end) } };
    }
    const match = /^\/v1\/histories\/(0x[0-9a-f]{64})(\/heads|\/key-events|\/heads\/(\d+))?$/.exec(path);
    if (match === null) return error(404, "NOT_FOUND", `no route ${method} ${path}`);
    const { nonce, refused } = match[3] === undefined ? nonceOf(query) : { nonce: undefined };
    if (refused !== undefined) return refused;
    const history = histories.get(match[1]);
    if (history === undefined) return error(404, "NOT_REGISTERED", "history not registered");
    if (method === "GET" && match[2] === undefined) {
      return { status: 200, body: noted({
        historyId: history.historyId, domain: history.domain, equivocations: history.equivocations, supersedes: history.supersedes, epochs: wireEpochs(history.epochs), latest: latestOf(history),
        ...(history.lastEquivocationIndex === undefined ? {} : { lastEquivocation: receiptOf(history.lastEquivocationIndex) }),
        ...(history.lastSupersedeIndex === undefined ? {} : { lastSupersede: receiptOf(history.lastSupersedeIndex) }),
      }, history, nonce) };
    }
    if (method === "POST" && match[2] === "/heads") return submitHead(history, body, nonce);
    if (method === "POST" && match[2] === "/key-events") { state.keyEventsReceived.push(body); return keyEvent(history, body, nonce, "key-events"); }
    if (method === "GET" && match[3] !== undefined) {
      const position = Number(match[3]);
      const held = history.heads.get(position);
      if (held === undefined) return error(404, "NOT_FOUND", "no head at that position");
      return { status: 200, body: withCheckpoint({ head: headOf(history, position), receipt: receiptOf(held.index) }) };
    }
    return error(404, "NOT_FOUND", `no route ${method} ${path}`);
  };

  const server = createServer((request, response) => {
    let raw = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { raw += chunk; });
    request.on("end", () => {
      const url = new URL(request.url, "http://localhost");
      state.requests.push(`${request.method} ${url.pathname}`);
      if (state.down) {
        response.writeHead(503, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { code: "INTERNAL", message: "down" } }));
        return;
      }
      let body;
      try { body = raw === "" ? undefined : JSON.parse(raw); } catch {
        response.writeHead(400, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { code: "INVALID_REQUEST", message: "not JSON" } }));
        return;
      }
      let result;
      try { result = route(request.method, url.pathname, url.searchParams, body, request.headers); } catch (failure) {
        result = error(500, "INTERNAL", String(failure?.stack ?? failure));
      }
      if (result.text !== undefined) {
        response.writeHead(result.status, { "content-type": "text/plain; charset=utf-8" });
        response.end(result.text);
      } else {
        response.writeHead(result.status, { "content-type": "application/json" });
        response.end(JSON.stringify(result.body));
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  return {
    url: `http://127.0.0.1:${port}`,
    verifierKey: vkey,
    origin,
    name,
    state,
    entries,
    histories,
    get size() { return tree.size; },
    set down(value) { state.down = value; },
    get down() { return state.down; },
    /** "proof" | "entry" | undefined: corrupt the receipts this witness returns. */
    set tamper(value) { state.tamper = value; },
    /** Sign a latest note for any fields (tests forging or replaying freshness answers). */
    signLatestNote(fields) { return signNote(formatLatestNote({ origin, ...fields }), signer); },
    /** Serve a different log from now on: every leaf re-hashed with a changed first entry (a split view against earlier checkpoints). */
    splitView() {
      const changed = [{ ...entries[0], receivedAt: entries[0].receivedAt + 1 }, ...entries.slice(1)];
      entries.splice(0, entries.length, ...changed);
      tree = new MerkleTree();
      for (const entry of entries) tree.append(entryLeafHash(entry));
    },
    /** Sign checkpoints with another key from now on (the configured verifier key no longer verifies them). */
    wrongKey() { signer = noteSignerFromSeed(name, seedOf(9999)); },
    /** Every HEAD statement the witness recorded for a history, oldest first. */
    heads(historyId) {
      return entries.filter((entry) => entry.kind === "HEAD" && entry.historyId === historyId).map((entry) => entry.signedStatement);
    },
    latest(historyId) {
      const history = histories.get(historyId);
      return history?.latest === undefined ? null : headOf(history, history.latest.position);
    },
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); }),
  };
}
