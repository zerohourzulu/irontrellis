/**
 * Target `witness-http`: a live witness server (packages/witness, in-process on
 * 127.0.0.1, fixed key, rate limits off) driven with valid requests built from
 * the seed histories (registration, owner-signed head statements,
 * commitment-only, pre-rotated and plain rotations, key-event bundles through the
 * admin route, every read route with and without nonces) and with mutations of
 * them: JSON bodies, body text, paths and query strings, methods, headers
 * (content type, authorization), signature swaps, and raw HTTP bytes on a socket.
 *
 * Invariants: never a 500 (INTERNAL) or a dropped connection on a well-formed
 * request; every error body is `{error: {code, message}}` with a documented code
 * and no stack trace; every receipt in a 2xx reply verifies with the witness
 * key and every checkpoint of one size has one root; no 2xx write accepts a
 * seed owner signature (statement or control event) over altered content; the
 * server stays healthy; on restart it re-opens its log with the same size and
 * root, and `checkLog` finds no problem.
 */
import { connect } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { core, plain, revive, t, witness as witnessModule } from '../lib/env.mjs';
import { signatureIndex } from '../lib/invariants.mjs';
import { Dictionary, clone, mutateString, mutateText, mutateValue } from '../lib/mutate.mjs';
import { ADMIN_TOKEN, keyRegistry, startFixedWitness, storeSeeds } from '../lib/seeds.mjs';

const canonical = (value) => { try { return core.canonicalEncode(core.jsonParseWithBigints(JSON.stringify(value))); } catch { return undefined; } };
const nonce = (n) => Buffer.alloc(32, n).toString('base64url');

/** Valid requests for one seed history: registration, statements (each head over the previous one), key events, bundles. */
function historyRequests(events, registry) {
  const state = core.replay(revive(events)).state;
  if (state === undefined || state.format !== core.TRELLIS_FORMAT) return [];
  const historyId = state.eventHistoryHashes[0];
  const domain = plain(state.genesis.domain);
  const head = (p) => ({ hash: state.eventHistoryHashes[p], position: p, canonicalTime: state.events[p].timestamp });
  const ref = (p) => ({ hash: state.eventHistoryHashes[p], position: p });
  const signerAt = (p) => registry.get(core.ownerKeysAt(state, p)[0].credential.toLowerCase());
  const statement = (p, q) => plain(t.signHeadStatementSync(signerAt(p), { version: t.HEAD_STATEMENT_VERSION, historyId, domain, head: head(p), previous: q === null ? null : ref(q) }));
  const json = (method, path, body, extra = {}) => ({ method, path, headers: { 'content-type': 'application/json', ...extra }, body: JSON.stringify(body) });
  const out = [json('POST', '/v1/histories', { genesis: events[0] }, { authorization: `Bearer ${ADMIN_TOKEN}` })];
  let previous = null;
  for (let p = 0; p < events.length; p += 1) {
    const type = events[p].type;
    if (p > 0 && type === 'OWNER_KEYS_ROTATED') {
      const body = { event: events[p], previousHead: ref(p - 1), eventHead: ref(p), statement: statement(p, p - 1) };
      out.push(json('POST', `/v1/histories/${historyId}/key-events`, body));
      out.push(json('POST', `/v1/histories/${historyId}/key-events`, { event: events[p], previousHead: ref(p - 1), eventHead: ref(p) }));
      out.push(json('POST', '/v1/admin/key-events', { version: t.KEY_EVENT_BUNDLE_VERSION, historyId, ...body }, { authorization: `Bearer ${ADMIN_TOKEN}` }));
    }
    out.push(json('POST', `/v1/histories/${historyId}/heads`, statement(p, previous)));
    if (p % 2 === 0 || p === events.length - 1) previous = p;
  }
  out.push({ method: 'GET', path: `/v1/histories/${historyId}?nonce=${nonce(7)}`, headers: {}, body: null });
  out.push({ method: 'GET', path: `/v1/histories/${historyId}/heads/${events.length - 1}`, headers: {}, body: null });
  return out;
}

const READS = [
  '/healthz', '/metrics', '/v1/witness', '/v1/checkpoint', '/v1/entries?start=0&end=4', '/v1/entries?start=0', '/v1/proofs/inclusion?index=0&size=3',
  '/v1/proofs/inclusion?index=1', '/v1/proofs/consistency?from=1&to=5', '/v1/proofs/consistency?from=2',
].map((path) => ({ method: 'GET', path, headers: {}, body: null }));

async function send(url, request) {
  if (request.raw !== undefined) return sendRaw(url, request.raw);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(`${url}${request.path.startsWith('/') ? '' : '/'}${request.path}`, {
      method: request.method, headers: request.headers, body: request.body === null || request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body, signal: controller.signal,
    });
    return { status: response.status, type: response.headers.get('content-type') ?? '', text: await response.text() };
  } finally {
    clearTimeout(timer);
  }
}

/** Raw bytes on a socket; the answer's status line and body (or `dropped`). */
function sendRaw(url, raw) {
  const { hostname, port } = new URL(url);
  return new Promise((resolve) => {
    const socket = connect(Number(port), hostname);
    let data = '';
    const done = (extra) => {
      socket.destroy();
      if (extra !== undefined || data === '') return resolve(extra ?? { status: 0, dropped: true, text: '' });
      const [head, ...rest] = data.split('\r\n\r\n');
      let text = rest.join('\r\n\r\n');
      // Bytes after a request's header block start a second (pipelined) request: the socket may carry two responses.
      const length = /content-length: (\d+)/i.exec(head)?.[1];
      if (length !== undefined) text = Buffer.from(text, 'latin1').subarray(0, Number(length)).toString('latin1');
      if (/transfer-encoding: chunked/i.test(head)) { // de-chunk
        let out = '';
        for (let at = 0; at < text.length;) {
          const end = text.indexOf('\r\n', at);
          const size = parseInt(text.slice(at, end), 16);
          if (!(size > 0)) break;
          out += text.slice(end + 2, end + 2 + size);
          at = end + 2 + size + 2;
        }
        text = out;
      }
      resolve({ status: Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1] ?? 0), type: /content-type: ([^\r\n]*)/i.exec(head)?.[1] ?? '', text: Buffer.from(text, 'latin1').toString('utf8') });
    };
    const timer = setTimeout(() => done(), 3000);
    socket.on('data', (chunk) => { data += chunk.toString('latin1'); });
    socket.on('end', () => { clearTimeout(timer); done(); });
    socket.on('error', () => { clearTimeout(timer); done(); });
    socket.write(Buffer.from(raw, 'latin1'));
    socket.end();
  });
}

async function restart(state) {
  const before = state.server.witness.checkpoint;
  const size = state.server.witness.size;
  await state.server.close();
  const lib = await witnessModule();
  state.server = await lib.serve({ dataDir: state.dataDir, listen: `127.0.0.1:${state.port}`, logger: { info() {}, warn() {}, error() {} }, configOverride: state.override });
  const failures = [];
  if (state.server.witness.size !== size) failures.push({ invariant: 'WITNESS_PERSISTENCE', key: 'WITNESS_RESTART_SIZE', message: `after a restart the log has ${state.server.witness.size} entries, before ${size}` });
  const check = lib.checkLog(state.dataDir, { verifierKey: state.server.witness.verifierKey, origin: state.server.witness.origin });
  if (!check.ok || (check.problems ?? []).length > 0) failures.push({ invariant: 'WITNESS_PERSISTENCE', key: 'WITNESS_CHECKLOG', message: `checkLog reports problems: ${JSON.stringify(check.problems ?? check).slice(0, 300)}` });
  void before;
  return failures;
}

export default {
  name: 'witness-http',
  async setup(ctx) {
    const lib = await witnessModule();
    const registry = keyRegistry();
    const seeds = await storeSeeds();
    const templates = [...READS];
    for (const seed of seeds) templates.push(...historyRequests(seed.events, registry));
    const dataDir = join(mkdtempSync(join(tmpdir(), 'irontrellis-fuzz-witness-')), 'data');
    let clock = 1_900_000_000_000;
    const server = await startFixedWitness(dataDir, { name: 'fuzz.http.witness', seed: 0x66, now: () => (clock += 3) });
    const port = Number(new URL(server.url).port);
    const dict = new Dictionary();
    for (const request of templates) { try { dict.add(JSON.parse(request.body ?? 'null')); } catch { /* reads */ } dict.strings.add(request.path); }
    const statements = new Map();
    for (const request of templates) {
      let body; try { body = JSON.parse(request.body ?? 'null'); } catch { continue; }
      for (const signed of [body, body?.statement, body?.chain]) if (signed?.signature && signed.statement) statements.set(signed.signature.toLowerCase(), canonical(signed.statement));
    }
    return {
      ctx, lib, server, dataDir, port, templates, dict: dict.freeze(), statements, index: signatureIndex(seeds.map((s) => ({ events: s.events }))),
      domains: new Map(seeds.map((s) => { const st = core.replay(revive(s.events)).state; return [st?.eventHistoryHashes[0], st?.genesis.domain]; })),
      roots: new Map(), count: 0, override: { adminTokenHashes: [lib.hashToken(ADMIN_TOKEN)], rateLimit: { perIpPerMinute: 0, perHistoryPerMinute: 0, monitoringPerIpPerMinute: 0 } },
      errorCodes: new Set(lib.ERROR_CODES),
    };
  },
  seedInputs(state) { return state.templates; },
  mutate(rng, base, state) {
    if (rng.chance(0.3)) return clone(rng.pick(state.templates)); // keep the server's state moving with valid requests
    const request = clone(base);
    const op = rng.weighted([[35, 'json'], [12, 'text'], [10, 'path'], [6, 'method'], [8, 'headers'], [8, 'sigswap'], [6, 'raw'], [5, 'history']]);
    switch (op) {
      case 'json': { let body; try { body = JSON.parse(request.body ?? '{}'); } catch { body = {}; } request.body = JSON.stringify(mutateValue(rng, body, state.dict, 3)); break; }
      case 'text': request.body = mutateText(rng, request.body ?? '', 3); break;
      case 'path': request.path = rng.chance(0.3) ? rng.pick(['/', '//v1/witness', '/v1/histories/', '/v1/histories/0x', `/v1/histories/${'0'.repeat(66)}/heads`, '/v1/entries?start=-1', '/v1/entries?start=1e3', '/v1/proofs/inclusion?index=99999999999999999', '/v1/histories?nonce=x', '/%', '/v1/entries?start=0&start=1', '/v1/checkpoint?x=%zz'])
        : mutateString(rng, request.path); break;
      case 'method': request.method = rng.pick(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']); if (request.method !== 'GET' && request.body === null) request.body = '{}'; break;
      case 'headers': {
        const type = rng.pick([undefined, 'application/json', 'application/json; charset=utf-8', 'application/json; charset="UTF-8"', 'application/json; charset=latin1', 'text/plain', 'APPLICATION/JSON', 'application/json;;', '']);
        if (type === undefined) delete request.headers['content-type']; else request.headers['content-type'] = type;
        if (rng.chance(0.4)) request.headers.authorization = rng.pick([`Bearer ${ADMIN_TOKEN}`, 'Bearer x', 'Basic abc', `Bearer ${ADMIN_TOKEN} `, `bearer ${ADMIN_TOKEN}`, 'Bearer ']);
        if (rng.chance(0.2)) request.headers['x-forwarded-for'] = rng.pick(['1.2.3.4', 'a, b, c', '', '::ffff:1.2.3.4']);
        break;
      }
      case 'sigswap': { // a genuine signature over other content
        let body; try { body = JSON.parse(request.body ?? '{}'); } catch { body = {}; }
        const donor = rng.pick(state.templates);
        let other; try { other = JSON.parse(donor.body ?? '{}'); } catch { other = {}; }
        const signed = [other, other?.statement].find((s) => s?.signature);
        const target = [body, body?.statement].find((s) => s?.signature) ?? body;
        if (signed && target && typeof target === 'object') target.signature = signed.signature;
        if (other?.event?.data?.controlAuthorization && body?.event?.data) body.event.data.controlAuthorization = clone(other.event.data.controlAuthorization);
        request.body = JSON.stringify(body);
        break;
      }
      case 'raw': {
        const body = request.body ?? '';
        const length = rng.pick([Buffer.byteLength(body), 0, Buffer.byteLength(body) + 10, 1e9, -1, 'abc']);
        const lines = [`${rng.pick([request.method, 'GET', 'POST', 'BREW', 'GET /x HTTP/1.1'])} ${rng.chance(0.9) ? request.path : mutateString(rng, request.path)} ${rng.pick(['HTTP/1.1', 'HTTP/1.0', 'HTTP/2.0', 'HTTP/1.1 x'])}`,
          'Host: 127.0.0.1', `Content-Type: ${request.headers['content-type'] ?? 'application/json'}`, ...(rng.chance(0.8) ? [`Content-Length: ${length}`] : ['Transfer-Encoding: chunked']),
          ...(request.headers.authorization ? [`Authorization: ${request.headers.authorization}`] : []), ...(rng.chance(0.1) ? [`X-Big: ${'a'.repeat(20000)}`] : []), 'Connection: close'];
        request.raw = `${lines.join('\r\n')}\r\n\r\n${rng.chance(0.2) ? mutateText(rng, body, 2) : body}`;
        break;
      }
      default: { // another history id in the path
        const ids = [...state.domains.keys()].filter(Boolean);
        request.path = request.path.replace(/0x[0-9a-f]{64}/, rng.chance(0.8) && ids.length ? rng.pick(ids) : `0x${rng.hex(64)}`);
      }
    }
    return request;
  },
  async check(request, state) {
    const failures = [];
    const sizeBefore = state.server.witness.size;
    const response = await send(state.server.url, request);
    const appended = state.server.witness.size > sizeBefore;
    const route = request.path.split('?')[0].replace(/0x[0-9a-f]{64}/g, ':id').replace(/\/\d+$/, '/:n').slice(0, 40);
    let body;
    if (/json/.test(response.type) && request.method !== 'HEAD' && !(request.raw !== undefined && /^HEAD /.test(request.raw))) { try { body = JSON.parse(response.text); } catch { failures.push({ invariant: 'WITNESS_REPLY', key: `REPLY_NOT_JSON:${route}`, message: `a JSON reply that does not parse: ${response.text.slice(0, 200)}` }); } }
    if (response.dropped && request.raw === undefined) failures.push({ invariant: 'WITNESS_REPLY', key: `DROPPED:${route}`, message: 'the connection was dropped without an answer' });
    if (response.status >= 500 && !(response.status === 503 && body?.error?.code === 'INTERNAL' && /shutting down/.test(body?.error?.message ?? ''))) {
      failures.push({ invariant: 'UNTYPED_CRASH', key: `HTTP_${response.status}:${request.method}:${route}:${body?.error?.code ?? ''}`, message: `${request.method} ${request.path} answered ${response.status}: ${response.text.slice(0, 300)}` });
    }
    if (/\n\s+at /.test(response.text)) failures.push({ invariant: 'WITNESS_REPLY', key: `STACK_TRACE:${route}`, message: 'a stack trace on the wire' });
    if (response.status >= 400 && body !== undefined) {
      const code = body?.error?.code;
      if (typeof code !== 'string' || !state.errorCodes.has(code) || typeof body.error.message !== 'string') failures.push({ invariant: 'WITNESS_REPLY', key: `ERROR_SHAPE:${route}:${String(code)}`, message: `error reply without a documented {code, message}: ${response.text.slice(0, 200)}` });
    }
    if (response.status >= 200 && response.status < 300 && body !== undefined) {
      // Every receipt verifies; one root per checkpoint size (no split view from one witness).
      const receipts = [];
      const visit = (value) => { if (value === null || typeof value !== 'object') return; if (value.version === t.WITNESS_RECEIPT_VERSION) receipts.push(value); else for (const child of Object.values(value)) visit(child); };
      visit(body);
      for (const receipt of receipts) {
        const verdict = t.verifyWitnessReceipt(receipt, [state.server.witness.verifierKey]);
        if (!verdict.ok) failures.push({ invariant: 'WITNESS_REPLY', key: `RECEIPT_INVALID:${route}:${verdict.reason}`, message: `a receipt the witness returned does not verify: ${verdict.reason} ${verdict.message}` });
        else {
          const root = t.encodeBase64(verdict.checkpoint.root);
          const known = state.roots.get(verdict.checkpoint.size);
          if (known !== undefined && known !== root) failures.push({ invariant: 'WITNESS_REPLY', key: 'SPLIT_VIEW', message: `two roots for checkpoint size ${verdict.checkpoint.size}` });
          state.roots.set(verdict.checkpoint.size, root);
        }
      }
    }
    if (appended && request.body) {
      // No request that appended to the log reuses a seed owner signature over other content (an idempotent answer appends nothing).
      {
        let sent; try { sent = JSON.parse(request.body); } catch { sent = undefined; }
        for (const signed of [sent, sent?.statement, sent?.chain]) {
          const original = typeof signed?.signature === 'string' ? state.statements.get(signed.signature.toLowerCase()) : undefined;
          if (original !== undefined && canonical(signed.statement) !== original) failures.push({ invariant: 'SIGNED_CONTENT_ALTERED', key: `WITNESS_STATEMENT_ALTERED:${route}`, message: `the witness accepted (${response.status}) a statement signature over altered content` });
        }
        const event = sent?.event ?? sent?.rotation;
        const signature = event?.data?.controlAuthorization?.signature;
        const known = typeof signature === 'string' ? state.index.get(signature.toLowerCase()) : undefined;
        const previous = sent?.previousHead;
        const historyId = /0x[0-9a-f]{64}/.exec(request.path)?.[0] ?? sent?.historyId;
        if (known?.owner && previous && state.domains.get(historyId)) {
          let challenge;
          try {
            const revived = revive(event);
            challenge = core.controlAuthorizationHash({ domain: state.domains.get(historyId), eventId: revived.id, eventType: revived.type, timestamp: revived.timestamp, previousHead: { hash: previous.hash, position: previous.position }, effectHash: core.controlEffectHash(revived, 'sha256') }, 'sha256');
          } catch { challenge = undefined; }
          if (challenge !== known.challenge) failures.push({ invariant: 'SIGNED_CONTENT_ALTERED', key: `WITNESS_EVENT_ALTERED:${route}`, message: `the witness accepted (${response.status}) a key event whose owner signature was made over another challenge` });
        }
      }
    }
    state.count += 1;
    if (state.count % 50 === 0) {
      const health = await send(state.server.url, { method: 'GET', path: '/healthz', headers: {}, body: null });
      if (health.status !== 200) failures.push({ invariant: 'WITNESS_HEALTH', key: `UNHEALTHY:${health.status}`, message: `/healthz answered ${health.status}: ${health.text.slice(0, 200)}` });
    }
    if (state.count % 400 === 0) failures.push(...await restart(state));
    const features = [`${request.raw === undefined ? request.method : 'RAW'}:${route}:${response.status}:${body?.error?.code ?? body?.status ?? ''}`];
    return { failures, features, outcome: { status: response.status, code: body?.error?.code ?? null } };
  },
  async reset(state) { await restart(state); },
  async teardown(state) {
    const failures = await restart(state);
    for (const failure of failures) state.ctx.log(`[witness-http] at teardown: ${failure.message}`);
    await state.server.close();
    rmSync(join(state.dataDir, '..'), { recursive: true, force: true });
  },
};
