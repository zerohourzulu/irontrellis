// The HTTP API (WITNESS-DESIGN §8.3) on an ephemeral port: every route and
// error code, body limits, auth, rate limits, proxies, timeouts, batching.
// Every receipt the tests receive is verified with core's verifyWitnessReceipt
// and every checkpoint is checked for consistency with the ones seen before.
import { test } from "node:test";
import assert from "node:assert/strict";
import { connect } from "node:net";
import { ADMIN_TOKEN, buildHistory, buildScenario, collectingLogger, core, startWitness, t, tempDir, TestClient, witnessLib, wire } from "./helpers.mjs";

async function withWitness(options, body) {
  const { dir, cleanup } = tempDir();
  const handle = await startWitness({ dir, ...options });
  const client = new TestClient(handle.url, handle.witness.verifierKey);
  try {
    await body({ handle, client, dir });
  } finally {
    await handle.close();
    cleanup();
  }
}

const errorCode = (reply) => reply.json?.error?.code;
const assertError = (reply, status, code) => {
  assert.equal(reply.status, status, `${reply.status} ${reply.text}`);
  assert.equal(errorCode(reply), code, reply.text);
  assert.equal(typeof reply.json.error.message, "string");
  assert.doesNotMatch(reply.text, /\n\s+at /, "no stack traces on the wire");
};

test("the full §8.3 flow over HTTP: register, heads, rotation, reads, proofs, entries", async () => {
  await withWitness({}, async ({ handle, client }) => {
    const s = await buildScenario();
    const id = s.historyId;
    const heads = `/v1/histories/${id}/heads`;

    const info = await client.get("/v1/witness");
    assert.equal(info.status, 200);
    assert.deepEqual(info.json, { version: "irontrellis-witness/1", origin: handle.witness.origin, verifierKey: handle.witness.verifierKey, software: `irontrellis-witness ${witnessLib.VERSION}` });

    const registered = await client.register(s.events[0]);
    assert.equal(registered.status, 201);
    assert.equal(registered.json.historyId, id);
    assert.equal(registered.json.receipt.entry.kind, "REGISTERED");
    assert.equal(registered.json.receipt.index, 0);
    const again = await client.register(s.events[0]);
    assert.equal(again.status, 200);
    assert.deepEqual(again.json.receipt.entry, registered.json.receipt.entry);

    const empty = await client.get(`/v1/histories/${id}`);
    assert.equal(empty.status, 200);
    assert.equal(empty.json.latest, null);
    assert.equal(empty.json.equivocations, 0);
    assert.equal(Object.hasOwn(empty.json, "forked"), false, "retired by §9.1");
    assert.deepEqual(empty.json.domain, wire(s.statement(s.heads[0], null).domain));
    assert.deepEqual(empty.json.epochs, wire([s.ownerKeyEpochs[0]]));

    const staleNull = await client.post(heads, s.statements.s3);
    assertError(staleNull, 409, "STALE_PREVIOUS");
    assert.equal(staleNull.json.latest, null);

    const h0 = await client.post(heads, s.statements.s0);
    assert.equal(h0.status, 201);
    assert.equal(h0.json.status, "APPENDED");
    assert.equal(h0.json.receipt.entry.kind, "HEAD");
    assert.deepEqual(h0.json.latest.head, s.heads[0]);
    assert.equal(t.parseCheckpoint(t.openNote(h0.json.checkpoint, [handle.witness.verifierKey]).body).size, h0.json.receipt.index + 1, "the checkpoint of the tree after the append");
    const h3 = await client.post(heads, s.statements.s3);
    assert.equal(h3.status, 201);
    const idem = await client.post(heads, s.statements.s3);
    assert.equal(idem.status, 200);
    assert.equal(idem.json.status, "ALREADY_WITNESSED");
    assert.equal(idem.json.receipt.index, h3.json.receipt.index);
    const older = await client.post(heads, s.statements.s0);
    assert.equal(older.status, 200);
    assert.equal(older.json.status, "ALREADY_WITNESSED");
    assert.equal(older.json.receipt.index, h0.json.receipt.index);
    assert.deepEqual(older.json.latest.head, s.heads[3], "rule 5 reports the actual latest");

    const stale = await client.post(heads, await t.signHeadStatement(s.owner1, s.statement(s.heads[6], s.heads[0])));
    assertError(stale, 409, "STALE_PREVIOUS");
    assert.deepEqual(stale.json.latest.head, s.heads[3]);
    assert.equal(stale.json.latest.receipt.index, h3.json.receipt.index);

    assert.equal((await client.post(heads, s.statements.s6)).status, 201);
    const rotation = { event: s.rotation, previousHead: { hash: s.heads[6].hash, position: 6 }, eventHead: { hash: s.heads[7].hash, position: 7 } };
    assertError(await client.post(`/v1/histories/${id}/key-events`, rotation), 409, "KEY_EVENT_HEAD_UNKNOWN");
    assert.equal((await client.post(heads, await t.signHeadStatement(s.owner1, s.statement(s.heads[7], s.heads[6])))).status, 201);
    assertError(await client.post(`/v1/histories/${id}/key-events`, { ...rotation, previousHead: { hash: s.heads[5].hash, position: 6 } }), 400, "KEY_EVENT_INVALID");
    const early = await client.post(heads, await t.signHeadStatement(s.owner2, s.statement(s.heads[8], s.heads[7])));
    assertError(early, 400, "SIGNATURE_INVALID");
    assert.equal(early.json.error.hint, "ROTATION_REQUIRED");
    const rotated = await client.post(`/v1/histories/${id}/key-events`, rotation);
    assert.equal(rotated.status, 201);
    assert.equal(rotated.json.receipt.entry.kind, "ROTATED");
    assert.deepEqual(rotated.json.epochs, wire(s.ownerKeyEpochs));
    const rotatedAgain = await client.post(`/v1/histories/${id}/key-events`, rotation);
    assert.equal(rotatedAgain.status, 200);
    assert.equal(rotatedAgain.json.receipt.index, rotated.json.receipt.index);
    const oldKey = await client.post(heads, await t.signHeadStatement(s.owner1, s.statement(s.heads[8], s.heads[7])));
    assertError(oldKey, 400, "SIGNATURE_INVALID");
    assert.equal(oldKey.json.error.hint, undefined);
    const h8 = await client.post(heads, await t.signHeadStatement(s.owner2, s.statement(s.heads[8], s.heads[7])));
    assert.equal(h8.status, 201);

    const history = await client.get(`/v1/histories/${id}`);
    assert.deepEqual(history.json.latest.head, s.heads[8]);
    assert.deepEqual(history.json.epochs, wire(s.ownerKeyEpochs));
    assert.equal(history.json.lastEquivocation, undefined);
    assert.deepEqual(rotated.json.receipt.entry.previousHead, rotation.previousHead, "§9.2: the ROTATED leaf carries previousHead");

    const at3 = await client.get(`/v1/histories/${id}/heads/3`);
    assert.equal(at3.status, 200);
    assert.deepEqual(at3.json.head, s.heads[3]);
    assert.equal(at3.json.receipt.index, h3.json.receipt.index);
    assertError(await client.get(`/v1/histories/${id}/heads/4`), 404, "NOT_FOUND");
    assertError(await client.get(`/v1/histories/${id}/heads/x`), 400, "INVALID_REQUEST");
    assertError(await client.get(`/v1/histories/${id}/heads/01`), 400, "INVALID_REQUEST");

    // Checkpoint, proofs and entries.
    const checkpoint = await client.get("/v1/checkpoint");
    assert.equal(checkpoint.status, 200);
    assert.match(checkpoint.headers.get("content-type"), /^text\/plain; charset=utf-8/);
    const cp = t.parseCheckpoint(t.openNote(checkpoint.text, [handle.witness.verifierKey]).body);
    assert.equal(cp.size, handle.witness.size);
    await client.observe(checkpoint.text);
    const inclusion = await client.get(`/v1/proofs/inclusion?index=${h3.json.receipt.index}&size=${cp.size}`);
    assert.equal(inclusion.status, 200);
    assert.equal(inclusion.json.size, cp.size);
    const leaf = t.entryLeafHash(h3.json.receipt.entry);
    assert.equal(t.verifyInclusion(leaf, h3.json.receipt.index, cp.size, inclusion.json.proof.map(t.decodeBase64), cp.root), true);
    const defaultSize = await client.get(`/v1/proofs/inclusion?index=0`);
    assert.equal(defaultSize.json.size, cp.size);
    const consistency = await client.get(`/v1/proofs/consistency?from=2&to=${cp.size}`);
    assert.equal(consistency.status, 200);
    assert.deepEqual([consistency.json.from, consistency.json.to], [2, cp.size]);
    assertError(await client.get(`/v1/proofs/consistency?from=5&to=4`), 400, "INVALID_REQUEST");
    assertError(await client.get(`/v1/proofs/consistency?from=1&to=${cp.size + 1}`), 400, "INVALID_REQUEST");
    assertError(await client.get(`/v1/proofs/consistency`), 400, "INVALID_REQUEST");
    assertError(await client.get(`/v1/proofs/inclusion?index=${cp.size}`), 400, "INVALID_REQUEST");
    assertError(await client.get(`/v1/proofs/inclusion?index=-1`), 400, "INVALID_REQUEST");

    const entries = await client.get(`/v1/entries?start=0&end=${cp.size + 5}`);
    assert.equal(entries.status, 200);
    assert.equal(entries.json.start, 0);
    assert.equal(entries.json.entries.length, cp.size, "clamped to the log size");
    const root = t.rootOf(entries.json.entries.map((entry) => t.entryLeafHash(entry)));
    assert.equal(t.encodeBase64(root), t.encodeBase64(cp.root), "the entries rebuild the checkpoint root");
    assert.deepEqual((await client.get(`/v1/entries?start=2&end=3`)).json.entries, [h0.json.receipt.entry].map(() => entries.json.entries[2]));
    assertError(await client.get(`/v1/entries?start=${cp.size + 1}`), 400, "INVALID_REQUEST");
    assertError(await client.get(`/v1/entries?start=3&end=2`), 400, "INVALID_REQUEST");
    assert.ok(client.checkpoints.length > 10);
  });
});

test("equivocation over HTTP (§9.1): 409 EQUIVOCATION with the evidence receipt and latest, deduped; the history stays open; GET counts it", async () => {
  await withWitness({}, async ({ client, handle }) => {
    const s = await buildScenario();
    const heads = `/v1/histories/${s.historyId}/heads`;
    await client.register(s.events[0]);
    for (const statement of [s.statements.s0, s.statements.s3, s.statements.s6]) assert.equal((await client.post(heads, statement)).status, 201);
    const eq = await client.post(heads, s.statements.s6fork);
    assertError(eq, 409, "EQUIVOCATION");
    assert.equal(eq.json.receipt.entry.kind, "EQUIVOCATION");
    assert.deepEqual(eq.json.receipt.entry.first, wire(s.statements.s6));
    assert.deepEqual(eq.json.receipt.entry.second, wire(s.statements.s6fork));
    assert.deepEqual(eq.json.latest.head, s.heads[6]);
    const size = handle.witness.size;
    const dup = await client.post(heads, s.statements.s6fork);
    assertError(dup, 409, "EQUIVOCATION");
    assert.equal(dup.json.receipt.index, eq.json.receipt.index, "recorded once");
    assert.equal(handle.witness.size, size);
    assert.equal((await client.post(heads, s.statements.s6)).json.status, "ALREADY_WITNESSED");
    const history = await client.get(`/v1/histories/${s.historyId}`);
    assert.equal(history.json.equivocations, 1);
    assert.equal(history.json.lastEquivocation.index, eq.json.receipt.index);
    assert.equal(history.json.forked, undefined);
    // Open: the head statement at 7 extends the latest, the rotation and new-key heads follow.
    const s7 = await t.signHeadStatement(s.owner1, s.statement(s.heads[7], s.heads[6]));
    assert.equal((await client.post(heads, s7)).status, 201);
    assert.equal((await client.post(`/v1/histories/${s.historyId}/key-events`, { event: s.rotation, previousHead: { hash: s.heads[6].hash, position: 6 }, eventHead: { hash: s.heads[7].hash, position: 7 } })).status, 201);
    assert.equal((await client.post(heads, await t.signHeadStatement(s.owner2, s.statement(s.heads[8], s.heads[7])))).status, 201);
    const metrics = await client.get("/metrics");
    assert.match(metrics.text, /^irontrellis_witness_equivocating_histories 1$/m);
    assert.match(metrics.text, /^irontrellis_witness_entries_by_kind\{kind="EQUIVOCATION"\} 1$/m);
  });
});

test("error codes: NOT_FOUND, INVALID_REQUEST (JSON, content type, method, ids), NOT_REGISTERED, INVALID_GENESIS, UNSUPPORTED_FORMAT, INVALID_STATEMENT, SIGNATURE_INVALID", async () => {
  await withWitness({}, async ({ client }) => {
    const h = await buildHistory({ name: "errors" });
    assertError(await client.get("/nope"), 404, "NOT_FOUND");
    assertError(await client.get("/v1/histories/0x00/extra/path/segments"), 404, "NOT_FOUND");
    const method = await client.request("DELETE", "/v1/checkpoint");
    assertError(method, 405, "INVALID_REQUEST");
    assert.equal(method.headers.get("allow"), "GET");
    assertError(await client.get("/v1/histories"), 405, "INVALID_REQUEST");
    assertError(await client.get("/v1/histories/0xABC"), 400, "INVALID_REQUEST");
    assertError(await client.get(`/v1/histories/0x${"AB".repeat(32)}`), 400, "INVALID_REQUEST");
    assertError(await client.get(`/v1/histories/${h.historyId}`), 404, "NOT_REGISTERED");
    assertError(await client.post(`/v1/histories/${h.historyId}/heads`, await h.statement(0, null)), 404, "NOT_REGISTERED");
    assertError(await client.post(`/v1/histories/${h.historyId}/key-events`, {}), 404, "NOT_REGISTERED");
    assertError(await client.post(`/v1/histories/${h.historyId}/rotations`, {}), 404, "NOT_FOUND");
    assertError(await client.get(`/v1/histories/${h.historyId}/heads/0`), 404, "NOT_REGISTERED");

    const auth = { authorization: `Bearer ${ADMIN_TOKEN}` };
    assertError(await client.post("/v1/histories", "{not json", auth), 400, "INVALID_REQUEST");
    assertError(await client.post("/v1/histories", JSON.stringify({ genesis: h.genesis }), { ...auth, "content-type": "text/plain" }), 415, "INVALID_REQUEST");
    assertError(await client.post("/v1/histories", JSON.stringify({ genesis: h.genesis }), { ...auth, "content-type": "application/json; charset=latin1" }), 415, "INVALID_REQUEST");
    assert.equal((await client.post("/v1/histories", JSON.stringify({ genesis: h.genesis }), { ...auth, "content-type": "application/json; charset=UTF-8" })).status, 201);
    const invalidUtf8 = await fetch(`${client.url}/v1/histories/${h.historyId}/heads`, { method: "POST", headers: { "content-type": "application/json" }, body: new Uint8Array([0x7b, 0xff, 0x7d]) });
    assert.equal(invalidUtf8.status, 400);
    assert.equal((await invalidUtf8.json()).error.code, "INVALID_REQUEST");
    assertError(await client.register({ ...h.genesis, id: 5 }), 400, "INVALID_GENESIS");
    const legacy = { ...h.genesis, data: { ...h.genesis.data, versions: { ...h.genesis.data.versions, eventSchemaVersion: core.LEGACY_VERSIONS.eventSchemaVersion } } };
    assertError(await client.register(legacy), 400, "UNSUPPORTED_FORMAT");
    assertError(await client.post("/v1/histories", { genesis: h.genesis, more: 1 }, auth), 400, "INVALID_REQUEST");

    const heads = `/v1/histories/${h.historyId}/heads`;
    assertError(await client.post(heads, { statement: 1 }), 400, "INVALID_STATEMENT");
    const bad = wire(await h.statement(0, null));
    bad.signature = `0x${"33".repeat(64)}`;
    assertError(await client.post(heads, bad), 400, "SIGNATURE_INVALID");
    assertError(await client.post(`/v1/histories/${h.historyId}/key-events`, { event: {} }), 400, "INVALID_REQUEST");
  });
});

test("registration auth: token mode needs a matching admin token; open mode needs none; SIGHUP-style reload", async () => {
  const h = await buildHistory({ name: "auth" });
  await withWitness({}, async ({ client, handle }) => {
    const none = await client.register(h.genesis, null);
    assertError(none, 401, "UNAUTHORIZED");
    assert.match(none.headers.get("www-authenticate"), /^Bearer/);
    assertError(await client.register(h.genesis, "itw_wrong"), 401, "UNAUTHORIZED");
    assertError(await client.post("/v1/histories", { genesis: h.genesis }, { authorization: `Basic ${ADMIN_TOKEN}` }), 401, "UNAUTHORIZED");
    assertError(await client.post("/v1/histories", { genesis: h.genesis }, { authorization: `Bearer ${ADMIN_TOKEN}x` }), 401, "UNAUTHORIZED");
    const fresh = witnessLib.newAdminToken();
    assertError(await client.register(h.genesis, fresh), 401, "UNAUTHORIZED");
    handle.server.setAdminTokenHashes([witnessLib.hashToken(fresh)]);
    assert.equal((await client.register(h.genesis, fresh)).status, 201);
    assertError(await client.register(h.genesis, ADMIN_TOKEN), 401, "UNAUTHORIZED", "the old token was dropped");
    // Heads never need a token.
    assert.equal((await client.post(`/v1/histories/${h.historyId}/heads`, await h.statement(0, null))).status, 201);
  });
  await withWitness({ override: { registration: "open", adminTokenHashes: [] } }, async ({ client }) => {
    assert.equal((await client.register(h.genesis, null)).status, 201);
  });
  assert.equal(witnessLib.tokenMatches("a", [witnessLib.hashToken("b"), witnessLib.hashToken("a")]), true);
  assert.equal(witnessLib.tokenMatches("a", []), false);
});

test("body limits: 64 KiB for statements and key events, 1 MiB for registration", async () => {
  await withWitness({}, async ({ client }) => {
    const h = await buildHistory({ name: "limits" });
    await client.register(h.genesis);
    const pad = (bytes) => JSON.stringify({ ...wire(h.genesis), pad: "x".repeat(bytes) });
    const big = await client.post(`/v1/histories/${h.historyId}/heads`, JSON.stringify({ pad: "x".repeat(70 * 1024) }));
    assertError(big, 413, "PAYLOAD_TOO_LARGE");
    assertError(await client.post(`/v1/histories/${h.historyId}/key-events`, JSON.stringify({ pad: "x".repeat(65 * 1024) })), 413, "PAYLOAD_TOO_LARGE");
    // Just under 64 KiB is read (and judged on its content).
    assertError(await client.post(`/v1/histories/${h.historyId}/heads`, JSON.stringify({ pad: "x".repeat(60 * 1024) })), 400, "INVALID_STATEMENT");
    const auth = { authorization: `Bearer ${ADMIN_TOKEN}` };
    // A 200 KiB registration body is within its 1 MiB limit (and then refused on content).
    assertError(await client.post("/v1/histories", `{"genesis":${pad(200 * 1024)}}`, auth), 400, "INVALID_GENESIS");
    assertError(await client.post("/v1/histories", `{"genesis":${pad(1100 * 1024)}}`, auth), 413, "PAYLOAD_TOO_LARGE");
    // Chunked (no Content-Length) bodies are counted as they stream.
    const stream = new ReadableStream({
      start(controller) {
        for (let i = 0; i < 20; i += 1) controller.enqueue(new TextEncoder().encode("x".repeat(8 * 1024)));
        controller.close();
      },
    });
    const chunked = await fetch(`${client.url}/v1/histories/${h.historyId}/heads`, { method: "POST", headers: { "content-type": "application/json" }, body: stream, duplex: "half" });
    assert.equal(chunked.status, 413);
    assert.equal((await chunked.json()).error.code, "PAYLOAD_TOO_LARGE");
  });
});

test("rate limits: token buckets per client address and per history; RATE_LIMITED with Retry-After", async () => {
  let now = 1_000_000;
  await withWitness({ now: () => now, override: { rateLimit: { perIpPerMinute: 4, perHistoryPerMinute: 0 } } }, async ({ client }) => {
    for (let i = 0; i < 4; i += 1) assert.equal((await client.get("/v1/witness")).status, 200);
    const limited = await client.get("/v1/witness");
    assertError(limited, 429, "RATE_LIMITED");
    assert.equal(limited.headers.get("retry-after"), "15");
    assert.equal((await client.get("/healthz")).status, 200, "health checks have their own bucket (the API's does not starve them)");
    now += 15_000;
    assert.equal((await client.get("/v1/witness")).status, 200, "a token refilled");
    assertError(await client.get("/v1/witness"), 429, "RATE_LIMITED");
  });
  await withWitness({ override: { rateLimit: { perIpPerMinute: 0, perHistoryPerMinute: 2 } } }, async ({ client }) => {
    const a = await buildHistory({ name: "rl-a" });
    const b = await buildHistory({ name: "rl-b" });
    await client.register(a.genesis);
    await client.register(b.genesis);
    const s0 = await a.statement(0, null);
    assert.equal((await client.post(`/v1/histories/${a.historyId}/heads`, s0)).status, 201);
    assert.equal((await client.post(`/v1/histories/${a.historyId}/heads`, s0)).status, 200);
    assertError(await client.post(`/v1/histories/${a.historyId}/heads`, s0), 429, "RATE_LIMITED");
    assert.equal((await client.post(`/v1/histories/${b.historyId}/heads`, await b.statement(0, null))).status, 201, "another history has its own bucket");
    assert.equal((await client.get(`/v1/histories/${a.historyId}`)).status, 200, "reads are not per-history limited");
    // Key events draw from their own per-history bucket (third review, F1): a flood of statements cannot starve them.
    const junk = { event: { id: "e", type: "OWNER_KEYS_ROTATED" }, previousHead: { hash: s0.statement.head.hash, position: 0 }, eventHead: { hash: s0.statement.head.hash, position: 1 } };
    assert.notEqual((await client.post(`/v1/histories/${a.historyId}/key-events`, junk)).status, 429, "the key-event bucket is separate");
    assert.notEqual((await client.post(`/v1/histories/${a.historyId}/key-events`, junk)).status, 429);
    assertError(await client.post(`/v1/histories/${a.historyId}/key-events`, junk), 429, "RATE_LIMITED");
  });
  const limiter = new witnessLib.RateLimiter(60, () => 0, 4);
  for (let i = 0; i < 10; i += 1) limiter.take(`k${i}`);
  assert.ok(limiter.size <= 4, "bucket map stays bounded");
});

test("B1 (review): every answer about a history's latest head carries a latest note signed over the client's nonce (§9.8); malformed nonces are refused", async () => {
  await withWitness({}, async ({ client, handle }) => {
    const vkey = handle.witness.verifierKey, origin = handle.witness.origin;
    const h = await buildHistory({ name: "fresh" });
    const nonceA = Buffer.alloc(32, 0xa1).toString("base64url"), nonceB = Buffer.alloc(16, 0xb2).toString("base64url");
    const check = (reply, nonce, latest, equivocations = 0) => {
      const verdict = t.verifyLatestNote(reply.json.latestNote, [vkey], { origin, historyId: h.historyId, nonce });
      assert.equal(verdict.ok, true, verdict.message);
      assert.deepEqual(verdict.latest.latest, latest);
      assert.equal(verdict.latest.treeSize, t.parseCheckpoint(t.openNote(reply.json.checkpoint, [vkey]).body).size, "the size of the reply's checkpoint");
      assert.equal(verdict.latest.equivocations, equivocations);
      return verdict.latest;
    };
    const registered = await client.post(`/v1/histories?nonce=${nonceA}`, { genesis: h.genesis }, { authorization: `Bearer ${ADMIN_TOKEN}` });
    assert.equal(registered.status, 201);
    check(registered, nonceA, null);
    const none = await client.get(`/v1/histories/${h.historyId}?nonce=${nonceB}`);
    check(none, nonceB, null);
    const appended = await client.post(`/v1/histories/${h.historyId}/heads?nonce=${nonceA}`, await h.statement(0, null));
    assert.equal(appended.status, 201);
    check(appended, nonceA, { position: 0, hash: h.heads[0].hash, index: appended.json.latest.receipt.index });
    const two = await client.post(`/v1/histories/${h.historyId}/heads?nonce=${nonceB}`, await h.statement(2, 0));
    const latest = { position: 2, hash: h.heads[2].hash, index: two.json.receipt.index };
    check(two, nonceB, latest);
    const stale = await client.post(`/v1/histories/${h.historyId}/heads?nonce=${nonceA}`, await h.statement(3, 0));
    assertError(stale, 409, "STALE_PREVIOUS");
    check(stale, nonceA, latest);
    const summary = await client.get(`/v1/histories/${h.historyId}?nonce=${nonceA}`);
    check(summary, nonceA, latest);
    // The same answer replayed to another request is detectable: the note names the other nonce.
    assert.equal(t.verifyLatestNote(summary.json.latestNote, [vkey], { historyId: h.historyId, nonce: nonceB }).reason, "NONCE_MISMATCH");
    // Without a nonce, no note (old clients); a malformed or repeated nonce is 400 INVALID_REQUEST.
    assert.equal((await client.get(`/v1/histories/${h.historyId}`)).json.latestNote, undefined);
    for (const query of ["nonce=short", `nonce=${nonceA}=`, `nonce=${Buffer.alloc(15).toString("base64url")}`, `nonce=${Buffer.alloc(65).toString("base64url")}`, `nonce=${nonceA}&nonce=${nonceB}`]) {
      assertError(await client.get(`/v1/histories/${h.historyId}?${query}`), 400, "INVALID_REQUEST");
      assertError(await client.post(`/v1/histories/${h.historyId}/heads?${query}`, await h.statement(3, 2)), 400, "INVALID_REQUEST");
    }
  });
});

test("L2 (review): /healthz and /metrics go through their own per-address bucket; /metrics can require metricsToken", async () => {
  let now = 1_000_000;
  const metricsToken = "metrics-token-0123456789abcdef";
  await withWitness({ now: () => now, override: { rateLimit: { perIpPerMinute: 1, perHistoryPerMinute: 0, monitoringPerIpPerMinute: 3 }, metricsToken } }, async ({ client }) => {
    // The API bucket runs dry; the monitoring bucket is separate.
    assert.equal((await client.get("/v1/witness")).status, 200);
    assertError(await client.get("/v1/witness"), 429, "RATE_LIMITED");
    assert.equal((await client.get("/healthz")).status, 200);
    // metricsToken: no token, a wrong one, another scheme → 401 (each still takes a monitoring token).
    const unauthorized = await client.get("/metrics");
    assertError(unauthorized, 401, "UNAUTHORIZED");
    assert.match(unauthorized.headers.get("www-authenticate"), /^Bearer /);
    const authorized = await client.request("GET", "/metrics", undefined, { authorization: `Bearer ${metricsToken}` });
    assert.equal(authorized.status, 200, authorized.text);
    // Three monitoring requests from this address this minute: the fourth is limited (before any token is looked at).
    assertError(await client.request("GET", "/healthz"), 429, "RATE_LIMITED");
    assertError(await client.request("GET", "/metrics", undefined, { authorization: `Bearer ${metricsToken}` }), 429, "RATE_LIMITED");
    now += 60_000;
    assertError(await client.request("GET", "/metrics", undefined, { authorization: "Bearer wrong-token-0123456789abcdef" }), 401, "UNAUTHORIZED");
    assertError(await client.request("GET", "/metrics", undefined, { authorization: `Basic ${metricsToken}` }), 401, "UNAUTHORIZED");
    const metrics = await client.request("GET", "/metrics", undefined, { authorization: `Bearer ${metricsToken}` });
    assert.equal(metrics.status, 200, metrics.text);
    assert.match(metrics.text, /^irontrellis_witness_entries 0$/m);
    assert.match(metrics.text, /^irontrellis_witness_equivocations_capped_total 0$/m);
    const limitedAgain = await client.get("/healthz");
    assertError(limitedAgain, 429, "RATE_LIMITED");
    assert.ok(Number(limitedAgain.headers.get("retry-after")) > 0);
  });
  // Without metricsToken /metrics is open (behind the monitoring bucket); a malformed token is refused at config time.
  await withWitness({}, async ({ client }) => assert.equal((await client.get("/metrics")).status, 200));
  assert.throws(() => witnessLib.normalizeConfig({ ...witnessLib.DEFAULTS, name: "w", metricsToken: "short" }), (e) => e instanceof witnessLib.ConfigError && /metricsToken/.test(e.message));
  assert.equal(witnessLib.normalizeConfig({ ...witnessLib.DEFAULTS, name: "w", metricsToken }).metricsToken, metricsToken);
  // §10.1 domain separation: a witness origin can never be the first line of a latest note.
  assert.throws(() => witnessLib.normalizeConfig({ ...witnessLib.DEFAULTS, name: "w", origin: "irontrellis-witness-latest/1" }), witnessLib.ConfigError);
  assert.throws(() => witnessLib.normalizeConfig({ ...witnessLib.DEFAULTS, name: "w", rateLimit: { perIpPerMinute: 1, perHistoryPerMinute: 1, monitoringPerIpPerMinute: -1 } }), witnessLib.ConfigError);
});

test("client addresses: X-Forwarded-For only behind a configured proxy", async () => {
  const { clientAddress } = witnessLib;
  assert.equal(clientAddress("::ffff:10.0.0.1", "1.2.3.4", false), "10.0.0.1");
  assert.equal(clientAddress("10.0.0.1", "1.2.3.4, 5.6.7.8", true), "5.6.7.8");
  assert.equal(clientAddress("10.0.0.1", undefined, true), "10.0.0.1");
  assert.equal(clientAddress("10.0.0.1", "1.2.3.4, 10.0.0.2", ["10.0.0.1", "10.0.0.2"]), "1.2.3.4");
  assert.equal(clientAddress("10.9.9.9", "1.2.3.4", ["10.0.0.1"]), "10.9.9.9", "an untrusted peer's header is ignored");

  await withWitness({ override: { rateLimit: { perIpPerMinute: 1, perHistoryPerMinute: 0 }, trustProxy: true } }, async ({ client }) => {
    assert.equal((await client.request("GET", "/v1/witness", undefined, { "x-forwarded-for": "203.0.113.1" })).status, 200);
    assert.equal((await client.request("GET", "/v1/witness", undefined, { "x-forwarded-for": "203.0.113.2" })).status, 200);
    assertError(await client.request("GET", "/v1/witness", undefined, { "x-forwarded-for": "203.0.113.1" }), 429, "RATE_LIMITED");
  });
  await withWitness({ override: { rateLimit: { perIpPerMinute: 1, perHistoryPerMinute: 0 } } }, async ({ client }) => {
    assert.equal((await client.request("GET", "/v1/witness", undefined, { "x-forwarded-for": "203.0.113.1" })).status, 200);
    assertError(await client.request("GET", "/v1/witness", undefined, { "x-forwarded-for": "203.0.113.2" }), 429, "RATE_LIMITED");
  });
});

test("max histories: HISTORY_LIMIT_REACHED", async () => {
  await withWitness({ override: { maxHistories: 1 } }, async ({ client }) => {
    const a = await buildHistory({ name: "max-a" });
    const b = await buildHistory({ name: "max-b" });
    assert.equal((await client.register(a.genesis)).status, 201);
    assertError(await client.register(b.genesis), 503, "HISTORY_LIMIT_REACHED");
    assert.equal((await client.register(a.genesis)).status, 200);
  });
});

test("request timeout: a request that never completes gets 408 and the connection is closed", async () => {
  await withWitness({ override: { requestTimeoutMs: 300 } }, async ({ handle }) => {
    const { port } = new URL(handle.url);
    const reply = await new Promise((resolve, reject) => {
      const socket = connect(Number(port), "127.0.0.1", () => socket.write(`POST /v1/histories/0x${"ab".repeat(32)}/heads HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{`));
      let data = "";
      socket.on("data", (chunk) => { data += chunk; });
      socket.on("close", () => resolve(data));
      socket.on("error", reject);
      setTimeout(() => reject(new Error("no timeout")), 5_000).unref();
    });
    assert.match(reply, /^HTTP\/1\.1 408/);
  });
});

test("healthz, metrics and the access log (no bodies)", async () => {
  const { lines, logger } = collectingLogger();
  await withWitness({ logger }, async ({ client }) => {
    const h = await buildHistory({ name: "metrics" });
    await client.register(h.genesis);
    await client.post(`/v1/histories/${h.historyId}/heads`, await h.statement(0, null));
    await client.post(`/v1/histories/${h.historyId}/heads`, await h.statement(3, 1));
    const health = await client.get("/healthz");
    assert.equal(health.status, 200);
    assert.equal(health.json.status, "ok");
    assert.equal(health.json.entries, 2);
    const metrics = await client.get("/metrics");
    assert.equal(metrics.status, 200);
    assert.match(metrics.headers.get("content-type"), /^text\/plain; version=0\.0\.4/);
    assert.match(metrics.text, /^irontrellis_witness_entries 2$/m);
    assert.match(metrics.text, /^irontrellis_witness_histories 1$/m);
    assert.match(metrics.text, /^irontrellis_witness_entries_by_kind\{kind="HEAD"\} 1$/m);
    assert.match(metrics.text, /^irontrellis_witness_rejections_total\{code="STALE_PREVIOUS"\} 1$/m);
    assert.match(metrics.text, /^irontrellis_witness_requests_total\{route="\/v1\/histories\/:id\/heads",method="POST",status="409"\} 1$/m);
    assert.match(metrics.text, /^irontrellis_witness_checkpoint_size 2$/m);
    assert.match(metrics.text, /^irontrellis_witness_checkpoint_age_seconds [0-9.]+$/m);
  });
  const requests = lines.filter((line) => line.msg === "request");
  assert.ok(requests.length >= 5);
  for (const line of requests) {
    assert.deepEqual(Object.keys(line).filter((key) => !["level", "msg", "method", "route", "path", "status", "ms", "ip", "code", "historyId", "bytesIn"].includes(key)), []);
  }
  assert.equal(requests.find((line) => line.status === 409).code, "STALE_PREVIOUS");
  assert.doesNotMatch(JSON.stringify(lines), /signature|genesis|DEPLOYMENT_INITIALIZED/, "no bodies in the log");
  assert.ok(lines.some((line) => line.msg === "listening"));
});

test("checkpointIntervalMs batches checkpoints; every reply's checkpoint still covers its entries", async () => {
  await withWitness({ override: { checkpointIntervalMs: 150 } }, async ({ client, handle, dir }) => {
    const histories = await Promise.all([0, 1, 2, 3, 4, 5].map((n) => buildHistory({ name: `batch-${n}`, seed: 0x5000 + 2 * n })));
    const before = handle.witness.checkpoint.size;
    const replies = await Promise.all(histories.map((h) => client.register(h.genesis)));
    for (const reply of replies) {
      assert.equal(reply.status, 201);
      const size = t.parseCheckpoint(t.openNote(reply.json.checkpoint, [handle.witness.verifierKey]).body).size;
      assert.ok(size > reply.json.receipt.index);
    }
    const heads = await Promise.all(histories.map(async (h) => client.post(`/v1/histories/${h.historyId}/heads`, await h.statement(0, null))));
    for (const reply of heads) assert.equal(reply.status, 201);
    const { readFileSync } = await import("node:fs");
    const issued = readFileSync(`${dir}/checkpoints.jsonl`, "utf8").trim().split("\n").length;
    assert.ok(issued < 1 + 12, `batched: ${issued} checkpoints for 12 appends`);
    assert.equal(handle.witness.size, before + 12);
  });
});

test("shutdown: in-flight appends finish; later calls get 503 INTERNAL; the lock is released", async () => {
  const { dir, cleanup } = tempDir();
  try {
    const handle = await startWitness({ dir });
    const client = new TestClient(handle.url, handle.witness.verifierKey);
    const h = await buildHistory({ name: "shutdown" });
    const pending = client.register(h.genesis);
    const closing = handle.close();
    const reply = await pending.catch((error) => error);
    await closing;
    if (!(reply instanceof Error)) assert.ok([201, 503].includes(reply.status));
    const late = await handle.witness.register({ genesis: h.genesis });
    assert.equal(late.status, 503);
    assert.equal(late.body.error.code, "INTERNAL");
    const { existsSync } = await import("node:fs");
    assert.equal(existsSync(`${dir}/server.lock`), false);
  } finally {
    cleanup();
  }
});

test("JOB76-07 (b): drainRequestBody settles at once on a body that has already ended (no further end or close event)", async () => {
  const { Readable } = await import("node:stream");
  const { once } = await import("node:events");
  const { drainRequestBody } = await import("../dist/server.js");
  const ended = Readable.from([Buffer.from("x")]);
  ended.resume();
  await once(ended, "end");
  const outcome = await Promise.race([drainRequestBody(ended).then(() => "settled"), new Promise((resolve) => setTimeout(() => resolve("hung"), 1000))]);
  assert.equal(outcome, "settled");
});

test("JOB76-07 (a) / S5-24: a client still writing a declared over-limit body in chunks reads the 413 (the server drains first), every time", async () => {
  const http = await import("node:http");
  await withWitness({}, async ({ client }) => {
    const h = await buildHistory({ name: "drain" });
    await client.register(h.genesis);
    const url = new URL(`${client.url}/v1/histories/${h.historyId}/heads`);
    for (let round = 0; round < 5; round += 1) {
      const size = 70 * 1024, chunk = Buffer.alloc(8 * 1024, 0x78);
      const answer = await new Promise((resolve, reject) => {
        const req = http.request(url, { method: "POST", headers: { "content-type": "application/json", "content-length": size } }, (res) => {
          let body = ""; res.setEncoding("utf8"); res.on("data", (d) => { body += d; }); res.on("end", () => resolve({ status: res.statusCode, body }));
        });
        req.on("error", reject);
        let sent = 0;
        const next = () => { if (sent >= size) { req.end(); return; } const n = Math.min(chunk.length, size - sent); req.write(chunk.subarray(0, n)); sent += n; setImmediate(next); };
        next();
      });
      assert.equal(answer.status, 413, `round ${round}`);
      assert.equal(JSON.parse(answer.body).error.code, "PAYLOAD_TOO_LARGE");
    }
  });
});
