// Differential test: the real witness server (this package) and the core's in-test fake witness
// (packages/core/test/helpers/fake-witness.mjs, which every client test in core, cli, hooks and the gateway talks to)
// are driven with the same seeded random request sequences — head statements that extend the latest, are stale, name
// held heads, conflict with held heads (equivocations, repeated ones included), are signed by retired or unknown keys —
// plus rotations (valid, early, altered), reads and proofs. Both witnesses share the note key and a fixed clock, so every
// answer must be identical: HTTP status, error code and hint, and the whole body (receipts, checkpoints, latest heads,
// epochs, equivocation counts, the signed latest notes over the request nonces, the capped equivocation answers) except
// the human `message`. The core cannot depend on this package (it would be a
// workspace cycle), so this is how the fake is kept honest.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ADMIN_TOKEN, buildHistory, buildKeyEventHistory, buildScenario, keyPair, signerOf, startWitness, t, tempDir } from "./helpers.mjs";
import { startFakeWitness } from "../../core/test/helpers/fake-witness.mjs";

const CLOCK = 1_800_000_000_000;

/** mulberry32: a small seeded PRNG, so a failing sequence can be replayed from its seed. */
const prng = (seed) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let x = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
  return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
};

async function call(base, method, path, body) {
  const headers = { accept: "application/json, text/plain" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method === "POST" && ["/v1/histories", "/v1/admin/key-events"].includes(path.split("?")[0])) headers.authorization = `Bearer ${ADMIN_TOKEN}`;
  const response = await fetch(`${base}${path}`, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const text = await response.text();
  let json;
  try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: response.status, json, text };
}

/** The comparable part of a reply: everything but the human-readable error message. */
const comparable = (reply) => {
  if (reply.json === undefined) return { status: reply.status, text: reply.text };
  const { error, ...rest } = reply.json;
  return { status: reply.status, body: rest, ...(error === undefined ? {} : { error: { code: error.code, ...(error.hint === undefined ? {} : { hint: error.hint }) } }) };
};

/** A pool of requests over two histories (the transparency scenario with its fork and rotation, and a second one with a forged fork). */
async function requestPool() {
  const s = await buildScenario();
  const h = await buildHistory({ name: "diff", agents: 6, rotateAt: 5 });
  const stranger = signerOf(keyPair("owner:stranger", 0x7777));
  const at = (head) => ({ hash: head.hash, position: head.position });
  const histories = [
    {
      id: s.historyId, genesis: s.events[0], domain: s.statement(s.heads[0], null).domain,
      // Main chain heads 0..8 (rotation at 7), a fork at 6 on the first six events.
      heads: s.heads, alt: s.fork.heads, keyFor: (p) => (p >= 8 ? s.owner2 : s.owner1), otherKey: (p) => (p >= 8 ? s.owner1 : s.owner2),
      rotation: { event: s.rotation, previousHead: at(s.heads[6]), eventHead: at(s.heads[7]) },
    },
    {
      id: h.historyId, genesis: h.genesis, domain: h.domain,
      // Main chain; "alt" heads are forged: another position's hash claimed at a position (same key).
      heads: h.heads, alt: h.heads.map((head, p) => (p === 0 ? head : { hash: h.heads[(p + 3) % h.heads.length].hash, position: p, canonicalTime: head.canonicalTime })),
      keyFor: (p) => h.signerAt(p), otherKey: (p) => (h.signerAt(p) === h.signer1 ? h.signer2 : h.signer1),
      rotation: { event: h.rotation, previousHead: at(h.heads[4]), eventHead: at(h.heads[5]) },
    },
  ];
  // A third history with owner key events (WITNESS-DESIGN §11): a commitment-only rotation, a pre-rotated rotation, and a thief
  // of the first key who pushes heads of their own (the M2 attack) and a rotation to their own key.
  const k = await buildKeyEventHistory({ name: "diff-ke", agents: 3 });
  histories.push({ id: k.historyId, genesis: k.genesis, domain: k.domain, keyEvents: k, heads: k.heads, track: { latest: null, held: new Set() } });
  return { s, h, k, histories, stranger, at };
}

/** One random operation on the key-event history: statements (real and forged), key events with statements and chains, bundles. */
async function drawKeyEventOperation(random, pool, history, sent) {
  const k = history.keyEvents;
  const pick = (items) => items[Math.floor(random() * items.length)];
  const upTo = (n) => Math.floor(random() * (n + 1));
  // What the witnesses answered so far (`track`, updated by runSequence): the honest owner extends the latest real head.
  const track = history.track;
  const latest = track.latest;
  const roll = random();
  if (roll < 0.2 && latest !== "forged") {
    const position = Math.min((latest ?? 0) + 1 + upTo(1), k.heads.length - 1);
    const statement = await k.statement(position, latest);
    sent.push({ id: history.id, statement });
    return { method: "POST", path: `/v1/histories/${history.id}/heads`, body: statement };
  }
  if (roll < 0.35) {
    if (random() < 0.35) {
      // The thief of key 1: an arbitrary head after a real one (valid wherever key 1 is in force at the witness).
      const position = 1 + upTo(k.rotateAt + 1);
      const statement = await k.forge(position, upTo(Math.min(position - 1, k.heads.length - 1)), upTo(3));
      sent.push({ id: history.id, statement });
      return { method: "POST", path: `/v1/histories/${history.id}/heads`, body: statement };
    }
    const position = 1 + upTo(k.heads.length - 2);
    const previous = random() < 0.1 ? null : upTo(position);
    const statement = await k.statement(position, previous === position ? position - 1 : previous);
    sent.push({ id: history.id, statement });
    return { method: "POST", path: `/v1/histories/${history.id}/heads`, body: statement };
  }
  if (roll < 0.5) {
    const variant = random();
    const honest = typeof latest === "number" && latest < k.commitAt ? latest : k.commitAt - 1;
    const statement = variant < 0.4 ? { statement: await k.statement(k.commitAt, honest) } : variant < 0.6 ? { statement: await k.statement(k.commitAt, upTo(k.commitAt - 1)) } : {};
    return { method: "POST", path: `/v1/histories/${history.id}/key-events`, body: k.keyEvent(k.commitment, k.commitAt, statement) };
  }
  if (roll < 0.78) {
    const variant = random();
    const r = k.rotateAt;
    const held = [...track.held].filter((position) => position < r);
    const chain = async () => ({ chain: await k.statement(r, held.length > 0 && random() < 0.8 ? pick(held) : 1 + upTo(r - 2), k.signer1) });
    const honest = typeof latest === "number" && latest < r ? latest : r - 1;
    const extra = variant < 0.25 ? { statement: await k.statement(r, honest) } : variant < 0.6 ? await chain() : variant < 0.75 ? { statement: await k.statement(r, r - 1), ...(await chain()) } : {};
    const event = random() < 0.12 ? k.plainRotation : k.rotation;
    return { method: "POST", path: `/v1/histories/${history.id}/key-events`, body: k.keyEvent(event, r, extra) };
  }
  if (roll < 0.86) {
    const rotation = random() < 0.6;
    const position = rotation ? k.rotateAt : k.commitAt;
    const bundle = {
      version: "irontrellis-key-event-bundle/1", historyId: random() < 0.05 ? pool.histories[0].id : history.id, ...k.keyEvent(rotation ? k.rotation : k.commitment, position),
      statement: await k.statement(position, position - 1), ...(rotation && random() < 0.5 ? { chain: await k.statement(position, 1 + upTo(position - 2), k.signer1) } : {}),
    };
    return { method: "POST", path: "/v1/admin/key-events", body: random() < 0.05 ? { ...bundle, version: "nope" } : bundle };
  }
  if (roll < 0.9) return { method: "POST", path: `/v1/histories/${history.id}/key-events`, body: k.keyEvent(k.rotation, k.rotateAt) };
  if (roll < 0.96) return { method: "GET", path: `/v1/histories/${history.id}` };
  if (roll < 0.98 && sent.length > 0) {
    const earlier = pick(sent.filter((item) => item.id === history.id).concat(sent.slice(-1)));
    return { method: "POST", path: `/v1/histories/${earlier.id}/heads`, body: earlier.statement };
  }
  return { method: "GET", path: `/v1/histories/${history.id}/heads/${upTo(k.heads.length - 1)}` };
}

/** One random operation (as a request description), drawn from `random`. */
async function drawOperation(random, pool, sent, conflicts) {
  const pick = (items) => items[Math.floor(random() * items.length)];
  const history = pick(pool.histories);
  if (history.keyEvents !== undefined) return drawKeyEventOperation(random, pool, history, sent);
  const roll = random();
  if (roll < 0.55) {
    // A head statement: main or alternative head, previous from either chain (or null), usually the key in force.
    const position = Math.floor(random() * history.heads.length);
    const useAlt = random() < 0.4 && position < history.alt.length && position > 0;
    const head = useAlt ? history.alt[position] : history.heads[position];
    let previous = null;
    if (random() < 0.9 && position > 0) {
      const p = Math.floor(random() * (position + 1));
      const chain = random() < 0.2 && p < history.alt.length ? history.alt : history.heads;
      previous = p === position ? pool.at(head) : pool.at(chain[p]);
    }
    const keyRoll = random();
    const signer = keyRoll < 0.85 ? history.keyFor(position) : keyRoll < 0.97 ? history.otherKey(position) : pool.stranger;
    const statement = await t.signHeadStatement(signer, { version: t.HEAD_STATEMENT_VERSION, historyId: history.id, domain: history.domain, head, previous });
    sent.push({ id: history.id, statement });
    return { method: "POST", path: `/v1/histories/${history.id}/heads`, body: statement };
  }
  if (roll < 0.65 && sent.length > 0) {
    // Resubmissions, half of them of statements that were answered EQUIVOCATION (the dedupe).
    const earlier = conflicts.length > 0 && random() < 0.5 ? pick(conflicts) : pick(sent);
    return { method: "POST", path: `/v1/histories/${earlier.id}/heads`, body: earlier.statement };
  }
  if (roll < 0.75) {
    const variant = random();
    const body = variant < 0.7 ? history.rotation
      : variant < 0.85 ? { ...history.rotation, previousHead: { ...history.rotation.previousHead, hash: history.heads[1].hash } }
      : { ...history.rotation, eventHead: pool.at(history.heads[history.rotation.eventHead.position + 1]) };
    return { method: "POST", path: `/v1/histories/${history.id}/key-events`, body };
  }
  if (roll < 0.77) return { method: "POST", path: "/v1/histories", body: { genesis: history.genesis } };
  if (roll < 0.8) {
    // Malformed, or another history's statement posted under this id (INVALID_STATEMENT).
    const other = pool.histories.find((candidate) => candidate !== history);
    const theirs = sent.find((item) => item.id === other.id);
    return { method: "POST", path: `/v1/histories/${history.id}/heads`, body: random() < 0.5 || theirs === undefined ? { statement: {} } : theirs.statement };
  }
  if (roll < 0.87) return { method: "GET", path: `/v1/histories/${history.id}` };
  if (roll < 0.93) return { method: "GET", path: `/v1/histories/${history.id}/heads/${Math.floor(random() * history.heads.length)}` };
  if (roll < 0.96) return { method: "GET", path: "/v1/checkpoint" };
  if (roll < 0.98) return { method: "GET", path: `/v1/histories/0x${"cd".repeat(32)}` };
  return { method: "GET", path: "/v1/witness" };
}

/**
 * The history routes carry a nonce most of the time (docs/reference/witness-protocol.md §9.8): both witnesses must then sign the very same
 * latest note (Ed25519 is deterministic, the key and the clock are shared). A few carry a malformed one (400 from both).
 */
function withNonce(op, random) {
  if (!/^\/v1\/(histories(\/0x[0-9a-f]{64}(\/heads|\/key-events)?)?|admin\/key-events)$/.test(op.path) || random() < 0.2) return op;
  const roll = random();
  const nonce = roll < 0.05 ? "not-a-nonce" : roll < 0.08 ? `${Buffer.alloc(16, 1).toString("base64url")}&nonce=${Buffer.alloc(16, 2).toString("base64url")}`
    : Buffer.from(Array.from({ length: 16 + Math.floor(random() * 49) }, () => Math.floor(random() * 256))).toString("base64url");
  return { ...op, path: `${op.path}?nonce=${nonce}`, noted: roll >= 0.08 };
}

/**
 * A scripted start for the key-event history (WITNESS-DESIGN §11.4, the M2 attack), so every sequence reaches a supersede:
 * honest heads up to the commitment, the commitment-only rotation (ROTATED), a thief's head (at a position ≤ r or past it, by seed), the owner's
 * pre-rotated rotation with a chain from the last good head (SUPERSEDED), the thief's statement again (409 SUPERSEDED
 * where the old key still counts), and a second supersede attempt (the rotation is recorded: idempotent or refused).
 */
async function supersedeScript(pool, seed) {
  const history = pool.histories.find((candidate) => candidate.keyEvents !== undefined);
  const k = history.keyEvents, r = k.rotateAt, id = history.id;
  const post = (path, body) => ({ method: "POST", path, body });
  const forged = await k.forge(seed % 2 === 0 ? r : r + 1, r - 1, seed % 4);
  const chain = await k.statement(r, r - 1, k.signer1);
  return [
    post(`/v1/histories/${id}/heads`, await k.statement(1, null)),
    post(`/v1/histories/${id}/heads`, await k.statement(k.commitAt, 1)),
    post(`/v1/histories/${id}/key-events`, k.keyEvent(k.commitment, k.commitAt)),
    post(`/v1/histories/${id}/heads`, await k.statement(r - 1, k.commitAt)),
    post(`/v1/histories/${id}/heads`, forged),
    post(`/v1/histories/${id}/key-events`, k.keyEvent(k.rotation, r, { chain })),
    post(`/v1/histories/${id}/heads`, forged),
    post(`/v1/histories/${id}/key-events`, k.keyEvent(k.rotation, r, { chain })),
    post(`/v1/histories/${id}/heads`, await k.statement(r + 1, r)),
    { method: "GET", path: `/v1/histories/${id}` },
  ];
}

async function runSequence(seed, steps) {
  const { dir, cleanup } = tempDir();
  const server = await startWitness({ dir, now: () => CLOCK });
  const key = JSON.parse(readFileSync(join(dir, "witness-key.json"), "utf8"));
  const fake = await startFakeWitness({ signerKey: key.privateKey, now: () => CLOCK });
  try {
    assert.equal(fake.verifierKey, server.witness.verifierKey, "one note key");
    assert.equal(fake.origin, server.witness.origin, "one origin");
    const pool = await requestPool();
    const random = prng(seed);
    const sent = [];
    const conflicts = [];
    const codes = new Map();
    // Both histories registered first (an empty log has no checkpoint to compare).
    const registrations = [
      ...pool.histories.map((history) => ({ method: "POST", path: "/v1/histories", body: { genesis: history.genesis } })),
      ...(await supersedeScript(pool, seed)),
    ];
    for (let step = 0; step < registrations.length + steps; step += 1) {
      const op = withNonce(step < registrations.length ? registrations[step] : await drawOperation(random, pool, sent, conflicts), random);
      const real = await call(server.url, op.method, op.path, op.body);
      const mirror = await call(fake.url, op.method, op.path, op.body);
      const where = `seed ${seed} step ${step}: ${op.method} ${op.path}`;
      if (op.path === "/v1/witness") {
        assert.deepEqual({ ...mirror.json, software: undefined }, { ...real.json, software: undefined }, where);
        continue;
      }
      assert.deepEqual(comparable(mirror), comparable(real), where);
      if (op.noted === true && real.json?.receipt !== undefined) {
        // A reply that carries log state for a known history carries the signed latest note over the nonce, and it verifies.
        assert.equal(typeof real.json.latestNote, "string", `${where}: latestNote`);
        const nonce = new URL(op.path, "http://x").searchParams.get("nonce");
        const verdict = t.verifyLatestNote(real.json.latestNote, [fake.verifierKey], { historyId: real.json.receipt.entry.historyId, nonce, origin: fake.origin });
        assert.equal(verdict.ok, true, `${where}: ${verdict.message}`);
        codes.set("LATEST_NOTE", (codes.get("LATEST_NOTE") ?? 0) + 1);
      }
      if (op.noted === false) codes.set("NONCE_REFUSED", (codes.get("NONCE_REFUSED") ?? 0) + (real.status === 400 ? 1 : 0));
      if (real.json?.superseded !== undefined) codes.set("SUPERSEDE_APPENDED", (codes.get("SUPERSEDE_APPENDED") ?? 0) + 1);
      if (real.status === 201 && real.json?.receipt?.entry?.kind === "ROTATED" && real.json.receipt.entry.rotation?.id === "commit:1") codes.set("COMMITMENT_ROTATED", (codes.get("COMMITMENT_ROTATED") ?? 0) + 1);
      if (real.status === 201 && real.json?.receipt?.entry?.kind === "ROTATED" && op.path.includes("key-events")) codes.set("KEY_EVENT_ROTATED", (codes.get("KEY_EVENT_ROTATED") ?? 0) + 1);
      if (op.path.startsWith("/v1/admin/") && (real.status === 201 || real.status === 200)) codes.set("ADMIN_IMPORTED", (codes.get("ADMIN_IMPORTED") ?? 0) + 1);
      const target = pool.histories.find((candidate) => candidate.track !== undefined && (op.path.includes(candidate.id) || op.body?.historyId === candidate.id));
      const witnessed = real.json?.latest?.head;
      if (target !== undefined && witnessed !== undefined && witnessed !== null) {
        // What the key-event history's witness holds now: a real head (the honest owner can extend it) or a thief's.
        const real = target.keyEvents.heads[witnessed.position]?.hash === witnessed.hash;
        target.track.latest = real ? witnessed.position : "forged";
        if (real) target.track.held.add(witnessed.position);
      }
      const code = real.json?.error?.code ?? (real.json?.status ?? String(real.status));
      if (code === "EQUIVOCATION") {
        const path = op.path.split("?")[0];
        const key = `${path}\n${JSON.stringify(op.body)}`;
        if (conflicts.some((item) => `/v1/histories/${item.id}/heads\n${JSON.stringify(item.statement)}` === key)) codes.set("EQUIVOCATION_REPEATED", (codes.get("EQUIVOCATION_REPEATED") ?? 0) + 1);
        else conflicts.push({ id: path.split("/")[3], statement: op.body });
        // The cap (one entry per position): another conflicting statement at a recorded position gets the recorded entry.
        if (JSON.stringify(real.json.receipt?.entry?.second) !== JSON.stringify(op.body)) codes.set("EQUIVOCATION_CAPPED", (codes.get("EQUIVOCATION_CAPPED") ?? 0) + 1);
      }
      codes.set(code, (codes.get(code) ?? 0) + 1);
    }
    // The logs are identical, leaf by leaf, and consistency/inclusion proofs agree.
    const size = server.witness.size;
    assert.equal(fake.size, size);
    for (let start = 0; start < size; start += 1000) {
      const range = `/v1/entries?start=${start}&end=${Math.min(size, start + 1000)}`;
      assert.deepEqual((await call(fake.url, "GET", range)).json, (await call(server.url, "GET", range)).json);
    }
    for (let n = 0; n < 5; n += 1) {
      const to = 1 + Math.floor(random() * size), from = Math.floor(random() * (to + 1)), index = Math.floor(random() * to);
      for (const path of [`/v1/proofs/consistency?from=${from}&to=${to}`, `/v1/proofs/inclusion?index=${index}&size=${to}`]) {
        assert.deepEqual(comparable(await call(fake.url, "GET", path)), comparable(await call(server.url, "GET", path)), `seed ${seed}: ${path}`);
      }
    }
    return codes;
  } finally {
    await fake.close();
    await server.close();
    cleanup();
  }
}

test("the fake witness answers exactly like the server over random statement, equivocation, stale and rotation sequences", async () => {
  const seen = new Map();
  for (const seed of [1, 2, 3, 4, 5, 6, 7, 8]) {
    const codes = await runSequence(seed, 120);
    for (const [code, count] of codes) seen.set(code, (seen.get(code) ?? 0) + count);
  }
  // The sequences must actually reach every rule (otherwise the comparison proves little).
  for (const code of [
    "APPENDED", "ALREADY_WITNESSED", "STALE_PREVIOUS", "EQUIVOCATION", "EQUIVOCATION_REPEATED", "EQUIVOCATION_CAPPED", "SIGNATURE_INVALID",
    "INVALID_STATEMENT", "NOT_REGISTERED", "LATEST_NOTE", "NONCE_REFUSED",
    // WITNESS-DESIGN §11.3, §11.4: key events, bundles and supersede.
    "KEY_EVENT_INVALID", "KEY_EVENT_HEAD_UNKNOWN", "COMMITMENT_ROTATED", "KEY_EVENT_ROTATED", "ADMIN_IMPORTED", "SUPERSEDE_APPENDED", "SUPERSEDE_REFUSED", "SUPERSEDED", "INVALID_REQUEST",
  ]) {
    assert.ok((seen.get(code) ?? 0) > 0, `the random sequences never produced ${code}: ${JSON.stringify([...seen])}`);
  }
  assert.ok((seen.get("201") ?? 0) > 0 || (seen.get("200") ?? 0) > 0, "rotations and registrations were answered");
});
