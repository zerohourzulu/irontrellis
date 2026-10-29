import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  readdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  symlinkSync,
  chmodSync,
  unlinkSync,
} from "node:fs";
import { governed, resolveAlwaysAsk, assertGuard } from "../dist/index.js";
import { openConfiguredEventStore } from "@ramex-labs/irontrellis/adapter";
import { generateKeyPair } from "@ramex-labs/irontrellis";
import { setup, page, event, deferred, hashCanonical } from "./helpers.mjs";

test("decide is advisory with no Core append or recovery write", async (t) => {
  const s = await setup(t),
    history = readFileSync(s.local.historyFile),
    journal = readFileSync(s.options.journalPath);
  const d = await s.backend.decide(s.call);
  assert.equal(d.verdict, "ALLOW");
  assert.equal(d.core.scope, "CAPTURED_HISTORY_ONLY");
  assert.equal(d.core.executionCapability, false);
  assert.deepEqual(readFileSync(s.local.historyFile), history);
  assert.deepEqual(readFileSync(s.options.journalPath), journal);
});
test("actual Core admission precedes fenced handler entry; receipt and restart never redispatch", async (t) => {
  let s;
  s = await setup(t, {
    mapping: {
      execute(args, context) {
        assert.ok(
          s.events().some((e) => e.type === "TRANSACTION_INTENT_ADMITTED"),
        );
        assert.match(context.idempotencyKey, /^0x/);
        return { ok: true };
      },
    },
  });
  const a = await s.backend.record(s.call);
  assert.equal(a.status, "CORE_RESULT", JSON.stringify(a));
  assert.equal(a.receipt.status, "RECEIPT_RESULT");
  s.backend.close();
  const reopened = governed({ ...s.options, initializeJournal: false });
  t.after(() => reopened.close());
  const b = await reopened.record(s.call);
  assert.equal(b.status, "CORE_RESULT", JSON.stringify(b));
  assert.equal(
    s.events().filter((e) => e.type === "TRANSACTION_INTENT_ADMITTED").length,
    1,
  );
});
test("stable call binds content mapping version and full workflow", async (t) => {
  const s = await setup(t);
  await s.backend.record(s.call);
  await assert.rejects(
    s.backend.record({ ...s.call, arguments: { text: "changed" } }),
    /CALL_CONFLICT/,
  );
  await assert.rejects(
    s.backend.decide({ ...s.call, workflowId: "other" }),
    /route/,
  );
  const b = governed({
    ...s.options,
    initializeJournal: false,
    mappings: { write: { ...s.mapping, version: "2" } },
  });
  t.after(() => b.close());
  await assert.rejects(b.record(s.call), /CALL_CONFLICT/);
});
test("bounded capture rejects getters proxies symbols sparse arrays cycles before first await", async (t) => {
  const s = await setup(t);
  let ran = 0;
  const getter = {
      get text() {
        ran++;
        return "x";
      },
    },
    proxy = new Proxy(
      {},
      {
        ownKeys() {
          ran++;
          return [];
        },
      },
    ),
    cycle = {};
  cycle.self = cycle;
  for (const args of [
    getter,
    proxy,
    { [Symbol()]: 1 },
    { sparse: new Array(2) },
    cycle,
  ])
    await assert.rejects(s.backend.record({ ...s.call, arguments: args }));
  assert.equal(ran, 0);
  assert.equal(s.effects, 0);
});
test("async resolving rejecting and custom thenable guards fail closed without unhandled rejection", async (t) => {
  const s = await setup(t);
  let thenRan = 0;
  for (const guard of [
    async () => {},
    async () => {
      throw Error("rejected");
    },
    () => ({
      then() {
        thenRan++;
      },
    }),
    () => false,
  ])
    await assert.rejects(
      s.backend.record(s.call, { assertCurrent: guard }),
      /synchronously/,
    );
  await new Promise((r) => setImmediate(r));
  assert.equal(thenRan, 0);
  assert.equal(s.effects, 0);
});
test("pending finality writes admission but no handler and restart does not redispatch", async (t) => {
  const s = await setup(t, {
    options: { awaitFinality: async () => ({ status: "PENDING" }) },
  });
  assert.equal((await s.backend.record(s.call)).status, "UNCERTAIN");
  assert.equal(s.effects, 0);
  assert.equal(
    s.events().filter((e) => e.type === "TRANSACTION_INTENT_ADMITTED").length,
    1,
  );
  const b = governed({
    ...s.options,
    initializeJournal: false,
    awaitFinality: async () => {
      throw Error("must not retry finality");
    },
  });
  t.after(() => b.close());
  assert.equal((await b.record(s.call)).status, "UNCERTAIN");
  assert.equal(s.effects, 0);
});
test("revocation during finality proves writer lock released and final handler recheck", async (t) => {
  const gate = deferred(),
    entered = deferred();
  const s = await setup(t, {
    options: {
      async awaitFinality(i) {
        entered.resolve();
        await gate.promise;
        return {
          status: "FINALIZED",
          idempotencyKey: i.idempotencyKey,
          admissionHeadHash: i.admissionHead.hash,
          fencingToken: "lease",
        };
      },
    },
  });
  const pending = s.backend.record(s.call);
  await entered.promise;
  await s.revoke();
  gate.resolve();
  assert.equal((await pending).status, "UNCERTAIN");
  assert.equal(s.effects, 0);
});
test("bad finality binding and lost dispatcher lease prevent effect entry", async (t) => {
  const s = await setup(t, {
    options: {
      async awaitFinality(i) {
        return {
          status: "FINALIZED",
          idempotencyKey: i.idempotencyKey,
          admissionHeadHash: "0x" + "0".repeat(64),
          fencingToken: "lease",
        };
      },
    },
  });
  assert.equal((await s.backend.record(s.call)).status, "UNCERTAIN");
  assert.equal(s.effects, 0);
  const s2 = await setup(t);
  s2.setFenced(true);
  assert.equal((await s2.backend.record(s2.call)).status, "UNCERTAIN");
  assert.equal(s2.effects, 0);
});
test("external rejection remains uncertain and never redispatches after restart", async (t) => {
  let entries = 0;
  const s = await setup(t, {
    mapping: {
      execute() {
        entries++;
        throw Error("lost reply");
      },
    },
  });
  assert.equal((await s.backend.record(s.call)).status, "UNCERTAIN");
  const b = governed({ ...s.options, initializeJournal: false });
  t.after(() => b.close());
  assert.equal((await b.record(s.call)).status, "UNCERTAIN");
  assert.equal(entries, 1);
});
test("revocation while handler pending withholds result without undoing entry", async (t) => {
  const gate = deferred(),
    entered = deferred();
  let effects = 0;
  const s = await setup(t, {
    mapping: {
      execute() {
        effects++;
        entered.resolve();
        return gate.promise;
      },
    },
  });
  const pending = s.backend.record(s.call);
  await entered.promise;
  await s.revoke();
  gate.resolve({ ok: true });
  assert.equal((await pending).status, "UNCERTAIN");
  assert.equal(effects, 1);
});
test("host session changes across signer await prevent dispatch", async (t) => {
  const s = await setup(t);
  const original = s.local.signHash;
  const b = governed({
    ...s.options,
    initializeJournal: false,
    local: {
      ...s.local,
      async signHash(h) {
        const sig = await original(h);
        s.setActive(false);
        return sig;
      },
    },
  });
  t.after(() => b.close());
  const result = await b.record(s.call);
  assert.equal(result.status, "INDETERMINATE");
  assert.equal(s.effects, 0);
});
test("native denial is retained and no handler executes", async (t) => {
  const s = await setup(t);
  await s.revoke();
  const r = await s.backend.record(s.call);
  assert.equal(r.status, "DENIED");
  assert.equal(r.core.status, "NOT_AUTHORIZED");
  assert.equal(s.effects, 0);
});
test("journal corruption duplicate keys arrays oversized file symlink and unsafe permissions fail closed", async (t) => {
  const s = await setup(t),
    path = s.options.journalPath,
    original = readFileSync(path);
  for (const body of [
    "{}",
    original.toString().replace('"calls":{}', '"calls":{},"calls":{}'),
    original.toString().replace('"calls":{}', '"calls":[]'),
    " ".repeat(4_194_305),
  ]) {
    writeFileSync(path, body);
    assert.throws(() => governed({ ...s.options, initializeJournal: false }));
  }
  writeFileSync(path, original);
  chmodSync(path, 0o644);
  assert.throws(
    () => governed({ ...s.options, initializeJournal: false }),
    /PERMISSIONS/,
  );
  chmodSync(path, 0o600);
  renameSync(path, path + ".real");
  symlinkSync(path + ".real", path);
  assert.throws(() => governed({ ...s.options, initializeJournal: false }));
  unlinkSync(path);
  renameSync(path + ".real", path);
  assert.equal(s.effects, 0);
});
test("native42 observed actor differs from reconciler and preserves missing fields zero time and zero amount", async (t) => {
  const s = await setup(t),
    r = s.makeRec();
  const answer = await r.reconcile(
    page(s, [
      event("one", { amount: "0" }),
      { id: "two", type: "opaque", data: { actorId: "a" } },
    ]),
  );
  assert.equal(answer.checkpointAdvanced, true, JSON.stringify(answer));
  const events = s.events().filter((e) => e.type === "RECONCILIATION_OBSERVED");
  assert.equal(events.length, 2);
  assert.equal(events[0].data.reconcilerAgentId, "rec");
  assert.equal(events[0].data.call.actorId, "a");
  assert.equal(events[0].data.call.amount, "0");
  assert.equal(events[0].data.call.observedAt, 0);
  assert.deepEqual(events[1].data.call.unsupplied, [
    "action",
    "observedAt",
    "resource",
  ]);
});
test("native G5 duplicates all prior digests including equivocation preserve source order and count", async (t) => {
  const s = await setup(t),
    r = s.makeRec();
  const one = event("one"),
    two = event("one", { observedAt: 1 });
  const a = await r.reconcile(page(s, [one, one, two, two, one]));
  assert.deepEqual(
    a.outcomes.map((x) => x.status),
    ["ACCEPTED", "DUPLICATE", "ACCEPTED", "DUPLICATE", "DUPLICATE"],
  );
  assert.equal(
    a.outcomes[2].observation.equivocates,
    a.outcomes[0].observation.head.position,
  );
  assert.equal(a.checkpointAdvanced, true);
  const other = s.makeRec();
  const b = await other.reconcile(page(s, [two]));
  assert.equal(b.outcomes[0].status, "DUPLICATE");
});
test("crash after native append before cursor safely retries duplicate and then checkpoints", async (t) => {
  const s = await setup(t);
  let crash = true;
  const r = s.makeRec({
    async afterObservation() {
      if (crash) {
        crash = false;
        throw Error("synthetic crash");
      }
    },
  });
  await assert.rejects(r.reconcile(page(s, [event()])), /synthetic crash/);
  assert.equal(r.cursor(), null);
  const result = await r.reconcile(page(s, [event()]));
  assert.equal(result.outcomes[0].status, "DUPLICATE");
  assert.equal(result.cursor, "page1");
  assert.equal(
    s.events().filter((e) => e.type === "RECONCILIATION_OBSERVED").length,
    1,
  );
});
test("missing observed actor and invalid resource block cursor without inventing actor", async (t) => {
  const s = await setup(t),
    r = s.makeRec();
  const result = await r.reconcile(
    page(s, [
      { id: "missing", type: "opaque" },
      event("bad", { resource: "x".repeat(129) }),
      event("okay"),
    ]),
  );
  assert.deepEqual(
    result.outcomes.map((x) => x.status),
    ["UNREPRESENTABLE", "BLOCKED", "ACCEPTED"],
  );
  assert.equal(result.cursor, null);
  assert.equal(result.coverage, "SUPPLIED_HOST_EVENTS_ONLY");
  assert.equal(result.providerDeclaredComplete, true);
});
test("stream route cursor gap and repeated token rejected", async (t) => {
  const s = await setup(t),
    r = s.makeRec();
  await assert.rejects(
    r.reconcile(page(s, [], { workflowId: "other" })),
    /route/,
  );
  await assert.rejects(r.reconcile(page(s, [], { after: "missing" })), /GAP/);
  await r.reconcile(page(s, []));
  await assert.rejects(
    r.reconcile(page(s, [], { after: "page1", nextCursor: "page1" })),
    /repeated/,
  );
});
test("native42 matches earlier admission and refusal with observed actor binding", async (t) => {
  const s = await setup(t);
  await s.backend.record(s.call);
  const intentId = s
    .events()
    .find((e) => e.type === "TRANSACTION_INTENT_ADMITTED").data.intentId;
  const refusal = await s.rt.recordRefusal({
    refusalId: "ref1",
    request: {
      actorId: "rec",
      action: "write",
      resource: "forbidden",
      claimedAt: 100,
    },
  });
  const r = s.makeRec({
    match: (e) => (e.id === "a" ? { intentId } : { refusalId: "ref1" }),
  });
  const result = await r.reconcile(
    page(s, [event("a"), event("b", { actorId: "rec" })]),
  );
  assert.deepEqual(
    result.outcomes.map((x) => x.observation?.match.result),
    ["MATCHED", "MATCHED"],
  );
});
test("always ask uses pinned selected tool policy and advisory native decisions without append", async (t) => {
  const s = await setup(t),
    config = { tools: { write: "always_ask" } },
    options = {
      backend: s.backend,
      route: s.route,
      assertCurrent: s.options.assertCurrent,
      selectedTools: ["write"],
      effectiveConfig: async () => config,
      pinnedConfigHash: hashCanonical(config, "sha256"),
      assertAlwaysAsk(c, names) {
        for (const n of names)
          if (c.tools[n] !== "always_ask") throw Error("not always ask");
      },
    };
  const e = event("ask", {
      tool_use_id: "call1",
      name: "write",
      input: { text: "hi" },
      evaluated_permission: "ask",
    }),
    before = readFileSync(s.local.historyFile);
  assert.equal((await resolveAlwaysAsk(options, e)).allow, true);
  assert.deepEqual(readFileSync(s.local.historyFile), before);
  assert.equal(
    (
      await resolveAlwaysAsk(
        {
          ...options,
          effectiveConfig: async () => ({ tools: { write: "allow" } }),
        },
        e,
      )
    ).allow,
    false,
  );
  await assert.rejects(
    resolveAlwaysAsk(options, {
      ...e,
      data: { ...e.data, evaluated_permission: "auto" },
    }),
    /actual ask/,
  );
});

test("unmapped and invalid mapping decide returns explicit INDETERMINATE without append", async (t) => {
  const s = await setup(t),
    before = readFileSync(s.local.historyFile);
  const d = await s.backend.decide({ ...s.call, tool: "missing" });
  assert.equal(d.verdict, "INDETERMINATE");
  assert.equal(d.reason, "UNMAPPED_TOOL");
  assert.match(d.callHash, /^0x/);
  assert.equal(
    (await s.backend.record({ ...s.call, tool: "missing" })).status,
    "INDETERMINATE",
  );
  assert.deepEqual(readFileSync(s.local.historyFile), before);
});
test("writer exclusion is absent during finality and present on fixed handler entry", async (t) => {
  let s,
    seenWait = false,
    seenEntry = false;
  s = await setup(t, {
    options: {
      async awaitFinality(i) {
        assert.equal(existsSync(s.local.historyFile + ".writer-lock"), false);
        const other = openConfiguredEventStore(s.local);
        other.withExclusiveWriter(() => {
          seenWait = true;
        });
        other.close();
        return {
          status: "FINALIZED",
          idempotencyKey: i.idempotencyKey,
          admissionHeadHash: i.admissionHead.hash,
          fencingToken: "lease",
        };
      },
    },
    mapping: {
      execute() {
        seenEntry = true;
        assert.equal(existsSync(s.local.historyFile + ".writer-lock"), true);
        const other = openConfiguredEventStore(s.local);
        try {
          assert.throws(
            () => other.withExclusiveWriter(() => {}),
            (e) => e.code === "STORE_BUSY",
          );
        } finally {
          other.close();
        }
        return { ok: true };
      },
    },
  });
  assert.equal((await s.backend.record(s.call)).status, "CORE_RESULT");
  assert.equal(seenWait, true);
  assert.equal(seenEntry, true);
});
test("raw canonical source preimages survive blocked page and crash before cursor", async (t) => {
  const s = await setup(t),
    r = s.makeRec();
  const result = await r.reconcile(
    page(s, [{ id: "missing", type: "opaque", data: { payload: "retained" } }]),
  );
  assert.equal(result.outcomes[0].status, "UNREPRESENTABLE");
  const raw = readFileSync(result.outcomes[0].sourceFile, "utf8");
  assert.equal(JSON.parse(raw).event.data.payload, "retained");
  assert.equal(result.outcomes[0].sourceEventIndex, 0);
  assert.equal(result.cursor, null);
  const r2 = s.makeRec({
    async afterObservation() {
      throw Error("crash");
    },
  });
  await assert.rejects(r2.reconcile(page(s, [event()])), /crash/);
  assert.equal(readdirSync(s.dir + "/cursor-2.json.sources").length, 1);
});
test("invalid page envelope is refused wholly before any native append", async (t) => {
  const s = await setup(t),
    r = s.makeRec(),
    before = readFileSync(s.local.historyFile);
  await assert.rejects(
    r.reconcile(page(s, [event(), { type: "bad" }])),
    /INVALID_PAGE_ENVELOPE/,
  );
  assert.deepEqual(readFileSync(s.local.historyFile), before);
  assert.equal(r.cursor(), null);
});
test("recovery journal rollback cannot make native admission redispatch", async (t) => {
  const s = await setup(t),
    initial = readFileSync(s.options.journalPath);
  await s.backend.record(s.call);
  writeFileSync(s.options.journalPath, initial);
  const r = await s.backend.record(s.call);
  assert.equal(s.effects, 1);
  assert.notEqual(r.status, "DENIED");
});
test("actual amount counterparty and downstream status recovery retain the admitted identity", async (t) => {
  let count = 0,
    statusKey;
  const s = await setup(t, {
    mapping: {
      map: (args) => ({
        resource: "notes",
        amount: args.amount,
        counterparty: args.counterparty,
      }),
      execute(args, ctx) {
        count++;
        statusKey = ctx.idempotencyKey;
        throw Error("reply lost");
      },
      async status(key) {
        assert.equal(key, statusKey);
        return { settled: true };
      },
    },
  });
  const key = generateKeyPair("ed25519", "vendor:key");
  await s.owner.registerCounterparty({
    counterpartyId: "vendor",
    keys: [
      { keyId: "vendor:key", scheme: "ed25519", credential: key.credential },
    ],
  });
  const call = {
    ...s.call,
    arguments: { amount: 1200n, counterparty: "vendor" },
  };
  assert.equal((await s.backend.record(call)).status, "UNCERTAIN");
  assert.equal((await s.backend.record(call)).status, "CORE_RESULT");
  assert.equal(count, 1);
  const intent = [...s.store.state().intentDeclarations.values()][0].data;
  assert.equal(intent.amount, 1200n);
  assert.equal(intent.counterpartyId, "vendor");
});
test("always ask refuses matching hash with non-ask selected tool or cross-session event", async (t) => {
  const s = await setup(t),
    config = { tools: { write: "allow" } },
    options = {
      backend: s.backend,
      route: s.route,
      assertCurrent: s.options.assertCurrent,
      selectedTools: ["write"],
      effectiveConfig: async () => config,
      pinnedConfigHash: hashCanonical(config, "sha256"),
      assertAlwaysAsk(c, tools) {
        for (const tool of tools)
          if (c.tools[tool] !== "always_ask")
            throw Error("policy not always ask");
      },
    };
  const e = event("ask", {
    tool_use_id: "call1",
    name: "write",
    input: { text: "x" },
    evaluated_permission: "ask",
  });
  assert.equal((await resolveAlwaysAsk(options, e)).allow, false);
  await assert.rejects(
    resolveAlwaysAsk(options, {
      ...e,
      data: { ...e.data, sessionId: "other" },
    }),
    /route/,
  );
});

test("control epoch rotation during finality fences the original runtime session", async (t) => {
  const gate = deferred(),
    entered = deferred();
  const s = await setup(t, {
    options: {
      async awaitFinality(i) {
        entered.resolve();
        await gate.promise;
        return {
          status: "FINALIZED",
          idempotencyKey: i.idempotencyKey,
          admissionHeadHash: i.admissionHead.hash,
          fencingToken: "lease",
        };
      },
    },
  });
  const pending = s.backend.record(s.call);
  await entered.promise;
  await s.owner.advanceEpoch({ agent: "a", from: 1, to: 2 });
  gate.resolve();
  assert.equal((await pending).status, "UNCERTAIN");
  assert.equal(s.effects, 0);
});
test("finality outage and expiry before final handler entry never dispatch", async (t) => {
  const s = await setup(t, {
    options: {
      async awaitFinality() {
        throw Object.assign(Error("outage"), {
          code: "FINALITY_UNAVAILABLE",
          detail: { provider: "synthetic" },
          mayHaveCommitted: false,
        });
      },
    },
  });
  const r = await s.backend.record(s.call);
  assert.equal(r.status, "UNCERTAIN");
  assert.equal(r.error.code, "FINALITY_UNAVAILABLE");
  assert.deepEqual(r.error.detail, { provider: "synthetic" });
  assert.equal(s.effects, 0);
});
test("composed governed backend implements three verbs with a distinct configured native reconciler", async (t) => {
  const s = await setup(t),
    b = governed({
      ...s.options,
      initializeJournal: false,
      reconciliation: {
        local: s.recLocal,
        journalPath: s.dir + "/composed.json",
        initializeJournal: true,
      },
    });
  t.after(() => b.close());
  assert.equal((await b.decide(s.call)).verdict, "ALLOW");
  assert.equal((await b.record(s.call)).status, "CORE_RESULT");
  assert.equal(
    (await b.reconcile(page(s, [event()]))).checkpointAdvanced,
    true,
  );
  assert.equal(s.events().at(-1).data.reconcilerAgentId, "rec");
});
test("native append then reopened reconciler retries duplicate after lost cursor acknowledgment", async (t) => {
  const s = await setup(t),
    r = s.makeRec({
      async afterObservation() {
        throw Error("simulated process loss");
      },
    });
  await assert.rejects(r.reconcile(page(s, [event()])), /process loss/);
  r.close();
  const reopened = s.makeRec({
    journalPath: s.dir + "/cursor-1.json",
    initializeJournal: false,
  });
  const result = await reopened.reconcile(page(s, [event()]));
  assert.equal(result.outcomes[0].status, "DUPLICATE");
  assert.equal(result.cursor, "page1");
});

test("native42 rejects invalid session signatures and retains cursor", async (t) => {
  const s = await setup(t),
    r = s.makeRec({
      local: { ...s.recLocal, signHash: async () => "0x" + "00".repeat(64) },
    });
  const answer = await r.reconcile(page(s, [event()]));
  assert.equal(answer.outcomes[0].status, "BLOCKED");
  assert.equal(answer.cursor, null);
  assert.equal(
    s.events().some((e) => e.type === "RECONCILIATION_OBSERVED"),
    false,
  );
});
test("native42 stale-head retry obtains fresh signature after concurrent owner append", async (t) => {
  const s = await setup(t);
  let signs = 0;
  const sign = s.recLocal.signHash,
    r = s.makeRec({
      local: {
        ...s.recLocal,
        async signHash(h) {
          const sig = await sign(h);
          if (++signs === 1) await s.owner.createAgent({ id: "concurrent" });
          return sig;
        },
      },
    });
  const answer = await r.reconcile(page(s, [event()]));
  assert.equal(answer.outcomes[0].status, "ACCEPTED");
  assert.equal(answer.cursor, "page1");
  assert.equal(signs, 2);
});
test("missing cursor journal cannot manufacture watermark", async (t) => {
  const s = await setup(t),
    r = s.makeRec();
  await r.reconcile(page(s, [event()]));
  r.close();
  unlinkSync(s.dir + "/cursor-1.json");
  assert.throws(
    () =>
      s.makeRec({
        journalPath: s.dir + "/cursor-1.json",
        initializeJournal: false,
      }),
    /ENOENT/,
  );
});
test("async mapping is refused and its rejected promise is observed", async (t) => {
  const s = await setup(t, {
    mapping: {
      async map() {
        throw Error("mapping rejected");
      },
    },
  });
  const result = await s.backend.decide(s.call);
  assert.equal(result.verdict, "INDETERMINATE");
  assert.equal(s.effects, 0);
  await new Promise((r) => setImmediate(r));
});

test("empty page cannot advance after reconciler epoch fencing or session expiry", async (t) => {
  const s = await setup(t),
    r = s.makeRec();
  await s.owner.advanceEpoch({ agent: "rec", from: 1, to: 2 });
  await assert.rejects(
    r.reconcile(page(s, [])),
    /RECONCILER_SESSION_NOT_CURRENT/,
  );
  assert.equal(r.cursor(), null);
  const s2 = await setup(t),
    r2 = s2.makeRec();
  s2.setTime(1000);
  await assert.rejects(
    r2.reconcile(page(s2, [])),
    /RECONCILER_SESSION_NOT_CURRENT/,
  );
  assert.equal(r2.cursor(), null);
});
test("post-checkpoint guard withholds acknowledgment if host revoked during durable write", async (t) => {
  const s = await setup(t);
  const path = s.dir + "/after-write.json";
  const r = s.makeRec({
    journalPath: path,
    assertCurrent() {
      if (
        existsSync(path) &&
        Object.values(JSON.parse(readFileSync(path, "utf8")).cursors).includes(
          "page1",
        )
      )
        throw Error("HOST_REVOKED_AFTER_CHECKPOINT");
    },
  });
  await assert.rejects(
    r.reconcile(page(s, [])),
    /HOST_REVOKED_AFTER_CHECKPOINT/,
  );
  assert.equal(r.cursor(), "page1");
});
test("pre-lock guard failure releases in-process busy flag for a valid later page", async (t) => {
  const s = await setup(t);
  let n = 0,
    fail = true;
  const r = s.makeRec({
    assertCurrent() {
      if (fail && ++n === 2) throw Error("PRELOCK_REVOKED");
    },
  });
  await assert.rejects(r.reconcile(page(s, [])), /PRELOCK_REVOKED/);
  fail = false;
  assert.equal((await r.reconcile(page(s, []))).checkpointAdvanced, true);
});

test("reconcile() rejects, never throws synchronously: a caller using only .catch() sees RECONCILIATION_NOT_CONFIGURED and CLOSED", async (t) => {
  const s = await setup(t);
  let thrown;
  let pending;
  try { pending = s.backend.reconcile({}); } catch (error) { thrown = error; }
  assert.equal(thrown, undefined, "no synchronous throw");
  await assert.rejects(pending, /RECONCILIATION_NOT_CONFIGURED/);
  s.backend.close();
  await assert.rejects(s.backend.reconcile({}), /CLOSED/);
});
