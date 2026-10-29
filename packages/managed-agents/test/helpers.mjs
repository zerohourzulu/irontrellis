import {
  mkdtempSync,
  realpathSync,
  rmSync,
  copyFileSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateKeyPair, signHashWith } from "@ramex-labs/irontrellis";
import {
  createLocalAttemptOwner,
  createLocalDomain,
  openLocalRuntime,
} from "@ramex-labs/irontrellis/local";
import {
  openConfiguredEventStore,
  hashCanonical,
} from "@ramex-labs/irontrellis/adapter";
import { governed, createManagedReconciler } from "../dist/index.js";
export { hashCanonical };
let sequence = 0;
export async function setup(t, overrides = {}) {
  const dir = realpathSync(
    mkdtempSync(join(tmpdir(), "irontrellis-adapters-")),
  );
  let clock = 100,
    effects = 0,
    active = true,
    fenced = false;
  const key = generateKeyPair("ed25519", "key:a"),
    recKey = generateKeyPair("ed25519", "key:rec");
  const local = {
    historyFile: join(dir, "history.jsonl"),
    domain: createLocalDomain(),
    owner: "operations",
    controller: "operator",
    now: () => clock,
    session: "session:a",
    signHash: signHashWith(key),
    witness: false,
    nextKey: false,
  };
  const owner = await createLocalAttemptOwner(local);
  for (const id of ["a", "rec"]) await owner.createAgent({ id });
  await owner.createRole({ id: "payer" });
  await owner.appoint({
    agent: "a",
    role: "payer",
    tenure: "shift",
    number: 1,
  });
  await owner.admitRuntime({
    agent: "a",
    session: local.session,
    epoch: 1,
    key: "key:a",
    credential: key.credential,
    expiresAt: 1000,
  });
  await owner.admitRuntime({
    agent: "rec",
    session: "session:rec",
    epoch: 1,
    key: "key:rec",
    credential: recKey.credential,
    expiresAt: 1000,
  });
  await owner.grant({
    id: "grant",
    to: "a",
    actions: ["write"],
    resources: ["notes"],
    expiresAt: 500,
  });
  const store = openConfiguredEventStore(local);
  const route = {
    tenantId: "tenant",
    host: "claude-managed-agents",
    workflowId: "workflow",
    sessionId: "host-session",
    actorId: "a",
    ...overrides.route,
  };
  const mapping = {
    version: "1",
    action: "write",
    role: "payer",
    tenure: "shift",
    destination: "synthetic-local",
    map: (args) => ({ resource: "notes" }),
    execute: () => {
      effects++;
      return { ok: true };
    },
    ...overrides.mapping,
  };
  const options = {
    local,
    route,
    mappings: { write: mapping },
    journalPath: join(dir, "recovery.json"),
    initializeJournal: true,
    assertCurrent() {
      if (!active) throw Error("HOST_REVOKED");
    },
    async awaitFinality(i) {
      return {
        status: "FINALIZED",
        idempotencyKey: i.idempotencyKey,
        admissionHeadHash: i.admissionHead.hash,
        fencingToken: "lease-1",
      };
    },
    assertFence() {
      if (fenced) throw Error("FENCED");
    },
    ...overrides.options,
  };
  const backend = governed(options),
    call = {
      ...route,
      callId: "call1",
      tool: "write",
      arguments: { text: "hello" },
    };
  const recLocal = {
    ...local,
    session: "session:rec",
    signHash: signHashWith(recKey),
  };
  let recCount = 0;
  const reconcilers = [];
  const makeRec = (extra = {}) => {
    const { actorId, ...streamRoute } = route;
    const r = createManagedReconciler({
      local: recLocal,
      route: streamRoute,
      journalPath: join(dir, `cursor-${++recCount}.json`),
      initializeJournal: true,
      assertCurrent: options.assertCurrent,
      ...extra,
    });
    reconcilers.push(r);
    return r;
  };
  t.after(() => {
    backend.close();
    for (const r of reconcilers) r.close();
    store.close();
    if (process.env.IRONTRELLIS_TEST_HISTORY_DIR) {
      const out = resolve(process.env.IRONTRELLIS_TEST_HISTORY_DIR);
      mkdirSync(out, { recursive: true });
      copyFileSync(
        local.historyFile,
        join(
          out,
          t.name.replace(/[^a-zA-Z0-9]+/g, "-") + "-" + ++sequence + ".jsonl",
        ),
      );
    }
    rmSync(dir, { recursive: true, force: true });
  });
  return {
    dir,
    local,
    recLocal,
    owner,
    store,
    options,
    mapping,
    route,
    call,
    backend,
    makeRec,
    key,
    get effects() {
      return effects;
    },
    setActive(x) {
      active = x;
    },
    setFenced(x) {
      fenced = x;
    },
    setTime(x) {
      clock = x;
    },
    async revoke() {
      await owner.revoke("grant");
    },
    events() {
      return store.state().events;
    },
    rt: openLocalRuntime(recLocal),
  };
}
export const page = (s, events, extra = {}) => {
  const { actorId, ...route } = s.route;
  return {
    ...route,
    after: null,
    nextCursor: "page1",
    providerDeclaredComplete: true,
    events,
    ...extra,
  };
};
export const event = (id = "event1", data = {}) => ({
  id,
  type: "agent.tool_use",
  data: {
    actorId: "a",
    action: "write",
    resource: "notes",
    observedAt: 0,
    ...data,
  },
});
export const deferred = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
