// The reader splits a history on the byte 0x0A and decodes each line on its own (review M1): a format-1 history
// may grow to 1 GiB, and V8 cannot hold a string past ~512 MiB, so decoding the whole file failed above that size
// with a wrong "not valid UTF-8" diagnosis. The large test writes a real history past 600 MB through the store and
// reads it back; it runs only when this host has the disk and memory for it (and never when
// IRONTRELLIS_SKIP_LARGE_TESTS is set), and reports a skip otherwise.
import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, statfsSync, statSync, writeFileSync } from "node:fs";
import { freemem, tmpdir, totalmem } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const { createHistoryStore: createHistoryStoreStrict, openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const createHistoryStore = (path, events, options = {}) => createHistoryStoreStrict(path, events, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { signerFromKeyPair, signControlEvent } = await import("../src/signer.ts");
const events = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const suites = await import("../src/crypto/suites.ts");

const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: "deployment:large" });
const owner = suites.generateKeyPair("ed25519", "owner:large");
const signer = signerFromKeyPair(owner);
const genesis = {
  id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
  data: {
    domain: DOMAIN, versions: { ...events.TRELLIS_VERSIONS, signatureScheme: "ed25519" },
    ownerKeys: [{ keyId: owner.keyId, scheme: "ed25519", credential: owner.credential }],
    adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: "lineage:large", policyVersion: "policy:large/1",
    rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:large", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
  },
};
const workspace = (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-large-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
const invalid = (fn, pattern) => assert.throws(fn, (error) => error.code === "INVALID_HISTORY" && pattern.test(error.message));

test("line reader: bad UTF-8 is located by record, a BOM is refused, an incomplete last record is named", async (t) => {
  const dir = workspace(t);
  const store = createHistoryStore(join(dir, "h.jsonl"), [genesis], { signer });
  store.append(await signControlEvent(signer, { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } }, DOMAIN, store.head(), "sha256"));
  const good = readFileSync(store.path);
  const secondLine = good.indexOf(0x0a) + 1;
  // An invalid byte inside record 1 (a lone continuation byte replacing a quote): the diagnosis names that record.
  const bad = Buffer.from(good);
  bad[good.indexOf(0x22, secondLine + 5)] = 0x80;
  writeFileSync(store.path, bad);
  invalid(() => openHistoryStore(store.path).state(), /^record 1: not valid UTF-8$/);
  // A valid multi-byte character never contains 0x0A, so it cannot split a line.
  const text = good.toString("utf8").replace('"principalId":"owner"', '"principalId":"owneré€"');
  writeFileSync(store.path, text);
  invalid(() => openHistoryStore(store.path).state(), /^record 1: record integrity check failed$/);
  // A BOM is kept and refused, not silently stripped.
  writeFileSync(store.path, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), good]));
  invalid(() => openHistoryStore(store.path).state(), /first record is unparsable/);
  writeFileSync(store.path, good.subarray(0, good.length - 3));
  invalid(() => openHistoryStore(store.path).state(), /incomplete record/);
  writeFileSync(store.path, good);
  assert.equal(openHistoryStore(store.path).head().position, 1);
});

const TARGET_BYTES = 620 * 1024 * 1024;
const freeDisk = (() => { try { const s = statfsSync(tmpdir()); return s.bavail * s.bsize; } catch { return 0; } })();
const skipLarge = process.env.IRONTRELLIS_SKIP_LARGE_TESTS ? "IRONTRELLIS_SKIP_LARGE_TESTS is set"
  : freeDisk < 3 * TARGET_BYTES ? `needs ${(3 * TARGET_BYTES / 2 ** 30).toFixed(1)} GiB free in ${tmpdir()}, has ${(freeDisk / 2 ** 30).toFixed(1)} GiB`
    : totalmem() < 6 * 2 ** 30 || freemem() < 3 * 2 ** 30 ? `needs 6 GiB of memory (3 GiB free), has ${(totalmem() / 2 ** 30).toFixed(1)} GiB (${(freemem() / 2 ** 30).toFixed(1)} GiB free)` : false;

test("a history past 600 MB (beyond V8's ~512 MiB string limit) is written, reopened, verified and extended", { skip: skipLarge, timeout: 900_000 }, async (t) => {
  const dir = workspace(t);
  const path = join(dir, "large.jsonl");
  const started = performance.now();
  const writer = createHistoryStore(path, [genesis], { signer, fsync: false });
  writer.append(await signControlEvent(signer, { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } }, DOMAIN, writer.head(), "sha256"));
  // ANCHOR_RECORDED events carry a receipt of up to 64 KiB (strings of up to 4 KiB each), so ~10k events pass 600 MB.
  const pad = Array.from({ length: 15 }, (_, i) => `${i}:`.padEnd(4_000, "x"));
  for (let n = 0; statSync(path).size < TARGET_BYTES; n += 1) {
    const head = writer.head();
    const event = { id: `anchor:${n}`, type: "ANCHOR_RECORDED", timestamp: 2 + n, data: { anchoredHead: head, anchor: "custom", receipt: { n, pad }, anchoredAt: 2 + n } };
    writer.append(await signControlEvent(signer, event, DOMAIN, head, "sha256"));
  }
  const expected = writer.head();
  writer.close();
  const size = statSync(path).size;
  t.diagnostic(`wrote ${(size / 2 ** 20).toFixed(0)} MiB (${expected.position + 1} events) in ${((performance.now() - started) / 1000).toFixed(1)} s`);
  assert.ok(size > 600 * 1024 * 1024 && size > 0x1fffffe8, "the file is larger than the longest string V8 can hold");
  const opening = performance.now();
  const reader = openHistoryStore(path, { signer, fsync: false });
  assert.deepEqual(reader.head(), expected);
  t.diagnostic(`open + replay in ${((performance.now() - opening) / 1000).toFixed(1)} s`);
  const report = reader.verify();
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.eventCount, expected.position + 1);
  assert.equal(report.pinnedHeadStatus, "MATCHES");
  // Tail reads keep working: an external append is absorbed incrementally, and this instance appends after it.
  const other = openHistoryStore(path, { signer, fsync: false });
  other.append(await signControlEvent(signer, { id: "tail", type: "ANCHOR_RECORDED", timestamp: expected.canonicalTime + 1, data: { anchoredHead: expected, anchor: "custom", receipt: { tail: true }, anchoredAt: expected.canonicalTime + 1 } }, DOMAIN, expected, "sha256"));
  other.close();
  const state = reader.state();
  assert.equal(reader.head().position, expected.position + 1);
  assert.equal(reader.state(), state, "the reader extended its live state from the tail");
  // A torn last line in a file this size is diagnosed as an incomplete record, not as bad UTF-8.
  appendFileSync(path, "{\"version\":");
  assert.throws(() => openHistoryStore(path, { fsync: false }).state(), (error) => error.code === "INVALID_HISTORY" && /incomplete record/.test(error.message));
});
