// Format 2 (SPEC §4): event hash, record chain, store lines, heads, and the read-only fence for older formats.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const core = await import("../src/index.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");
const V2 = join(import.meta.dirname, "..", "..", "..", "conformance", "v2-g3");
const EVENTS = JSON.parse(readFileSync(join(V2, "histories", "budget-v2.json"), "utf8"));
const JSONL = readFileSync(join(V2, "histories", "budget-v2.jsonl"), "utf8");
const SELF_CHECK = JSON.parse(readFileSync(join(V2, "SELF-CHECK.json"), "utf8"));
const MANIFEST = JSON.parse(readFileSync(join(V2, "MANIFEST.json"), "utf8"));
const VECTORS = JSON.parse(readFileSync(join(V2, "vectors.json"), "utf8"));
const vector = (id) => VECTORS.find((v) => v.id === id);
const OWNER_SEED = `0x${(0x1001).toString(16).padStart(64, "0")}`;
const ownerSigner = () => signerFromKeyPair(core.keyPairFromPrivateKey("ed25519", "owner:1", OWNER_SEED));

test("format 2: the record chain reproduces every recordHash of the architect's store file, whose sha256 is the self-check's", () => {
  assert.equal(createHash("sha256").update(JSONL).digest("hex"), SELF_CHECK.sha256OfHistoryJsonl);
  const lines = JSONL.split("\n").filter(Boolean).map((line) => JSON.parse(line));
  assert.equal(lines.length, 40);
  const chain = new core.RecordChain();
  let previous = null;
  lines.forEach((line, position) => {
    assert.equal(line.version, "irontrellis-portable-file-store/2");
    assert.equal(line.previousHash, previous);
    assert.equal(core.recordHash(previous, line.event, position), line.recordHash, `line ${position}`);
    assert.equal(chain.push(line.event), line.recordHash, `chain ${position}`);
    assert.equal(chain.lastEventHash, core.eventHash(line.event));
    previous = line.recordHash;
  });
  assert.equal(previous, MANIFEST.histories["budget-v2"].head.hash);
  assert.equal(chain.count, 40);
  // SPEC §4.3: 93-byte preimage, prev = 0^32 at position 0; the hash is sha256 over it.
  const eh = Buffer.from(core.eventHash(EVENTS[0]).slice(2), "hex");
  const preimage = Buffer.concat([Buffer.from("irontrellis-record/2", "utf8"), Buffer.from([0]), Buffer.alloc(32), eh, Buffer.from("0000000000000000", "hex")]);
  assert.equal(preimage.length, 93);
  assert.equal(`0x${createHash("sha256").update(preimage).digest("hex")}`, lines[0].recordHash);
  // There is no empty-history hash in format 2.
  assert.throws(() => core.hashEventHistory([], core.TRELLIS2_FORMAT));
  assert.deepEqual(core.hashEventHistoryPrefixes(EVENTS, core.TRELLIS2_FORMAT), lines.map((line) => line.recordHash));
});

test("format 2: replay heads are recordHash(p), eventHistoryHashes[0] is the history id, and the result carries root and projection head", () => {
  const result = core.replay(EVENTS);
  assert.equal(result.status, "ACCEPTED");
  const lines = JSONL.split("\n").filter(Boolean).map((line) => JSON.parse(line));
  assert.deepEqual(result.state.eventHistoryHashes, lines.map((line) => line.recordHash));
  assert.deepEqual(result.head, MANIFEST.histories["budget-v2"].head);
  assert.equal(result.stateRoot, MANIFEST.histories["budget-v2"].stateRoot);
  assert.equal(result.projectionHead, MANIFEST.histories["budget-v2"].projectionHead);
  assert.equal(result.state.format, core.TRELLIS2_FORMAT);
  assert.equal(result.state.hashAlgorithm, "sha256");
});

test("format 2 store: the architect's file opens read-only, a store written here re-chains, and lines are plain JSON", () => {
  const dir = mkdtempSync(join(tmpdir(), "itc-f2-chain-"));
  try {
    const copy = join(dir, "architect.jsonl");
    writeFileSync(copy, JSONL);
    const opened = core.openHistoryStore(copy, { allowUnpinned: true });
    assert.equal(opened.format, core.TRELLIS2_FORMAT);
    assert.deepEqual(opened.head(), MANIFEST.histories["budget-v2"].head);
    assert.equal(opened.verify().chain, "OK");
    opened.close();
    // Written by this store: the same events, the same chain, canonical event text, no bigint markers anywhere.
    const own = join(dir, "own.jsonl");
    const store = core.createHistoryStore(own, EVENTS, { signer: ownerSigner() });
    assert.deepEqual(store.head(), MANIFEST.histories["budget-v2"].head);
    const written = readFileSync(own, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
    const lines = JSONL.split("\n").filter(Boolean).map((line) => JSON.parse(line));
    written.forEach((line, position) => {
      assert.equal(line.recordHash, lines[position].recordHash);
      assert.equal(line.previousHash, lines[position].previousHash);
      assert.equal(JSON.stringify(line.event), core.canonicalEncode(EVENTS[position]));
    });
    assert.ok(!readFileSync(own, "utf8").includes("$continuity.bigint"));
    // The pin carries a /2 attestation that commits to the root and the projection head.
    const pin = store.pinnedHead();
    assert.equal(pin.attestation.version, "irontrellis-head-attestation/2");
    assert.equal(pin.attestation.stateRoot, MANIFEST.histories["budget-v2"].stateRoot);
    assert.equal(pin.attestation.projectionHead, MANIFEST.histories["budget-v2"].projectionHead);
    assert.deepEqual(pin.attestation.domain, EVENTS[0].data.domain);
    assert.equal(core.verifyHeadAttestationFacts(pin.attestation, store.state()).valid, true);
    store.close();
    const reopened = core.openHistoryStore(own);
    assert.deepEqual(reopened.head(), MANIFEST.histories["budget-v2"].head);
    assert.equal(reopened.verify().ok, true);
    reopened.close();
    // A planted bigint marker in a format-2 line is parsed as plain JSON and refused by the schema, never decoded.
    const planted = lines.map((line, position) => (position === 11 ? { ...line, event: { ...line.event, data: { ...line.event.data, amount: { "$continuity.bigint": "60" } } } } : line));
    let prev = null;
    for (const [position, line] of planted.entries()) { line.previousHash = prev; line.recordHash = core.recordHash(prev, line.event, position); prev = line.recordHash; }
    writeFileSync(copy, planted.map((line) => `${JSON.stringify(line)}\n`).join(""));
    assert.throws(() => core.openHistoryStore(copy, { allowUnpinned: true }).head(), (error) => error.code === "INVALID_HISTORY" && error.detail.code === "EVENT_DATA_INVALID" && error.detail.position === 11);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("format 2: legacy and format-1 files are read-only writers under the SPEC §16.1 fence (FORMAT_READ_ONLY)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "itc-f2-fence-"));
  try {
    const v1 = vector("replay/v2/still-reads-format-1-history").events;
    const legacy = vector("replay/v2/still-reads-legacy-history").events;
    const f1Path = join(dir, "f1.jsonl");
    const f1 = core.createHistoryStore(f1Path, core.jsonParseWithBigints(JSON.stringify(v1)), { allowUnpinned: true, [FORMAT1_TEST_TOOLING]: true });
    f1.close();
    for (const [path, events, reason] of [[f1Path, v1, "FORMAT_1"], [join(dir, "legacy.jsonl"), legacy, "LEGACY"]]) {
      if (reason === "LEGACY") { const s = core.createHistoryStore(path, core.jsonParseWithBigints(JSON.stringify(events)), { [FORMAT1_TEST_TOOLING]: true }); s.close(); }
      const store = core.openHistoryStore(path, { readOnlyFormats: true, allowUnpinned: true });
      assert.equal(store.head().position, events.length - 1);
      assert.equal(store.verify().chain, "OK");
      assert.throws(() => store.append({ id: "x", type: "PRINCIPAL_CREATED", timestamp: 0, data: { principalId: "p" } }), (error) => error.code === "FORMAT_READ_ONLY" && error.detail.reason === reason);
      store.close();
      // The fence is the default (SPEC §16.1); the earlier writer is asked for by name (`readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true`).
      assert.equal(core.FORMAT_READ_ONLY_DEFAULT, true);
      assert.throws(() => core.openHistoryStore(path, { allowUnpinned: true }).append({ id: "x", type: "PRINCIPAL_CREATED", timestamp: 0, data: { principalId: "p" } }), (error) => error.code === "FORMAT_READ_ONLY");
      assert.equal(core.openHistoryStore(path, { allowUnpinned: true }).readOnlyReason(), reason);
      assert.equal(core.openHistoryStore(path, { allowUnpinned: true, readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true }).readOnlyReason(), undefined);
    }
    // A format-2 file is never fenced by the format rule.
    const f2Path = join(dir, "f2.jsonl");
    const f2 = core.createHistoryStore(f2Path, EVENTS.slice(0, 1), { signer: ownerSigner(), readOnlyFormats: true });
    const signed = await core.signControlEvent(ownerSigner(), { id: "p:fence", type: "PRINCIPAL_CREATED", timestamp: 100, data: { principalId: "fence" } }, EVENTS[0].data.domain, f2.head(), "sha256");
    assert.equal(f2.append(signed).position, 1);
    f2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
