// Read a published record from the chain and check it, with nothing but public inputs (the post-send revision list,
// item 8: the public page says anyone can check the record; until now the reader ran only inside live-run.mjs).
//
//   node experimental/anchor-shadownet/tools/read-record.mjs \
//     --rpc <https Etherlink JSON-RPC URL> --contract <0x address> --block <number, or 0x block hash> \
//     --trust-root <trust root file> [--trust-root-sha256 <0x digest the page publishes>] [--statements <n>] [--json]
//
// The trust root is the canonical JSON document the record was published under; it names the contract (destination),
// the namespace and the publisher, and the reader checks it against the contract's code and immutables. Read-only: no
// keys, no config, no run folder, and nothing is written; every call is an eth_* read at the one pinned block. Prints
// Setup is the repository's own: `pnpm install --frozen-lockfile && pnpm build` in a clone. The reader's one outside library,
// viem 2.55.19, is the copy the repository already pins (packages/anchor-outbox depends on exactly that version, and
// pnpm-lock.yaml pins its integrity); IRONTRELLIS_EVM_RUNTIME, if set, names another pinned copy, as for the other tools.
// Prints availability, anchors, closure and the failures; exits 0 only if all three verify (and, with --statements, the record
// holds exactly that many statements at the block: an earlier block shows a shorter record that is itself valid), 1 if
// not, 2 on bad arguments.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "../src/history.mjs";
import { recordingRpc } from "../src/chain.mjs";
import { httpsJsonRpc } from "../src/https-rpc.mjs";
import { reconstruct } from "../src/reader.mjs";

const arg = n => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : null; };
const usage = m => { console.error(`read-record: ${m}\nusage: read-record.mjs --rpc <https URL> --contract <0x address> --block <number|0x hash> --trust-root <file> [--trust-root-sha256 <0x digest>] [--statements <n>] [--json]`); process.exit(2); };
const rpcUrl = arg("--rpc") ?? usage("--rpc is required"), contract = (arg("--contract") ?? usage("--contract is required")).toLowerCase();
const blockArg = arg("--block") ?? usage("--block is required"), trustRootPath = arg("--trust-root") ?? usage("--trust-root is required");
let url; try { url = new URL(rpcUrl); } catch { usage("--rpc is not a URL"); }
if (url.protocol !== "https:") usage("--rpc must be an https URL");
if (!/^0x[0-9a-f]{40}$/.test(contract)) usage("--contract must be a 0x address");
const wantStatements = arg("--statements") === null ? null : /^\d+$/.test(arg("--statements")) ? Number(arg("--statements")) : usage("--statements must be a number");
const byHash = /^0x[0-9a-fA-F]{64}$/.test(blockArg);
if (!byHash && !/^\d+$/.test(blockArg)) usage("--block must be a decimal number or a 0x block hash");

const trustRootBytes = readFileSync(trustRootPath);
const digest = "0x" + sha256(trustRootBytes).replace(/^0x/, "");
const expected = arg("--trust-root-sha256");
if (expected !== null && expected.toLowerCase() !== digest) { console.error(`TRUST_ROOT_DIGEST: the file's sha256 is ${digest}, not ${expected}`); process.exit(1); }
let destination; try { destination = String(JSON.parse(trustRootBytes.toString("utf8")).destination).toLowerCase(); } catch { console.error("TRUST_ROOT_UNREADABLE: not JSON"); process.exit(1); }
if (destination !== contract) { console.error(`TRUST_ROOT_FOR_ANOTHER_CONTRACT: it names ${destination}, not ${contract}`); process.exit(1); }

// Calls are kept in memory only (the run tool saves each one; a reader writes nothing).
let calls = 0;
const recorder = { next() { if (++calls > 1_000_000) throw Error("RPC_CALL_LIMIT"); return calls; }, save() {}, get count() { return calls; } };
const evm = httpsJsonRpc(url.href, { recorder, origins: [url.origin] });
// viem, exactly 2.55.19: from IRONTRELLIS_EVM_RUNTIME if set, else the repository's own pinned copy (see the header).
const viemFrom = process.env.IRONTRELLIS_EVM_RUNTIME ? join(process.env.IRONTRELLIS_EVM_RUNTIME, "package.json") : fileURLToPath(new URL("../../../packages/anchor-outbox/package.json", import.meta.url));
let viem;
try {
  const require = createRequire(viemFrom);
  if (require("viem/package.json").version !== "2.55.19") throw Error("viem is not 2.55.19");
  viem = require("viem");
} catch (e) { console.error(`SETUP: viem 2.55.19 not found from ${viemFrom} (${e.message}); run pnpm install --frozen-lockfile && pnpm build in the repository`); process.exit(2); }
// A block hash is looked up first (the reader finds blocks by number), and the block it pins must have that hash.
let block = byHash ? null : "0x" + BigInt(blockArg).toString(16);
if (byHash) {
  const b = await evm.request({ method: "eth_getBlockByHash", params: [blockArg, false] }).catch(() => null);
  if (!b) { console.error(`NOT VERIFIED: BLOCK_NOT_FOUND: the node has no block ${blockArg}`); process.exit(1); }
  block = b.number;
}
const abi = JSON.parse(readFileSync(new URL("../artifacts/IronTrellisAnchorNamespace.json", import.meta.url), "utf8")).abi;
// By block hash (EIP-1898) where the node accepts it, else by number: the same rule live-run uses.
let result;
const read = pinBy => reconstruct({ rpc: recordingRpc(evm.request, { limit: 1_000_000 }), viem, abi, trustRootBytes, block, pinBy });
try {
  try { result = await read("hash"); }
  catch (e) { if (e.code === "TRUST_ROOT_INVALID") throw e; result = await read("number"); }
} catch (e) {
  // A trust root that does not open (T1–T4), a contract that does not match it, or a node that cannot serve the block.
  console.error(`NOT VERIFIED: ${e.code ?? e.name}: ${String(e.message).slice(0, 300)}`);
  process.exit(1);
}
const s = result.snapshot;
// Both ends of the read: the block hash when the reads began and the one read again after them (src/reader.mjs) must be the
// hash asked for; a change during the read is also a reader failure, so it cannot verify either way.
if (byHash && [s.block.hash, s.block.hashAfterRead].some(h => String(h).toLowerCase() !== blockArg.toLowerCase())) {
  console.error(`NOT VERIFIED: BLOCK_HASH_CHANGED: block ${s.block.number} was ${s.block.hash} and is ${s.block.hashAfterRead} after the reads, not ${blockArg}`); process.exit(1);
}
const countOk = wantStatements === null || s.statements.length === wantStatements;
const ok = s.availabilityVerified === true && s.anchorsVerified === true && s.closureVerified === true && countOk;
if (process.argv.includes("--json")) console.log(JSON.stringify(s, null, 1));
else {
  console.log([`record at ${contract} (trust root ${digest})`,
    `pinned block ${s.block.number} ${s.block.hash} (by ${s.block.pinnedBy})`,
    `statements ${s.statements.length}${wantStatements === null ? "" : countOk ? " (as expected)" : ` (EXPECTED ${wantStatements})`}, bodies ${s.bodies.length}, artifacts ${s.artifacts.length}`,
    `availability verified: ${s.availabilityVerified}`, `anchors verified: ${s.anchorsVerified}`, `closure verified: ${s.closureVerified}`,
    `failures: ${s.failures.length === 0 ? "none" : JSON.stringify(s.failures)}`,
    `finality: ${s.finality.label} (${s.finality.note})`, `${calls} read-only calls`, ok ? "VERIFIED" : "NOT VERIFIED"].join("\n"));
}
process.exit(ok ? 0 : 1);
