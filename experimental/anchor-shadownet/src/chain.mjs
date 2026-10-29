// The chain side of a run: a recording JSON-RPC client, a journaled single-send transaction sender (journal before submit,
// one send per submission, reconcile only; Continuity's discipline and anchor-outbox §16–§17), the six read adapters the
// outbox expects (anchor-outbox ReadAdapters), the T5 immutables read, and the outbox's sender transport.
import { existsSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { canonical, sha256 } from "./history.mjs";
import { writeRecord, readRecord, setAsideIfEmpty } from "./durable.mjs";

/** Every request and response is kept, in order, for the evidence bundle. Signed transaction bytes are never logged. */
export function recordingRpc(request, { clock = () => Date.now(), limit = 4096 } = {}) {
  const log = [];
  async function call(method, params = []) {
    if (log.length >= limit) throw Error("RPC_CALL_LIMIT");
    const entry = { n: log.length + 1, at: clock(), method, params: method === "eth_sendRawTransaction" ? ["<signed bytes withheld>"] : params };
    log.push(entry);
    try { entry.result = await request({ method, params }); return entry.result; }
    catch (e) { entry.error = { message: String(e.message).slice(0, 2048), code: e.code ?? null }; throw e; }
  }
  return Object.freeze({ call, log });
}

const quantity = n => "0x" + BigInt(n).toString(16);
/** JSON-RPC returns r and s as QUANTITY (leading zeros dropped); anchor-outbox's reconciliation expects 32-byte words. */
const word = q => "0x" + BigInt(q).toString(16).padStart(64, "0");

// Each record whole or absent (src/durable.mjs); a torn one from an older tool stops with TORN_RECORD.
const durable = (path, value) => writeRecord(path, JSON.stringify(value, null, 1) + "\n");
const readJson = readRecord;

/**
 * Sends non-statement transactions (deployment, bodies, artifacts). For each submission id: an intent record, then the
 * signed record, then "send started", then exactly one eth_sendRawTransaction. A resumed submission whose send started is
 * only reconciled, never sent again. Any nonce observation that disagrees with the journal stops the run.
 *
 * The run's identity is bound into every intent (the coordinator 20261024T064530Z, Astra's finding): the chain id, which
 * the endpoint must report (eth_chainId); the sender, derived from the key (`deriveSender`), never taken from the config
 * alone; the run id and the hash of the network entry. Before an intent is written, and again before any signing, resigning
 * or sending, the live context must equal the run's and, on resume, the intent's. Every signed transaction is decoded and
 * checked (chain id from v, the recovered sender, nonce, recipient, data, gas, gas price, value, hash) before it is
 * recorded and before it is sent.
 *
 * An intent without a signed record is re-signed from the intent: nothing is ever sent before both the signed record and
 * the send-started record are durable, so that crash left nothing on the wire. The resumed call must give the same
 * recipient, data and gas price in the same run context with the nonce still free; legacy ECDSA signing is deterministic
 * (RFC 6979), so the transaction is signed twice and the two must be byte-identical.
 */
/**
 * Etherlink's inclusion (data-availability) fee (docs.etherlink.com/evm/developing/fees, "Inclusion fee" and "Gas limit",
 * updated 2026-10-07): 0.000004 XTZ x (150 + data bytes + access-list bytes), charged as gas units at the base fee, whose
 * minimum is 1 gwei. eth_estimateGas returns execution gas plus those units as one number (measured on Shadownet,
 * 2026-10-24: the units do not change with the transaction's gasPrice), and the 30,000,000 per-transaction limit is on
 * execution gas only. The legacy transactions here carry no access list.
 * Which base fee converts the fee into units (the coordinator 20261024T183425Z, Astra's question): in the kernel that both
 * Shadownet and mainnet ran on 2026-10-24 (tez_kernelVersion 54a7b0920d33be3ce011edcc7dfed25a64868fb4, tezos/tezos
 * etherlink/kernel_latest/kernel/src/fees.rs), the estimate adds the units at the MINIMUM base fee
 * (simulation_add_gas_for_fees), and a transaction's execution limit is its gas limit less the units at the minimum
 * (tx_execution_gas_limit); the fee charged is execution x the block's base fee plus the inclusion fee in wei
 * (FeeUpdates::of_gas_and_da_fee). planGas does not rely on that: it infers the execution both ways and keeps the larger.
 */
export const ETHERLINK_INCLUSION = Object.freeze({ weiPerByte: 4_000_000_000_000n, overheadBytes: 150n, minBaseFeeWei: 1_000_000_000n });
export const inclusionWei = (model, dataBytes) => model === null ? 0n : model.weiPerByte * (model.overheadBytes + BigInt(dataBytes));
/** The inclusion fee as gas units at `baseFeeWei` (never below the minimum; the minimum when null), rounded up. At the minimum,
 * a byte is 4,000 units, the most it can be. */
export const inclusionGas = (model, dataBytes, baseFeeWei = null) => {
  if (model === null) return 0n;
  const denominator = baseFeeWei !== null && BigInt(baseFeeWei) > model.minBaseFeeWei ? BigInt(baseFeeWei) : model.minBaseFeeWei;
  return (inclusionWei(model, dataBytes) + denominator - 1n) / denominator;
};
/**
 * A transaction's gas limit from its estimate: the gas rule's headroom on the execution part only, plus the inclusion units,
 * and the cap on the execution part (Etherlink's own limit is on execution). With no inclusion model (a local chain) this is
 * exactly gasRule(estimate) against maxGas, as before.
 * - The execution, robust to either base fee (the coordinator 20261024T183425Z): estimate less the inclusion units at the
 *   current block's `baseFeeWei` (never below the minimum). Fewer units are subtracted at a higher base fee, so this is the
 *   larger of the two inferred executions and is never an underestimate; at the minimum base fee the two agree. The cap check
 *   and the gas rule use it.
 * - The gas limit adds the units at the minimum base fee, the most there can be, which is what the kernel subtracts before
 *   execution: the transaction's execution limit is then at least the gas rule's limit, whichever base fee the estimate used.
 * - The fee reserved is gas x gasPrice, the most the transaction can pay. A gasPrice below the current base fee is refused
 *   (GAS_PRICE_BELOW_BASE_FEE: the fee would be charged at the base fee, above the reservation).
 * Fails closed when the estimate is smaller than the inclusion units it must contain plus 21,000: then the network does not
 * charge as modelled.
 */
export function planGas({ id, estimate, dataBytes, gasRule, maxGas, inclusion = null, gasPrice = null, baseFeeWei = null }) {
  const included = inclusionGas(inclusion, dataBytes), atBaseFee = inclusionGas(inclusion, dataBytes, baseFeeWei);
  const execution = estimate - atBaseFee;
  if (inclusion !== null && execution < 21_000n) throw Error(`INCLUSION_MODEL_MISMATCH ${id}: the estimate ${estimate} is below the ${atBaseFee} inclusion units plus 21,000; stop, nothing signed`);
  if (inclusion !== null && baseFeeWei !== null && gasPrice !== null && gasPrice < BigInt(baseFeeWei)) throw Error(`GAS_PRICE_BELOW_BASE_FEE ${id}: gasPrice ${gasPrice} < the current base fee ${baseFeeWei}; stop, nothing signed`);
  const executionLimit = gasRule(execution);
  if (executionLimit > maxGas) throw Error(`GAS_CAP ${id}: ${executionLimit} > ${maxGas}${inclusion === null ? "" : " (execution gas; inclusion units " + included + " are outside the cap)"}`);
  const gas = executionLimit + included;
  return { gas, execution, inclusion: included, ...(inclusion === null || baseFeeWei === null ? {} : { baseFeeWei: BigInt(baseFeeWei), executionAtMinimum: estimate - included }),
    ...(gasPrice === null ? {} : { reserveWei: gas * gasPrice }) };
}
/** The current block's base fee for planGas (eth_getBlockByNumber "latest"); null if the block carries none. */
export async function latestBaseFee(rpc) {
  const block = await rpc.call("eth_getBlockByNumber", ["latest", false]);
  return block?.baseFeePerGas == null ? null : BigInt(block.baseFeePerGas);
}

export function createTxJournal({ directory, rpc, chainId, publisher, sign, hashOf, gasPrice, maxGas, gasRule = g => g * 125n / 100n + 100_000n,
  confirm = { polls: 1, intervalMs: 0 }, budget = { reserve() {} }, beforeSend = () => {}, hook = () => {}, viem, deriveSender, runId, networkEntryHash, inclusion = null }) {
  if (!viem || typeof deriveSender !== "function" || typeof runId !== "string" || !/^0x[0-9a-f]{64}$/.test(networkEntryHash ?? "")) throw Error("JOURNAL_IDENTITY_OPTIONS");
  mkdirSync(directory, { recursive: true, mode: 0o700 }); chmodSync(directory, 0o700);
  const p = (id, suffix) => join(directory, `${id}.${suffix}.json`);
  async function nonceNow() {
    const [latest, pending] = await Promise.all([rpc.call("eth_getTransactionCount", [publisher, "latest"]), rpc.call("eth_getTransactionCount", [publisher, "pending"])]);
    if (latest !== pending) throw Error(`NONCE_OBSERVATION_CONFLICT_RECONCILE_ONLY latest=${latest} pending=${pending}`);
    return Number(BigInt(latest));
  }
  const MAX_REBROADCASTS = 3;
  /**
   * After "send started": the receipt of the recorded hash, or (SEND-STARTED-PROPOSAL-01, the coordinator's GO
   * 20261024T063842Z) a rebroadcast of the identical recorded bytes, only while the node does not know the transaction and
   * the account's nonce is still the intent's, in the same run context, at most MAX_REBROADCASTS times, each journalled
   * first. Identical bytes are one transaction and one nonce, so they are included at most once. Another transaction at the
   * nonce stops the run (CONSUMED_BY_OTHER); a transaction still in the node's pool is waited for, never resent.
   */
  async function reconcile(id) {
    const signed = readJson(p(id, "signed")), intent = readJson(p(id, "intent"));
    for (;;) {
      let receipt = null;
      for (let i = 0; i < confirm.polls && receipt === null; i++) {
        if (i > 0) await new Promise(r => setTimeout(r, confirm.intervalMs));
        receipt = await rpc.call("eth_getTransactionReceipt", [signed.transactionHash]);
      }
      if (receipt !== null) return recordResult(id, intent, receipt, signed);
      const latest = Number(BigInt(await rpc.call("eth_getTransactionCount", [publisher, "latest"])));
      if (latest > intent.nonce) throw Error(`CONSUMED_BY_OTHER ${id} nonce ${intent.nonce}: another transaction took it; stop`);
      if ((await rpc.call("eth_getTransactionByHash", [signed.transactionHash])) !== null) throw Error(`OUTCOME_PENDING ${id}: in the node's pool, not yet included; rerun to reconcile, nothing resent`);
      if ((await nonceNow()) !== intent.nonce) throw Error(`NONCE_OBSERVATION_CONFLICT_RECONCILE_ONLY ${id}`);
      let k = 0;
      while (k < MAX_REBROADCASTS && existsSync(p(id, `rebroadcast-${k + 1}`))) k += 1;
      if (k >= MAX_REBROADCASTS) throw Error(`OUTCOME_UNKNOWN ${id}: not included after ${MAX_REBROADCASTS} rebroadcasts; reconcile only`);
      const now = await context();
      if (!sameContext(intent, now)) throw Error(`INTENT_CONTEXT_MISMATCH ${id}: the intent was written for chain ${intent.chainId}, sender ${intent.sender}, run ${intent.runId}; stop, nothing sent`);
      if ((await checkSigned(signed.raw, intent)) !== signed.transactionHash) throw Error(`SIGNED_RECORD_INVALID ${id}; stop`);
      beforeSend(id);
      durable(p(id, `rebroadcast-${k + 1}`), { id, transactionHash: signed.transactionHash, rebroadcast: k + 1 });
      hook("after:JOURNAL_REBROADCAST_STARTED");
      try { await rpc.call("eth_sendRawTransaction", [signed.raw]); } catch { /* ambiguous: the next round decides */ }
      hook("after:JOURNAL_REBROADCAST");
    }
  }
  function recordResult(id, intent, receipt, signed) {
    if (receipt.transactionHash !== signed.transactionHash) throw Error("RECEIPT_CONTRADICTS " + id);
    const result = { id, transactionHash: receipt.transactionHash, status: receipt.status, blockNumber: Number(BigInt(receipt.blockNumber)),
      blockHash: receipt.blockHash, gasUsed: Number(BigInt(receipt.gasUsed)), gasLimit: intent.gas, contractAddress: receipt.contractAddress ?? null,
      logs: receipt.logs.length, label: "RPC_OBSERVED" };
    if (!existsSync(p(id, "result"))) { durable(p(id, "result"), result); hook("after:JOURNAL_RESULT"); }
    if (receipt.status !== "0x1") throw Error(`INCLUDED_REVERTED ${id} ${receipt.transactionHash}`);
    return result;
  }
  /** The live run context: the endpoint's chain id and the key's derived address must be the run's. */
  async function context() {
    const live = Number(BigInt(await rpc.call("eth_chainId", [])));
    if (live !== Number(chainId)) throw Error(`CHAIN_ID_MISMATCH: the endpoint reports ${live}, the run is ${chainId}; stop, nothing signed or sent`);
    const sender = String(await deriveSender()).toLowerCase();
    if (sender !== publisher) throw Error(`SENDER_MISMATCH: the key derives ${sender}, the run sends from ${publisher}; stop, nothing signed or sent`);
    return { chainId: Number(chainId), sender, runId, networkEntryHash };
  }
  const sameContext = (intent, now) => intent.chainId === now.chainId && intent.sender === now.sender && intent.runId === now.runId && intent.networkEntryHash === now.networkEntryHash;
  /** Decodes a signed transaction and checks it is exactly the intent's; returns its hash. */
  async function checkSigned(raw, intent) {
    let t, from;
    try { t = viem.parseTransaction(raw); from = (await viem.recoverTransactionAddress({ serializedTransaction: raw })).toLowerCase(); }
    catch { throw Error(`SIGNED_TRANSACTION_UNREADABLE ${intent.id}; stop`); }
    const to = t.to ? t.to.toLowerCase() : null, data = t.data ?? "0x";
    const ok = t.type === "legacy" && Number(t.chainId) === intent.chainId && from === intent.sender && Number(t.nonce) === intent.nonce && to === intent.to &&
      sha256(Buffer.from(data.slice(2), "hex")) === intent.dataSha256 && Number(t.gas) === intent.gas && Number(t.gasPrice) === intent.gasPrice && BigInt(t.value ?? 0n) === 0n;
    if (!ok) throw Error(`SIGNED_TRANSACTION_MISMATCH ${intent.id}: the signed transaction is not the intent's; stop`);
    return hashOf(raw);
  }
  async function submit(id, { to, data }) {
    if (!/^[a-z0-9-]{1,96}$/.test(id)) throw Error("SUBMISSION_ID");
    // An older tool could leave an empty intent (created, killed before the write). The intent is written before signing, so
    // with no later record nothing was signed or sent for this id: it is set aside and a new intent is made (TORN-JOURNAL-RECOVERY-01).
    if (!["signed", "send-started", "result", "rebroadcast-1"].some(s => existsSync(p(id, s)))) setAsideIfEmpty(p(id, "intent"));
    if (existsSync(p(id, "result"))) return readJson(p(id, "result"));
    if (existsSync(p(id, "send-started"))) return reconcile(id);
    const now = await context();
    const target = to ? to.toLowerCase() : null, dataSha256 = sha256(Buffer.from(data.slice(2), "hex"));
    if (!existsSync(p(id, "signed"))) {
      const resumed = existsSync(p(id, "intent"));
      let tx, intent;
      if (resumed) {
        intent = readJson(p(id, "intent"));
        if (!sameContext(intent, now)) throw Error(`INTENT_CONTEXT_MISMATCH ${id}: the intent was written for chain ${intent.chainId}, sender ${intent.sender}, run ${intent.runId}; stop, nothing signed or sent`);
        if (intent.to !== target || intent.dataSha256 !== dataSha256 || intent.gasPrice !== Number(gasPrice) || intent.value !== "0") {
          throw Error(`INTENT_MISMATCH ${id}: the resumed submission differs from its intent; stop`);
        }
        if ((await nonceNow()) !== intent.nonce) throw Error(`NONCE_OBSERVATION_CONFLICT_RECONCILE_ONLY ${id}: the nonce moved since the intent; stop, nothing signed`);
        tx = { type: "legacy", chainId: intent.chainId, nonce: intent.nonce, to: intent.to, data, gas: BigInt(intent.gas), gasPrice, value: 0n };
      } else {
        const nonce = await nonceNow();
        const estimate = BigInt(await rpc.call("eth_estimateGas", [{ from: publisher, ...(to ? { to } : {}), data, gasPrice: quantity(gasPrice) }]));
        const baseFeeWei = inclusion === null ? null : await latestBaseFee(rpc);
        const plan = planGas({ id, estimate, dataBytes: (data.length - 2) / 2, gasRule, maxGas, inclusion, gasPrice, baseFeeWei }), gas = plan.gas;
        // The amount that bounds this submission: a reservation left by an attempt that died before its intent stands if the
        // recomputed plan is no larger, and a larger one is refused (src/budget.mjs). The intent records the ledger's amount.
        const reservedWei = budget.reserve(id, plan.reserveWei) ?? plan.reserveWei;
        tx = { type: "legacy", chainId: now.chainId, nonce, to: target, data, gas, gasPrice, value: 0n };
        intent = { id, ...now, to: target, dataSha256, dataBytes: (data.length - 2) / 2, value: "0",
          nonce, gas: Number(gas), gasPrice: Number(gasPrice), estimate: Number(estimate), feeReservationWei: reservedWei.toString(),
          ...(inclusion === null ? {} : { inclusionGas: Number(plan.inclusion), ...(plan.baseFeeWei === undefined ? {} : { baseFeeWei: plan.baseFeeWei.toString() }) }) };
        durable(p(id, "intent"), intent);
      }
      const raw = await sign(tx);
      if (resumed && (await sign(tx)) !== raw) throw Error(`SIGNING_NOT_DETERMINISTIC ${id}: two signatures of one transaction differ; stop`);
      hook("after:JOURNAL_INTENT");
      durable(p(id, "signed"), { id, transactionHash: await checkSigned(raw, intent), raw });
      hook("after:JOURNAL_SIGNED");
    }
    const signed = readJson(p(id, "signed")), intent = readJson(p(id, "intent"));
    // Before the one send: the same run context as the intent, the current request equal to the intent (as in the
    // unsigned branch; a resume after the signed record otherwise sent the old transaction for a changed request, Astra's
    // review of 51cdd55), and the recorded bytes still exactly the intent's.
    if (!sameContext(intent, now)) throw Error(`INTENT_CONTEXT_MISMATCH ${id}: the intent was written for chain ${intent.chainId}, sender ${intent.sender}, run ${intent.runId}; stop, nothing sent`);
    if (intent.to !== target || intent.dataSha256 !== dataSha256 || intent.gasPrice !== Number(gasPrice) || intent.value !== "0") {
      throw Error(`INTENT_MISMATCH ${id}: the resumed submission differs from its signed intent; stop, nothing sent`);
    }
    if ((await checkSigned(signed.raw, intent)) !== signed.transactionHash) throw Error(`SIGNED_RECORD_INVALID ${id}; stop`);
    if ((await nonceNow()) !== intent.nonce) throw Error(`NONCE_OBSERVATION_CONFLICT_RECONCILE_ONLY ${id}`);
    beforeSend(id);
    durable(p(id, "send-started"), { id, transactionHash: signed.transactionHash });
    hook("after:JOURNAL_SEND_STARTED");
    try { await rpc.call("eth_sendRawTransaction", [signed.raw]); } catch { /* ambiguous: reconcile decides */ }
    hook("after:JOURNAL_SEND");
    return reconcile(id);
  }
  return Object.freeze({ submit, reconcile, directory });
}

/** The anchor-outbox read adapters over JSON-RPC (each result as canonical bytes). `l1LevelOf` maps a mined transaction to an L1 level. */
export function createReadAdapters({ rpc, viem, abi, l1LevelOf }) {
  const legacyView = t => {
    if (t === null) return null;
    const v = { type: t.type ?? "0x0", hash: t.hash, from: t.from.toLowerCase(), to: t.to === null ? null : t.to.toLowerCase(), nonce: t.nonce,
      chainId: t.chainId ?? quantity((BigInt(t.v) - 35n) / 2n), gas: t.gas, gasPrice: t.gasPrice, value: t.value, v: t.v, r: word(t.r), s: word(t.s),
      input: t.input, blockHash: t.blockHash ?? null, blockNumber: t.blockNumber ?? null };
    return v;
  };
  async function transactionAtNonce(publisher, nonce) {
    let lo = 0, hi = Number(BigInt(await rpc.call("eth_blockNumber")));
    const countAt = async b => Number(BigInt(await rpc.call("eth_getTransactionCount", [publisher, quantity(b)])));
    if ((await countAt(hi)) <= nonce) return null;
    while (lo < hi) { const mid = Math.floor((lo + hi) / 2); if ((await countAt(mid)) > nonce) hi = mid; else lo = mid + 1; }
    const block = await rpc.call("eth_getBlockByNumber", [quantity(lo), true]);
    return block.transactions.find(t => t.from.toLowerCase() === publisher && Number(BigInt(t.nonce)) === nonce) ?? null;
  }
  return Object.freeze({
    async transactionByHash({ transactionHash }) { return canonical(legacyView(await rpc.call("eth_getTransactionByHash", [transactionHash]))); },
    async receiptByHash({ transactionHash }) {
      const r = await rpc.call("eth_getTransactionReceipt", [transactionHash]);
      return canonical(r === null ? null : { transactionHash: r.transactionHash, blockHash: r.blockHash, blockNumber: r.blockNumber, status: r.status });
    },
    async latestNonce({ publisher }) { return canonical({ accountNonce: Number(BigInt(await rpc.call("eth_getTransactionCount", [publisher, "latest"]))), observedAt: Date.now() }); },
    async minedTransactionAtNonce({ publisher, nonce }) { return canonical(legacyView(await transactionAtNonce(publisher, nonce))); },
    async l1Level({ transactionHash }) { return canonical({ level: await l1LevelOf(transactionHash) }); },
    async retainedStatementDigest({ destination, transactionHash }) {
      const t = await rpc.call("eth_getTransactionByHash", [transactionHash]);
      if (t === null || t.blockNumber === null || t.to?.toLowerCase() !== destination) return canonical({ digest: null });
      const { args } = viem.decodeFunctionData({ abi, data: t.input });
      const digest = sha256(Buffer.from(args[0].slice(2), "hex"));
      const out = await rpc.call("eth_call", [{ to: destination, data: viem.encodeFunctionData({ abi, functionName: "statementIndex", args: [digest] }) }, t.blockNumber]);
      const [found] = viem.decodeFunctionResult({ abi, functionName: "statementIndex", data: out });
      return canonical({ digest: found ? digest : null });
    } });
}

/** T5 (SPEC §19.3): the instance's immutables, read once, as the outbox's `observeImmutables` expects. */
export function createImmutablesRead({ rpc, viem, abi }) {
  const get = async (to, functionName, block) => viem.decodeFunctionResult({ abi, functionName,
    data: await rpc.call("eth_call", [{ to, data: viem.encodeFunctionData({ abi, functionName }) }, block]) });
  return async ({ destination }, block = "latest") => canonical({ destination, namespaceId: await get(destination, "namespaceId", block),
    publisher: (await get(destination, "publisher", block)).toLowerCase(), chainId: "eip155:" + (await get(destination, "chainId", block)) });
}

/** The fetch the outbox's single sender uses (anchor-outbox createSingleHttpSender), routed to a local request function. */
export function localFetch(rpc) {
  return async (_url, init) => {
    const body = JSON.parse(init.body);
    try { return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: await rpc.call(body.method, body.params) }), { status: 200 }); }
    catch (e) { return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: e.code ?? -32000, message: String(e.message) } }), { status: 200 }); }
  };
}
