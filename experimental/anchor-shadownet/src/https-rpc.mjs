// Guarded HTTPS access to public nodes, after Continuity's runner (demo/run-public-cheshire.mjs): only the configured
// origins, redirects refused, a 30 s timeout, an 8 MiB response cap, a call limit, and every request and response saved
// to its own numbered file. Signed transaction bytes are never saved; the send's response (a hash) is.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

export function createRecorder(directory, { limit = 4096 } = {}) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  let n = 0;
  return {
    next() { if (++n > limit) throw Error("RPC_CALL_LIMIT"); return n; },
    save(k, record) { writeFileSync(join(directory, `rpc-${String(k).padStart(4, "0")}.json`), JSON.stringify(record, null, 1) + "\n", { flag: "wx" }); },
    get count() { return n; } };
}

async function guardedFetch(url, init, origins) {
  const u = new URL(url);
  if (u.protocol !== "https:" || !origins.includes(u.origin) || u.username || u.password) throw Error("ORIGIN_REFUSED " + u.origin);
  const response = await fetch(u, { ...init, redirect: "error", credentials: "omit", signal: AbortSignal.timeout(30_000) });
  const body = Buffer.from(await response.arrayBuffer());
  if (body.length > 8 << 20) throw Error("RESPONSE_TOO_LARGE");
  return { status: response.status, body };
}

/** JSON-RPC over HTTPS to `url`, recorded. Returns `request({method, params})` for recordingRpc and the outbox's fetch. */
export function httpsJsonRpc(url, { recorder, origins }) {
  let id = 0;
  // `omitParams`: a method such as Etherlink's tez_kernelVersion refuses any `params` member, even [] or null.
  async function request({ method, params = [], omitParams = false }) {
    const k = recorder.next(), payload = { jsonrpc: "2.0", id: ++id, method, ...(omitParams ? {} : { params }) };
    const at = new Date().toISOString();
    const shown = method === "eth_sendRawTransaction" ? { ...payload, params: ["<signed bytes withheld>"] } : payload;
    let r;
    try { r = await guardedFetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }, origins); }
    catch (e) { recorder.save(k, { at, url, request: shown, error: String(e.message) }); throw e; }
    let json = null; try { json = JSON.parse(r.body.toString("utf8")); } catch { /* recorded as text */ }
    recorder.save(k, { at, url, request: shown, status: r.status, bodySha256: createHash("sha256").update(r.body).digest("hex"), body: json ?? r.body.toString("utf8").slice(0, 65536) });
    if (json === null || r.status !== 200) throw Error(`RPC_HTTP_${r.status}`);
    if (json.error) { const e = Error(String(json.error.message).slice(0, 512)); e.code = json.error.code; e.data = json.error.data; throw e; }
    return json.result;
  }
  /** The anchor outbox's single sender calls this as fetch; it goes through the same guard and recorder. */
  async function outboxFetch(_url, init) {
    const body = JSON.parse(init.body);
    try { return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: await request({ method: body.method, params: body.params }) }), { status: 200 }); }
    catch (e) { return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: e.code ?? -32000, message: "send failed" } }), { status: 200 }); }
  }
  return { request, outboxFetch };
}

/**
 * GET JSON from a Tezos L1 node's RPC, recorded. A server error (HTTP 5xx or 429) or a timeout or connection failure is
 * retried with backoff, each attempt recorded, up to `retries` times; then the last error stops the run as before. These
 * are reads only; nothing is ever sent to L1. (The post-send revision list, item 3: on 10-25 one HTTP 503 from the public
 * node stopped the mainnet send and needed a manual --resume.) Any other status, or a refused origin, stops at once.
 */
export function httpsTezos(base, { recorder, origins, retries = 5, backoffMs = [2_000, 5_000, 10_000, 20_000, 30_000], sleep = ms => new Promise(r => setTimeout(r, ms)), log = m => console.error(m) }) {
  const transient = e => e.retryable === true || e.name === "TimeoutError" || e.name === "AbortError" || (e.name === "TypeError" && /fetch failed/.test(e.message));
  async function once(path) {
    const k = recorder.next(), at = new Date().toISOString(), url = base.replace(/\/$/, "") + path;
    let r;
    try { r = await guardedFetch(url, { method: "GET" }, origins); }
    catch (e) { recorder.save(k, { at, url, error: String(e.message) }); throw e; }
    let json = null; try { json = JSON.parse(r.body.toString("utf8")); } catch { /* text */ }
    recorder.save(k, { at, url, status: r.status, bodySha256: createHash("sha256").update(r.body).digest("hex"), body: json ?? r.body.toString("utf8").slice(0, 65536) });
    if (json === null || r.status !== 200) throw Object.assign(Error(`L1_HTTP_${r.status} ${path}`), { retryable: r.status >= 500 || r.status === 429 });
    return json;
  }
  return async path => {
    for (let attempt = 0; ; attempt++) {
      try { return await once(path); }
      catch (e) {
        if (attempt >= retries || !transient(e)) throw e;
        const wait = backoffMs[Math.min(attempt, backoffMs.length - 1)];
        log(`L1 read ${path}: ${String(e.message).slice(0, 120)}; retry ${attempt + 1} of ${retries} in ${wait / 1000} s`);
        await sleep(wait);
      }
    }
  };
}
