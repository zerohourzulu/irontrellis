/**
 * The witness HTTP API (docs/reference/witness-protocol.md §9.2, §9.6) on `node:http`: routing,
 * body limits, content types, registration auth, token-bucket rate limits,
 * client addresses behind a trusted proxy, structured access logs (no bodies),
 * `/healthz` and Prometheus `/metrics`. Every error is `{ error: { code,
 * message, hint? } }` with a stable code; stack traces never leave the process.
 * Plain HTTP only: terminate TLS in a reverse proxy.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { ContentHash } from "@ramex-labs/irontrellis";
import { isValidNonce } from "@ramex-labs/irontrellis/transparency";
import { hashToken, tokenMatches, type WitnessConfig } from "./config.ts";
import type { WitnessErrorCode } from "./state.ts";
import type { Logger, Reply, Witness } from "./witness.ts";

export const BODY_LIMIT = 64 * 1024;
export const REGISTER_BODY_LIMIT = 1024 * 1024;

const HISTORY_ID = /^0x[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,15})$/;
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

class HttpError extends Error {
  readonly status: number;
  readonly code: WitnessErrorCode;
  readonly headers: Readonly<Record<string, string>>;
  constructor(status: number, code: WitnessErrorCode, message: string, headers: Readonly<Record<string, string>> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

// ---------------------------------------------------------------- rate limits

/** Token buckets keyed by client address or history id: `perMinute` tokens, refilled continuously, burst = one minute's worth. */
export class RateLimiter {
  readonly #perMinute: number;
  readonly #buckets = new Map<string, { tokens: number; at: number }>();
  readonly #now: () => number;
  readonly #maxKeys: number;

  constructor(perMinute: number, now: () => number = Date.now, maxKeys = 100_000) {
    this.#perMinute = perMinute;
    this.#now = now;
    this.#maxKeys = maxKeys;
  }

  /** 0 when a token was taken, else the seconds until one is available. Always 0 when the limit is disabled. */
  take(key: string): number {
    if (this.#perMinute <= 0) return 0;
    const now = this.#now();
    const rate = this.#perMinute / 60_000;
    let bucket = this.#buckets.get(key);
    if (bucket === undefined) {
      if (this.#buckets.size >= this.#maxKeys) this.#sweep(now);
      bucket = { tokens: this.#perMinute, at: now };
      this.#buckets.set(key, bucket);
    } else {
      bucket.tokens = Math.min(this.#perMinute, bucket.tokens + (now - bucket.at) * rate);
      bucket.at = now;
    }
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return 0;
    }
    return Math.max(1, Math.ceil((1 - bucket.tokens) / rate / 1000));
  }

  /** Drops buckets that are full again (idle keys); if none are, the oldest half. */
  #sweep(now: number): void {
    const rate = this.#perMinute / 60_000;
    for (const [key, bucket] of this.#buckets) if (bucket.tokens + (now - bucket.at) * rate >= this.#perMinute) this.#buckets.delete(key);
    if (this.#buckets.size >= this.#maxKeys) {
      let drop = Math.floor(this.#buckets.size / 2);
      for (const key of this.#buckets.keys()) {
        if (drop-- <= 0) break;
        this.#buckets.delete(key);
      }
    }
  }

  get size(): number {
    return this.#buckets.size;
  }
}

// ---------------------------------------------------------------- client address

const normalizeAddress = (address: string): string => {
  const trimmed = address.trim();
  return trimmed.startsWith("::ffff:") && trimmed.includes(".") ? trimmed.slice(7) : trimmed;
};

/** The client address: the peer, or with `trustProxy` the address the trusted proxy chain reports in X-Forwarded-For. */
export function clientAddress(peer: string | undefined, forwardedFor: string | string[] | undefined, trustProxy: boolean | readonly string[]): string {
  const direct = normalizeAddress(peer ?? "unknown");
  if (trustProxy === false) return direct;
  const header = Array.isArray(forwardedFor) ? forwardedFor.join(",") : forwardedFor ?? "";
  const hops = header.split(",").map(normalizeAddress).filter((hop) => hop.length > 0);
  if (trustProxy === true) return hops.at(-1) ?? direct;
  const trusted = new Set(trustProxy.map(normalizeAddress));
  if (!trusted.has(direct)) return direct;
  for (let index = hops.length - 1; index >= 0; index -= 1) {
    const hop = hops[index] as string;
    if (!trusted.has(hop)) return hop;
  }
  return hops[0] ?? direct;
}

// ---------------------------------------------------------------- metrics

class Metrics {
  readonly requests = new Map<string, number>();
  readonly rejections = new Map<string, number>();
  requestSeconds = 0;
  requestCount = 0;

  count(route: string, method: string, status: number, code: string | undefined, seconds: number): void {
    const key = `route="${route}",method="${method}",status="${status}"`;
    this.requests.set(key, (this.requests.get(key) ?? 0) + 1);
    if (code !== undefined) this.rejections.set(code, (this.rejections.get(code) ?? 0) + 1);
    this.requestSeconds += seconds;
    this.requestCount += 1;
  }

  render(witness: Witness, now: number, software: string): string {
    const stats = witness.stats();
    const lines: string[] = [];
    const metric = (name: string, type: string, help: string, samples: readonly (readonly [string, number])[]): void => {
      lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`);
      for (const [labels, value] of samples) lines.push(`${name}${labels === "" ? "" : `{${labels}}`} ${value}`);
    };
    metric("irontrellis_witness_info", "gauge", "Witness software and origin.", [[`software="${software}",origin="${witness.origin.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`, 1]]);
    metric("irontrellis_witness_entries", "gauge", "Leaves in the witness log.", [["", stats.entries]]);
    metric("irontrellis_witness_entries_by_kind", "gauge", "Leaves in the witness log by entry kind.", Object.entries(stats.kinds).map(([kind, value]) => [`kind="${kind}"`, value] as const));
    metric("irontrellis_witness_histories", "gauge", "Registered histories.", [["", stats.histories]]);
    metric("irontrellis_witness_equivocating_histories", "gauge", "Histories with at least one recorded equivocation (evidence; the history stays open).", [["", stats.equivocatingHistories]]);
    metric("irontrellis_witness_equivocations_capped_total", "counter", "Conflicting head statements answered EQUIVOCATION from the cap without a new entry (one per position, 64 per history) since start.", [["", stats.cappedEquivocations]]);
    metric("irontrellis_witness_log_bytes", "gauge", "Size of log.jsonl in bytes.", [["", stats.logBytes]]);
    metric("irontrellis_witness_checkpoint_size", "gauge", "Tree size of the latest signed checkpoint.", [["", stats.checkpointSize]]);
    metric("irontrellis_witness_checkpoint_age_seconds", "gauge", "Seconds since the latest checkpoint was signed.", [["", Math.max(0, (now - stats.checkpointTime) / 1000)]]);
    metric("irontrellis_witness_appends_total", "counter", "Entries appended since start.", [["", stats.appendCount]]);
    metric("irontrellis_witness_append_seconds_total", "counter", "Time spent appending (write and fsync) since start.", [["", stats.appendSeconds]]);
    metric("irontrellis_witness_storage_failed", "gauge", "1 when the witness stopped accepting writes after a storage failure.", [["", witness.failure === undefined ? 0 : 1]]);
    metric("irontrellis_witness_requests_total", "counter", "HTTP requests by route, method and status.", [...this.requests.entries()].sort());
    metric("irontrellis_witness_rejections_total", "counter", "Error replies by code.", [...this.rejections.entries()].sort().map(([code, value]) => [`code="${code}"`, value] as const));
    metric("irontrellis_witness_request_seconds_total", "counter", "Total request handling time.", [["", this.requestSeconds]]);
    return `${lines.join("\n")}\n`;
  }
}

// ---------------------------------------------------------------- server

export type WitnessServerOptions = Readonly<{
  witness: Witness;
  config: WitnessConfig;
  software: string;
  logger?: Logger;
  now?: () => number;
}>;

export type WitnessServer = Readonly<{
  server: Server;
  listen(host: string, port: number): Promise<AddressInfo>;
  /** Stops accepting, finishes in-flight requests and appends, closes the witness (releasing its lock). */
  close(graceMs?: number): Promise<void>;
  /** Replaces the accepted admin token hashes (SIGHUP reload). */
  setAdminTokenHashes(hashes: readonly string[]): void;
}>;

const silent: Logger = Object.freeze({ info: () => {}, warn: () => {}, error: () => {} });

type Route = Readonly<{ name: string; methods: readonly string[] }>;

function route(path: string): Readonly<{ route: Route; params: readonly string[] }> | undefined {
  const parts = path.split("/");
  if (parts[0] !== "") return undefined;
  const p = parts.slice(1);
  const r = (name: string, ...methods: string[]): Route => ({ name, methods });
  if (p.length === 1 && p[0] === "healthz") return { route: r("/healthz", "GET"), params: [] };
  if (p.length === 1 && p[0] === "metrics") return { route: r("/metrics", "GET"), params: [] };
  if (p[0] !== "v1") return undefined;
  if (p.length === 2 && p[1] === "witness") return { route: r("/v1/witness", "GET"), params: [] };
  if (p.length === 2 && p[1] === "checkpoint") return { route: r("/v1/checkpoint", "GET"), params: [] };
  if (p.length === 2 && p[1] === "entries") return { route: r("/v1/entries", "GET"), params: [] };
  if (p.length === 2 && p[1] === "histories") return { route: r("/v1/histories", "POST"), params: [] };
  if (p.length === 3 && p[1] === "admin" && p[2] === "key-events") return { route: r("/v1/admin/key-events", "POST"), params: [] };
  if (p.length === 3 && p[1] === "proofs" && p[2] === "inclusion") return { route: r("/v1/proofs/inclusion", "GET"), params: [] };
  if (p.length === 3 && p[1] === "proofs" && p[2] === "consistency") return { route: r("/v1/proofs/consistency", "GET"), params: [] };
  if (p[1] !== "histories" || p.length < 3) return undefined;
  const id = p[2] as string;
  if (p.length === 3) return { route: r("/v1/histories/:id", "GET"), params: [id] };
  if (p.length === 4 && p[3] === "heads") return { route: r("/v1/histories/:id/heads", "POST"), params: [id] };
  if (p.length === 4 && p[3] === "key-events") return { route: r("/v1/histories/:id/key-events", "POST"), params: [id] };
  if (p.length === 5 && p[3] === "heads") return { route: r("/v1/histories/:id/heads/:position", "GET"), params: [id, p[4] as string] };
  return undefined;
}

/**
 * The optional `nonce` query parameter of the history routes (docs/reference/witness-protocol.md §9.8): canonical unpadded base64url of
 * 16..64 bytes. With it, every reply that carries log state also carries the signed `latestNote` over the nonce.
 */
const nonceParam = (url: URL): string | undefined => {
  const values = url.searchParams.getAll("nonce");
  if (values.length === 0) return undefined;
  if (values.length > 1 || !isValidNonce(values[0])) throw new HttpError(400, "INVALID_REQUEST", "nonce must be one canonical unpadded base64url value of 16..64 bytes");
  return values[0];
};

const historyIdParam = (value: string | undefined): ContentHash => {
  if (value === undefined || !HISTORY_ID.test(value)) throw new HttpError(400, "INVALID_REQUEST", "a history id is 0x followed by 64 lowercase hex digits");
  return value as ContentHash;
};

const numberParam = (value: string | null | undefined, name: string, required: boolean): number | undefined => {
  if (value === null || value === undefined || value === "") {
    if (required) throw new HttpError(400, "INVALID_REQUEST", `${name} is required`);
    return undefined;
  }
  const n = Number(value);
  if (!DECIMAL.test(value) || !Number.isSafeInteger(n)) throw new HttpError(400, "INVALID_REQUEST", `${name} must be a non-negative decimal integer`);
  return n;
};

/**
 * Consume and drop the rest of a request body; settles on its end, close or error, and at once when the body has already
 * ended or the request is destroyed (those events do not fire again; independent review JOB76-07).
 */
export const drainRequestBody = (req: IncomingMessage): Promise<void> => new Promise<void>((resolve) => {
  if (req.readableEnded || req.complete || req.destroyed) { resolve(); return; }
  req.on("end", resolve);
  req.on("close", resolve);
  req.on("error", () => resolve());
  req.resume();
});

async function readJson(req: IncomingMessage, limit: number): Promise<Readonly<{ value: unknown; bytes: number }>> {
  const type = (req.headers["content-type"] ?? "").toLowerCase();
  const [mediaType, ...params] = type.split(";").map((part) => part.trim());
  const charset = params.find((param) => param.startsWith("charset="))?.slice(8).replaceAll('"', "");
  if (mediaType !== "application/json" || (charset !== undefined && charset !== "utf-8" && charset !== "utf8")) {
    throw new HttpError(415, "INVALID_REQUEST", "the body must be application/json (UTF-8)");
  }
  const declared = req.headers["content-length"];
  if (declared !== undefined && Number(declared) > limit) {
    // Read and discard a declared body up to 4× the limit before answering, as the streaming branch does: a 413 sent with
    // `connection: close` while the client is still writing can reset the connection before the client reads it.
    if (Number(declared) <= limit * 4) await drainRequestBody(req);
    throw new HttpError(413, "PAYLOAD_TOO_LARGE", `the body exceeds ${limit} bytes`, { connection: "close" });
  }
  const chunks: Buffer[] = [];
  const bytes = await new Promise<number>((resolve, reject) => {
    let total = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        // Keep draining (so the 413 reaches the client) but stop buffering; give up on absurd bodies.
        tooLarge = true;
        chunks.length = 0;
        if (total > limit * 4) req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => (tooLarge ? reject(new HttpError(413, "PAYLOAD_TOO_LARGE", `the body exceeds ${limit} bytes`, { connection: "close" })) : resolve(total)));
    req.on("error", reject);
    req.on("close", () => {
      if (!req.complete) reject(new HttpError(400, "INVALID_REQUEST", "the request body was cut off"));
    });
  });
  let text: string;
  try {
    text = STRICT_UTF8.decode(Buffer.concat(chunks));
  } catch {
    throw new HttpError(400, "INVALID_REQUEST", "the body is not valid UTF-8");
  }
  try {
    return { value: JSON.parse(text), bytes };
  } catch {
    throw new HttpError(400, "INVALID_REQUEST", "the body is not valid JSON");
  }
}

export function createWitnessServer(options: WitnessServerOptions): WitnessServer {
  const { witness, config, software } = options;
  const logger = options.logger ?? silent;
  const now = options.now ?? Date.now;
  const metrics = new Metrics();
  const perIp = new RateLimiter(config.rateLimit.perIpPerMinute, now);
  const perHistory = new RateLimiter(config.rateLimit.perHistoryPerMinute, now);
  // /healthz and /metrics: their own, more generous per-address bucket (probes never starve the API, nor the API the probes).
  const monitoring = new RateLimiter(config.rateLimit.monitoringPerIpPerMinute, now);
  const metricsTokenHashes = config.metricsToken === undefined ? undefined : [hashToken(config.metricsToken)];
  let adminTokenHashes = config.adminTokenHashes;
  let shuttingDown = false;
  const inFlight = new Set<Promise<void>>();

  const send = (res: ServerResponse, status: number, body: string, type: string, headers: Readonly<Record<string, string>> = {}): void => {
    if (res.headersSent) return;
    res.writeHead(status, {
      "content-type": type, "content-length": String(Buffer.byteLength(body)), "cache-control": "no-store", "x-content-type-options": "nosniff",
      ...(shuttingDown ? { connection: "close" } : {}), ...headers,
    });
    res.end(body);
  };
  const sendJson = (res: ServerResponse, reply: Reply, headers: Readonly<Record<string, string>> = {}): void =>
    send(res, reply.status, `${JSON.stringify(reply.body)}\n`, "application/json; charset=utf-8", headers);
  const errorOf = (status: number, code: WitnessErrorCode, message: string): Reply => ({ status, body: { error: { code, message } } });

  async function dispatch(req: IncomingMessage, res: ServerResponse, context: { route: string; ip: string; code?: string; bytesIn: number; historyId?: string }): Promise<void> {
    const out = (reply: Reply): void => {
      const error = reply.body.error as { code?: unknown } | undefined;
      if (error !== undefined && typeof error.code === "string") context.code = error.code;
      sendJson(res, reply);
    };
    if (shuttingDown) throw new HttpError(503, "INTERNAL", "the witness is shutting down", { connection: "close" });
    let url: URL;
    try {
      url = new URL(req.url ?? "/", "http://witness.invalid");
    } catch {
      throw new HttpError(400, "INVALID_REQUEST", "malformed request target");
    }
    const match = route(url.pathname);
    if (match === undefined) throw new HttpError(404, "NOT_FOUND", `no route ${url.pathname}`);
    context.route = match.route.name;
    const method = req.method ?? "GET";
    if (!match.route.methods.includes(method)) throw new HttpError(405, "INVALID_REQUEST", `${method} is not allowed on ${match.route.name}`, { allow: match.route.methods.join(", ") });
    const name = match.route.name;

    if (name === "/healthz" || name === "/metrics") {
      const wait = monitoring.take(`ip:${context.ip}`);
      if (wait > 0) throw new HttpError(429, "RATE_LIMITED", "too many monitoring requests from this address", { "retry-after": String(wait) });
    }
    if (name === "/healthz") {
      const failed = witness.failure !== undefined;
      out({ status: failed ? 503 : 200, body: { status: failed ? "failed" : "ok", entries: witness.size, checkpointSize: witness.checkpoint.size, checkpointAgeMs: Math.max(0, now() - witness.checkpoint.time) } });
      return;
    }
    if (name === "/metrics") {
      if (metricsTokenHashes !== undefined) {
        const token = /^Bearer ([\x21-\x7e]{1,512})$/.exec(req.headers.authorization ?? "")?.[1];
        if (token === undefined || !tokenMatches(token, metricsTokenHashes)) {
          throw new HttpError(401, "UNAUTHORIZED", "metrics need the metrics token (Authorization: Bearer <metricsToken>)", { "www-authenticate": 'Bearer realm="irontrellis-witness-metrics"' });
        }
      }
      send(res, 200, metrics.render(witness, now(), software), "text/plain; version=0.0.4; charset=utf-8");
      return;
    }

    const wait = perIp.take(`ip:${context.ip}`);
    if (wait > 0) throw new HttpError(429, "RATE_LIMITED", "too many requests from this address", { "retry-after": String(wait) });

    switch (name) {
      case "/v1/witness":
        out(witness.info(software));
        return;
      case "/v1/checkpoint":
        send(res, 200, witness.checkpoint.note, "text/plain; charset=utf-8");
        return;
      case "/v1/entries":
        out(witness.entries(numberParam(url.searchParams.get("start"), "start", true) as number, numberParam(url.searchParams.get("end"), "end", false)));
        return;
      case "/v1/proofs/inclusion":
        out(witness.inclusion(numberParam(url.searchParams.get("index"), "index", true) as number, numberParam(url.searchParams.get("size"), "size", false)));
        return;
      case "/v1/proofs/consistency":
        out(witness.consistency(numberParam(url.searchParams.get("from"), "from", true) as number, numberParam(url.searchParams.get("to"), "to", false)));
        return;
      case "/v1/admin/key-events": {
        // The token only gates the channel (docs/reference/witness-operations.md §7.3): trust comes from the owner signatures in the bundle,
        // which get exactly the checks of POST /v1/histories/:id/key-events.
        const token = /^Bearer ([\x21-\x7e]{1,512})$/.exec(req.headers.authorization ?? "")?.[1];
        if (token === undefined || !tokenMatches(token, adminTokenHashes)) {
          throw new HttpError(401, "UNAUTHORIZED", "importing a key-event bundle needs an admin token (Authorization: Bearer <token>)", { "www-authenticate": 'Bearer realm="irontrellis-witness"' });
        }
        const nonce = nonceParam(url);
        const { value, bytes } = await readJson(req, BODY_LIMIT);
        context.bytesIn = bytes;
        const historyId = (value as { historyId?: unknown } | null)?.historyId;
        if (typeof historyId === "string" && HISTORY_ID.test(historyId)) context.historyId = historyId;
        out(await witness.importBundle(value, nonce));
        return;
      }
      case "/v1/histories": {
        if (config.registration === "token") {
          const header = req.headers.authorization ?? "";
          const token = /^Bearer ([\x21-\x7e]{1,512})$/.exec(header)?.[1];
          if (token === undefined || !tokenMatches(token, adminTokenHashes)) {
            throw new HttpError(401, "UNAUTHORIZED", "registration needs an admin token (Authorization: Bearer <token>)", { "www-authenticate": 'Bearer realm="irontrellis-witness"' });
          }
        }
        const nonce = nonceParam(url);
        const { value, bytes } = await readJson(req, REGISTER_BODY_LIMIT);
        context.bytesIn = bytes;
        const reply = await witness.register(value, nonce);
        if (typeof reply.body.historyId === "string") context.historyId = reply.body.historyId;
        out(reply);
        return;
      }
      case "/v1/histories/:id": {
        const id = historyIdParam(match.params[0]);
        context.historyId = id;
        out(await witness.history(id, nonceParam(url)));
        return;
      }
      case "/v1/histories/:id/heads/:position": {
        const id = historyIdParam(match.params[0]);
        context.historyId = id;
        out(await witness.headAt(id, numberParam(match.params[1], "position", true) as number));
        return;
      }
      case "/v1/histories/:id/heads":
      case "/v1/histories/:id/key-events": {
        const id = historyIdParam(match.params[0]);
        context.historyId = id;
        // Key events (rotations, a supersede) draw from their own per-history bucket: a flood of head
        // statements signed with a leaked key cannot starve the owner's delivery of the rotation that supersedes them.
        const historyWait = perHistory.take(name === "/v1/histories/:id/heads" ? `history:${id}` : `key-events:${id}`);
        if (historyWait > 0) throw new HttpError(429, "RATE_LIMITED", "too many requests for this history", { "retry-after": String(historyWait) });
        const nonce = nonceParam(url);
        const { value, bytes } = await readJson(req, BODY_LIMIT);
        context.bytesIn = bytes;
        out(name === "/v1/histories/:id/heads" ? await witness.submitHead(id, value, nonce)
          : await witness.keyEvent(id, value, nonce));
        return;
      }
      default:
        throw new HttpError(404, "NOT_FOUND", `no route ${url.pathname}`);
    }
  }

  const server = createServer({
    requestTimeout: config.requestTimeoutMs,
    headersTimeout: Math.min(config.requestTimeoutMs, 10_000),
    keepAliveTimeout: 5_000,
    connectionsCheckingInterval: Math.max(50, Math.min(1_000, Math.floor(config.requestTimeoutMs / 4))),
  }, (req, res) => {
    const started = performance.now();
    const context: { route: string; ip: string; code?: string; bytesIn: number; historyId?: string } = {
      route: "unknown", ip: clientAddress(req.socket.remoteAddress, req.headers["x-forwarded-for"], config.trustProxy), bytesIn: 0,
    };
    res.on("finish", () => {
      const seconds = (performance.now() - started) / 1000;
      metrics.count(context.route, req.method ?? "", res.statusCode, context.code, seconds);
      logger.info("request", {
        method: req.method, route: context.route, path: (req.url ?? "").split("?")[0], status: res.statusCode, ms: Math.round(seconds * 10_000) / 10,
        ip: context.ip, ...(context.code === undefined ? {} : { code: context.code }), ...(context.historyId === undefined ? {} : { historyId: context.historyId }),
        bytesIn: context.bytesIn,
      });
    });
    const handling = (async () => {
      try {
        await dispatch(req, res, context);
      } catch (error) {
        if (error instanceof HttpError) {
          context.code = error.code;
          sendJson(res, errorOf(error.status, error.code, error.message), error.headers);
        } else {
          context.code = "INTERNAL";
          logger.error("request failed", { route: context.route, error: error instanceof Error ? error.message : String(error), stack: error instanceof Error ? error.stack : undefined });
          sendJson(res, errorOf(500, "INTERNAL", "internal error"));
        }
      }
      if (!res.headersSent) sendJson(res, errorOf(500, "INTERNAL", "internal error"));
    })();
    inFlight.add(handling);
    void handling.finally(() => inFlight.delete(handling));
  });
  server.on("clientError", (error, socket) => {
    if (!socket.writable) return;
    const code = (error as NodeJS.ErrnoException).code;
    const status = code === "ERR_HTTP_REQUEST_TIMEOUT" ? 408 : code === "HPE_HEADER_OVERFLOW" ? 431 : 400;
    const body = `${JSON.stringify({ error: { code: "INVALID_REQUEST", message: status === 408 ? "request timeout" : "malformed request" } })}\n`;
    socket.end(`HTTP/1.1 ${status} ${status === 408 ? "Request Timeout" : status === 431 ? "Request Header Fields Too Large" : "Bad Request"}\r\ncontent-type: application/json; charset=utf-8\r\ncontent-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`);
  });

  return Object.freeze({
    server,
    listen: (host: string, port: number): Promise<AddressInfo> => new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.off("error", reject);
        resolve(server.address() as AddressInfo);
      });
    }),
    close: async (graceMs = 10_000): Promise<void> => {
      if (shuttingDown) return;
      shuttingDown = true;
      const closed = new Promise<void>((resolve) => server.close(() => resolve()));
      server.closeIdleConnections();
      const deadline = new Promise<void>((resolve) => setTimeout(resolve, graceMs).unref());
      await Promise.race([Promise.allSettled([...inFlight]).then(() => undefined), deadline]);
      await witness.close();
      server.closeAllConnections();
      await closed;
    },
    setAdminTokenHashes: (hashes: readonly string[]): void => {
      adminTokenHashes = hashes;
    },
  });
}
