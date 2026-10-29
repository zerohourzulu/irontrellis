/**
 * Protected stdio transport for upstream MCP servers: an SDK `Transport` that
 * spawns the approved executable without a shell, with a default environment
 * (no tool-selected variables), discards its stderr (it may print secrets) and
 * validates every received frame as bounded strict JSON before the SDK parses
 * it. Frames: 64 KiB each, 128 KiB buffered, and at most 1,024 in any 60
 * seconds (a rate, not a per-process total: GATEWAY-RATE-01).
 */
import { spawn, type ChildProcess } from "node:child_process";
import type { JSONRPCMessage, Transport } from "@modelcontextprotocol/client";
import { getDefaultEnvironment } from "@modelcontextprotocol/client/stdio";
import { check } from "./data.ts";
import { parseStrictJson } from "./strict-json.ts";
import { rateWindow } from "./guard.ts";

/** `protocol`: the upstream's protocol era. Absent or "legacy": the 2025 `initialize` handshake; "2026-07-28": that revision exactly, no fallback. */
export type UpstreamConfig = Readonly<{ id: string; command: string; args: readonly string[]; cwd?: string; protocol?: UpstreamProtocol }>;
export type UpstreamProtocol = "legacy" | "2026-07-28";
/** The upstream frame rate (defaults 1,024 frames in any 60,000 ms); `now` is for tests. Not part of the approved configuration. */
export type UpstreamFrameRate = Readonly<{ maxFrames?: number; windowMs?: number; now?: () => number }>;

export class ProtectedStdioTransport implements Transport {
  readonly #config: UpstreamConfig;
  #child: ChildProcess | undefined;
  #exited: Promise<void> | undefined;
  #pending = Buffer.alloc(0);
  readonly #admit: () => boolean;
  #closed = false;
  #frameTimer: NodeJS.Timeout | undefined;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  constructor(config: UpstreamConfig, rate: UpstreamFrameRate = {}) {
    this.#config = config;
    this.#admit = rateWindow(rate.maxFrames ?? 1024, rate.windowMs ?? 60_000, rate.now ?? Date.now);
  }

  async start(): Promise<void> {
    check(this.#child === undefined && !this.#closed);
    const c = spawn(this.#config.command, [...this.#config.args], {
      ...(this.#config.cwd === undefined ? {} : { cwd: this.#config.cwd }), env: getDefaultEnvironment(), shell: false, stdio: ["pipe", "pipe", "ignore"],
    });
    this.#child = c;
    this.#exited = new Promise((resolve) => c.once("close", () => { clearTimeout(this.#frameTimer); this.#closed = true; this.onclose?.(); resolve(); }));
    const reject = (): void => { this.onerror?.(new Error("UPSTREAM_INVALID_FRAME")); void this.close(); };
    c.stdin!.on("error", () => reject());
    c.stdout!.on("error", () => reject());
    c.stdout!.on("data", (chunk: Buffer) => {
      if (this.#closed) return;
      try {
        // Bound the raw receive buffer as well as each complete frame.
        check(this.#pending.length + chunk.length <= 131072);
        this.#pending = Buffer.concat([this.#pending, chunk]);
        let end: number;
        while ((end = this.#pending.indexOf(10)) !== -1) {
          const frame = this.#pending.subarray(0, end);
          this.#pending = this.#pending.subarray(end + 1);
          check(this.#admit());
          const message = parseStrictJson(frame, { maxBytes: 65536, maxDepth: 24, maxNodes: 8192 });
          this.onmessage?.(message as JSONRPCMessage);
        }
        check(this.#pending.length <= 65536);
        clearTimeout(this.#frameTimer);
        if (this.#pending.length) this.#frameTimer = setTimeout(reject, 5000);
      } catch {
        reject();
      }
    });
    c.stdout!.on("end", () => { if (this.#pending.length) reject(); });
    await new Promise<void>((resolve, rejectSpawn) => { c.once("spawn", () => resolve()); c.once("error", rejectSpawn); });
  }

  async send(message: JSONRPCMessage): Promise<void> {
    check(this.#child !== undefined && !this.#closed, "UPSTREAM_UNAVAILABLE");
    const bytes = Buffer.from(JSON.stringify(message) + "\n");
    check(bytes.length <= 65536, "UPSTREAM_REQUEST_LIMIT");
    await new Promise<void>((resolve, reject) => this.#child!.stdin!.write(bytes, (error) => (error ? reject(error) : resolve())));
  }

  async close(): Promise<void> {
    if (this.#child === undefined || this.#closed) return;
    this.#closed = true;
    clearTimeout(this.#frameTimer);
    this.#child.stdin!.end();
    this.#child.kill("SIGTERM");
    const timer = setTimeout(() => this.#child?.kill("SIGKILL"), 1000);
    timer.unref();
    await this.#exited;
    clearTimeout(timer);
  }
}
