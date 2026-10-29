/**
 * Client-facing stdin guard: every inbound frame is bounded and parsed as
 * strict JSON (no duplicate keys, no invalid UTF-8) before the MCP SDK sees it.
 * An unfinished frame older than five seconds, an oversized frame or a flood of
 * more than 1,024 messages within any 60 seconds terminates the host process;
 * the transport never interprets partially validated bytes. The message bound is
 * a rate, not a lifetime total (GATEWAY-RATE-01): a long session of ordinary
 * calls never reaches it.
 */
import { Transform, type Readable } from "node:stream";
import { parseStrictJson } from "./strict-json.ts";

/** `maxMessages` frames at most in any sliding window of `windowMs` (defaults 1,024 and 60,000); `now` is for tests. */
export type GuardOptions = Readonly<{ maxFrameBytes?: number; maxMessages?: number; windowMs?: number; now?: () => number; frameTimeoutMs?: number; onRefused?: (reason: string) => void }>;

/** At most `max` admissions in any window of `windowMs`: keeps the times of the last `max` admitted, oldest first. */
export function rateWindow(max: number, windowMs: number, now: () => number = Date.now): () => boolean {
  const times: number[] = [];
  return () => {
    const t = now();
    while (times.length > 0 && times[0]! <= t - windowMs) times.shift();
    if (times.length >= max) return false;
    times.push(t);
    return true;
  };
}

export function guardedInput(source: Readable, options: GuardOptions = {}): Transform {
  const maxFrame = options.maxFrameBytes ?? 16384, maxMessages = options.maxMessages ?? 1024, deadline = options.frameTimeoutMs ?? 5000;
  const refused = options.onRefused ?? ((reason: string): void => { process.stderr.write(reason + "\n"); process.exit(2); });
  const admit = rateWindow(maxMessages, options.windowMs ?? 60_000, options.now ?? Date.now);
  let pending = Buffer.alloc(0), timer: NodeJS.Timeout | undefined;
  const input = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      try {
        pending = Buffer.concat([pending, chunk]);
        if (pending.length > maxFrame * 4) throw new Error("INPUT_LIMIT");
        let end: number;
        while ((end = pending.indexOf(10)) !== -1) {
          const frame = pending.subarray(0, end);
          pending = pending.subarray(end + 1);
          if (!admit()) throw new Error("MESSAGE_RATE_LIMIT");
          parseStrictJson(frame, { maxBytes: maxFrame, maxDepth: 12, maxNodes: 2048 });
          this.push(Buffer.concat([frame, Buffer.from("\n")]));
        }
        if (pending.length > maxFrame) throw new Error("FRAME_LIMIT");
        clearTimeout(timer);
        if (pending.length) timer = setTimeout(() => refused("FRAME_TIMEOUT"), deadline);
        callback();
      } catch {
        callback(new Error("INVALID_FRAME"));
      }
    },
    flush(callback) {
      clearTimeout(timer);
      callback(pending.length ? new Error("INCOMPLETE_FRAME") : undefined);
    },
  });
  input.on("error", () => refused("INPUT_REFUSED"));
  source.pipe(input);
  return input;
}
