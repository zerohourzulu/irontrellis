/**
 * The command signer: a generic external program (like git's `gpg.program`)
 * signs for a key reference whose `signer` is
 * `{ kind: "command", argv: ["/abs/program", …], timeoutMs?, env?, passEnv? }`.
 *
 * Protocol (docs/CUSTODY.md §6): the program is started without a shell
 * (`argv[0]` must be an absolute path), with a minimal environment (PATH, HOME,
 * the platform essentials, plus `passEnv` names and `env` values), and gets one
 * JSON document on stdin:
 *
 *   {"version":"irontrellis-sign-request/1","keyId":"owner:1","scheme":"ed25519",
 *    "publicKey":"0x…","message":"<base64 of the 32 bytes>","purpose":"control-authorization","historyId":"0x…"}
 *
 * It answers on stdout with `{"signature":"<base64 of the 64-byte Ed25519 signature>"}` and exit status 0. Any other
 * exit status is a failure; stdout `{"error":{"code":"KEY_UNAVAILABLE","message":"…"}}` marks a key the program does
 * not hold (KEY_UNAVAILABLE), anything else is SIGNER_FAILED. The signature is verified locally before use
 * (reference.ts), so a wrong one is SIGNER_FAILED and never written.
 */
import { spawn } from "node:child_process";
import { parse as parsePath } from "node:path";
import { EngineError } from "../errors.ts";
import { isFullyQualifiedPath } from "../platform.ts";
import type { ReferencedKey, SignContext, SignerBackend, SignerSpec } from "./registry.ts";

export const SIGN_REQUEST_VERSION = "irontrellis-sign-request/1";
export const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;
const MAX_STDOUT = 64 * 1024;
const MAX_STDERR = 8 * 1024;
/**
 * What every command signer gets from this process's environment, besides `passEnv`. PATH is NOT among them: the child gets `FIXED_PATH` (or the reference's `path`), never the caller's, which may name a directory
 * the agent can write.
 */
const BASE_ENV: readonly string[] = Object.freeze(["HOME", "LANG", "TMPDIR", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PATHEXT", "COMSPEC"]);
/** The PATH a command signer runs with unless its reference sets `path` (POSIX; on Windows the system directories). */
export const COMMAND_SIGNER_PATH = "/usr/bin:/bin";
/** Arguments that name a file: they must be absolute (the child runs in the file-system root, and must not resolve anything against a caller's directory). */
const SCRIPT_EXTENSION = /\.(?:m?js|cjs|ts|mts|py|sh|bash|rb|pl|php|ps1|cmd|bat|exe|jar|json|pem|key)$/i;
/**
 * A relative file argument: starts with `.` or `~`, or ends in a script or key-file extension. Other arguments (resource
 * names such as `projects/…/cryptoKeyVersions/1`, ARNs, URLs, words) pass as they are; the program runs in the
 * file-system root, so nothing resolves against the caller's directory either way.
 */
const looksLikePath = (value: string): boolean => SCRIPT_EXTENSION.test(value) || value.startsWith(".") || value.startsWith("~");
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

const failed = (message: string, detail: Readonly<Record<string, unknown>>): EngineError => new EngineError("SIGNER_FAILED", message, { signer: "command", ...detail });

const parseSpec = (spec: Readonly<Record<string, unknown>>): SignerSpec => {
  const allowed = ["kind", "argv", "timeoutMs", "env", "passEnv", "path"];
  const extra = Object.keys(spec).filter((key) => !allowed.includes(key));
  if (extra.length > 0) throw new Error(`unknown command signer field(s): ${extra.join(", ")} (allowed: argv, timeoutMs, env, passEnv, path)`);
  const argv = spec.argv;
  if (!Array.isArray(argv) || argv.length === 0 || argv.length > 64 || !argv.every((a) => typeof a === "string" && a.length <= 4096 && !a.includes("\0"))) {
    throw new Error("command signer: argv must be a list of 1..64 strings (the program and its arguments; no shell is used)");
  }
  if (!isFullyQualifiedPath(argv[0] as string)) throw new Error(`command signer: argv[0] must be an absolute path to the program (got ${JSON.stringify(argv[0])}); PATH is not searched`);
  // Every other argument that names a file (it starts with . or ~, or has a script/key extension), also as the value of
  // --option=value, must be absolute.
  for (const arg of (argv as string[]).slice(1)) {
    const value = arg.startsWith("-") && arg.includes("=") ? arg.slice(arg.indexOf("=") + 1) : arg.startsWith("-") ? "" : arg;
    if (value !== "" && looksLikePath(value) && !isFullyQualifiedPath(value) && !/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      throw new Error(`command signer: argument ${JSON.stringify(arg)} names a file by a relative path; every file argument must be absolute (the program runs in the file-system root, never in the caller's directory)`);
    }
  }
  if (spec.timeoutMs !== undefined && !(Number.isSafeInteger(spec.timeoutMs) && (spec.timeoutMs as number) >= 100 && (spec.timeoutMs as number) <= 600_000)) {
    throw new Error("command signer: timeoutMs must be an integer from 100 to 600000");
  }
  const env = spec.env;
  if (env !== undefined && (env === null || typeof env !== "object" || Array.isArray(env) || Object.entries(env).some(([k, v]) => !ENV_NAME.test(k) || typeof v !== "string" || v.includes("\0")))) {
    throw new Error("command signer: env must map variable names to string values");
  }
  const passEnv = spec.passEnv;
  if (passEnv !== undefined && (!Array.isArray(passEnv) || passEnv.length > 64 || !passEnv.every((name) => typeof name === "string" && ENV_NAME.test(name)))) {
    throw new Error("command signer: passEnv must be a list of variable names");
  }
  const pathNames = [...(Array.isArray(passEnv) ? passEnv as string[] : []), ...(env !== undefined && env !== null && typeof env === "object" ? Object.keys(env) : [])].filter((name) => name.toUpperCase() === "PATH");
  if (pathNames.length > 0) throw new Error("command signer: PATH is not taken from passEnv or env; set the reference's path field (absolute directories) if the program needs more than /usr/bin:/bin");
  const path = spec.path;
  const sep = process.platform === "win32" ? ";" : ":";
  if (path !== undefined && (typeof path !== "string" || path.length === 0 || path.length > 4096 || !path.split(sep).every((dir) => isFullyQualifiedPath(dir)))) {
    throw new Error(`command signer: path must be a ${sep}-separated list of absolute directories`);
  }
  return Object.freeze({
    kind: "command", argv: Object.freeze([...(argv as string[])]),
    ...(spec.timeoutMs === undefined ? {} : { timeoutMs: spec.timeoutMs as number }),
    ...(env === undefined ? {} : { env: Object.freeze({ ...(env as Record<string, string>) }) }),
    ...(passEnv === undefined ? {} : { passEnv: Object.freeze([...(passEnv as string[])]) }),
    ...(path === undefined ? {} : { path: path as string }),
  });
};

/** The child's environment: the base names and `passEnv` copied from this process, then `env`. Nothing else. */
export function commandEnvironment(spec: SignerSpec, from: Readonly<Record<string, string | undefined>> = process.env): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of [...BASE_ENV, ...((spec.passEnv as readonly string[] | undefined) ?? [])]) {
    const value = from[name];
    if (value !== undefined) out[name] = value;
  }
  Object.assign(out, (spec.env as Readonly<Record<string, string>> | undefined) ?? {});
  const root = from.SystemRoot ?? from.SYSTEMROOT ?? "C:\\Windows";
  out.PATH = typeof spec.path === "string" ? spec.path : process.platform === "win32" ? `${root}\\System32;${root}` : COMMAND_SIGNER_PATH;
  return out;
}

/**
 * Redacts what may be a credential in a signer's stderr or error message (an error may reach the agent's context through a
 * hook, and a cloud CLI's output may carry secrets). In order:
 * - "Authorization: <scheme> <credential>" keeps the scheme's name (Bearer, Basic, Token, Negotiate, Digest) and loses the
 *   credential ("Authorization: Bearer s.x" becomes "Authorization: Bearer [redacted]");
 * - the value after token, secret, password, passwd, authorization, bearer, api_key, credential (AWS4's Credential=),
 *   signature, session or basic, with any delimiter: whitespace, "=" or ":", spaces around it allowed;
 * - after "key": always a `key=`/`key:` value; a plain following word only with `looseKey` (stderr), so a signer's
 *   "no such key version" stays readable;
 * - runs of 32 or more base64, hex or JWT-like characters.
 */
function redactSecrets(text: string, looseKey: boolean): string {
  const SCHEMES = "bearer|basic|token|negotiate|digest";
  // A delimiter is whitespace, "=" or ":", with optional spaces around it ("token = x", "Bearer: x", "Bearer=x").
  const DELIM = "(\\s*[:=]\\s*|\\s+)";
  return text
    // "Authorization: <scheme> <credential>": the scheme's name stays, its credential goes.
    .replace(new RegExp(`\\b(authorization)\\b${DELIM}(${SCHEMES})\\b${DELIM}(?!\\[redacted\\])[^\\s,;]+`, "gi"), "$1$2$3$4[redacted]")
    // Every secret name, with any delimiter; a scheme word after "authorization" was handled above.
    .replace(new RegExp(`\\b(token|secret|password|passwd|authorization|bearer|api[_-]?key|credential|signature|session|basic)\\b${DELIM}(?!\\[redacted\\])(?!(?:${SCHEMES})\\b${DELIM}\\[redacted\\])[^\\s,;]+`, "gi"), "$1$2[redacted]")
    .replace(looseKey ? /\b(key)\b(\s*[:=]\s*|\s+)(?!\[redacted\])\S+/gi : /\b(key)\b(\s*[:=]\s*)(?!\[redacted\])\S+/gi, "$1$2[redacted]")
    .replace(/[A-Za-z0-9+/_=.-]{32,}/g, "[redacted]");
}
/** The signer's own error message for an error message: control characters removed, redacted (redactSecrets), at most 240 characters. */
export function signerMessage(message: string): string {
  let text = message.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, " ").replace(/\s+/g, " ").trim();
  if (text === "") return "";
  text = redactSecrets(text, false);
  if (text.length > 240) text = `${text.slice(0, 237)}...`;
  return `: ${text}`;
}
/**
 * The last lines of a signer's stderr for an error message: at most 3 lines and 240 characters, control characters and
 * anything that looks like a credential (redactSecrets, with the looser rule after "key") replaced: an
 * error may reach the agent's context through a hook, and a cloud CLI's stderr may carry secrets.
 */
export function stderrTail(stderr: Buffer): string {
  const text = stderr.toString("utf8").replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, " ").trim();
  if (text === "") return "";
  let tail = text.split("\n").map((line) => line.trim()).filter((line) => line !== "").slice(-3).join(" | ");
  tail = redactSecrets(tail, true);
  if (tail.length > 240) tail = `${tail.slice(0, 237)}...`;
  return `: ${tail}`;
}

const decodeBase64 = (text: string): Buffer | undefined => (/^[A-Za-z0-9+/_-]+={0,2}$/.test(text) ? Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/"), "base64") : undefined);

export const COMMAND_BACKEND: SignerBackend = Object.freeze({
  kind: "command",
  parse: parseSpec,
  describe(spec: SignerSpec): string {
    return `command ${(spec.argv as readonly string[]).join(" ")}`;
  },
  identity(spec: SignerSpec): string {
    return JSON.stringify(spec.argv);
  },
  sign(spec: SignerSpec, key: ReferencedKey, message: Uint8Array, context: SignContext): Promise<Uint8Array> {
    const argv = spec.argv as readonly string[];
    const timeoutMs = typeof spec.timeoutMs === "number" ? spec.timeoutMs : DEFAULT_COMMAND_TIMEOUT_MS;
    const program = argv[0]!;
    const request = `${JSON.stringify({
      version: SIGN_REQUEST_VERSION, keyId: key.keyId, scheme: key.scheme, publicKey: key.publicKey, message: Buffer.from(message).toString("base64"),
      purpose: context.purpose ?? "unspecified", ...(context.historyId === undefined ? {} : { historyId: context.historyId }),
    })}\n`;
    return new Promise((resolve, reject) => {
      let settled = false;
      let timer: NodeJS.Timeout | undefined;
      const finish = (error: Error | undefined, value?: Uint8Array): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error !== undefined) reject(error); else resolve(value!);
      };
      let child: ReturnType<typeof spawn>;
      try {
        // cwd: the file-system root (never the caller's directory, which may be the agent's project); detached on POSIX so
        // that a timeout kills the whole process group, grandchildren included.
        child = spawn(program, argv.slice(1), { shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"], env: commandEnvironment(spec), cwd: parsePath(program).root || "/", detached: process.platform !== "win32" });
      } catch (error) {
        finish(failed(`the command signer ${program} could not be started: ${error instanceof Error ? error.message : String(error)}`, { program, reason: "SPAWN" }));
        return;
      }
      const killTree = (): void => {
        if (process.platform === "win32") {
          if (child.pid !== undefined) { try { spawn("taskkill", ["/T", "/F", "/PID", String(child.pid)], { windowsHide: true, stdio: "ignore" }).on("error", () => {}); } catch { /* best effort */ } }
          try { child.kill("SIGKILL"); } catch { /* gone */ }
        } else if (child.pid !== undefined) {
          try { process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch { /* gone */ } }
        }
        for (const stream of [child.stdin, child.stdout, child.stderr]) { try { stream?.destroy(); } catch { /* closed */ } }
      };
      timer = setTimeout(() => {
        killTree();
        finish(failed(`the command signer ${program} did not answer within ${timeoutMs} ms and was stopped; nothing was signed`, { program, reason: "TIMEOUT", timeoutMs }));
      }, timeoutMs);
      let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), overflow = false;
      child.stdout!.on("data", (chunk: Buffer) => {
        if (stdout.length + chunk.length > MAX_STDOUT) { overflow = true; killTree(); return; }
        stdout = Buffer.concat([stdout, chunk]);
      });
      child.stderr!.on("data", (chunk: Buffer) => { if (stderr.length < MAX_STDERR) stderr = Buffer.concat([stderr, chunk]).subarray(0, MAX_STDERR); });
      child.on("error", (error: NodeJS.ErrnoException) => {
        finish(failed(`the command signer ${program} could not be started: ${error.code ?? error.message}`, { program, reason: "SPAWN", cause: error.code ?? error.message }));
      });
      child.stdin!.on("error", () => { /* the program may exit without reading stdin; its exit status says what happened */ });
      child.stdin!.end(request);
      child.on("close", (code, signal) => {
        const tail = stderrTail(stderr);
        if (overflow) { finish(failed(`the command signer ${program} wrote more than ${MAX_STDOUT} bytes`, { program, reason: "MALFORMED" })); return; }
        let answer: unknown;
        try { answer = JSON.parse(stdout.toString("utf8")); } catch { answer = undefined; }
        const record = answer !== null && typeof answer === "object" && !Array.isArray(answer) ? answer as Record<string, unknown> : undefined;
        if (code !== 0) {
          const error = record?.error as { code?: unknown; message?: unknown } | undefined;
          if (error !== undefined && error !== null && error.code === "KEY_UNAVAILABLE") {
            finish(new EngineError("KEY_UNAVAILABLE", `the command signer ${program} does not hold owner key ${key.keyId}${typeof error.message === "string" ? signerMessage(error.message) : ""}`, { signer: "command", program, keyId: key.keyId, reason: "KEY_NOT_HELD" }));
            return;
          }
          const why = signal !== null ? `was killed by ${signal}` : `exited with status ${code}`;
          // The signer's own message is redacted and bounded as its stderr is: it can carry a token or control characters too.
          const said = error !== undefined && error !== null && typeof error.message === "string" ? signerMessage(error.message) : tail;
          finish(failed(`the command signer ${program} ${why}${said}; nothing was signed`, { program, reason: "EXIT", exitCode: code, ...(signal === null ? {} : { signal }) }));
          return;
        }
        const signature = typeof record?.signature === "string" ? decodeBase64(record.signature) : undefined;
        if (signature === undefined) {
          finish(failed(`the command signer ${program} did not print {"signature":"<base64>"} on stdout${tail}`, { program, reason: "MALFORMED" }));
          return;
        }
        if (record!.publicKey !== undefined && (typeof record!.publicKey !== "string" || record!.publicKey.toLowerCase() !== key.publicKey.toLowerCase())) {
          finish(new EngineError("KEY_UNAVAILABLE", `the command signer ${program} answered for another key (${String(record!.publicKey)}), not owner key ${key.keyId} (${key.publicKey})`, { signer: "command", program, keyId: key.keyId, reason: "PUBLIC_KEY_MISMATCH" }));
          return;
        }
        if (signature.length !== 64) { finish(failed(`the command signer ${program} returned ${signature.length} bytes; an Ed25519 signature has 64`, { program, reason: "MALFORMED" })); return; }
        finish(undefined, new Uint8Array(signature));
      });
    });
  },
});
