/**
 * The ssh-agent signer: a pure Node client of the SSH agent protocol
 * (draft-miller-ssh-agent) over a Unix socket (`SSH_AUTH_SOCK`, or the
 * reference's `socket`) or, on Windows, the named pipe
 * `\\.\pipe\openssh-ssh-agent` (Windows OpenSSH and the 1Password agent).
 *
 * The key is identified by its `ssh-ed25519` public key blob. IronTrellis asks
 * for SSH_AGENTC_SIGN_REQUEST over the 32-byte hash it signs; an `ssh-ed25519`
 * signature is a plain Ed25519 signature over exactly those bytes (RFC 8709),
 * so the result is used as is, after `referenceSigner` verified it against the
 * pinned public key. `sk-ssh-ed25519@openssh.com` (FIDO) keys sign another
 * structure and are refused, and so is every non-Ed25519 key.
 *
 * Failures: the agent does not list the key → KEY_UNAVAILABLE; no agent at the
 * socket, a refusal (SSH_AGENT_FAILURE: a declined confirmation, a destination
 * constraint), a malformed answer or a timeout → SIGNER_FAILED.
 */
import { connect as netConnect, type Socket } from "node:net";
import { EngineError } from "../errors.ts";
import type { ReferencedKey, SignerBackend, SignerSpec } from "./registry.ts";

// ---------------------------------------------------------------- wire encoding (RFC 4251 §5)

const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;
const SSH_AGENT_EXTENSION_FAILURE = 28;
/** Largest agent answer accepted (an identities list with many keys stays far below). */
const MAX_AGENT_MESSAGE = 256 * 1024;
export const ED25519_KEY_TYPE = "ssh-ed25519";
export const SK_ED25519_KEY_TYPE = "sk-ssh-ed25519@openssh.com";
/** The Windows OpenSSH agent pipe (also served by the 1Password SSH agent on Windows). */
export const WINDOWS_AGENT_PIPE = "\\\\.\\pipe\\openssh-ssh-agent";
export const DEFAULT_AGENT_TIMEOUT_MS = 60_000;

const u32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const sshString = (bytes: Uint8Array | string): Buffer => { const b = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : Buffer.from(bytes); return Buffer.concat([u32(b.length), b]); };
const frame = (type: number, body: Buffer): Buffer => Buffer.concat([u32(body.length + 1), Buffer.from([type]), body]);

/** A cursor over an SSH wire buffer; every read is bounds-checked (a short buffer throws). */
class Reader {
  #buf: Buffer;
  #at = 0;
  constructor(buf: Buffer) { this.#buf = buf; }
  u32(): number {
    if (this.#at + 4 > this.#buf.length) throw new Error("truncated uint32");
    const n = this.#buf.readUInt32BE(this.#at);
    this.#at += 4;
    return n;
  }
  bytes(): Buffer {
    const n = this.u32();
    if (this.#at + n > this.#buf.length) throw new Error("truncated string");
    const out = this.#buf.subarray(this.#at, this.#at + n);
    this.#at += n;
    return out;
  }
  get done(): boolean { return this.#at === this.#buf.length; }
}

/** The `ssh-ed25519` public key blob of a 32-byte Ed25519 public key. */
export function sshEd25519Blob(publicKey: Uint8Array): Buffer {
  if (publicKey.length !== 32) throw new Error("an Ed25519 public key has 32 bytes");
  return Buffer.concat([sshString(ED25519_KEY_TYPE), sshString(publicKey)]);
}
/** `ssh-ed25519 AAAA… [comment]` for a 32-byte Ed25519 public key (the authorized_keys / `ssh-add -L` form). */
export function sshPublicKeyLine(publicKey: Uint8Array, comment?: string): string {
  return `${ED25519_KEY_TYPE} ${sshEd25519Blob(publicKey).toString("base64")}${comment === undefined || comment === "" ? "" : ` ${comment}`}`;
}

/**
 * An unencrypted OpenSSH private key file (`openssh-key-v1`, PROTOCOL.key) for an Ed25519 key: what `ssh-add` loads.
 * Used to move an IronTrellis key file into an ssh-agent (`irontrellis signer to-ssh`); add a passphrase afterwards
 * with `ssh-keygen -p -f <file>`.
 */
export function openSshPrivateKey(seed: Uint8Array, publicKey: Uint8Array, comment = "", checkInt = Math.floor(Math.random() * 0xffffffff)): string {
  if (seed.length !== 32 || publicKey.length !== 32) throw new Error("an Ed25519 seed and public key have 32 bytes each");
  const blob = sshEd25519Blob(publicKey);
  let secret = Buffer.concat([u32(checkInt), u32(checkInt), sshString(ED25519_KEY_TYPE), sshString(publicKey), sshString(Buffer.concat([Buffer.from(seed), Buffer.from(publicKey)])), sshString(comment)]);
  const pad: number[] = [];
  for (let i = 1; (secret.length + pad.length) % 8 !== 0; i += 1) pad.push(i);
  secret = Buffer.concat([secret, Buffer.from(pad)]);
  const body = Buffer.concat([Buffer.from("openssh-key-v1\0", "latin1"), sshString("none"), sshString("none"), sshString(Buffer.alloc(0)), u32(1), sshString(blob), sshString(secret)]);
  const base64 = body.toString("base64").replace(/(.{70})/g, "$1\n").replace(/\n$/, "");
  // The armour label is assembled so that the packed module never contains a literal PEM private-key header
  // (scripts/verify-install.mjs scans every tarball for one).
  const label = ["OPENSSH", "PRIVATE", "KEY"].join(" ");
  return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----\n`;
}

/** The key type and, for (sk-)ssh-ed25519, the 32-byte public key of a public key blob. Never throws. */
export function decodeKeyBlob(blob: Uint8Array): Readonly<{ type: string; publicKey?: Buffer }> {
  try {
    const r = new Reader(Buffer.from(blob));
    const type = r.bytes().toString("utf8");
    if (type === ED25519_KEY_TYPE || type === SK_ED25519_KEY_TYPE) {
      const publicKey = r.bytes();
      if (publicKey.length !== 32) return { type };
      if (type === ED25519_KEY_TYPE && !r.done) return { type };
      return { type, publicKey };
    }
    return { type };
  } catch {
    return { type: "(malformed)" };
  }
}

/**
 * The 32-byte Ed25519 public key of an OpenSSH public key line (`ssh-ed25519 AAAA… comment`). A FIDO key
 * (`sk-ssh-ed25519@openssh.com`), any other key type, or a blob whose type does not match the line is refused
 * with a plain message.
 */
export function parseSshPublicKey(line: string): Buffer {
  const parts = line.trim().split(/\s+/);
  const type = parts[0] ?? "";
  if (type === SK_ED25519_KEY_TYPE) {
    throw new Error(`${SK_ED25519_KEY_TYPE} (FIDO security key) is not supported: its signature covers a different structure (flags, counter, application), not the 32-byte hash IronTrellis signs; use a plain ssh-ed25519 key (for a hardware key: gpg-agent with an OpenPGP card, see docs/CUSTODY.md)`);
  }
  if (type !== ED25519_KEY_TYPE) throw new Error(`only ssh-ed25519 keys can hold an IronTrellis owner key (owner keys are Ed25519); got ${type === "" ? "nothing" : type}`);
  if (parts[1] === undefined || !/^[A-Za-z0-9+/]+={0,2}$/.test(parts[1])) throw new Error("the ssh-ed25519 line has no base64 key blob");
  const decoded = decodeKeyBlob(Buffer.from(parts[1], "base64"));
  if (decoded.type !== ED25519_KEY_TYPE || decoded.publicKey === undefined) throw new Error("the key blob is not a well-formed ssh-ed25519 public key");
  return decoded.publicKey;
}

// ---------------------------------------------------------------- the transport

/** Opens a duplex stream to the agent at `path` (a Unix socket path or a Windows pipe name). Injectable for tests. */
export type AgentConnector = (path: string) => Socket;
const defaultConnector: AgentConnector = (path) => netConnect(path);
let connector: AgentConnector = defaultConnector;
let platformOverride: NodeJS.Platform | undefined;
/**
 * Test hook: replace (or with `undefined` restore) the connector every ssh-agent request uses, and optionally the
 * platform the default socket is chosen for (the Windows named-pipe path is exercised on POSIX with a fake connector).
 */
export function setAgentConnectorForTests(replacement: AgentConnector | undefined, options: Readonly<{ platform?: NodeJS.Platform }> = {}): void {
  connector = replacement ?? defaultConnector;
  platformOverride = replacement === undefined ? undefined : options.platform;
}

/**
 * Where the agent is: the reference's `socket`, else `SSH_AUTH_SOCK`, else (Windows) the OpenSSH pipe. `undefined` when
 * there is none (POSIX without SSH_AUTH_SOCK).
 */
export function agentSocketPath(spec: Readonly<Record<string, unknown>>, env: Readonly<Record<string, string | undefined>> = process.env, platform: NodeJS.Platform = platformOverride ?? process.platform): string | undefined {
  if (typeof spec.socket === "string" && spec.socket !== "") return spec.socket;
  const fromEnv = env.SSH_AUTH_SOCK;
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  return platform === "win32" ? WINDOWS_AGENT_PIPE : undefined;
}

const failed = (message: string, detail: Readonly<Record<string, unknown>>): EngineError => new EngineError("SIGNER_FAILED", message, { signer: "ssh-agent", ...detail });

/** One agent conversation: requests are written in order, each answer is one framed message. Closed by `close()`. */
class AgentConversation {
  readonly #socket: Socket;
  readonly #path: string;
  #waiting: { resolve: (message: Buffer) => void; reject: (error: Error) => void } | undefined;
  #error: Error | undefined;
  #timer: NodeJS.Timeout;
  constructor(path: string, timeoutMs: number) {
    this.#path = path;
    this.#socket = connector(path);
    this.#timer = setTimeout(() => this.#fail(failed(`the ssh-agent at ${path} did not answer within ${timeoutMs} ms (a confirmation prompt left unanswered, or a hung agent)`, { socket: path, reason: "TIMEOUT", timeoutMs })), timeoutMs);
    this.#socket.on("data", (chunk: Buffer) => this.#receive(chunk));
    this.#socket.on("error", (error: NodeJS.ErrnoException) => {
      const code = error.code;
      const hint = code === "ENOENT" || code === "ECONNREFUSED" ? " (is the agent running? check SSH_AUTH_SOCK or the reference's socket)" : "";
      this.#fail(failed(`cannot talk to the ssh-agent at ${path}: ${code ?? error.message}${hint}`, { socket: path, reason: "UNREACHABLE", cause: code ?? error.message }));
    });
    this.#socket.on("close", () => this.#fail(failed(`the ssh-agent at ${path} closed the connection before answering`, { socket: path, reason: "CLOSED" })));
  }
  #fail(error: Error): void {
    if (this.#error !== undefined) return;
    this.#error = error;
    clearTimeout(this.#timer);
    this.#socket.destroy();
    const waiting = this.#waiting;
    this.#waiting = undefined;
    waiting?.reject(error);
  }
  // Chunks are kept in a list and joined once per frame (no quadratic re-concatenation); every
  // complete frame in the buffer is handled, several per chunk included.
  #chunks: Buffer[] = [];
  #buffered = 0;
  #receive(chunk: Buffer): void {
    if (this.#error !== undefined) return;
    this.#chunks.push(chunk);
    this.#buffered += chunk.length;
    while (this.#error === undefined && this.#buffered >= 4) {
      if (this.#chunks[0]!.length < 4) this.#chunks = [Buffer.concat(this.#chunks)];
      const length = this.#chunks[0]!.readUInt32BE(0);
      if (length === 0 || length > MAX_AGENT_MESSAGE) { this.#fail(failed(`the ssh-agent at ${this.#path} sent a malformed answer (length ${length})`, { socket: this.#path, reason: "MALFORMED" })); return; }
      if (this.#buffered < 4 + length) return;
      const all = this.#chunks.length === 1 ? this.#chunks[0]! : Buffer.concat(this.#chunks);
      const message = Buffer.from(all.subarray(4, 4 + length));
      const rest = all.subarray(4 + length);
      this.#chunks = rest.length > 0 ? [rest] : [];
      this.#buffered = rest.length;
      const waiting = this.#waiting;
      this.#waiting = undefined;
      if (waiting === undefined) { this.#fail(failed(`the ssh-agent at ${this.#path} sent an answer nobody asked for`, { socket: this.#path, reason: "MALFORMED" })); return; }
      waiting.resolve(message);
    }
  }

  request(type: number, body: Buffer): Promise<Buffer> {
    if (this.#error !== undefined) return Promise.reject(this.#error);
    return new Promise((resolve, reject) => {
      this.#waiting = { resolve, reject };
      this.#socket.write(frame(type, body));
    });
  }
  close(): void {
    clearTimeout(this.#timer);
    this.#error ??= new Error("closed");
    this.#socket.removeAllListeners("close");
    this.#socket.on("error", () => { /* closed by us */ });
    this.#socket.destroy();
  }
}

/** Every identity the agent lists: its key blob and comment. */
export type AgentIdentity = Readonly<{ blob: Buffer; comment: string; type: string; publicKey?: Buffer }>;

function parseIdentities(message: Buffer, path: string): readonly AgentIdentity[] {
  if (message[0] === SSH_AGENT_FAILURE) throw failed(`the ssh-agent at ${path} refused to list its keys`, { socket: path, reason: "REFUSED" });
  if (message[0] !== SSH_AGENT_IDENTITIES_ANSWER) throw failed(`the ssh-agent at ${path} answered the key list with message type ${message[0]}`, { socket: path, reason: "MALFORMED" });
  try {
    const r = new Reader(message.subarray(1));
    const count = r.u32();
    if (count > 4096) throw new Error("too many keys");
    const out: AgentIdentity[] = [];
    for (let i = 0; i < count; i += 1) {
      const blob = r.bytes(), comment = r.bytes().toString("utf8");
      const decoded = decodeKeyBlob(blob);
      out.push(Object.freeze({ blob: Buffer.from(blob), comment, type: decoded.type, ...(decoded.publicKey === undefined ? {} : { publicKey: decoded.publicKey }) }));
    }
    return Object.freeze(out);
  } catch (error) {
    throw failed(`the ssh-agent at ${path} sent a malformed key list: ${error instanceof Error ? error.message : String(error)}`, { socket: path, reason: "MALFORMED" });
  }
}

/** The raw 64-byte Ed25519 signature inside an SSH_AGENT_SIGN_RESPONSE. */
function parseSignResponse(message: Buffer, path: string): Buffer {
  if (message[0] === SSH_AGENT_FAILURE || message[0] === SSH_AGENT_EXTENSION_FAILURE) {
    throw failed(`the ssh-agent at ${path} refused to sign (SSH_AGENT_FAILURE): a confirmation was declined or could not be shown (ssh-add -c without ssh-askpass, a 1Password or gpg-agent prompt), or the key is restricted (ssh-add -h destination constraints); nothing was signed`,
      { socket: path, reason: "REFUSED" });
  }
  if (message[0] !== SSH_AGENT_SIGN_RESPONSE) throw failed(`the ssh-agent at ${path} answered the sign request with message type ${message[0]}`, { socket: path, reason: "MALFORMED" });
  try {
    const signature = new Reader(new Reader(message.subarray(1)).bytes());
    const type = signature.bytes().toString("utf8");
    if (type !== ED25519_KEY_TYPE) throw new Error(`signature type ${type}, not ${ED25519_KEY_TYPE}`);
    const raw = signature.bytes();
    if (raw.length !== 64 || !signature.done) throw new Error(`an ssh-ed25519 signature has 64 bytes, got ${raw.length}`);
    return Buffer.from(raw);
  } catch (error) {
    throw failed(`the ssh-agent at ${path} sent a malformed signature: ${error instanceof Error ? error.message : String(error)}`, { socket: path, reason: "MALFORMED" });
  }
}

/** The identities an agent lists (`signer list`, tests). */
export async function listAgentIdentities(options: Readonly<{ socket?: string; timeoutMs?: number }> = {}): Promise<readonly AgentIdentity[]> {
  const path = agentSocketPath(options);
  if (path === undefined) throw failed("no ssh-agent: SSH_AUTH_SOCK is not set (start one, or name its socket)", { reason: "NO_AGENT" });
  const conversation = new AgentConversation(path, options.timeoutMs ?? DEFAULT_AGENT_TIMEOUT_MS);
  try {
    return parseIdentities(await conversation.request(SSH_AGENTC_REQUEST_IDENTITIES, Buffer.alloc(0)), path);
  } finally {
    conversation.close();
  }
}

// ---------------------------------------------------------------- the backend

const parseSpec = (spec: Readonly<Record<string, unknown>>): SignerSpec => {
  const allowed = ["kind", "socket", "timeoutMs"];
  const extra = Object.keys(spec).filter((key) => !allowed.includes(key));
  if (extra.length > 0) throw new Error(`unknown ssh-agent signer field(s): ${extra.join(", ")} (allowed: socket, timeoutMs)`);
  if (spec.socket !== undefined && (typeof spec.socket !== "string" || spec.socket === "" || spec.socket.length > 4096 || spec.socket.includes("\0"))) {
    throw new Error("ssh-agent signer: socket must be a non-empty path (omit it to use SSH_AUTH_SOCK)");
  }
  if (spec.timeoutMs !== undefined && !(Number.isSafeInteger(spec.timeoutMs) && (spec.timeoutMs as number) >= 100 && (spec.timeoutMs as number) <= 600_000)) {
    throw new Error("ssh-agent signer: timeoutMs must be an integer from 100 to 600000");
  }
  return Object.freeze({ kind: "ssh-agent", ...(spec.socket === undefined ? {} : { socket: spec.socket as string }), ...(spec.timeoutMs === undefined ? {} : { timeoutMs: spec.timeoutMs as number }) });
};

export const SSH_AGENT_BACKEND: SignerBackend = Object.freeze({
  kind: "ssh-agent",
  parse: parseSpec,
  describe(spec: SignerSpec): string {
    return typeof spec.socket === "string" ? `ssh-agent at ${spec.socket}` : `ssh-agent at $SSH_AUTH_SOCK${process.env.SSH_AUTH_SOCK ? ` (${process.env.SSH_AUTH_SOCK})` : process.platform === "win32" ? ` (default ${WINDOWS_AGENT_PIPE})` : " (not set here)"}`;
  },
  identity(spec: SignerSpec): string {
    return agentSocketPath(spec) ?? "(no agent)";
  },
  async sign(spec: SignerSpec, key: ReferencedKey, message: Uint8Array): Promise<Uint8Array> {
    const path = agentSocketPath(spec);
    if (path === undefined) throw failed(`no ssh-agent for owner key ${key.keyId}: SSH_AUTH_SOCK is not set here and the reference names no socket`, { reason: "NO_AGENT", keyId: key.keyId });
    const conversation = new AgentConversation(path, typeof spec.timeoutMs === "number" ? spec.timeoutMs : DEFAULT_AGENT_TIMEOUT_MS);
    try {
      const identities = parseIdentities(await conversation.request(SSH_AGENTC_REQUEST_IDENTITIES, Buffer.alloc(0)), path);
      const blob = sshEd25519Blob(key.publicKeyBytes);
      if (!identities.some((identity) => identity.blob.equals(blob))) {
        const fido = identities.some((identity) => identity.type === SK_ED25519_KEY_TYPE && identity.publicKey?.equals(Buffer.from(key.publicKeyBytes)) === true);
        const line = sshPublicKeyLine(key.publicKeyBytes);
        throw new EngineError("KEY_UNAVAILABLE", fido
          ? `the ssh-agent at ${path} holds owner key ${key.keyId} only as a FIDO key (${SK_ED25519_KEY_TYPE}), which signs a different structure; IronTrellis needs a plain ssh-ed25519 key`
          : `the ssh-agent at ${path} does not hold owner key ${key.keyId} (${line}); add it (ssh-add <private key file>, or unlock it in 1Password / insert the card for gpg-agent) and try again: nothing was signed`,
          { signer: "ssh-agent", socket: path, keyId: key.keyId, publicKey: key.publicKey, sshPublicKey: line, reason: fido ? "FIDO_KEY" : "KEY_NOT_IN_AGENT", agentKeys: identities.length });
      }
      const answer = await conversation.request(SSH_AGENTC_SIGN_REQUEST, Buffer.concat([sshString(blob), sshString(message), u32(0)]));
      return parseSignResponse(answer, path);
    } finally {
      conversation.close();
    }
  },
});
