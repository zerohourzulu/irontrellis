/**
 * Owner-key custody on the command line (docs/CUSTODY.md): the flags that name a
 * key held by a signer (`--signer ssh-agent --public-key …`, `--owner-key-ref`,
 * `--next-key-ref`, `--next-public-key`), and the `signer` commands:
 *
 *   signer test   ask the signer for a signature over a random challenge and verify it
 *   signer ref    write a key reference file (0600) for a key a signer holds
 *   signer list   the Ed25519 keys an ssh-agent offers, in the forms IronTrellis takes
 *
 * A reference holds no secret; it names the key (its public key) and the signer.
 */
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, openSync, readFileSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import {
  OWNER_KEY_REF_VERSION, OWNER_NEXT_KEY_REF_VERSION, keyReference, listAgentIdentities, loadNextOwnerKeyFile, loadOwnerKeyFile, nextOwnerKeyPathFor, openHistoryStore, ownerKeyDigest,
  ownerKeyInForce, ownerKeyPathFor, parseKeyReference, parsePublicKey, referenceSigner, sshPublicKeyOf, writeKeyReferenceFile, agentSocketPath,
  OWNER_KEY_VERSION, OWNER_NEXT_KEY_VERSION, keyPairFromPrivateKey, openSshPrivateKey, readVaultKey, readKeyReferenceFile, EngineError,
  type OwnerKeyReference, type Signer, type VaultKeyInfo,
} from "@ramex-labs/irontrellis";
import { UsageError, flag, need, num, positionals, str, type OptionSpec, type Parsed } from "./args.ts";
import { CliError, historyPath, type Global } from "./history.ts";
import { dim, rows, type Lines, type Style } from "./output.ts";

const o = (name: string, kind: OptionSpec["kind"], help: string, extra: Partial<OptionSpec> = {}): OptionSpec => ({ name, kind, help, ...extra });

/** The flags that describe a signer inline (init, signer ref, signer test). */
export const SIGNER_OPTIONS: readonly OptionSpec[] = [
  o("signer", "string", "the signer that holds the owner key: ssh-agent, command or vault-transit (docs/CUSTODY.md); with --public-key (optional for vault-transit: read from Vault)", { value: "<kind>" }),
  o("public-key", "string", "the key's Ed25519 public key: an OpenSSH line (ssh-ed25519 AAAA…, e.g. from ssh-add -L) or 0x + 64 hex", { value: "<key>" }),
  o("agent-socket", "string", "--signer ssh-agent: the agent's socket (default $SSH_AUTH_SOCK; on Windows \\\\.\\pipe\\openssh-ssh-agent)", { value: "<path>" }),
  o("signer-command", "string", "--signer command: the program and its arguments as a JSON array, the program an absolute path (no shell), e.g. '[\"/usr/bin/node\",\"/opt/kms-sign.mjs\"]'", { value: "<json>" }),
  o("signer-timeout-ms", "number", "how long the signer may take to answer (ssh-agent default 60000, command default 30000; a person approving each use needs time)", { value: "<ms>" }),
  o("pass-env", "string", "--signer command: comma-separated environment variable names the program also gets (default only PATH, HOME and platform basics)", { value: "<A,B>" }),
  o("vault-addr", "string", "--signer vault-transit: the Vault address, https:// (plain http only to a loopback host); default $VAULT_ADDR", { value: "<url>" }),
  o("vault-key", "string", "--signer vault-transit: the Transit key's name (an ed25519 key)", { value: "<name>" }),
  o("vault-mount", "string", "--signer vault-transit: the Transit mount path (default transit)", { value: "<path>" }),
  o("vault-key-version", "number", "--signer vault-transit: the key version to pin (default: the version holding --public-key, else the latest); a Vault key rotation never switches it", { value: "<n>" }),
  o("vault-namespace", "string", "--signer vault-transit: the Vault Enterprise namespace (default $VAULT_NAMESPACE at signing time)", { value: "<ns>" }),
  o("vault-ca-file", "string", "--signer vault-transit: a PEM CA bundle for Vault's certificate (default $VAULT_CACERT at signing time)", { value: "<file>" }),
  o("vault-token-file", "string", "--signer vault-transit: a file holding the Vault token (default $VAULT_TOKEN, then ~/.vault-token); the token itself is never written to the reference", { value: "<file>" }),
];
const VAULT_FLAGS = ["vault-addr", "vault-key", "vault-mount", "vault-key-version", "vault-namespace", "vault-ca-file", "vault-token-file"];

/** The `signer` record the flags describe, or `undefined` when `--signer` is absent. */
function signerSpecOf(p: Parsed): Readonly<Record<string, unknown>> | undefined {
  const kind = str(p, "signer");
  const only = ["agent-socket", "signer-command", "signer-timeout-ms", "pass-env", ...VAULT_FLAGS].filter((name) => p.options.has(name));
  if (kind === undefined) {
    if (only.length > 0) throw new UsageError(`--${only[0]} needs --signer <kind>`);
    return undefined;
  }
  const timeout = num(p, "signer-timeout-ms");
  const vaultFlag = VAULT_FLAGS.find((name) => p.options.has(name));
  if (kind !== "vault-transit" && vaultFlag !== undefined) throw new UsageError(`--${vaultFlag} goes with --signer vault-transit`);
  if (kind === "vault-transit") {
    for (const name of ["agent-socket", "signer-command", "pass-env"]) if (p.options.has(name)) throw new UsageError(`--${name} does not go with --signer vault-transit`);
    const address = str(p, "vault-addr") ?? (process.env.VAULT_ADDR === undefined || process.env.VAULT_ADDR === "" ? undefined : process.env.VAULT_ADDR);
    if (address === undefined) throw new UsageError("--signer vault-transit needs --vault-addr <url> (or VAULT_ADDR)");
    const version = num(p, "vault-key-version");
    return {
      kind, address, key: need(p, "vault-key"), ...(str(p, "vault-mount") === undefined ? {} : { mount: str(p, "vault-mount")! }),
      ...(version === undefined ? {} : { keyVersion: version }),
      ...(str(p, "vault-namespace") === undefined ? {} : { namespace: str(p, "vault-namespace")! }),
      ...(str(p, "vault-ca-file") === undefined ? {} : { caFile: resolve(str(p, "vault-ca-file")!) }),
      ...(str(p, "vault-token-file") === undefined ? {} : { tokenFile: resolve(str(p, "vault-token-file")!) }),
      ...(timeout === undefined ? {} : { timeoutMs: timeout }),
    };
  }
  if (kind === "ssh-agent") {
    for (const name of ["signer-command", "pass-env"]) if (p.options.has(name)) throw new UsageError(`--${name} goes with --signer command`);
    return { kind, ...(str(p, "agent-socket") === undefined ? {} : { socket: resolve(str(p, "agent-socket")!) }), ...(timeout === undefined ? {} : { timeoutMs: timeout }) };
  }
  if (kind === "command") {
    if (p.options.has("agent-socket")) throw new UsageError("--agent-socket goes with --signer ssh-agent");
    let argv: unknown;
    try { argv = JSON.parse(need(p, "signer-command")); } catch (error) {
      if (error instanceof UsageError) throw error;
      throw new UsageError(`--signer-command: not a JSON array of strings (${error instanceof Error ? error.message : String(error)})`);
    }
    const passEnv = str(p, "pass-env")?.split(",").map((name) => name.trim()).filter((name) => name !== "");
    return { kind, argv, ...(timeout === undefined ? {} : { timeoutMs: timeout }), ...(passEnv === undefined ? {} : { passEnv }) };
  }
  throw new UsageError(`--signer: unknown signer "${kind}" (ssh-agent, command or vault-transit; a host can register more, see docs/CUSTODY.md)`);
}

/**
 * A key reference from the inline flags (`--signer … --public-key …`), or `undefined` without `--signer`. For
 * `--signer vault-transit` the public key and the version to pin may be left out: they are read from Vault (the key
 * read only; nothing is signed), and the version is pinned in the reference.
 */
export async function inlineReference(p: Parsed, keyId: string, next = false): Promise<OwnerKeyReference | undefined> {
  let spec = signerSpecOf(p);
  if (spec === undefined) return undefined;
  let publicKey = publicKeyFlag(p, "public-key");
  if (spec.kind === "vault-transit" && (publicKey === undefined || spec.keyVersion === undefined)) {
    let info: VaultKeyInfo;
    try { info = await readVaultKey(spec); } catch (error) {
      if (error instanceof UsageError) throw error;
      if (error instanceof Error && !(error instanceof EngineError)) throw new UsageError(`--signer vault-transit: ${error.message.replace(/^vault-transit signer: /, "")}`);
      throw error;
    }
    if (info.type !== "ed25519") throw new CliError("KEY_UNAVAILABLE", `Vault key ${String(spec.key)} is a ${info.type} key; an IronTrellis owner key is ed25519 (vault write <mount>/keys/<name> type=ed25519)`);
    let version = spec.keyVersion as number | undefined;
    if (version === undefined) {
      version = publicKey === undefined ? info.latestVersion : [...info.publicKeys].find(([, key]) => key === publicKey)?.[0];
      if (version === undefined) throw new CliError("KEY_UNAVAILABLE", `no version of Vault key ${String(spec.key)} holds --public-key ${publicKey!}`);
    }
    const held = info.publicKeys.get(version);
    if (held === undefined) throw new CliError("KEY_UNAVAILABLE", `Vault key ${String(spec.key)} has no version ${version} (it holds ${[...info.publicKeys.keys()].map((v) => `v${v}`).join(", ")})`);
    if (publicKey !== undefined && publicKey !== held) throw new CliError("KEY_UNAVAILABLE", `Vault key ${String(spec.key)} v${version} holds ${held}, not --public-key ${publicKey}`);
    publicKey = held;
    spec = { ...spec, keyVersion: version };
  }
  if (publicKey === undefined) throw new UsageError("--signer needs --public-key <key> (ssh-add -L prints it for an agent key)");
  // The flags make the reference: a defect in them is a usage error, not an unreadable key.
  try { return keyReference({ keyId, publicKey, signer: spec, next }); } catch (error) { throw new UsageError(`--signer ${String(spec.kind)}: ${error instanceof Error ? error.message.replace(/^the key reference is not a valid key reference: /, "") : String(error)}`); }
}

/**
 * Reads a key reference file (any version: the owner API files it as an owner or a next key) with the key loaders'
 * checks: not a symbolic link, and on POSIX mode 0600 and owned by this user. A reference decides
 * which program signs as the owner; one kept where others can write it is not copied into the history's own.
 */
export function readReferenceFile(path: string, flagName: string): OwnerKeyReference {
  const file = resolve(path);
  if (!existsSync(file)) throw new CliError("REFERENCE_NOT_FOUND", `--${flagName}: no key reference at ${file}`);
  try { return readKeyReferenceFile(file, "any"); } catch (error) {
    throw new CliError("KEY_UNAVAILABLE", `--${flagName}: ${error instanceof Error ? error.message : String(error)}`, (error as { detail?: unknown }).detail);
  }
}

/** `--public-key` style values in the 0x form, with the flag named in the error. */
export function publicKeyFlag(p: Parsed, name: string): string | undefined {
  const value = str(p, name);
  if (value === undefined) return undefined;
  try { return parsePublicKey(value); } catch (error) { throw new UsageError(`--${name}: ${error instanceof Error ? error.message : String(error)}`); }
}

/** What `owner status` / `init` show for a key's custody. */
export const custodyLine = (signer: Signer | undefined): string =>
  signer?.custody === undefined ? "a caller's signer" : signer.custody.description;

// ---------------------------------------------------------------- signer test

type Command = Readonly<{ name: string; usage: string; summary: string; positionals: readonly string[]; options: readonly OptionSpec[]; run(p: Parsed, g: Global): Promise<Outcome> }>;
type Outcome = Readonly<{ json: unknown; render: (s: Style, out: Lines) => void; exit?: number }>;
const command = (name: string, usage: string, summary: string, pos: readonly string[], options: readonly OptionSpec[], run: Command["run"]): Command =>
  Object.freeze({ name, usage, summary, positionals: pos, options, run });

export const signerTest = command("signer test", "signer test (--ref <file> | --key current|next | --signer <kind> --public-key <key> [signer options])",
  "ask the signer that holds a key for one signature over a random challenge and verify it against the key (nothing is written)", [], [
    o("ref", "string", "a key reference file (an owner or next-key reference)", { value: "<file>" }),
    o("key", "string", "the history's own key file: current (<history>.owner-key.json) or next (<history>.owner-next-key.json)", { value: "<which>" }),
    ...SIGNER_OPTIONS,
  ], async (p, g) => {
    positionals(p, []);
    const sources = ["ref", "key", "signer"].filter((name) => p.options.has(name));
    if (sources.length !== 1) throw new UsageError("give exactly one of --ref <file>, --key current|next or --signer <kind> --public-key <key>");
    let signer: Signer, source: string, role: "current" | "next" | undefined;
    if (p.options.has("ref")) {
      const file = resolve(need(p, "ref"));
      signer = referenceSigner(readReferenceFile(file, "ref"), file);
      source = file;
    } else if (p.options.has("key")) {
      const which = need(p, "key");
      if (which !== "current" && which !== "next") throw new UsageError(`--key: "${which}" is not current or next`);
      const history = historyPath(g);
      const file = which === "current" ? ownerKeyPathFor(history) : nextOwnerKeyPathFor(history);
      if (!existsSync(file)) throw new CliError("KEY_UNAVAILABLE", `no ${which === "current" ? "owner key" : "next-key"} file at ${file}`);
      signer = which === "current" ? loadOwnerKeyFile(file) : loadNextOwnerKeyFile(file);
      source = file;
      role = which;
    } else {
      signer = referenceSigner((await inlineReference(p, "signer-test"))!);
      source = "the command line";
    }
    const challenge = `0x${randomBytes(32).toString("hex")}` as const;
    const started = Date.now();
    // A reference signer verifies the answer against the key before returning it; a key file signs locally.
    const signature = await signer.signHash(challenge, { purpose: "signer-test" });
    const elapsedMs = Date.now() - started;
    // Against the history, when one is named: is this key in force, or the committed next key?
    let standing: string | null = null;
    const history = g.history ?? process.env.IRONTRELLIS_HISTORY;
    if (history !== undefined && history !== "" && existsSync(resolve(history)) && signer.scheme === "ed25519") {
      const store = openHistoryStore(resolve(history), { inspect: true, witness: false, allowUnpinned: true });
      try {
        const state = store.state(), next = state.head.position + 1;
        const epoch = state.ownerKeyEpochs.at(-1);
        standing = ownerKeyInForce(state, next, signer) ? "an owner key in force"
          : epoch?.nextKeyDigests?.includes(ownerKeyDigest(signer)) === true ? "the committed next key"
          : state.ownerKeyEpochs.some((e) => e.keys.some((k) => k.credential.toLowerCase() === signer.credential.toLowerCase())) ? "a retired owner key"
          : "not a key of this history";
      } finally { store.close(); }
    }
    const result = {
      ok: true, source, ...(role === undefined ? {} : { key: role }), keyId: signer.keyId, scheme: signer.scheme, publicKey: signer.credential,
      ...(signer.scheme === "ed25519" ? { sshPublicKey: sshPublicKeyOf(signer.credential) } : {}), custody: signer.custody ?? null, challenge, signature, elapsedMs, standing,
    };
    return {
      json: result,
      render: (s, out) => {
        out.add(`${s.strong("SIGNED")}  a random challenge with ${signer.keyId}, and the signature verifies against its public key`);
        out.add(...rows(s, [
          ["signer", custodyLine(signer)], ["public key", signer.credential], ...(result.sshPublicKey === undefined ? [] : [["ssh form", result.sshPublicKey] as const]),
          ["took", `${elapsedMs} ms`], ...(standing === null ? [] : [["in the history", standing] as const]),
        ]));
        out.add(dim(s, "Nothing was written. Every signature a signer returns is verified like this before IronTrellis uses it."));
      },
    };
  });

// ---------------------------------------------------------------- signer ref

export const signerRef = command("signer ref", "signer ref --out <file> --signer <kind> --public-key <key> [--key-id <id>] [--next] [signer options]",
  "write a key reference file (mode 0600): it names a key a signer holds and holds no secret; use it with init --owner-key-ref, owner commit-next-key --next-key-ref or owner rotate-key --next-key-ref", [], [
    o("out", "string", "where to write the reference (never overwritten)", { value: "<file>", required: true }),
    o("key-id", "string", "the key id the reference proposes (default owner:1, or owner:next with --next)", { value: "<id>", identifier: true }),
    o("next", "boolean", "write a next-key reference (irontrellis-owner-next-key-ref/1) instead of an owner key reference"),
    o("comment", "string", "a note for people, kept in the file", { value: "<text>" }),
    ...SIGNER_OPTIONS,
  ], async (p) => {
    positionals(p, []);
    if (!p.options.has("signer")) throw new UsageError("signer ref needs --signer <kind> and --public-key <key> (for vault-transit: --vault-addr and --vault-key)");
    const next = flag(p, "next");
    const base = (await inlineReference(p, str(p, "key-id") ?? (next ? "owner:next" : "owner:1"), next))!;
    const reference = str(p, "comment") === undefined ? base : keyReference({ keyId: base.keyId, publicKey: base.publicKey, signer: base.signer, next, comment: str(p, "comment")! });
    const out = resolve(need(p, "out"));
    writeKeyReferenceFile(out, reference);
    return {
      json: { written: out, reference, sshPublicKey: sshPublicKeyOf(reference.publicKey) },
      render: (s, lines) => {
        lines.add(`WRITTEN  ${next ? "next-key" : "owner key"} reference ${out} (mode 0600)`);
        lines.add(...rows(s, [["key", `${reference.keyId} · ${sshPublicKeyOf(reference.publicKey)}`], ["signer", JSON.stringify(reference.signer)], ["version", next ? OWNER_NEXT_KEY_REF_VERSION : OWNER_KEY_REF_VERSION]]));
        lines.add(dim(s, "The file holds no secret, but it decides which program signs as the owner: keep it 0600 and out of the agent's reach. Check it with irontrellis signer test --ref <file>."));
      },
    };
  });

// ---------------------------------------------------------------- signer list

export const signerList = command("signer list", "signer list [--agent-socket <path>]", "the keys an ssh-agent offers; the ssh-ed25519 ones can hold an IronTrellis owner key", [], [
  o("agent-socket", "string", "the agent's socket (default $SSH_AUTH_SOCK; on Windows the OpenSSH pipe)", { value: "<path>" }),
], async (p) => {
  positionals(p, []);
  const socket = str(p, "agent-socket") === undefined ? undefined : resolve(str(p, "agent-socket")!);
  const path = agentSocketPath(socket === undefined ? {} : { socket });
  const identities = await listAgentIdentities(socket === undefined ? {} : { socket });
  const keys = identities.map((identity) => {
    const usable = identity.type === "ssh-ed25519" && identity.publicKey !== undefined;
    const publicKey = usable ? `0x${identity.publicKey!.toString("hex")}` : null;
    return {
      type: identity.type, comment: identity.comment, usable, publicKey, sshPublicKey: usable ? sshPublicKeyOf(publicKey!, identity.comment) : null,
      ...(usable ? {} : { reason: identity.type === "sk-ssh-ed25519@openssh.com" ? "a FIDO key signs a different structure" : "not an Ed25519 key" }),
    };
  });
  return {
    json: { socket: path ?? null, keys },
    render: (s, out) => {
      out.add(`SSH-AGENT  ${path ?? "(none)"} · ${keys.length === 1 ? "1 key" : `${keys.length} keys`}`);
      for (const key of keys) {
        out.add(`  ${key.usable ? s.strong("USABLE") : s.strong("NOT USABLE")}  ${key.type} ${key.comment}${key.usable ? "" : dim(s, ` — ${key.reason}`)}`);
        if (key.publicKey !== null) out.add(dim(s, `    ${key.publicKey}`));
      }
      out.add(dim(s, "Name a usable key with --signer ssh-agent --public-key '<its ssh-ed25519 line>' (init, signer ref)."));
    },
  };
});

// ---------------------------------------------------------------- signer to-ssh

export const signerToSsh = command("signer to-ssh", "signer to-ssh (--key current|next | --from <key file>) --out <file>",
  "write an IronTrellis Ed25519 key file as an OpenSSH private key (mode 0600, unencrypted: add a passphrase with ssh-keygen -p), to move an existing owner or next key into an ssh-agent", [], [
    o("key", "string", "the history's own key file: current (<history>.owner-key.json) or next (<history>.owner-next-key.json)", { value: "<which>" }),
    o("from", "string", "an owner key file or next-key file elsewhere", { value: "<file>" }),
    o("out", "string", "where to write the OpenSSH private key (never overwritten)", { value: "<file>", required: true }),
  ], async (p, g) => {
    positionals(p, []);
    if (p.options.has("key") === p.options.has("from")) throw new UsageError("give exactly one of --key current|next or --from <key file>");
    let file: string;
    if (p.options.has("key")) {
      const which = need(p, "key");
      if (which !== "current" && which !== "next") throw new UsageError(`--key: "${which}" is not current or next`);
      file = which === "current" ? ownerKeyPathFor(historyPath(g)) : nextOwnerKeyPathFor(historyPath(g));
    } else file = resolve(need(p, "from"));
    // Loaded through the core loader first: the same 0600 and integrity checks as any key file.
    let signer: Signer;
    try { signer = loadOwnerKeyFile(file); } catch { signer = loadNextOwnerKeyFile(file); }
    if (signer.custody?.holder !== "file") throw new CliError("KEY_UNAVAILABLE", `${file} is a key reference: the key is already held by ${signer.custody?.description ?? "a signer"}`);
    const record = JSON.parse(readFileSync(file, "utf8")) as { version?: unknown; privateKey?: unknown; scheme?: unknown };
    if ((record.version !== OWNER_KEY_VERSION && record.version !== OWNER_NEXT_KEY_VERSION) || record.scheme !== "ed25519" || typeof record.privateKey !== "string") {
      throw new CliError("KEY_UNAVAILABLE", `${file} does not hold an Ed25519 key`);
    }
    const pair = keyPairFromPrivateKey("ed25519", signer.keyId, record.privateKey);
    const out = resolve(need(p, "out"));
    const text = openSshPrivateKey(Buffer.from(pair.privateKey.slice(2), "hex"), Buffer.from(pair.credential.slice(2), "hex"), `irontrellis ${signer.keyId}`);
    let fd: number;
    try { fd = openSync(out, "wx", 0o600); } catch (error) {
      if ((error as { code?: unknown }).code === "EEXIST") throw new CliError("FILE_EXISTS", `--out: ${out} already exists; it is never overwritten`);
      throw new CliError("FILE_UNWRITABLE", `--out: ${out} cannot be created (${error instanceof Error ? error.message : String(error)})`);
    }
    try { writeSync(fd, text); } finally { closeSync(fd); }
    const sshPublicKey = sshPublicKeyOf(pair.credential, `irontrellis ${signer.keyId}`);
    return {
      json: { written: out, from: file, keyId: signer.keyId, publicKey: pair.credential, sshPublicKey },
      render: (s, lines) => {
        lines.add(`WRITTEN  ${out} (OpenSSH private key of ${signer.keyId}, mode 0600, no passphrase)`);
        lines.add(...rows(s, [["from", file], ["public key", sshPublicKey]]));
        lines.add(dim(s, `Next: ssh-keygen -p -f ${out} (a passphrase), ssh-add ${out} (or import it into 1Password), then move ${file} offline and replace it with a reference: irontrellis signer ref --signer ssh-agent --public-key '${sshPublicKey}' --key-id ${signer.keyId}${file.endsWith(".owner-next-key.json") ? " --next" : ""} --out ${file}. Check with irontrellis signer test. Destroy ${out} once the agent (or 1Password) holds the key.`));
      },
    };
  });

export const SIGNER_COMMANDS: readonly Command[] = Object.freeze([signerTest, signerRef, signerList, signerToSsh]);
