/**
 * The history identity a verifier confirms from outside the file (founder decision 4cb): the history id and the first
 * owner key set. A substitute history, the same events re-signed under keys of its author's own, verifies clean on its
 * own terms; only the id and the keys published by the history's owner tell the two apart.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { RECORD_CHAIN_VERSION, openHistoryStore, ownerKeysAt, parsePublicKey, type OwnerKey } from "@ramex-labs/irontrellis";
import { UsageError, list, str, type OptionSpec, type Parsed } from "./args.ts";
import { CliError } from "./history.ts";

/** What the file states: the position-0 hash (what init prints as historyId) and the genesis owner keys as credentials. */
export type Identity = Readonly<{ historyId: string; ownerKeys: readonly string[] }>;
/** What the verifier was given; either part may be absent. */
export type Expected = Readonly<{ historyId?: string; ownerKeys?: readonly string[] }>;
export type Mismatch = Readonly<{ code: "HISTORY_ID_MISMATCH" | "OWNER_KEYS_MISMATCH"; expected: unknown; found: unknown; line: string }>;
/** The JSON `identity` of verify and export verify. `confirmed` is true only when every part was given and matched. */
export type IdentityView = Readonly<{
  confirmed: boolean;
  historyId: string | null;
  ownerKeys: readonly string[] | null;
  expected: Readonly<{ historyId: string | null; ownerKeys: readonly string[] | null }>;
  mismatches: readonly Mismatch[];
  /** verify: the HISTORY_CHANGED line when the file changed between the identity read and the verification. */
  changed?: string;
}>;

const HISTORY_ID = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export const IDENTITY_OPTIONS = (o: (name: string, kind: OptionSpec["kind"], help: string, extra?: Partial<OptionSpec>) => OptionSpec): readonly OptionSpec[] => [
  o("expect-history-id", "string", "refuse unless the history id is this one (0x + 64 hex, as published by the history's owner; init prints it, and verify shows it)", { value: "<0x…>" }),
  o("expect-owner-key", "list", "refuse unless the first owner key set (the genesis's) is exactly these keys: an Ed25519 public key as 0x + 64 hex, or an account address as 0x + 40 hex (repeat or comma-separate; order and key ids are not compared)", { value: "<0x…>" }),
  o("expect-owner-keys", "string", "the same, from a file: one key per line (0x hex or an OpenSSH ssh-ed25519 line); blank lines and lines starting with # are ignored", { value: "<file>" }),
];

/** One expected key in the form the genesis stores it (lowercase): an Ed25519 key as 0x + 64 hex, an address as 0x + 40 hex. */
function keyOf(text: string, where: string): string {
  const trimmed = text.trim();
  if (ADDRESS.test(trimmed)) return trimmed.toLowerCase();
  try { return parsePublicKey(trimmed); } catch (error) { throw new UsageError(`${where}: ${error instanceof Error ? error.message : String(error)}`); }
}

/** The expectations given on the command line, or undefined when there are none. */
export function expectedIdentity(p: Parsed): Expected | undefined {
  const id = str(p, "expect-history-id");
  if (id !== undefined && !HISTORY_ID.test(id)) throw new UsageError(`--expect-history-id needs 0x + 64 hex, got "${id}"`);
  const keys: string[] = (list(p, "expect-owner-key") ?? []).map((k) => keyOf(k, `--expect-owner-key "${k}"`));
  const file = str(p, "expect-owner-keys");
  if (file !== undefined) {
    const path = resolve(file);
    if (!existsSync(path)) throw new CliError("FILE_NOT_FOUND", `--expect-owner-keys: no file at ${path}`);
    const lines = readFileSync(path, "utf8").split(/\r?\n/);
    lines.forEach((line, n) => { if (line.trim() !== "" && !line.trim().startsWith("#")) keys.push(keyOf(line, `--expect-owner-keys ${path}:${n + 1}`)); });
    if (keys.length === 0) throw new UsageError(`--expect-owner-keys: ${path} lists no key`);
  }
  if (id === undefined && keys.length === 0) return undefined;
  return { ...(id === undefined ? {} : { historyId: id.toLowerCase() }), ...(keys.length === 0 && file === undefined ? {} : { ownerKeys: [...new Set(keys)].sort() }) };
}

const credentialsOf = (keys: readonly OwnerKey[]): readonly string[] => [...new Set(keys.map((k) => k.credential.toLowerCase()))].sort();

/**
 * Test-only hooks (this module is internal: the package exports dist/cli.js alone). `afterIdentity` runs between verify's
 * identity read and its verification, `beforeRecheck` between the verification and the re-check.
 */
export const IDENTITY_TEST_SEAMS: { afterIdentity?: () => void; beforeRecheck?: () => void } = {};

/** One read-only open (no remote witness): the identity, and the head hashes to place a head on this file's chain. */
function readFile(path: string): Readonly<{ identity: Identity; hashes: readonly string[] }> {
  const store = openHistoryStore(path, { inspect: true, witness: false });
  try {
    const state = store.state();
    return { identity: { historyId: state.eventHistoryHashes[0]!, ownerKeys: credentialsOf(ownerKeysAt(state, 0)) }, hashes: state.eventHistoryHashes };
  } finally { store.close(); }
}

/** The identity a history file states (read-only, no remote witness). Throws what the open throws for a damaged file. */
export const identityOfFile = (path: string): Identity => readFile(path).identity;

/**
 * After the verification: a `HISTORY_CHANGED` failure line when the file is no longer the one whose identity was checked
 * first (its history id or first owner keys differ, or it cannot be read again), or when the head the verification judged
 * is not on its chain (the file was replaced for the verification and put back). Undefined when it is the same history.
 */
export function changedSince(path: string, first: Identity, head: Readonly<{ hash: string; position: number }> | undefined): string | undefined {
  IDENTITY_TEST_SEAMS.beforeRecheck?.();
  let again: ReturnType<typeof readFile>;
  try { again = readFile(path); } catch (error) {
    return `HISTORY_CHANGED: the file could not be read again after the verification (${error instanceof Error ? error.message : String(error)}), so the identity checked first may not be the verified file's`;
  }
  if (again.identity.historyId !== first.historyId) return `HISTORY_CHANGED: the history id changed during the verification: ${first.historyId} was checked, the file now has ${again.identity.historyId}`;
  if (again.identity.ownerKeys.join(",") !== first.ownerKeys.join(",")) return "HISTORY_CHANGED: the first owner keys changed during the verification";
  if (head !== undefined && again.hashes[head.position] !== head.hash) return `HISTORY_CHANGED: the head the verification judged (position ${head.position}) is not on the chain of the file whose identity was checked`;
  return undefined;
}

/**
 * A format-2 history id from its genesis event hash: `recordHash(0) = sha256("irontrellis-record/2" ‖ 0x00 ‖ 0^32 ‖
 * eventHash ‖ be64(0))` (SPEC §4.3). An export view states `genesisEventHash`, which its verification binds to the events.
 */
export function historyIdOfGenesisEventHash(genesisEventHash: string): string {
  if (!HISTORY_ID.test(genesisEventHash)) throw new CliError("INVALID_INPUT", `genesisEventHash ${genesisEventHash} is not 0x + 64 hex`);
  const hash = createHash("sha256");
  for (const part of [Buffer.from(RECORD_CHAIN_VERSION, "utf8"), Buffer.from([0]), Buffer.alloc(32), Buffer.from(genesisEventHash.slice(2), "hex"), Buffer.alloc(8)]) hash.update(part);
  return `0x${hash.digest("hex")}`;
}

/** The identity an export view states: the history id of its genesis and, when it carries the genesis, the first owner keys. */
export function identityOfView(genesisEventHash: string, epochs: readonly Readonly<{ keys: readonly OwnerKey[] }>[]): Identity {
  return { historyId: historyIdOfGenesisEventHash(genesisEventHash), ownerKeys: epochs.length === 0 ? [] : credentialsOf(epochs[0]!.keys) };
}

/** Each part that was given and does not match; the key sets are compared as sets. */
export function mismatchesOf(expected: Expected, found: Identity): readonly Mismatch[] {
  const out: Mismatch[] = [];
  if (expected.historyId !== undefined && expected.historyId !== found.historyId.toLowerCase()) {
    out.push({ code: "HISTORY_ID_MISMATCH", expected: expected.historyId, found: found.historyId, line: `HISTORY_ID_MISMATCH: the history id is ${found.historyId}, not the expected ${expected.historyId}` });
  }
  if (expected.ownerKeys !== undefined) {
    const missing = expected.ownerKeys.filter((k) => !found.ownerKeys.includes(k)), extra = found.ownerKeys.filter((k) => !expected.ownerKeys!.includes(k));
    if (missing.length > 0 || extra.length > 0) {
      out.push({
        code: "OWNER_KEYS_MISMATCH", expected: expected.ownerKeys, found: found.ownerKeys,
        line: `OWNER_KEYS_MISMATCH: the first owner keys are ${found.ownerKeys.length === 0 ? "none" : found.ownerKeys.join(", ")}, not the expected ${expected.ownerKeys.join(", ")}${missing.length === 0 ? "" : ` (missing ${missing.join(", ")})`}${extra.length === 0 ? "" : ` (not expected ${extra.join(", ")})`}`,
      });
    }
  }
  return out;
}

/** `found` parts are null when not established (an unreadable file, or keys of a view that did not verify). */
export function identityView(expected: Expected | undefined, found: Readonly<{ historyId: string | null; ownerKeys: readonly string[] | null }> | undefined, mismatches: readonly Mismatch[], changed?: string): IdentityView {
  return {
    ...(changed === undefined ? {} : { changed }),
    confirmed: changed === undefined && expected?.historyId !== undefined && expected.ownerKeys !== undefined && found?.historyId != null && found.ownerKeys !== null && mismatches.length === 0,
    historyId: found?.historyId ?? null, ownerKeys: found?.ownerKeys ?? null,
    expected: { historyId: expected?.historyId ?? null, ownerKeys: expected?.ownerKeys ?? null },
    mismatches,
  };
}

/** The closing sentence on what the identity rests on. */
export function identityCaveat(v: IdentityView): string {
  if (v.mismatches.length > 0) return "This is not the history you named: its identity differs from the values you gave.";
  if (v.changed !== undefined) return "The file changed while it was being verified, so the identity checked first may not be the verified file's: nothing it states is established. Verify a copy nothing else writes to.";
  if (v.confirmed) return "The history id and the first owner keys match the values you gave from outside the file.";
  const pass = "Pass --expect-history-id and --expect-owner-key with the values the history's owner published to confirm them.";
  if (v.expected.historyId === null && v.expected.ownerKeys === null) return `The history id and the first owner keys were read from the file itself, not confirmed against a source outside it: a substitute history signed with other keys would verify the same way. ${pass}`;
  const part = (given: unknown, value: unknown, what: string): string => given !== null && value !== null ? `${what} matches the value you gave`
    : given !== null ? `${what} could not be established, so it was not compared` : `${what} was read from the file itself, not confirmed against a source outside it`;
  return `${part(v.expected.historyId, v.historyId, "The history id")}; ${part(v.expected.ownerKeys, v.ownerKeys, "the first owner key set")}. ${pass}`;
}
