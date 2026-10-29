/**
 * The command set. Each command declares its usage and options, runs against
 * the history named by `--history` / IRONTRELLIS_HISTORY, and returns one
 * outcome: a JSON document plus a human rendering (and an exit code when the
 * answer itself is the exit status, as with `verify` and `authorize`).
 */
import { closeSync, existsSync, openSync, readFileSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import {
  EngineError, IronTrellisError, LEGACY_FORMAT, TRELLIS2_FORMAT, anchorRecordedEvent, attestHead, createLocalDomain, createLocalOwner, generateKeyPair,
  loadNextOwnerKeyFile, loadOwnerKeyFile, localAnchorLog, migrateHistory, migrationStatus, nextOwnerKeyPathFor, readMigratedMarker, markerTargetPath, openHistoryStore, openLocalOwner, ownerKeyPathFor, ownerKeyStatusOf, ownerKeysAt, rekorAnchor,
  signControlEvent, verifyHistoryAsync, NEXT_KEY_ON_HOST_WARNING, checkpointPolicyListings, sameHead,
  verifyHistoryWithWitnesses, anchorContextOf, type WitnessChange, type WitnessPolicyUpdate,
  type Action, type AuthorizationDomain, type HistoryFormat, type HistoryHead, type HistoryStore, type OwnerPolicy, type OwnerVerification, type SignatureScheme, type Signer, type WriteResult, type AnchorTarget,
} from "@ramex-labs/irontrellis";
import { UsageError, flag, list, need, num, positionals, str, type OptionSpec, type Parsed } from "./args.ts";
import {
  CliError, LOCK_WAIT_MS, capacity, writableFormat, codeOf, evaluationTime, historyPath, observe, openReader, openWriter, optionalTime, parseAmount, parseTime, profileOf, queryAt, submitQueued, withRetry, write, writtenUnattested,
  type Global,
} from "./history.ts";
import { describe } from "./messages.ts";
import { formatTime, plural, type Lines, type Style } from "./output.ts";
import { handoverReport } from "./report.ts";
import { SIGNER_COMMANDS, SIGNER_OPTIONS, custodyLine, inlineReference, publicKeyFlag, readReferenceFile } from "./custody.ts";
import { DOCTOR_OPTIONS, runDoctor } from "./doctor.ts";
import { IDENTITY_OPTIONS, IDENTITY_TEST_SEAMS, changedSince, expectedIdentity, identityOfFile, identityView, mismatchesOf, type Identity } from "./identity.ts";
import { FORMAT2_COMMANDS, REFUSAL_OPTIONS, format2Status, recordRefusal } from "./format2.ts";
import {
  headLine, pinLine, renderAuthorize, renderCapacity, renderHandover, renderOwnerKeyWarnings, renderOwnerStatus, renderResponsible, renderStatus, renderSurvives, renderVerify, renderWhy,
  renderWitnessStatus, witnessWarnings,
  type Status, type VerifyView,
} from "./render.ts";

export type Outcome = Readonly<{ json: unknown; render: (s: Style, out: Lines) => void; exit?: number; raw?: string }>;
export type Command = Readonly<{
  name: string;
  usage: string;
  summary: string;
  positionals: readonly string[];
  options: readonly OptionSpec[];
  run(p: Parsed, g: Global): Promise<Outcome>;
}>;

/** `CODE` of a `CODE: explanation` failure or note. */
const failureCode = (line: string): string => line.split(":")[0]!;

// ---------------------------------------------------------------- shared option groups

const o = (name: string, kind: OptionSpec["kind"], help: string, extra: Partial<OptionSpec> = {}): OptionSpec => ({ name, kind, help, ...extra });
/** An option whose value(s) the owner API checks as identifiers (≤ 128 characters; lists ≤ 32 distinct values). */
const id = (name: string, kind: "string" | "list", help: string, extra: Partial<OptionSpec> = {}): OptionSpec => o(name, kind, help, { ...extra, identifier: true });
const TIME = "<ms|ISO|+30m>";
const ACTION_OPTIONS: readonly OptionSpec[] = [
  o("actor", "string", "the agent asking", { value: "<agent>" }),
  o("action", "string", "the action name", { value: "<name>" }),
  o("resource", "string", "the resource identifier", { value: "<id>" }),
  o("amount", "string", "amount in the smallest unit (quantitative grants)", { value: "<integer>" }),
  o("counterparty", "string", "counterparty identifier", { value: "<id>" }),
  o("terms", "string", "terms commitment hash (0x + 64 hex)", { value: "<hash>" }),
];
const GRANT_OPTIONS: readonly OptionSpec[] = [
  id("to", "string", "the grantee agent", { value: "<agent>", required: true }),
  id("actions", "list", "allowed actions (at most 32)", { value: "<a,b>", required: true }),
  id("resources", "list", "allowed resources (at most 32)", { value: "<r1,r2>", required: true }),
  o("expires", "string", "expiry time", { value: TIME, required: true }),
  o("not-before", "string", "validity start", { value: TIME }),
  o("max-amount", "string", "per-action amount ceiling", { value: "<integer>" }),
  o("max-cumulative", "string", "cumulative amount ceiling", { value: "<integer>" }),
  o("max-transactions", "number", "transaction count ceiling", { value: "<n>" }),
  o("delegable", "number", "how many levels the grantee may delegate (default 0)", { value: "<depth>" }),
  id("requires", "list", "intersection partners that must also allow", { value: "<id,id>" }),
  o("independent", "boolean", "--no-independent makes the grant an intersection partner only"),
];

const POSITION = o("position", "number", "evaluate at this history position (the prefix) while observing the whole history", { value: "<n>" });
const INTENT = o("intent", "string", "evaluate the recorded admission of this intent (its prefix, time, request and session binding)", { value: "<id>" });
const requestOf = (p: Parsed, q: { request?: Action }): Action => {
  if (q.request !== undefined) {
    if (["actor", "action", "resource", "amount", "counterparty", "terms"].some((name) => str(p, name) !== undefined)) throw new UsageError("--intent supplies the request; do not pass --actor/--action/--resource");
    return q.request;
  }
  return action(p);
};
const action = (p: Parsed): Action => ({
  actor: need(p, "actor"), action: need(p, "action"), resource: need(p, "resource"),
  ...(str(p, "amount") === undefined ? {} : { amount: parseAmount(str(p, "amount")!, "amount") }),
  ...(str(p, "counterparty") === undefined ? {} : { counterparty: str(p, "counterparty")! }),
  ...(str(p, "terms") === undefined ? {} : { termsCommitment: str(p, "terms") as `0x${string}` }),
});
const grantInput = (p: Parsed, id: string) => ({
  id, to: need(p, "to"), actions: list(p, "actions")!, resources: list(p, "resources")!, expiresAt: parseTime(need(p, "expires"), "expires"),
  ...optionalTime(str(p, "not-before"), "notBefore"),
  ...(str(p, "max-amount") === undefined ? {} : { maxAmount: parseAmount(str(p, "max-amount")!, "max-amount") }),
  ...(str(p, "max-cumulative") === undefined ? {} : { maxCumulativeAmount: parseAmount(str(p, "max-cumulative")!, "max-cumulative") }),
  ...(num(p, "max-transactions") === undefined ? {} : { maxTransactions: num(p, "max-transactions")! }),
  ...(num(p, "delegable") === undefined ? {} : { delegable: num(p, "delegable")! }),
  ...(list(p, "requires") === undefined ? {} : { requires: list(p, "requires")! }),
  ...(p.options.get("independent") === false ? { independent: false } : {}),
  ...(str(p, "parent") === undefined ? {} : { parent: str(p, "parent")! }),
  ...(str(p, "from") === undefined ? {} : { from: str(p, "from")! }),
});

const written = (what: string, result: WriteResult): Outcome => ({
  json: { recorded: what, eventId: result.eventId, head: result.head },
  render: (s, out) => { out.add(`RECORDED  ${what}`); out.add(`  ${s.paint("event", "secondary")}  ${result.eventId}`); out.add(`  ${s.paint("head ", "secondary")}  ${headLine(result.head)}`); },
});

const command = (name: string, usage: string, summary: string, pos: readonly string[], options: readonly OptionSpec[], run: Command["run"]): Command =>
  Object.freeze({ name, usage, summary, positionals: pos, options, run });

// ---------------------------------------------------------------- history lifecycle

const init = command("init", "init --history <file> [--owner <id>] [--controller <id>] [--max-events <n>] [--max-state-records <n>] [--checkpoint-every <n>] [--session-time-horizon <ms>] [--owner-key-ref <file> | --signer ssh-agent|command --public-key <key> [signer options] | --signer vault-transit --vault-addr <url> --vault-key <name> [--vault-mount <path>] [--vault-key-version <n>] [--vault-namespace <ns>] [--vault-ca-file <file>] [--vault-token-file <file>]] [--no-next-key | --next-public-key <key> | --next-key-ref <file>] [--reuse-existing-key] [--witness <url> --verifier-key <key> [--token <token>] [--mode sync|async] [--no-require-on-open]]", "create a history, its owner key (a key file, or a key held by an ssh-agent, a Vault Transit key or a command signer) and its committed next key, bound to a remote witness from its first write", [], [
  id("deployment", "string", "deployment id for the domain (default local:<uuid>)", { value: "<id>" }),
  o("next-key", "boolean", "commit the history to a next owner key in its genesis (default): the key is written to <history>.owner-next-key.json, to be moved off this host; --no-next-key creates the history without a commitment (add one later with owner commit-next-key)"),
  o("max-events", "number", "event limit stored in the genesis (default unlimited)", { value: "<n>" }),
  o("max-state-records", "number", "state record limit stored in the genesis (default unlimited)", { value: "<n>" }),
  o("checkpoint-every", "number", "write a signed state checkpoint after every <n> events (default: only when you run irontrellis checkpoint create)", { value: "<n>" }),
  o("session-time-horizon", "number", "the session time horizon in ms (A-179): a session may carry history time at most this far past the latest time-advancing owner event (default: no horizon)", { value: "<ms>" }),
  o("scheme", "string", "runtime signature scheme declared by the genesis: ed25519 (default) or eip191-personal-sign-keccak256", { value: "<scheme>" }),
  o("reuse-existing-key", "boolean", "adopt an owner key file already at <history>.owner-key.json as the owner key, and a next-key file already at <history>.owner-next-key.json as the committed next key (refused with KEY_EXISTS by default)"),
  o("witness", "string", "bind this remote witness at creation: the genesis is registered before the file exists and the binding is written with the first events, so no copy of the history exists without it", { value: "<url>" }),
  o("verifier-key", "string", "the witness's note verifier key (with --witness)", { value: "<key>" }),
  o("token", "string", "the witness's registration token (with --witness; kept in <history>.witness.json, mode 0600)", { value: "<token>" }),
  o("mode", "string", "with --witness: sync (submit before each write returns) or async (default)", { value: "<mode>" }),
  o("require-on-open", "boolean", "with --witness: readers ask the witness before reading (the default; --no-require-on-open turns it off)"),
  o("allow-insecure-http", "boolean", "with --witness: accept a plain http:// URL to a host that is not loopback (replayed witness answers cannot be ruled out)"),
  o("owner-key-ref", "string", "the owner key is held by the signer this key reference names (irontrellis signer ref writes one); it is copied to <history>.owner-key.json (no secret) and no key material is generated", { value: "<file>" }),
  ...SIGNER_OPTIONS,
  id("key-id", "string", "with --signer: the owner key's id (default owner:1)", { value: "<id>" }),
  o("next-public-key", "string", "commit to this next key (ssh-ed25519 AAAA… or 0x + 64 hex) whose private half never touches this host; nothing is written for it", { value: "<key>" }),
  o("next-key-ref", "string", "commit to the next key this key reference names; the reference is copied to <history>.owner-next-key.json (no secret)", { value: "<file>" }),
], async (p, g) => {
  positionals(p, []);
  const path = g.history ?? process.env.IRONTRELLIS_HISTORY;
  if (path === undefined || path === "") throw new CliError("HISTORY_REQUIRED");
  const historyFile = resolve(path);
  // init writes format 2 only (SPEC §16.1, A-9): no option creates a legacy or format-1 history.
  const format: HistoryFormat = TRELLIS2_FORMAT;
  const ownerId = g.owner ?? "owner", controllerId = g.controller ?? ownerId;
  const base = createLocalDomain();
  const deployment = str(p, "deployment");
  const domain = (deployment === undefined ? base : { ...base, deploymentId: deployment }) as AuthorizationDomain;
  const scheme = str(p, "scheme");
  if (scheme !== undefined && scheme !== "ed25519" && scheme !== "eip191-personal-sign-keccak256") throw new UsageError(`--scheme: unknown scheme "${scheme}"`);
  const witnessUrl = str(p, "witness");
  const witnessOnly = ["verifier-key", "token", "mode", "require-on-open", "allow-insecure-http"].filter((name) => p.options.has(name));
  if (witnessUrl === undefined && witnessOnly.length > 0) throw new UsageError(`--${witnessOnly[0]} needs --witness <url>`);
  const mode = str(p, "mode");
  if (mode !== undefined && mode !== "sync" && mode !== "async") throw new UsageError(`--mode: "${mode}" is not sync or async`);
  const witness = witnessUrl === undefined ? undefined : {
    witnesses: [{
      url: witnessUrl, verifierKey: need(p, "verifier-key"), ...(str(p, "token") === undefined ? {} : { token: str(p, "token")! }),
      ...(flag(p, "allow-insecure-http") ? { allowInsecureHttp: true } : {}),
    }],
    ...(mode === undefined ? {} : { mode: mode as "sync" | "async" }), ...(p.options.get("require-on-open") === false ? {} : { requireOnOpen: true }), // A-39.3: on by default with --witness
  };
  // Custody (docs/CUSTODY.md): the owner key held by a signer, the next key held elsewhere.
  if (p.options.has("owner-key-ref") && p.options.has("signer")) throw new UsageError("give the owner key once: --owner-key-ref <file> or --signer <kind> --public-key <key>");
  if (p.options.has("key-id") && !p.options.has("signer")) throw new UsageError("--key-id goes with --signer (a reference file carries its own key id)");
  const ownerKeyReference = str(p, "owner-key-ref") !== undefined ? readReferenceFile(str(p, "owner-key-ref")!, "owner-key-ref") : await inlineReference(p, str(p, "key-id") ?? "owner:1");
  const nextPublicKey = publicKeyFlag(p, "next-public-key");
  const nextKeyReference = str(p, "next-key-ref") === undefined ? undefined : readReferenceFile(str(p, "next-key-ref")!, "next-key-ref");
  if (nextPublicKey !== undefined && nextKeyReference !== undefined) throw new UsageError("give the next key once: --next-public-key or --next-key-ref");
  if ((nextPublicKey !== undefined || nextKeyReference !== undefined) && p.options.get("next-key") === false) throw new UsageError("--no-next-key excludes --next-public-key and --next-key-ref");
  const owner = await createLocalOwner({
    historyFile, domain, owner: ownerId, controller: controllerId, now: () => Date.now(),
    ...(num(p, "max-events") === undefined ? {} : { maxEvents: num(p, "max-events")! }),
    ...(num(p, "max-state-records") === undefined ? {} : { maxStateRecords: num(p, "max-state-records")! }),
    ...(num(p, "checkpoint-every") === undefined ? {} : { checkpointPolicy: { everyEvents: num(p, "checkpoint-every")! } }),
    ...(num(p, "session-time-horizon") === undefined ? {} : { sessionTimeHorizonMs: num(p, "session-time-horizon")! }),
    ...(scheme === undefined ? {} : { signatureScheme: scheme as SignatureScheme }),
    ...(flag(p, "reuse-existing-key") ? { reuseExistingKey: true } : {}),
    ...(witness === undefined ? {} : { witness }),
    ...(p.options.get("next-key") === false ? { nextKey: false } : {}),
    ...(ownerKeyReference === undefined ? {} : { ownerKeyReference }), ...(nextPublicKey === undefined ? {} : { nextPublicKey }),
    ...(nextKeyReference === undefined ? {} : { nextKeyReference }),
  }).catch((error: unknown) => {
    // An asynchronous signer can fail on the pin's attestation after the genesis is written; the history then
    // exists, so the answer is WRITTEN_UNATTESTED (exit 4), never "nothing written" (a retried init would only meet
    // "the history exists").
    throw (existsSync(historyFile) ? writtenUnattested(error, undefined) : undefined) ?? error;
  });
  // Best effort: the binding's head goes to the witness before the command exits (an unreachable witness keeps it queued).
  // A signer failure here comes after the history was written: WRITTEN_UNATTESTED (exit 4), not "nothing written".
  try { await submitQueued(owner); } catch (error) { throw writtenUnattested(error, undefined) ?? error; }
  const witnessState = owner.witnessStatus();
  const events = owner.exportHistory();
  const genesis = events[0]!.data as { ownerKeys?: readonly { keyId: string }[] };
  const head = owner.verify().head!;
  const keyStatus = owner.ownerKeyStatus();
  // A-41.3 / A-19.4: the identity readers pin (`historyId` in hook and gateway configs): the genesis record-chain hash.
  const historyId = openHistoryStore(historyFile, { inspect: true, witness: false }).state().eventHistoryHashes[0]!;
  // Founder decision 4cb: what the owner publishes, in the form verify --expect-history-id / --expect-owner-key takes.
  const publish = identityOfFile(historyFile);
  const result = {
    created: historyFile, format, owner: ownerId, controller: controllerId, domain, head, historyId, publish,
    ownerKeyFile: ownerKeyPathFor(historyFile), ownerKeys: (genesis.ownerKeys ?? []).map((k) => k.keyId),
    ownerKeyHolder: ownerKeyReference === undefined ? "file" : "reference",
    ownerKeySigner: ownerKeyReference === undefined ? null : custodyLine(loadOwnerKeyFile(ownerKeyPathFor(historyFile))),
    nextPublicKey: nextPublicKey ?? null,
    custody: keyStatus.custody,
    doctor: `irontrellis doctor ${historyFile}`,
    maxEvents: num(p, "max-events") ?? null,
    sessionTimeHorizonMs: num(p, "session-time-horizon") ?? null,
    witnesses: witnessState === undefined ? [] : witnessState.bound.map((b) => ({ url: b.url, verifierKey: b.verifierKey })),
    unwitnessedEvents: witnessState === undefined ? null : witnessState.unwitnessedEvents,
    ...nextKeyView(keyStatus),
  };
  owner.close();
  return {
    json: result,
    render: (s, out) => {
      out.add(`CREATED  ${historyFile}`);
      out.add(`  ${s.paint("format    ", "secondary")}  ${format}`);
      out.add(`  ${s.paint("owner     ", "secondary")}  ${ownerId} · controller ${controllerId}`);
      out.add(`  ${s.paint("domain    ", "secondary")}  ${domain.deploymentId}`);
      out.add(`  ${s.paint("historyId ", "secondary")}  ${historyId} (set it as "historyId" in hook and gateway configs)`);
      out.add(`  ${s.paint("head      ", "secondary")}  ${headLine(head)}`);
      if (result.ownerKeyFile !== null && result.ownerKeyHolder === "reference") out.add(`  ${s.paint("owner key ", "secondary")}  ${result.ownerKeys.join(", ")} held by ${result.ownerKeySigner} · ${result.ownerKeyFile} is a reference (no secret; mode 0600)`);
      else if (result.ownerKeyFile !== null) out.add(`  ${s.paint("owner key ", "secondary")}  ${result.ownerKeyFile} (${result.ownerKeys.join(", ")}; mode 0600 — keep it private)`);
      if (result.maxEvents !== null) out.add(`  ${s.paint("capacity  ", "secondary")}  ${result.maxEvents} events`);
      if (result.sessionTimeHorizonMs !== null) out.add(`  ${s.paint("horizon   ", "secondary")}  sessions may run ${result.sessionTimeHorizonMs} ms past the latest owner event (A-179); a FIXED_WINDOW budget whose window is that long or shorter can be outrun by a session alone (A-179.4)`);
      for (const w of result.witnesses) out.add(`  ${s.paint("witness   ", "secondary")}  ${w.url} · bound in the history from position 2${result.unwitnessedEvents === 0 ? " · holds the head" : " · head queued (irontrellis witness sync)"}`);
      if (result.nextKeyFile !== null && nextKeyReference !== undefined) out.add(`  ${s.paint("next key  ", "secondary")}  committed · held by ${custodyLine(loadNextOwnerKeyFile(result.nextKeyFile))} · ${result.nextKeyFile} is a reference`);
      else if (result.nextKeyFile !== null) out.add(`  ${s.paint("next key  ", "secondary")}  ${result.nextKeyFile} (mode 0600 — the only key that can rotate the owner key)`);
      else if (result.nextKeyCommitted) out.add(`  ${s.paint("next key  ", "secondary")}  committed${nextPublicKey === undefined ? "" : " · public key only (its private half is not on this host)"}`);
      else out.add(`  ${s.paint("next key  ", "secondary")}  none (irontrellis owner commit-next-key adds one)`);
      renderOwnerKeyWarnings(s, out, result.warnings);
      out.add(s.paint(`Check the custody and the deployment: irontrellis doctor ${historyFile} (and, as the agent's OS user, with --as-agent).`, "secondary"));
      renderPublish(s, out, publish, historyFile);
    },
  };
});

const status = command("status", "status", "head, event count, format, state root and latest checkpoint, capacity, pinned head and its attestation, witnesses and anchors; says when the file is read only", [], [], async (p, g) => {
  positionals(p, []);
  const r = await openReader(g);
  const state = r.state, head = state.head;
  // The judgement verify makes (pin, its attestation, witnesses), read-only; the open above already refused a rolled-back file.
  const v = r.store.verify();
  const pin = v.pinnedHead;
  const authorities = [...state.authorities.values()];
  const counts = {
    "agents": [...state.agents.values()].filter((a) => !a.terminated).length,
    "agents terminated": [...state.agents.values()].filter((a) => a.terminated).length,
    "roles": state.roles.size,
    "grants live": authorities.filter((a) => a.grant.kind === "PERMISSION" && a.revocationEventId === undefined).length,
    "grants revoked": authorities.filter((a) => a.revocationEventId !== undefined).length,
    "prohibitions": authorities.filter((a) => a.grant.kind === "PROHIBITION").length,
    "sessions": state.runtimeSessions.size,
    "duties open": [...state.obligations.values()].filter((x) => x.status === "OPEN").length + [...state.attemptDuties.values()].filter((x) => String(x.record.status) === "OPEN").length,
    "intents declared": state.intentDeclarations.size,
  };
  const st: Status = {
    path: r.path, format: state.format, head, eventCount: state.events.length, capacity: capacity(r), verification: v,
    anchors: state.anchors.map((a) => ({ position: a.head.position, anchor: a.anchor })), owner: profileOf(state).owner,
    ownerKeys: ownerKeysAt(state, state.head.position + 1).map((k) => k.keyId), migratedFrom: state.genesis.migratedFrom === undefined ? undefined : { position: state.genesis.migratedFrom.position }, counts,
    format2: format2Status(state), readOnly: r.store.readOnlyReason(),
  };
  return {
    json: {
      path: st.path, format: st.format, head, eventCount: st.eventCount, capacity: st.capacity,
      pinnedHead: pin === undefined ? null : { ...pin, status: v.pinnedHeadStatus }, pinnedHeadStatus: v.pinnedHeadStatus, pinnedAttestation: v.pinnedAttestation ?? null,
      ...(v.attestedHead === undefined ? {} : { attestedHead: v.attestedHead }), ...(v.rollbackAcceptedAt === undefined ? {} : { rollbackAcceptedAt: v.rollbackAcceptedAt, previousPin: v.previousPin ?? null }),
      anchorLogStatus: v.anchorLogStatus, anchorLogHeads: v.anchorLogHeads, anchors: st.anchors, owner: st.owner, ownerKeys: st.ownerKeys,
      migratedFrom: state.genesis.migratedFrom ?? null, counts, ...(st.format2 ?? {}), readOnly: st.readOnly ?? null, ok: v.ok, failures: v.failures, notes: v.notes,
    },
    render: (s, out) => renderStatus(s, out, st),
  };
});

// verify opens the file for inspection: a missing or malformed pin is part of its report instead of failing the open.
const verify = command("verify", "verify [--expect-history-id <0x…>] [--expect-owner-key <0x…> | --expect-owner-keys <file>] [--allow-unpinned] [--accept-rollback] [--anchors-file <file>] [--no-remote] [--allow-unreachable-witness]", "check the history's identity against the values you give, then the chain, pinned head and its attestation, anchors, local anchor logs, remote witnesses and control signatures (exit 1 on any failure)", [], [
  o("allow-unpinned", "boolean", "accept a history whose pin is missing or carries no owner attestation (reported as a note, not a failure)"),
  o("accept-rollback", "boolean", "re-pin a history whose pin is behind, missing, malformed or without a valid owner attestation, or whose anchor log holds a later head, as the file is now, attested with the owner key (a write; the pin records the accepted rollback)"),
  o("anchors-file", "string", "also consult this local anchor log (<history>.anchors is always consulted when present)", { value: "<file>" }),
  o("remote", "boolean", "ask the remote witnesses configured for the history or bound in it (default); --no-remote checks the file alone"),
  o("allow-unreachable-witness", "boolean", "a remote witness that cannot be reached is a note instead of a failure (a restored older copy is then not ruled out)"),
  ...IDENTITY_OPTIONS(o),
], async (p, g) => {
  positionals(p, []);
  const path = historyPath(g);
  if (!existsSync(path)) throw new CliError("HISTORY_NOT_FOUND", `no history at ${path}`);
  // Founder decision 4cb: the identity the verifier was given is checked before anything else; a mismatch (or a file whose
  // identity cannot be read) stops here: nothing is re-pinned and no witness is asked.
  // The identity has its own read-only open, apart from the verification's: one more linear read, kept so the identity check
  // does not depend on the verification path (the coordinator's review of post5-08). The re-check after the verification
  // closes the window between the two reads.
  const expected = expectedIdentity(p);
  let found: Identity | undefined, unreadable: { code: string; message: string; detail: string } | undefined;
  try { found = identityOfFile(path); } catch (error) {
    if (!(error instanceof IronTrellisError)) throw error;
    unreadable = { code: error.code, message: describe(error.code, error.message, error.detail), detail: error.message };
  }
  IDENTITY_TEST_SEAMS.afterIdentity?.();
  const mismatches = expected === undefined || found === undefined ? [] : mismatchesOf(expected, found);
  const stopped = mismatches.length > 0 || (expected !== undefined && unreadable !== undefined);
  const acceptRollback = flag(p, "accept-rollback"), allowUnpinned = flag(p, "allow-unpinned");
  // --accept-rollback re-pins (a write) and checks the file alone; otherwise the remote witnesses are asked unless --no-remote.
  const remote = p.options.get("remote") !== false && !acceptRollback;
  const anchorsFile = str(p, "anchors-file") === undefined ? undefined : resolve(str(p, "anchors-file")!);
  if (anchorsFile !== undefined && !existsSync(anchorsFile)) throw new CliError("ANCHORS_NOT_FOUND", `no anchor log at ${anchorsFile}`);
  // The re-pin of --accept-rollback is attested with the owner key when the key file is there.
  const keyPath = ownerKeyPathFor(path);
  const signer: Signer | undefined = acceptRollback && !stopped && existsSync(keyPath) ? loadOwnerKeyFile(keyPath) : undefined;
  let report: OwnerVerification | undefined, thrown: { code: string; message: string; detail: string } | undefined = stopped ? unreadable : undefined;
  if (!stopped) try {
    report = remote
      ? await verifyHistoryWithWitnesses(path, {
        allowUnpinned, ...(anchorsFile === undefined ? {} : { anchorLogs: [localAnchorLog(anchorsFile)] }), ...(flag(p, "allow-unreachable-witness") ? { allowUnreachableWitness: true } : {}),
      })
      // Async: a signer without signHashSync (ssh-agent, command) attests the re-pin after the open; the report waits for it.
      : await verifyHistoryAsync(path, {
        acceptRollback, allowUnpinned, ...(signer === undefined ? {} : { signer }), ...(anchorsFile === undefined ? {} : { anchorLogs: [localAnchorLog(anchorsFile)] }),
      });
  } catch (error) {
    // A damaged file is the verdict, not a command failure: report it with exit 1.
    if (!(error instanceof IronTrellisError)) throw error;
    thrown = { code: error.code, message: describe(error.code, error.message, error.detail), detail: error.message };
  }
  // With values given: the file the verification judged must still be the one whose identity was checked (HISTORY_CHANGED).
  const changed = expected !== undefined && !stopped && found !== undefined && (report !== undefined || thrown !== undefined) ? changedSince(path, found, report?.head) : undefined;
  const identity = identityView(expected, found, mismatches, changed);
  const ok = !stopped && changed === undefined && thrown === undefined && report !== undefined && report.ok;
  const failures = mismatches.length > 0 ? mismatches.map((m) => m.line) : [...(changed === undefined ? [] : [changed]), ...(report?.failures ?? [])], notes = report?.notes ?? [];
  const error = ok ? undefined : (changed === undefined ? undefined : { code: "HISTORY_CHANGED", message: changed.slice("HISTORY_CHANGED: ".length) }) ?? thrown ?? (mismatches.length > 0 ? { code: mismatches[0]!.code, message: mismatches.map((m) => m.line.slice(m.code.length + 2)).join("; ") } : undefined) ?? {
    code: report?.rollback === true ? "ROLLBACK_DETECTED" : "VERIFICATION_FAILED",
    message: `${failures.length === 1 ? "1 check failed" : `${failures.length} checks failed`}: ${failures.map(failureCode).join(", ")}`,
  };
  const view: VerifyView = {
    ok, path: report?.path ?? path, failures, notes, ...(report === undefined ? {} : { report }), ...(error === undefined ? {} : { error }),
    ...(acceptRollback && !stopped ? { acceptRollback: { signed: signer !== undefined } } : {}), identity,
  };
  const warnings = witnessWarnings(report?.remoteWitnesses);
  // A-151.2 is an advisory listing, independent of the verification verdict. Bind the second read
  // to the exact verified head; a concurrent append must not silently mix two report snapshots.
  let checkpointPolicies: Readonly<Record<string, unknown>> | undefined;
  let checkpointFindings: ReturnType<typeof checkpointPolicyListings> = [];
  if (report?.format === TRELLIS2_FORMAT) {
    let inspected: HistoryStore | undefined;
    try {
      inspected = openHistoryStore(path, { inspect: true, allowUnpinned });
      const state = inspected.state();
      if (report.head === undefined || !sameHead(state.head, report.head)) {
        checkpointPolicies = { status: "UNAVAILABLE", reason: "HISTORY_CHANGED" };
      } else {
        checkpointFindings = checkpointPolicyListings(state.ownerKeyEpochs);
        checkpointPolicies = { status: "LISTED", head: state.head, policies: checkpointFindings };
      }
    } catch {
      checkpointPolicies = { status: "UNAVAILABLE", reason: "READ_UNAVAILABLE" };
    } finally { try { inspected?.close(); } catch { /* Advisory cleanup cannot change verification. */ } }
  }
  return {
    json: { ok, path: view.path, failures, notes, warnings, identity, ...(report === undefined ? {} : { report }), ...(error === undefined ? {} : { error }), ...(checkpointPolicies === undefined ? {} : { checkpointPolicies }) },
    render: (s, out) => {
      renderVerify(s, out, view);
      for (const finding of checkpointFindings) out.add(`  Checkpoint policy at position ${finding.fromPosition}: requires ${finding.checkpointThreshold} signatures; ${finding.nonAgentCredentials} non-AGENT credentials. Committee loss may block checkpoints (A-151; advisory only).`);
      if (checkpointPolicies?.status === "UNAVAILABLE") out.add(`  Checkpoint policy listing unavailable: ${String(checkpointPolicies.reason)} (advisory only).`);
    },
    exit: ok ? 0 : 1,
  };
});

/** A path quoted for a POSIX shell when it needs it, so the printed command can be copied as it is. */
const shellWord = (p: string): string => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(p) ? p : `'${p.replace(/'/g, "'\\''")}'`);

/** The end of init (here and in irontrellis-hook): the history id and first owner keys to publish (founder decision 4cb). */
function renderPublish(s: Style, out: Lines, publish: Identity, history: string): void {
  out.blank();
  out.add("Publish these where readers can check them independently of this file:");
  out.add(`  history id  ${publish.historyId}`);
  for (const key of publish.ownerKeys) out.add(`  owner key   ${key}`);
  out.add(s.paint(`A reader checks them with: irontrellis --history ${shellWord(history)} verify --expect-history-id ${publish.historyId}${publish.ownerKeys.map((k) => ` --expect-owner-key ${k}`).join("")}`, "secondary"));
}

/** The pin file as it is on disk, for the report (`undefined` when absent or unparsable). */
const pinOnDisk = (path: string): Readonly<Record<string, unknown>> | undefined => {
  try {
    const value: unknown = JSON.parse(readFileSync(`${path}.head`, "utf8"));
    if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
    const { version: _version, ...pin } = value as Record<string, unknown>;
    return pin;
  } catch {
    return undefined;
  }
};

// repin opens the history leniently (allowUnpinned) so that a pin or witness finding is reported as REPIN_REFUSED with its reason,
// not as the bare open failure; the store's repin() judges the pin and the witnesses again under the writer lock.
const repin = command("repin", "repin [--accept-rollback] [--anchors-file <file>]", "attest the current head with the owner key again; refused when the pin or an anchor log shows a rollback, unless --accept-rollback", [], [
  o("accept-rollback", "boolean", "re-pin although the pin has no valid owner attestation of this file, the file is behind its pin, or the local anchor log holds a later head (a remote witness that holds one still refuses): accept the file as it is (the pin records the accepted rollback and the pin it replaced)"),
  o("anchors-file", "string", "also consult this local anchor log (<history>.anchors is always consulted when present)", { value: "<file>" }),
], async (p, g) => {
  positionals(p, []);
  const path = historyPath(g);
  if (!existsSync(path)) throw new CliError("HISTORY_NOT_FOUND", `no history at ${path}`);
  const acceptRollback = flag(p, "accept-rollback");
  const anchorsFile = str(p, "anchors-file") === undefined ? undefined : resolve(str(p, "anchors-file")!);
  if (anchorsFile !== undefined && !existsSync(anchorsFile)) throw new CliError("ANCHORS_NOT_FOUND", `no anchor log at ${anchorsFile}`);
  const anchorLogs: AnchorTarget[] = anchorsFile === undefined ? [] : [localAnchorLog(anchorsFile)];
  const keyPath = ownerKeyPathFor(path);
  const signer = existsSync(keyPath) ? loadOwnerKeyFile(keyPath) : undefined;
  // Format and key first, before an --accept-rollback open could re-pin anything.
  const probe = openHistoryStore(path, { inspect: true });
  if (probe.head() === undefined) throw new CliError("HISTORY_EMPTY", `history ${path} has no events`);
  try { writableFormat(probe, "repin"); } finally { probe.close(); }
  if (signer === undefined) throw new CliError("KEY_UNAVAILABLE", `no owner key file at ${keyPath}`);
  const previous = pinOnDisk(path);
  let store: HistoryStore;
  try {
    store = openHistoryStore(path, { signer, lockTimeoutMs: LOCK_WAIT_MS, ...(acceptRollback ? { acceptRollback: true } : { allowUnpinned: true }) });
  } catch (error) {
    if (error instanceof EngineError && (error.code === "ROLLBACK_DETECTED" || error.code === "ANCHOR_LOG_UNREADABLE")) {
      const detail = (error.detail ?? {}) as Record<string, unknown>;
      throw new CliError("REPIN_REFUSED", `repin refused: ${error.message}`, { ...detail, reason: detail.reason ?? error.code, cause: error.code });
    }
    throw error;
  }
  const pin = store.repin({ acceptRollback, anchorLogs });
  try {
    await store.flush();
  } catch (error) {
    // flush() also submits to remote witnesses; an unreachable one leaves the head statement queued (the attestation is written).
    if (!(error instanceof EngineError && ["WITNESS_UNAVAILABLE", "WITNESS_REJECTED", "WITNESS_INVALID_RESPONSE"].includes(error.code))) throw error;
  }
  const v = store.verify({ allowUnpinned: false, anchorLogs });
  const accepted = pin.rollbackAcceptedAt !== undefined;
  return {
    json: {
      repinned: store.path, pin, previousPin: previous ?? null, acceptedRollback: accepted, pinnedHeadStatus: v.pinnedHeadStatus, pinnedAttestation: v.pinnedAttestation ?? null,
      anchorLogStatus: v.anchorLogStatus, ok: v.ok, failures: v.failures, notes: v.notes,
    },
    render: (s, out) => {
      out.add(`REPINNED  ${store.path}`);
      out.add(`  ${s.paint("pinned head", "secondary")}  ${pinLine(v)}`);
      out.add(`  ${s.paint("previous   ", "secondary")}  ${previous === undefined ? "none" : `position ${String(previous.position)} · ${previous.attestation === undefined ? "no owner attestation" : "attested"}`}`);
      if (accepted) out.add(s.paint(`The rollback was accepted: the pin records it (rollbackAcceptedAt) and the pin it replaced.`, "secondary"));
      out.add(s.paint(v.ok ? "The pin now carries the owner's attestation of the current head; verify passes."
        : `verify still reports: ${v.failures.map(failureCode).join(", ")}.${v.anchorLogStatus === "ROLLBACK" ? " A anchor log still holds heads this file lacks: archive it deliberately once the rollback is understood." : ""}`, "secondary"));
    },
    exit: v.ok ? 0 : 1,
  };
});


const migrate = command("migrate", "migrate <source> <target> [--plan <file>] [--accept-unpinned-source] [--reuse-existing-key] [--owner-key-ref <file> | --signer ssh-agent|command --public-key <key> [signer options] | --signer vault-transit --vault-addr <url> --vault-key <name> [vault options]] [--no-next-key | --next-public-key <key> | --next-key-ref <file>] | migrate --status [<plan>]", "transcribe a Continuity 0.2 or format-1 history into a signed format-2 history (SPEC §16.2: plan, target, pin, snapshot, then the .migrated fence beside the source), under a new owner key file or a key a signer holds; a re-run resumes the same plan; --status reports the phase from the files", ["source", "target"], [
  o("status", "boolean", "report where a migration stands: with <plan>, its phase (PLANNED, WRITTEN, PINNED, FENCED), whether its outputs verify and the next step; without one, whether the --history file is native format 2, a migration target, a fenced source or an older file that still needs migrating"),
  o("plan", "string", "the plan file (default <target>.migration-plan.json)", { value: "<file>" }),
  o("accept-unpinned-source", "boolean", "migrate a source without a matching pinned head; required for Continuity-written histories, which have no pin (check the source first: migration signs it under the new owner key)"),
  o("reuse-existing-key", "boolean", "adopt an owner key file already at <target>.owner-key.json (refused with KEY_EXISTS by default; with a key reference, only a file naming the same key), and a next-key file already at <target>.owner-next-key.json as the committed next key"),
  o("next-key", "boolean", "commit the target's genesis to a next owner key (default): the key is written to <target>.owner-next-key.json, to be moved off this host; --no-next-key migrates without a commitment (add one later with owner commit-next-key)"),
  o("next-public-key", "string", "commit to this next key (ssh-ed25519 AAAA… or 0x + 64 hex) whose private half never touches this host; nothing is written for it", { value: "<key>" }),
  o("next-key-ref", "string", "commit to the next key this key reference names (its signer must prove possession first); the reference is copied to <target>.owner-next-key.json (no secret)", { value: "<file>" }),
  o("session-time-horizon", "number", "set the target genesis's session time horizon in ms (A-179); sessions that survive the prefix cannot write until the first time-advancing owner event after it", { value: "<ms>" }),
  o("owner-key-ref", "string", "the target's owner key is held by the signer this key reference names (irontrellis signer ref writes one); it is copied to <target>.owner-key.json (no secret) and no key material is generated", { value: "<file>" }),
  ...SIGNER_OPTIONS,
  id("key-id", "string", "with --signer: the owner key's id (default owner:1)", { value: "<id>" }),
], async (p, g) => {
  if (flag(p, "status")) return migrateStatus(p, g);
  const [source, target] = positionals(p, ["source", "target"], false);
  if (p.options.has("owner-key-ref") && p.options.has("signer")) throw new UsageError("give the owner key once: --owner-key-ref <file> or --signer <kind> --public-key <key>");
  if (p.options.has("key-id") && !p.options.has("signer")) throw new UsageError("--key-id goes with --signer (a reference file carries its own key id)");
  const ownerKeyReference = str(p, "owner-key-ref") !== undefined ? readReferenceFile(str(p, "owner-key-ref")!, "owner-key-ref") : await inlineReference(p, str(p, "key-id") ?? "owner:1");
  const nextPublicKey = publicKeyFlag(p, "next-public-key");
  const nextKeyReference = str(p, "next-key-ref") === undefined ? undefined : readReferenceFile(str(p, "next-key-ref")!, "next-key-ref");
  if (nextPublicKey !== undefined && nextKeyReference !== undefined) throw new UsageError("give the next key once: --next-public-key or --next-key-ref");
  if ((nextPublicKey !== undefined || nextKeyReference !== undefined) && p.options.get("next-key") === false) throw new UsageError("--no-next-key excludes --next-public-key and --next-key-ref");
  const result = await migrateHistory({
    source: resolve(source!), target: resolve(target!), now: () => Date.now(), ...(str(p, "plan") === undefined ? {} : { plan: resolve(str(p, "plan")!) }),
    ...(flag(p, "accept-unpinned-source") ? { acceptUnpinnedSource: true } : {}), ...(flag(p, "reuse-existing-key") ? { reuseExistingKey: true } : {}),
    ...(ownerKeyReference === undefined ? {} : { ownerKeyReference }),
    ...(p.options.get("next-key") === false ? { nextKey: false } : {}), ...(nextPublicKey === undefined ? {} : { nextPublicKey }),
    ...(nextKeyReference === undefined ? {} : { nextKeyReference }),
    ...(num(p, "session-time-horizon") === undefined ? {} : { sessionTimeHorizonMs: num(p, "session-time-horizon")! }),
  });
  const keyFile = ownerKeyPathFor(resolve(target!));
  // What holds the key is read from the file on disk, never inferred from the flags.
  const onDisk = loadOwnerKeyFile(keyFile);
  const holder = onDisk.custody?.holder === "reference" ? "reference" : "file";
  const signerLine = holder === "reference" ? custodyLine(onDisk) : null;
  return {
    json: {
      migrated: resolve(source!), ...result, ownerKeyFile: keyFile, ownerKeyHolder: holder, ownerKeySigner: signerLine,
      nextKeyCommitted: result.nextKeyDigests !== undefined, nextKeyDigests: result.nextKeyDigests ?? null, nextKeyFile: result.nextKeyFile ?? null,
    },
    render: (s, out) => {
      out.add(`MIGRATED  ${resolve(source!)} → ${resolve(target!)}`);
      out.add(`  ${s.paint("events    ", "secondary")}  ${result.eventCount} (source head position ${result.sourceHead.position})`);
      out.add(`  ${s.paint("target    ", "secondary")}  ${headLine(result.targetHead)} · state root ${result.stateRoot} · ${result.phase} (source fenced: ${resolve(source!)}.migrated; plan ${result.plan})`);
      out.add(`  ${s.paint("historyId ", "secondary")}  ${result.historyId} (set it as "historyId" in hook and gateway configs; point them at the target: the fenced source is refused, A-41)`);
      out.add(holder === "reference"
        ? `  ${s.paint("owner key ", "secondary")}  ${result.ownerKeyId} held by ${signerLine!} · ${keyFile} is a reference (no secret; mode 0600)`
        : `  ${s.paint("owner key ", "secondary")}  ${keyFile} (${result.ownerKeyId})`);
      if (result.nextKeyFile !== undefined && nextKeyReference !== undefined) out.add(`  ${s.paint("next key  ", "secondary")}  committed · held by ${custodyLine(loadNextOwnerKeyFile(result.nextKeyFile))} · ${result.nextKeyFile} is a reference`);
      else if (result.nextKeyFile !== undefined) out.add(`  ${s.paint("next key  ", "secondary")}  ${result.nextKeyFile} (mode 0600 — the only key that can rotate the owner key; move it off this host)`);
      else if (result.nextKeyDigests !== undefined) out.add(`  ${s.paint("next key  ", "secondary")}  committed${nextPublicKey === undefined ? "" : " · public key only (its private half is not on this host)"}`);
      else out.add(`  ${s.paint("next key  ", "secondary")}  none (irontrellis owner commit-next-key adds one)`);
      // A-179.4: with a horizon, sessions surviving the prefix wait for the first post-migration time-advancing owner event.
      if (num(p, "session-time-horizon") !== undefined) out.add(`  ${s.paint("horizon   ", "secondary")}  ${num(p, "session-time-horizon")} ms: sessions that survive the prefix cannot write until the first time-advancing owner event after the migration`);
      out.add(s.paint("The source file is untouched and remains the archive; the target genesis names its final head.", "secondary"));
    },
  };
});

/** What to do next in each phase (SPEC §16.2): a re-run of the same plan resumes it. */
const NEXT_STEP: Readonly<Record<string, string>> = {
  PLANNED: "run the same irontrellis migrate command again: it writes the target from the plan",
  WRITTEN: "run the same irontrellis migrate command again: it pins and fences",
  PINNED: "run the same irontrellis migrate command again: it writes the fence beside the source",
  FENCED: "done: point hooks, gateways and the CLI at the target; the source stays a read-only archive",
};
/** `migrate --status [<plan>]`: the plan's phase from the actual files, or, without a plan, what the --history file is. */
async function migrateStatus(p: Parsed, g: Global): Promise<Outcome> {
  if (p.positionals.length > 1) throw new UsageError(`unexpected argument "${p.positionals[1]}"`);
  const plan = p.positionals[0];
  if (plan === undefined) {
    const path = historyPath(g);
    if (!existsSync(path)) throw new CliError("HISTORY_NOT_FOUND", `no history at ${path}`);
    const store = openHistoryStore(path, { inspect: true, witness: false });
    let view: Record<string, unknown>;
    try {
      const state = store.state(), marker = readMigratedMarker(path), from = state.genesis.migratedFrom;
      const kind = marker !== undefined ? "FENCED_SOURCE" : from !== undefined ? "MIGRATION_TARGET" : state.format === TRELLIS2_FORMAT ? "NATIVE_FORMAT_2" : "NEEDS_MIGRATION";
      view = {
        history: path, format: state.format, kind, head: state.head,
        ...(marker === undefined ? {} : { target: markerTargetPath(path, marker.target), targetHead: marker.targetHead, migratedAt: marker.migratedAt }),
        ...(from === undefined ? {} : { migratedFrom: { format: from.format, position: from.position, historyHash: from.historyHash } }),
        next: kind === "NEEDS_MIGRATION" ? `irontrellis migrate ${path} <target.jsonl>${state.format === LEGACY_FORMAT ? " --accept-unpinned-source" : ""}` : kind === "FENCED_SOURCE" ? `use the target ${markerTargetPath(path, marker!.target)}` : "nothing to migrate",
      };
    } finally { store.close(); }
    return {
      json: view,
      render: (s, out) => {
        const words: Readonly<Record<string, string>> = {
          NATIVE_FORMAT_2: "a format-2 history created in format 2: there is nothing to migrate",
          MIGRATION_TARGET: `a format-2 history migrated from ${String((view.migratedFrom as Record<string, unknown> | undefined)?.format)} (the source's head was position ${String((view.migratedFrom as Record<string, unknown> | undefined)?.position)})`,
          FENCED_SOURCE: `a migrated source, kept read only; its target is ${String(view.target)}`,
          NEEDS_MIGRATION: `a ${String(view.format)} history this release reads but does not write`,
        };
        out.add(`${String(view.kind)}  ${path}`);
        out.add(`  ${s.paint("is        ", "secondary")}  ${words[view.kind as string]}`);
        out.add(`  ${s.paint("next      ", "secondary")}  ${String(view.next)}`);
      },
    };
  }
  const status = migrationStatus(resolve(plan));
  let target: Record<string, unknown> | undefined;
  if (status.outputs.target) {
    try {
      const store = openHistoryStore(status.target, { inspect: true, witness: false });
      try { const st = store.state(), root = st.stateRoots.at(-1); target = { head: st.head, historyId: st.eventHistoryHashes[0], ...(root === undefined ? {} : { stateRoot: root, recordCount: st.stateRecords.size }) }; } finally { store.close(); }
    } catch (error) { target = { error: codeOf(error).code }; }
  }
  const next = status.verified ? NEXT_STEP[status.phase] : "fix the problems below (or remove the outputs it names), then run the same irontrellis migrate command again";
  return {
    json: { ...status, ...(target === undefined ? {} : { targetState: target }), next },
    render: (s, out) => {
      out.add(`${status.phase.padEnd(9)} ${status.source} → ${status.target}`);
      out.add(`  ${s.paint("verified  ", "secondary")}  ${status.verified ? "yes" : "no"}`);
      out.add(`  ${s.paint("source    ", "secondary")}  ${headLine(status.sourceHead)}`);
      out.add(`  ${s.paint("outputs   ", "secondary")}  target ${status.outputs.target ? "yes" : "no"} · pin ${status.outputs.pin ? "yes" : "no"} · snapshot ${status.outputs.snapshot ? "yes" : "no"} · fence ${status.outputs.fence ? "yes" : "no"}`);
      if (target?.head !== undefined) out.add(`  ${s.paint("target    ", "secondary")}  ${headLine(target.head as HistoryHead)}${target.stateRoot === undefined ? "" : ` · state root ${String(target.stateRoot)}`}`);
      if (target?.historyId !== undefined) out.add(`  ${s.paint("historyId ", "secondary")}  ${String(target.historyId)}`);
      for (const problem of status.problems) out.add(`  ${s.paint("problem   ", "secondary")}  ${problem}`);
      out.add(`  ${s.paint("next      ", "secondary")}  ${next}`);
    },
  };
}

// ---------------------------------------------------------------- agents, roles, sessions, succession

const agentCreate = command("agent create", "agent create <id>", "register an agent under the owner and controller", ["id"], [], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  return written(`agent ${id}`, await write(g, (w) => w.owner.createAgent({ id: id! })));
});
const agentTerminate = command("agent terminate", "agent terminate <id> --succession <rule> --role <role> --tenure <tenure>", "terminate an agent under a succession rule", ["id"], [
  id("succession", "string", "the succession rule", { value: "<rule>", required: true }),
  id("role", "string", "the role the rule covers", { value: "<role>", required: true }),
  id("tenure", "string", "the agent's current tenure of that role", { value: "<tenure>", required: true }),
], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  return written(`termination of ${id}`, await write(g, (w) => w.owner.terminate({ agent: id!, succession: need(p, "succession"), role: need(p, "role"), tenure: need(p, "tenure") })));
});
// Roles are exclusive (one current tenure): both history formats require it, so there is no shared-role option.
const roleCreate = command("role create", "role create <id>", "create an exclusive role (one current tenure at a time)", ["id"], [], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  return written(`role ${id}`, await write(g, (w) => w.owner.createRole({ id: id! })));
});
const appoint = command("appoint", "appoint <agent> --role <role> --tenure <id> --number <n> [--succession <rule>]", "open a role tenure for an agent", ["agent"], [
  id("role", "string", "the role", { value: "<role>", required: true }),
  id("tenure", "string", "identifier of the new tenure", { value: "<id>", required: true }),
  o("number", "number", "tenure number (1 for the first holder)", { value: "<n>", required: true }),
  id("succession", "string", "succession rule that governs this tenure", { value: "<rule>" }),
], async (p, g) => {
  const [agent] = positionals(p, ["agent"]);
  return written(`appointment of ${agent}`, await write(g, (w) => w.owner.appoint({
    agent: agent!, role: need(p, "role"), tenure: need(p, "tenure"), number: num(p, "number")!, ...(str(p, "succession") === undefined ? {} : { succession: str(p, "succession")! }),
  })));
});
const unappoint = command("unappoint", "unappoint <agent> --role <role> --tenure <id>", "close an agent's role tenure", ["agent"], [
  id("role", "string", "the role", { value: "<role>", required: true }),
  id("tenure", "string", "the tenure to close", { value: "<id>", required: true }),
], async (p, g) => {
  const [agent] = positionals(p, ["agent"]);
  return written(`unappointment of ${agent}`, await write(g, (w) => w.owner.unappoint({ agent: agent!, role: need(p, "role"), tenure: need(p, "tenure") })));
});
const successionDeclare = command("succession declare", "succession declare <id> --from <agent> --to <agent> --role <role>", "declare who succeeds whom in a role", ["id"], [
  id("from", "string", "the predecessor", { value: "<agent>", required: true }),
  id("to", "string", "the successor", { value: "<agent>", required: true }),
  id("role", "string", "the role", { value: "<role>", required: true }),
], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  return written(`succession rule ${id}`, await write(g, (w) => w.owner.declareSuccession({ id: id!, from: need(p, "from"), to: need(p, "to"), role: need(p, "role") })));
});
const succeed = command("succeed", "succeed <id> --rule <rule> --from <agent> --from-tenure <t> --to <agent> --to-tenure <t> --role <role> --number <n>", "hand a role over: terminate the predecessor and transfer the tenure", ["id"], [
  id("rule", "string", "the declared succession rule", { value: "<rule>", required: true }),
  id("from", "string", "the predecessor", { value: "<agent>", required: true }),
  id("from-tenure", "string", "the predecessor's tenure", { value: "<tenure>", required: true }),
  id("to", "string", "the successor", { value: "<agent>", required: true }),
  id("to-tenure", "string", "the successor's new tenure", { value: "<tenure>", required: true }),
  id("role", "string", "the role", { value: "<role>", required: true }),
  o("number", "number", "the new tenure number", { value: "<n>", required: true }),
], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  const result = await write(g, (w) => w.owner.succeed({
    id: id!, rule: need(p, "rule"), fromAgent: need(p, "from"), fromTenure: need(p, "from-tenure"), toAgent: need(p, "to"), toTenure: need(p, "to-tenure"), role: need(p, "role"), number: num(p, "number")!,
  }));
  return {
    json: { recorded: `handover ${id}`, ...result },
    render: (s, out) => {
      out.add(`${result.status}  handover ${id}: ${need(p, "from")} → ${need(p, "to")} as ${need(p, "role")}`);
      out.add(`  ${s.paint("events", "secondary")}  ${result.eventIds.join(", ")}`);
      out.add(`  ${s.paint("head  ", "secondary")}  ${headLine(result.head)}`);
      // A-174.2: the seal needs M_eff(STATE_CHECKPOINT) signers; this handle alone could not sign it.
      if (result.checkpoint !== undefined) out.add(`  ${s.paint("seal  ", "secondary")}  not written (${result.checkpoint.code} ${result.checkpoint.reason}): the policy needs more owner signatures for a checkpoint; write it with the two-phase API (prepareControlEvent, submitControlEvent)`);
      out.add(s.paint("The successor holds the role, not the predecessor's grants; duties follow when the successor's session assigns them.", "secondary"));
    },
  };
});
const sessionAdmit = command("session admit", "session admit <id> --agent <a> --epoch <n> --key <keyId> --expires <t> (--credential <0x…> | --address <0x…> | --new-key <file>)", "admit a runtime session for an agent", ["id"], [
  id("agent", "string", "the agent the session acts for", { value: "<agent>", required: true }),
  o("epoch", "number", "the agent's current control epoch", { value: "<n>", required: true }),
  id("key", "string", "credential key id (unique per history)", { value: "<keyId>", required: true }),
  o("expires", "string", "session expiry", { value: TIME, required: true }),
  o("credential", "string", "ed25519 public key (0x + 64 hex) or eip191 address", { value: "<0x…>" }),
  o("address", "string", "legacy credential: an Ethereum address", { value: "<0x…>" }),
  o("new-key", "string", "generate a key pair, write it here (mode 0600) and admit its public key", { value: "<file>" }),
  o("scheme", "string", "credential scheme for --new-key: ed25519 (default in format 1) or eip191-personal-sign-keccak256", { value: "<scheme>" }),
], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  const reader = await openReader(g);
  const given = ["credential", "address", "new-key"].filter((name) => str(p, name) !== undefined);
  if (given.length !== 1) throw new UsageError("give exactly one of --credential, --address or --new-key");
  let credential: { credential: string } | { address: string };
  let keyFile: string | undefined;
  if (str(p, "new-key") !== undefined) {
    const scheme = str(p, "scheme") ?? (reader.state.format === LEGACY_FORMAT ? "eip191-personal-sign-keccak256" : "ed25519");
    if (scheme !== "ed25519" && scheme !== "eip191-personal-sign-keccak256") throw new UsageError(`--scheme: unknown scheme "${scheme}"`);
    const pair = generateKeyPair(scheme, need(p, "key"));
    keyFile = resolve(str(p, "new-key")!);
    let fd: number;
    try {
      fd = openSync(keyFile, "wx", 0o600);
    } catch (error) {
      if ((error as { code?: unknown }).code === "EEXIST") throw new CliError("FILE_EXISTS", `--new-key: ${keyFile} already exists; a session key file is never overwritten`);
      // A missing directory, no permission, a name too long…: nothing was written or admitted.
      throw new CliError("FILE_UNWRITABLE", `--new-key: ${keyFile} cannot be created (${(error as { code?: unknown }).code ?? "error"}: ${error instanceof Error ? error.message : String(error)}); nothing was admitted`);
    }
    try { writeSync(fd, `${JSON.stringify({ version: "irontrellis-session-key/1", keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, privateKey: pair.privateKey }, null, 2)}\n`); } finally { closeSync(fd); }
    credential = { credential: pair.credential };
  } else if (str(p, "credential") !== undefined) credential = { credential: str(p, "credential")! };
  else credential = { address: str(p, "address")! };
  const result = await write(g, (w) => w.owner.admitRuntime({ session: id!, agent: need(p, "agent"), epoch: num(p, "epoch")!, key: need(p, "key"), expiresAt: parseTime(need(p, "expires"), "expires"), ...credential }));
  const base = written(`session ${id}`, result);
  return { ...base, json: { ...(base.json as object), ...(keyFile === undefined ? {} : { keyFile }) }, render: (s, out) => { base.render(s, out); if (keyFile !== undefined) out.add(`  ${s.paint("key file", "secondary")}  ${keyFile} (private; the history holds only the public credential)`); } };
});
const epochAdvance = command("epoch advance", "epoch advance <agent> --from <n> --to <n>", "advance an agent's control epoch (fences its current sessions)", ["agent"], [
  o("from", "number", "the current epoch", { value: "<n>", required: true }),
  o("to", "number", "the next epoch (from + 1)", { value: "<n>", required: true }),
], async (p, g) => {
  const [agent] = positionals(p, ["agent"]);
  return written(`epoch ${num(p, "to")} for ${agent}`, await write(g, (w) => w.owner.advanceEpoch({ agent: agent!, from: num(p, "from")!, to: num(p, "to")! })));
});

// ---------------------------------------------------------------- authority

const grant = command("grant", "grant <id> --to <agent> --actions <a,b> --resources <r1,r2> --expires <t> [constraints]", "grant a permission from the owner (or --from a grantor with --parent)", ["id"], [
  ...GRANT_OPTIONS,
  id("parent", "string", "parent authority of a delegation", { value: "<id>" }),
  id("from", "string", "grantor (default the owner)", { value: "<agent>" }),
], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  return written(`grant ${id}`, await write(g, (w) => w.owner.grant(grantInput(p, id!))));
});
const delegate = command("delegate", "delegate <id> --parent <grant> --from <agent> --to <agent> --actions <a,b> --resources <r1,r2> --expires <t> [constraints]", "delegate under an existing grant (attenuation is enforced on replay)", ["id"], [
  ...GRANT_OPTIONS,
  id("parent", "string", "the grant being delegated", { value: "<id>", required: true }),
  id("from", "string", "the delegating agent (holder of --parent)", { value: "<agent>", required: true }),
], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  const input = grantInput(p, id!);
  return written(`delegation ${id}`, await write(g, (w) => w.owner.delegate({ ...input, parent: need(p, "parent"), from: need(p, "from") })));
});
const prohibit = command("prohibit", "prohibit <id> --actions <a,b> --resources <r1,r2> (--root <grant> | --global) [--subject <agent>] [--expires <t>]", "record a prohibition on a root grant or globally", ["id"], [
  id("actions", "list", "prohibited actions", { value: "<a,b>", required: true }),
  id("resources", "list", "prohibited resources", { value: "<r1,r2>", required: true }),
  id("subject", "string", "limit the prohibition to one agent", { value: "<agent>" }),
  id("root", "string", "the root grant the prohibition applies under", { value: "<id>" }),
  id("anchor", "string", "the issuing agent's own permission on that root (with --from)", { value: "<id>" }),
  id("from", "string", "issuing agent (default the owner)", { value: "<agent>" }),
  o("global", "boolean", "issue from the genesis policy source instead of a root"),
  o("expires", "string", "expiry time", { value: TIME }),
  o("not-before", "string", "validity start", { value: TIME }),
  o("max-amount", "string", "amount threshold", { value: "<integer>" }),
], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  return written(`prohibition ${id}`, await write(g, (w) => w.owner.prohibit({
    id: id!, actions: list(p, "actions")!, resources: list(p, "resources")!,
    ...(str(p, "subject") === undefined ? {} : { subject: str(p, "subject")! }),
    ...(str(p, "root") === undefined ? {} : { root: str(p, "root")! }),
    ...(str(p, "anchor") === undefined ? {} : { anchor: str(p, "anchor")! }),
    ...(str(p, "from") === undefined ? {} : { from: str(p, "from")! }),
    ...(flag(p, "global") ? { global: true } : {}),
    ...optionalTime(str(p, "expires"), "expiresAt"), ...optionalTime(str(p, "not-before"), "notBefore"),
    ...(str(p, "max-amount") === undefined ? {} : { maxAmount: parseAmount(str(p, "max-amount")!, "max-amount") }),
  })));
});
const revoke = command("revoke", "revoke <id>", "revoke a grant, delegation or prohibition (always admitted)", ["id"], [], async (p, g) => {
  const [id] = positionals(p, ["id"]);
  return written(`revocation of ${id}`, await write(g, (w) => w.owner.revoke(id!)));
});

// ---------------------------------------------------------------- questions

const authorize = command("authorize", "authorize --actor <agent> --action <name> --resource <id> [--amount <n>] [--counterparty <id>] [--metric <name>] [--record-refusal --session <id> --session-key <file>]", "decide an action (exit 0 ALLOW, 2 DENY, 3 INDETERMINATE); with --record-refusal a DENY or INDETERMINATE answer is recorded in the history", [], [
  ...ACTION_OPTIONS, o("metric", "string", "the request metric budgets are matched against (default amount; format 2)", { value: "<name>" }), ...REFUSAL_OPTIONS,
], async (p, g) => {
  positionals(p, []);
  const record = flag(p, "record-refusal");
  if (!record && (p.options.has("session") || p.options.has("session-key"))) throw new UsageError("--session and --session-key go with --record-refusal");
  if (record && g.at !== undefined) throw new UsageError("--record-refusal decides at the writer's own time; do not pass --at");
  const a = action(p), r = await openReader(g), at = evaluationTime(g), metric = str(p, "metric");
  if (metric !== undefined && r.state.format !== TRELLIS2_FORMAT) throw new UsageError("--metric needs a format-2 history");
  const decision = observe(r, g).authorize(metric === undefined ? a : { ...a, metric } as Action);
  // SPEC §10.1.1: the writer re-derives the decision at its own time and head before it signs; an ALLOW there is REFUSAL_NOT_REPRODUCED.
  const refusal = record && decision.decision !== "ALLOW"
    ? await recordRefusal(g, p, { actorId: a.actor, action: a.action, resource: a.resource, claimedAt: Date.now(), ...(a.amount === undefined ? {} : { amount: a.amount.toString() }),
      ...(a.counterparty === undefined ? {} : { counterpartyId: a.counterparty }), ...(a.termsCommitment === undefined ? {} : { termsCommitment: a.termsCommitment }), ...(metric === undefined ? {} : { metric }) })
    : undefined;
  return {
    json: { request: a, ...decision, ...(refusal === undefined ? {} : { refusal }) },
    render: (s, out) => renderAuthorize(s, out, a, decision.evidence, decision.head, at, refusal),
    exit: decision.decision === "ALLOW" ? 0 : decision.decision === "DENY" ? 2 : 3,
  };
});
const why = command("why", "why (--actor <agent> --action <name> --resource <id> [--position <n>] | --intent <id>)", "WHY: the recorded grants behind a decision", [], [...ACTION_OPTIONS, POSITION, INTENT], async (p, g) => {
  positionals(p, []);
  const r = await openReader(g);
  const q = queryAt(r, g, num(p, "position"), str(p, "intent"));
  const a = requestOf(p, q);
  const result = q.why(a);
  return { json: { request: a, ...result }, render: (s, out) => renderWhy(s, out, a, result, q.at) };
});
const responsible = command("responsible", "responsible (--actor <agent> --action <name> --resource <id> [--position <n>] | --intent <id>)", "RESPONSIBLE: who is attributed for an action, then and now", [], [...ACTION_OPTIONS, POSITION, INTENT], async (p, g) => {
  positionals(p, []);
  const r = await openReader(g);
  const q = queryAt(r, g, num(p, "position"), str(p, "intent"));
  const a = requestOf(p, q);
  const result = q.responsible(a);
  return { json: { request: a, ...result }, render: (s, out) => renderResponsible(s, out, a, result, q.at) };
});
const survives = command("survives", "survives <agent>", "SURVIVES: what outlives an agent (tenures, duties, intents)", ["agent"], [], async (p, g) => {
  const [agent] = positionals(p, ["agent"]);
  const r = await openReader(g), at = evaluationTime(g);
  const result = observe(r, g).survives(agent!);
  return { json: { agent, ...result }, render: (s, out) => renderSurvives(s, out, agent!, result, at) };
});
const handover = command("handover", "handover <agent>", "the offboarding report: open duties, grants that do not follow, sessions", ["agent"], [], async (p, g) => {
  const [agent] = positionals(p, ["agent"]);
  const r = await openReader(g);
  const report = handoverReport(r.state, agent!, evaluationTime(g));
  return { json: report, render: (s, out) => renderHandover(s, out, report) };
});
const capacityCommand = command("capacity", "capacity", "the point-in-time capacity report", [], [], async (p, g) => {
  positionals(p, []);
  const report = capacity(await openReader(g));
  return { json: report, render: (s, out) => renderCapacity(s, out, report) };
});

// ---------------------------------------------------------------- owner keys

/** Format 2 (A-91, A-96.4): the owner approval policy a rotation sets. Without either flag a key rotation keeps only the default. */
const policyOptions = [
  o("owner-policy", "string", "format 2: the owner approval policy the new owner keys get, as a JSON file ({\"threshold\": 2, …}, docs/HISTORY-FORMAT.md §15); restate the policy in force to keep it", { value: "<file>" }),
  o("reset-policy", "boolean", "format 2: return the owner approval policy to the default (any one owner key signs); a rotation under a policy is refused without --owner-policy or this flag"),
];
function policyFlags(p: Parsed): { ownerPolicy?: OwnerPolicy; resetPolicy?: true } {
  const file = str(p, "owner-policy");
  if (file !== undefined && flag(p, "reset-policy")) throw new UsageError("give the owner approval policy once: --owner-policy <file> or --reset-policy");
  if (flag(p, "reset-policy")) return { resetPolicy: true };
  if (file === undefined) return {};
  let value: unknown;
  try { value = JSON.parse(readFileSync(resolve(file), "utf8")); } catch (error) { throw new UsageError(`--owner-policy: cannot read a JSON policy from ${file}: ${error instanceof Error ? error.message : String(error)}`); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new UsageError(`--owner-policy: ${file} must hold a JSON object such as {"threshold": 2}`);
  return { ownerPolicy: value as OwnerPolicy };
}

/** A-151: the current policy's checkpoint dependency, listed after owner writes without changing their validity. */
const currentCheckpointPolicies = (st: ReturnType<typeof ownerKeyStatusOf>) => checkpointPolicyListings([
  { fromPosition: st.fromPosition, keys: st.ownerKeys, ...(st.ownerPolicy === null ? {} : { policy: st.ownerPolicy }) },
]);
const checkpointPolicyMessages = (st: ReturnType<typeof ownerKeyStatusOf>): readonly string[] => currentCheckpointPolicies(st).map(
  (p) => `Checkpoint policy at position ${p.fromPosition}: requires ${p.checkpointThreshold} signatures; ${p.nonAgentCredentials} non-AGENT credentials. Committee loss may block checkpoints (A-151; advisory only).`,
);
/** What `init`, `owner rotate-key` and `owner commit-next-key` report about the next key (pre-rotation). */
const nextKeyView = (st: ReturnType<typeof ownerKeyStatusOf>) => ({
  nextKeyCommitted: st.commitment !== null, nextKeyDigests: st.commitment?.nextKeyDigests ?? null,
  nextKeyFile: st.nextKeyFile?.state === "COMMITTED" ? st.nextKeyFile.path : null, warnings: st.warnings, checkpointPolicies: currentCheckpointPolicies(st),
});

const ownerRotateKey = command("owner rotate-key", "owner rotate-key [--next-key <file> | --next-key-ref <file>] [--new-next-public-key <key> | --new-next-key-ref <file>] [--reason <text>] [--key-id <id>] [--emergency] [--owner-policy <file> | --reset-policy]", "replace the owner key: record OWNER_KEYS_ROTATED signed by the current key; with a committed next key, that key becomes the owner key and a fresh next key is committed. With bound witnesses, every bound witness first records the prepared rotation (two phases)", [], [
  o("next-key", "string", "the next-key file holding the key the owner keys in force committed to (default <history>.owner-next-key.json when it is there): bring it back from offline storage for the rotation", { value: "<file>" }),
  o("next-key-ref", "string", "the committed next key is held by a signer: this next-key reference names it (irontrellis signer ref --next); the signer signs the revealed key's proof and the key becomes the owner key, still held by that signer", { value: "<file>" }),
  o("new-next-public-key", "string", "commit the new owner key set to this next key (ssh-ed25519 AAAA… or 0x + 64 hex), held off this host; nothing is written for it (default: a fresh next-key file)", { value: "<key>" }),
  o("new-next-key-ref", "string", "commit the new owner key set to the key this reference names; the reference becomes <history>.owner-next-key.json", { value: "<file>" }),
  o("emergency", "boolean", "rotate locally first and deliver to the witnesses afterwards (queue, key-event bundle): for a leaked key while a bound witness is down; a pre-rotated rotation later supersedes whatever the old key signed at that witness meanwhile"),
  o("reason", "string", "why the key is replaced, recorded in the event (1..256 bytes, no control characters)", { value: "<text>" }),
  id("key-id", "string", "id of the new owner key (default the id the next-key file proposes, or the next free owner:N)", { value: "<id>" }),
  ...policyOptions,
], async (p, g) => {
  positionals(p, []);
  const reason = str(p, "reason"), keyId = str(p, "key-id"), policy = policyFlags(p);
  if (p.options.has("next-key") && p.options.has("next-key-ref")) throw new UsageError("give the committed next key once: --next-key <file> or --next-key-ref <file>");
  const nextKeyFlag = p.options.has("next-key-ref") ? "next-key-ref" : "next-key";
  const nextKeyFile = str(p, nextKeyFlag) === undefined ? undefined : resolve(str(p, nextKeyFlag)!);
  if (nextKeyFile !== undefined && !existsSync(nextKeyFile)) throw new CliError("NEXT_KEY_NOT_FOUND", `no next-key ${nextKeyFlag === "next-key-ref" ? "reference" : "file"} at ${nextKeyFile}`);
  // A next-key reference is a next-key file too (the owner API reads both): --next-key-ref only checks that it is one.
  if (nextKeyFile !== undefined && nextKeyFlag === "next-key-ref") readReferenceFile(nextKeyFile, "next-key-ref");
  if (p.options.has("new-next-public-key") && p.options.has("new-next-key-ref")) throw new UsageError("give the new next key once: --new-next-public-key or --new-next-key-ref");
  const newNextPublicKey = publicKeyFlag(p, "new-next-public-key");
  const newNextKeyReference = str(p, "new-next-key-ref") === undefined ? undefined : readReferenceFile(str(p, "new-next-key-ref")!, "new-next-key-ref");
  const done = await write(g, async (w) => {
    writableFormat(w.reader.store, "owner rotate-key");
    const result = await w.owner.rotateOwnerKey({
      ...(reason === undefined ? {} : { reason }), ...(keyId === undefined ? {} : { keyId }), ...(nextKeyFile === undefined ? {} : { nextKeyFile }), ...(flag(p, "emergency") ? { emergency: true } : {}),
      ...(newNextPublicKey === undefined ? {} : { newNextPublicKey }), ...(newNextKeyReference === undefined ? {} : { newNextKeyReference }), ...policy,
    });
    const event = w.owner.exportHistory().find((e) => e.id === result.eventId);
    const signedBy = (event?.data.controlAuthorization as { keyId?: string } | undefined)?.keyId ?? null;
    return { result, signedBy, status: w.owner.ownerKeyStatus() };
  });
  const { result, signedBy, status } = done;
  const history = historyPath(g);
  // The file the committed key came from: the default next-key path was replaced by the fresh next key; any other copy now holds the owner key in force.
  const source = nextKeyFile ?? (result.preRotated ? nextOwnerKeyPathFor(history) : undefined);
  const sourceNowOwnerKey = source !== undefined && source !== nextOwnerKeyPathFor(history);
  return {
    json: {
      rotated: true, eventId: result.eventId, head: result.head, signedBy, keyId: result.keyId, ownerKeys: result.ownerKeys.map((k) => k.keyId), retired: result.retired,
      fromPosition: result.fromPosition, keyFile: result.keyFile ?? null, retiredKeyFile: result.retiredKeyFile ?? null, reason: reason ?? null,
      custody: status.custody,
      // The retired key file signs the rotation-head statement for any witness that has not recorded the rotation yet.
      retiredKeyNeeded: result.retiredKeyFile === undefined ? null : "until every witness bound to the history has recorded the rotation (witness status: pendingRotations 0)",
      preRotated: result.preRotated, nextKeySource: result.preRotated ? source ?? null : null,
      emergency: result.emergency === true, witnesses: result.witnesses ?? null, rotationIncomplete: result.rotationIncomplete ?? null, bundle: result.bundle ?? null,
      ...nextKeyView(status),
    },
    render: (s, out) => {
      out.add(`ROTATED  owner key ${result.retired.length === 0 ? "added" : result.retired.join(", ")} → ${result.keyId}${result.preRotated ? " (pre-rotated: the committed next key)" : ""}`);
      out.add(`  ${s.paint("event      ", "secondary")}  ${result.eventId} · signed by ${signedBy ?? "—"}`);
      out.add(`  ${s.paint("head       ", "secondary")}  ${headLine(result.head)}`);
      out.add(`  ${s.paint("owner keys ", "secondary")}  ${result.ownerKeys.map((k) => k.keyId).join(", ")} from position ${result.fromPosition}`);
      const newKey = status.custody.find((c) => c.role === "current" && c.keyId === result.keyId);
      if (result.keyFile !== undefined && newKey?.holder === "reference") out.add(`  ${s.paint("key file   ", "secondary")}  ${result.keyFile} → a reference: the new owner key is held by ${newKey.description} (no secret on this host)`);
      else if (result.keyFile !== undefined) out.add(`  ${s.paint("key file   ", "secondary")}  ${result.keyFile} (mode 0600 — keep it private)`);
      if (result.retiredKeyFile !== undefined) out.add(`  ${s.paint("retired    ", "secondary")}  ${result.retiredKeyFile} (mode 0600)`);
      const nextCustody = status.custody.find((c) => c.role === "next");
      if (result.nextKeyFile !== undefined && nextCustody?.holder === "reference") out.add(`  ${s.paint("next key   ", "secondary")}  committed · held by ${nextCustody.description} · ${result.nextKeyFile} is a reference`);
      else if (result.nextKeyFile !== undefined) out.add(`  ${s.paint("next key   ", "secondary")}  ${result.nextKeyFile} (mode 0600 — the only key that can rotate the new owner key)`);
      else if (result.nextKeyDigests !== undefined) out.add(`  ${s.paint("next key   ", "secondary")}  committed${newNextPublicKey === undefined ? "" : " · public key only (its private half is not on this host)"}`);
      if (result.witnesses !== undefined) {
        const w = result.witnesses;
        out.add(`  ${s.paint("witnesses  ", "secondary")}  two-phase: recorded by ${w.accepted.length === 0 ? "none" : w.accepted.join(", ")} before the local append${w.refused.length === 0 ? "" : ` · refused by ${w.refused.map((r) => `${r.url} (${r.code})`).join(", ")}`}${w.unknown.length === 0 ? "" : ` · no answer from ${w.unknown.map((u) => u.url).join(", ")}`}`);
      } else if (result.emergency === true) {
        out.add(`  ${s.paint("witnesses  ", "secondary")}  ${result.rotationIncomplete === true ? s.strong("delivered afterwards (emergency): queued for the witnesses that do not have it yet") : "delivered afterwards"}`);
      }
      if (result.bundle !== undefined) out.add(`  ${s.paint("bundle     ", "secondary")}  ${result.bundle} (hand it to a witness operator: irontrellis-witness import-key-events)`);
      if (result.rotationIncomplete === true) {
        out.add(s.strong("ROTATION INCOMPLETE: a bound witness has not recorded this rotation yet, and until it does it still accepts heads signed by the retired key. irontrellis witness sync delivers it when the witness answers; the bundle above hands it over offline."));
      }
      out.add(s.paint(`Control events and pinned heads from position ${result.fromPosition} on must be signed by ${result.ownerKeys.map((k) => k.keyId).join(" or ")}; heads up to position ${result.head.position} stay attested by the keys they were signed with.`, "secondary"));
      if (sourceNowOwnerKey && newKey?.holder === "reference") out.add(s.paint(`${source} names the owner key in force now (${result.keyId}), not a next key: remove it or keep it with your other references.`, "secondary"));
      else if (sourceNowOwnerKey) out.add(s.paint(`${source} now holds the owner key in force (${result.keyId}), not a next key: destroy that copy, or keep it as a protected backup of the current owner key.`, "secondary"));
      const retiredHeld = status.custody.find((c) => c.role === "retired" && c.path === result.retiredKeyFile);
      if (result.retiredKeyFile !== undefined && retiredHeld?.holder === "reference") {
        out.add(s.paint(`The retired key stays in ${retiredHeld.description} (${result.retiredKeyFile} is a reference to it). It can no longer sign this history's new heads, but it can still sign a copy cut back before the rotation: take it out of that signer once every witness bound to the history has recorded the rotation (irontrellis witness status); until then a witness that has not recorded it needs the statement for the rotation head signed with it.`, "secondary"));
      } else if (result.retiredKeyFile !== undefined) {
        out.add(s.paint("The retired key can no longer sign this history's new heads, but it can still sign a copy cut back before the rotation, so keep it away from the agent host. Do not destroy it yet: a remote witness that has not recorded this rotation (one that was unreachable now, or one added later) needs the statement for the rotation head signed with the retired key. Keep the archived file offline and backed up until every witness bound to the history has recorded the rotation (irontrellis witness status shows it per witness), and bring it back beside the history for a witness add or witness sync that needs it.", "secondary"));
      }
      renderOwnerKeyWarnings(s, out, status.warnings);
      for (const message of checkpointPolicyMessages(status)) out.add(message);
    },
  };
});

const ownerCommitNextKey = command("owner commit-next-key", "owner commit-next-key [--public-key <key> | --next-key-ref <file>] [--reason <text>] [--emergency] [--owner-policy <file> | --reset-policy]", "commit the owner keys in force to a next key (pre-rotation), for a history without a commitment: record an OWNER_KEYS_ROTATED that keeps every owner key and adds the commitment, and write the next key to <history>.owner-next-key.json, to be moved off this host; or commit to a key held elsewhere (--public-key, --next-key-ref). With bound witnesses, every bound witness first records it (two phases, as owner rotate-key)", [], [
  o("public-key", "string", "commit to this next key (ssh-ed25519 AAAA… or 0x + 64 hex): its private half never touches this host and nothing is written for it", { value: "<key>" }),
  o("next-key-ref", "string", "commit to the key this next-key reference names (a key an ssh-agent or a command signer holds); the reference is written to <history>.owner-next-key.json (no secret)", { value: "<file>" }),
  o("reason", "string", "recorded in the event (default \"next-key commitment\")", { value: "<text>" }),
  o("emergency", "boolean", "record it locally first and deliver it to the bound witnesses afterwards (as owner rotate-key --emergency)"),
  ...policyOptions,
], async (p, g) => {
  positionals(p, []);
  const policy = policyFlags(p);
  if (p.options.has("public-key") && p.options.has("next-key-ref")) throw new UsageError("give the next key once: --public-key or --next-key-ref");
  const nextPublicKey = publicKeyFlag(p, "public-key");
  const nextKeyReference = str(p, "next-key-ref") === undefined ? undefined : readReferenceFile(str(p, "next-key-ref")!, "next-key-ref");
  const done = await write(g, async (w) => {
    writableFormat(w.reader.store, "owner commit-next-key");
    const result = await w.owner.commitNextKey({
      ...(nextPublicKey === undefined ? {} : { nextPublicKey }), ...(nextKeyReference === undefined ? {} : { nextKeyReference }),
      ...(str(p, "reason") === undefined ? {} : { reason: str(p, "reason")! }), ...(flag(p, "emergency") ? { emergency: true } : {}), ...policy,
    });
    return { result, status: w.owner.ownerKeyStatus() };
  });
  const { result, status } = done;
  return {
    json: {
      committed: true, eventId: result.eventId, head: result.head, keyId: result.keyId, ...nextKeyView(status), nextKeyDigests: result.nextKeyDigests, nextKeyFile: result.nextKeyFile ?? null,
      nextPublicKey: nextPublicKey ?? null, nextKeyHolder: nextPublicKey !== undefined ? "public-key-only" : nextKeyReference !== undefined ? "reference" : "file", custody: status.custody,
      ownerKeysUnchanged: true, emergency: result.emergency ?? false, bundle: result.bundle ?? null, rotationIncomplete: result.rotationIncomplete ?? false,
      ...(result.witnesses === undefined ? {} : { witnesses: result.witnesses }),
    },
    render: (s, out) => {
      out.add(`COMMITTED  next owner key ${result.keyId}`);
      out.add(`  ${s.paint("event   ", "secondary")}  ${result.eventId} (OWNER_KEYS_ROTATED keeping every owner key: only the commitment is new)`);
      out.add(`  ${s.paint("head    ", "secondary")}  ${headLine(result.head)}`);
      out.add(`  ${s.paint("digest  ", "secondary")}  ${result.nextKeyDigests.join(", ")}`);
      if (result.nextKeyFile !== undefined && nextKeyReference !== undefined) out.add(`  ${s.paint("next key", "secondary")}  ${result.nextKeyFile} → a reference: the key is held by ${custodyLine(loadNextOwnerKeyFile(result.nextKeyFile))}`);
      else if (result.nextKeyFile !== undefined) out.add(`  ${s.paint("next key", "secondary")}  ${result.nextKeyFile} (mode 0600)`);
      else if (nextPublicKey !== undefined) out.add(`  ${s.paint("next key", "secondary")}  public key only: ${nextPublicKey} (nothing written; its private half is not on this host)`);
      out.add(s.paint(nextPublicKey !== undefined
        ? "Only this key can rotate the owner keys in force now; the current owner key alone cannot. When the time comes, write a reference to it (irontrellis signer ref --next) or bring its next-key file, and rotate with irontrellis owner rotate-key --next-key-ref <file> (or --next-key <file>)."
        : nextKeyReference !== undefined ? "Only this key can rotate the owner keys in force now; the current owner key alone cannot. Rotate with irontrellis owner rotate-key (the reference beside the history names it)."
        : "Only this key can rotate the owner keys in force now; the current owner key alone cannot. Rotate with irontrellis owner rotate-key --next-key <file>.", "secondary"));
      renderOwnerKeyWarnings(s, out, status.warnings);
      for (const message of checkpointPolicyMessages(status)) out.add(message);
    },
  };
});

const ownerExportKeyEvents = command("owner export-key-events", "owner export-key-events [--since <position>]",
  "write a self-authenticating key-event bundle (<history>.key-event-<position>.bundle.json) for every owner key rotation (commitment-only ones included), for a witness that cannot be reached over the network (irontrellis-witness import-key-events)", [], [
    o("since", "number", "only key events at or after this position (default all)", { value: "<position>" }),
  ], async (p, g) => {
    positionals(p, []);
    const since = num(p, "since");
    const exported = await write(g, (w) => {
      writableFormat(w.reader.store, "owner export-key-events");
      return w.owner.exportKeyEvents(since === undefined ? {} : { since });
    });
    const failed = exported.filter((e) => e.error !== undefined);
    return {
      json: { exported: exported.filter((e) => e.path !== undefined).length, bundles: exported },
      render: (s, out) => {
        out.add(`EXPORTED  ${plural(exported.length - failed.length, "key-event bundle")}`);
        for (const e of exported) {
          out.add(`  ${s.paint(`${e.kind === "ROTATED" ? "rotation  " : "commitment"} ${String(e.position).padStart(5)}`, "secondary")}  ${e.path ?? s.strong(`not written: ${e.error}`)}${e.chain === undefined ? "" : ` · chain from position ${e.chain.position} (supersede)`}`);
        }
        out.add(s.paint("A bundle carries only owner-signed data; the witness checks it exactly like a network delivery. Give it to the witness operator: irontrellis-witness import-key-events --data <dir> <bundle>… (server stopped) or POST /v1/admin/key-events with an admin token.", "secondary"));
      },
      exit: failed.length === 0 ? 0 : 1,
    };
  });

const ownerStatus = command("owner status", "owner status", "the owner keys in force, their next-key commitment, and each key's custody: a key file on this host, a key held by a signer (ssh-agent, command), or only a public key here (warns while a private key is on this host)", [], [], async (p, g) => {
  positionals(p, []);
  const r = await openReader(g);
  const st = ownerKeyStatusOf(r.path, r.state);
  return {
    json: {
      path: r.path, format: st.format, head: r.state.head, ownerKeys: st.ownerKeys, fromPosition: st.fromPosition, keyRotations: st.keyRotations, commitmentRotations: st.commitmentRotations,
      policyRotations: st.policyRotations, ownerPolicy: st.ownerPolicy, commitment: st.commitment, ownerKeyFile: st.ownerKeyFile, nextKeyFile: st.nextKeyFile, nextKeyOnHost: st.nextKeyOnHost, pending: st.pending, warnings: st.warnings, custody: st.custody,
    },
    render: (s, out) => renderOwnerStatus(s, out, r.path, st),
  };
});

// ---------------------------------------------------------------- remote witnesses

const policyUpdate = (p: Parsed): WitnessPolicyUpdate => {
  const mode = str(p, "mode");
  if (mode !== undefined && mode !== "sync" && mode !== "async") throw new UsageError(`--mode: "${mode}" is not sync or async`);
  const requireOnOpen = p.options.get("require-on-open") as boolean | undefined;
  return {
    ...(num(p, "quorum") === undefined ? {} : { quorum: num(p, "quorum")! }), ...(mode === undefined ? {} : { mode }),
    ...(requireOnOpen === undefined ? {} : { requireOnOpen }), ...(num(p, "max-unwitnessed") === undefined ? {} : { maxUnwitnessedEvents: num(p, "max-unwitnessed")! }),
    ...(num(p, "cache-ms") === undefined ? {} : { cacheMs: num(p, "cache-ms")! }),
  };
};
const changeLines = (s: Style, out: Lines, change: WitnessChange): void => {
  out.add(`  ${s.paint("witness  ", "secondary")}  ${change.witness.url}`);
  out.add(`  ${s.paint("key      ", "secondary")}  ${change.witness.verifierKey}`);
  if (change.eventId !== undefined) out.add(`  ${s.paint("event    ", "secondary")}  ${change.eventId} (owner-signed ${change.bound ? "binding" : "unbinding"})`);
  const st = change.status;
  if (st !== undefined) {
    out.add(`  ${s.paint("policy   ", "secondary")}  quorum ${st.policy.quorum} of ${st.witnesses.length} · ${st.policy.mode}${st.policy.requireOnOpen ? " · checked before reads" : ""} · at most ${st.policy.maxUnwitnessedEvents} unwitnessed events`);
  }
};

const witnessAdd = command("witness add", "witness add <url> --verifier-key <key> [--name <name>] [--quorum <n>] [--mode sync|async] [--require-on-open] [--max-unwitnessed <n>] [--token <token>] [--allow-offline] [--allow-insecure-http]",
  "add a remote witness: check it, register the history with it, bind it in the history and submit the head", ["url"], [
    o("verifier-key", "string", "the witness's note verifier key (irontrellis-witness verifier-key prints it); the only thing the client trusts", { value: "<key>", required: true }),
    o("name", "string", "a display name for the witness", { value: "<name>" }),
    o("token", "string", "registration token, when the witness requires one (kept in <history>.witness.json, mode 0600)", { value: "<token>" }),
    o("timeout-ms", "number", "per-request timeout (default 10000)", { value: "<ms>" }),
    o("quorum", "number", "how many witnesses must hold a head before it counts as witnessed (default 1)", { value: "<n>" }),
    o("mode", "string", "sync: submit before each write returns; async (default): submit in the background", { value: "<mode>" }),
    o("require-on-open", "boolean", "readers ask the witnesses before reading (writers always ask before their first write)"),
    o("max-unwitnessed", "number", "refuse owner writes while this many events are not yet witnessed (default 1000)", { value: "<n>" }),
    o("cache-ms", "number", "how long a reader may rely on an earlier, owner-sealed witness answer (default 60000)", { value: "<ms>" }),
    o("allow-offline", "boolean", "when the witness cannot be reached, bind it anyway and register it later (default: fail and write nothing)"),
    o("allow-insecure-http", "boolean", "accept a plain http:// URL to a host that is not loopback (replayed witness answers cannot be ruled out)"),
  ], async (p, g) => {
    const [url] = positionals(p, ["url"], false);
    const update = policyUpdate(p);
    const config = {
      url: url!, verifierKey: need(p, "verifier-key"), ...(str(p, "name") === undefined ? {} : { name: str(p, "name")! }),
      ...(str(p, "token") === undefined ? {} : { token: str(p, "token")! }), ...(num(p, "timeout-ms") === undefined ? {} : { timeoutMs: num(p, "timeout-ms")! }),
      ...(flag(p, "allow-insecure-http") ? { allowInsecureHttp: true } : {}),
    };
    const change = await write(g, (w) => w.owner.addWitness(config, update, flag(p, "allow-offline") ? { allowOffline: true } : {}));
    return {
      json: change,
      render: (s, out) => {
        out.add(`ADDED  remote witness ${change.witness.url}`);
        changeLines(s, out, change);
        out.add(`  ${s.paint("registered", "secondary")}  ${change.registered === false ? "not yet (the witness could not be reached; the queue registers the history, run irontrellis witness sync)" : "yes (the binding carries its signed registration receipt)"}`);
        out.add(`  ${s.paint("head     ", "secondary")}  ${change.submitted ? "held by the witnesses" : `queued (${change.error?.code ?? "not submitted"}: ${change.error?.message ?? ""})`}`);
        out.add(s.paint("The binding is part of the history: every copy from here on names this witness, whatever happens to <history>.witness.json. verify asks it whether the file is the latest copy the owner vouched for.", "secondary"));
      },
    };
  });

const witnessRemove = command("witness remove", "witness remove <url|verifier-key>... [--accept-loss --reason <text>]",
  "remove remote witnesses (an owner-signed unbinding when the history binds them); --accept-loss continues without witnesses that hold a head no surviving copy contains", ["witness"], [
    o("accept-loss", "boolean", "the witness(es) hold a head that no surviving copy of the history contains (they show a rollback of this copy): record, with the owner key, that the history continues on this copy without them"),
    o("reason", "string", "why the loss is accepted, recorded in the unbinding event (required with --accept-loss; 1..256 bytes)", { value: "<text>" }),
  ], async (p, g) => {
    const which = p.positionals;
    if (which.length === 0) throw new UsageError("missing <witness>");
    const acceptLoss = flag(p, "accept-loss"), reason = str(p, "reason");
    if (acceptLoss && reason === undefined) throw new UsageError("--accept-loss needs --reason <text>");
    if (!acceptLoss && reason !== undefined) throw new UsageError("--reason goes with --accept-loss");
    const change = acceptLoss
      ? await withRetry(async () => {
        // The copy is refused by the witness(es) whose loss is accepted, so it is opened for recovery: every read and write still
        // refuses until the owner-signed unbinding is written, and any other witness still applies to that write.
        const path = historyPath(g);
        if (!existsSync(path)) throw new CliError("HISTORY_NOT_FOUND", `no history at ${path}`);
        const inspect = openHistoryStore(path, { inspect: true, witness: false });
        let state;
        try { state = inspect.state(); } finally { inspect.close(); }
        const profile = profileOf(state);
        const ownerId = g.owner ?? profile.owner, controllerId = g.controller ?? process.env.IRONTRELLIS_CONTROLLER ?? profile.controller ?? ownerId;
        const owner = openLocalOwner({ historyFile: path, domain: state.genesis.domain, owner: ownerId, controller: controllerId, now: () => Date.now(), witnessRecovery: true });
        try {
          const removed = await owner.removeWitness(which, { acceptRemoteLoss: true, reason: reason! });
          try { await submitQueued(owner); } catch (error) { throw writtenUnattested(error, removed) ?? error; }
          return removed;
        } finally {
          owner.close();
        }
      })
      : await write(g, (w) => w.owner.removeWitness(which));
    const removed = change.removed ?? [change.witness];
    return {
      json: change,
      render: (s, out) => {
        for (const w of removed) out.add(`${change.acceptedLoss === undefined ? "REMOVED" : s.strong("REMOVED, LOSS ACCEPTED")}  remote witness ${w.url}`);
        changeLines(s, out, change);
        if (change.acceptedLoss !== undefined) {
          for (const lost of change.acceptedLoss.heads) out.add(`  ${s.paint("lost head", "secondary")}  position ${lost.head.position} (${lost.head.hash}) held by ${removed.find((w) => w.verifierKey === lost.verifierKey)?.url ?? lost.verifierKey}`);
          out.add(`  ${s.paint("reason   ", "secondary")}  ${change.acceptedLoss.reason}`);
          out.add(s.paint("The owner key recorded that this history continues on this copy, a branch the removed witness(es) never saw: the events they hold past it are gone from the history, and the removed witnesses will never accept a head of this branch. Copies from before the unbinding still name them and fail against them. Every other witness bound to the history still applies. Add a new witness (irontrellis witness add) to protect the history from here on.", "secondary"));
        } else {
          out.add(s.paint("Copies of the history from before the unbinding still name this witness; the witness keeps what it received.", "secondary"));
        }
      },
    };
  });

const witnessStatus = command("witness status", "witness status [--no-remote]", "the witness policy, the queue and, per witness, the latest witnessed head, receipt and consistency checks and whether it recorded every owner key rotation", [], [
  o("remote", "boolean", "ask the witnesses now (default); --no-remote shows what is known locally"),
], async (p, g) => {
  positionals(p, []);
  const path = historyPath(g);
  if (!existsSync(path)) throw new CliError("HISTORY_NOT_FOUND", `no history at ${path}`);
  const store = openHistoryStore(path, { inspect: true });
  try {
    if (store.witnessStatus() === undefined) throw new CliError("NO_WITNESS");
    const asked = p.options.get("remote") === false ? undefined : await store.verifyWithWitnesses({ allowUnreachableWitness: true, allowUnpinned: true });
    const st = store.witnessStatus()!;
    const bad = st.alarm !== undefined || st.rejected !== undefined || ["ROLLBACK", "SPLIT_VIEW", "INVALID"].includes(asked?.remoteWitnessStatus ?? "OK");
    return {
      json: { ...st, remoteStatus: asked?.remoteWitnessStatus ?? null, remote: asked?.remoteWitnesses ?? null, warnings: witnessWarnings(asked?.remoteWitnesses), ok: !bad },
      render: (s, out) => renderWitnessStatus(s, out, st, asked?.remoteWitnesses, asked?.remoteWitnessStatus, asked?.notes ?? []),
      exit: bad ? 1 : 0,
    };
  } finally {
    store.close();
  }
});

const witnessSync = command("witness sync", "witness sync", "submit queued head statements and owner key rotations to the remote witnesses now", [], [], async (p, g) => {
  positionals(p, []);
  const w = await openWriter(g);
  if (w.owner.witnessStatus() === undefined) throw new CliError("NO_WITNESS");
  let failed: { code: string; message: string } | undefined;
  try {
    await w.owner.flush();
  } catch (error) {
    if (error instanceof IronTrellisError && (error.code === "ROLLBACK_DETECTED" || error.code === "WITNESS_SPLIT_VIEW")) throw error;
    const { code, detail } = codeOf(error);
    failed = { code, message: detail };
  }
  const st = w.owner.witnessStatus()!;
  return {
    json: { synced: failed === undefined, ...(failed === undefined ? {} : { error: failed }), status: st },
    render: (s, out) => {
      out.add(failed === undefined ? `SYNCED  ${w.reader.path}` : `${s.strong("QUEUED")}  ${w.reader.path}`);
      out.add(`  ${s.paint("witnessed", "secondary")}  ${st.witnessedPosition === null ? "unknown" : `up to position ${st.witnessedPosition} by a quorum`} · ${st.unwitnessedEvents} not yet witnessed`);
      if (!st.ownerKeyed) out.add(s.paint("No owner key is held here, so no head statement can be signed; run this where the owner key is.", "secondary"));
      if (failed !== undefined) out.add(`  ${s.strong(failed.code)}  ${failed.message}`);
    },
    exit: failed === undefined ? 0 : 1,
  };
});

// ---------------------------------------------------------------- anchoring

const anchor = command("anchor", "anchor [--kind local|rekor] [--url <url>]", "attest the head, submit it to an anchor log and record the receipt (evidence about the head; remote witnesses are bound with witness add)", [], [
  o("kind", "string", "the anchor kind: local (default; appends to <history>.anchors) or rekor (experimental: never exercised against a live Rekor log; --url overrides the Rekor base URL)", { value: "<kind>" }),
  o("url", "string", "Rekor base URL (with --kind rekor)", { value: "<url>" }),
  o("anchors-file", "string", "path of the local anchor log (default <history>.anchors)", { value: "<file>" }),
], async (p, g) => {
  positionals(p, []);
  // The owner key signs the attestation, the ANCHOR_RECORDED control event and the pinned head the append leaves behind.
  const keyPath = ownerKeyPathFor(historyPath(g));
  if (!existsSync(keyPath)) writableFormat((await openReader(g)).store, "anchor");
  const signer = loadOwnerKeyFile(keyPath);
  // The append waits for another writer's lock instead of failing at once; the anchor target is not asked twice.
  const r = await openReader(g, { signer, lockTimeoutMs: LOCK_WAIT_MS });
  writableFormat(r.store, "anchor");
  const kind = str(p, "kind") ?? "local";
  let target: AnchorTarget;
  if (kind === "local") target = localAnchorLog(str(p, "anchors-file") === undefined ? `${r.path}.anchors` : resolve(str(p, "anchors-file")!));
  else if (kind === "rekor") target = rekorAnchor(str(p, "url") === undefined ? {} : { baseUrl: str(p, "url")! });
  else throw new UsageError(`--kind: unknown anchor kind "${kind}" (local or rekor)`);
  const experimental = kind === "rekor";
  const state = r.state, context = anchorContextOf(state);
  const attestation = await attestHead(signer, context.domain, state.head, context.algorithm);
  let receipt: Awaited<ReturnType<AnchorTarget["submit"]>>;
  try {
    receipt = await target.submit(attestation, context);
  } catch (error) {
    // An engine refusal keeps its code; a network or file failure gets one (never a bare "fetch failed").
    if (error instanceof EngineError || error instanceof IronTrellisError) throw error;
    throw new CliError("ANCHOR_LOG_UNAVAILABLE", `${target.name}${target.location === undefined ? "" : ` (${target.location})`}: ${error instanceof Error ? error.message : String(error)}`);
  }
  const anchoredAt = Date.now();
  const unsigned = anchorRecordedEvent(attestation, target, receipt, anchoredAt, `event:anchor:${anchoredAt}:${state.head.position}`);
  // The receipt is recorded as a signed control event under the writer lock, at the head the attestation names.
  let signedId: string | undefined;
  const result = await r.store.withExclusiveWriter(async (writer) => {
    const previous = r.store.head();
    if (previous === undefined || previous.hash !== attestation.head.hash) throw new CliError("HISTORY_CONFLICT", "the history moved while the anchor target was answering; anchor again");
    const event = await signControlEvent(signer, unsigned, context.domain, previous, context.algorithm);
    signedId = event.id;
    return { event, head: writer.appendAtExpectedHead(event, previous) };
  }).catch((error: unknown) => {
    // The pin's attestation after the append can fail (an asynchronous signer): the anchor IS recorded, so the
    // answer is WRITTEN_UNATTESTED (exit 4), decided by whether the signed event is in the file.
    const state = signedId === undefined ? undefined : openHistoryStore(r.store.path, { inspect: true, witness: false }).state();
    const recorded = state?.events.some((e) => e.id === signedId) === true;
    throw (recorded ? writtenUnattested(error, { eventId: signedId, head: state!.head }) : undefined) ?? error;
  });
  // The pin after the append: an asynchronous signer (ssh-agent, command) attests it now; an unreachable remote witness only queues.
  try { await r.store.flush(); } catch (error) {
    const unattested = writtenUnattested(error, { eventId: result.event.id, head: result.head });
    if (unattested !== undefined) throw unattested;
    if (!(error instanceof EngineError && ["WITNESS_UNAVAILABLE", "WITNESS_REJECTED", "WITNESS_INVALID_RESPONSE"].includes(error.code))) throw error;
  }
  return {
    json: { recorded: "anchor", anchor: target.name, ...(experimental ? { experimental: true } : {}), anchoredHead: attestation.head, receipt, eventId: result.event.id, head: result.head },
    render: (s, out) => {
      out.add(`ANCHORED  position ${attestation.head.position} via ${target.name}`);
      if (experimental) out.add(s.strong("  experimental: the Rekor anchor was never exercised against a live Rekor log; treat its receipt as unverified."));
      out.add(`  ${s.paint("attested", "secondary")}  ${headLine(attestation.head)} by ${attestation.keyId}`);
      out.add(`  ${s.paint("receipt ", "secondary")}  ${JSON.stringify(receipt)}`);
      out.add(`  ${s.paint("event   ", "secondary")}  ${result.event.id} · head now ${headLine(result.head)}`);
      out.add(s.paint(`Anchored at ${formatTime(anchoredAt)}. verify checks that every anchored head stays a prefix of the history.`, "secondary"));
    },
  };
});

const doctorCommand = command("doctor", "doctor [<history>] [--as-agent] [--offline] [--hook-config <file>]",
  "audit owner-key custody and the deployment, read-only: who holds each key, whether this OS user can read or use it, hooks and their protect list, witnesses, pre-rotation, history size, platform (exit 1 on any FAIL, 2 on a usage error)",
  ["history"], DOCTOR_OPTIONS, (p, g) => runDoctor(p, g));

export const COMMANDS: readonly Command[] = Object.freeze([
  init, status, verify, repin, migrate, ownerStatus, ownerCommitNextKey, ownerRotateKey, ownerExportKeyEvents,
  agentCreate, agentTerminate, roleCreate, appoint, unappoint, successionDeclare, succeed, sessionAdmit, epochAdvance,
  grant, delegate, prohibit, revoke,
  authorize, why, responsible, survives, handover, anchor, capacityCommand,
  witnessAdd, witnessStatus, witnessSync, witnessRemove, ...SIGNER_COMMANDS, doctorCommand, ...FORMAT2_COMMANDS,
]);
