/**
 * The format-2 commands (SPEC §7.3, §9, §11, §13, §15; docs/API.md §1): budgets, checkpoints, counterparties, the
 * duty-policy writer and the export view. Owner writes go through the owner API (`write`); the duty commands and a
 * recorded refusal sign with an admitted runtime session whose key file the caller names (`--session`,
 * `--session-key`); every read works on the captured history alone.
 */
import { createHash } from "node:crypto";
import { closeSync, constants, existsSync, fstatSync, openSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  MAX_MATCHING_BUDGETS, headroom, inspectDutyPolicyState, keyPairFromPrivateKey, openLocalDutyPolicy, openLocalRuntime, projectionHeadAt, replay, rootAt, signHashWith, stateRootOf,
  exportViewState, jsonStringifyWithBigints, verifyExportView,
  type BudgetDeclaration, type ContentHash, type CounterpartyKey, type ReplayState, type SignHash, type WriteResult,
} from "@ramex-labs/irontrellis";
import { UsageError, flag, list, need, num, positionals, str, type OptionSpec, type Parsed } from "./args.ts";
import type { Command, Outcome } from "./commands.ts";
import { CliError, evaluationTime, openReader, parseAmount, parseTime, profileOf, write, writableFormat, type Global, type Reader } from "./history.ts";
import { formatTime, plural, rows, type Lines, type Style } from "./output.ts";
import { headLine, identityRows } from "./render.ts";
import { IDENTITY_OPTIONS, expectedIdentity, historyIdOfGenesisEventHash, identityCaveat, identityOfView, identityView, mismatchesOf } from "./identity.ts";

const o = (name: string, kind: OptionSpec["kind"], help: string, extra: Partial<OptionSpec> = {}): OptionSpec => ({ name, kind, help, ...extra });
const id = (name: string, kind: "string" | "list", help: string, extra: Partial<OptionSpec> = {}): OptionSpec => o(name, kind, help, { ...extra, identifier: true });
const command = (name: string, usage: string, summary: string, pos: readonly string[], options: readonly OptionSpec[], run: Command["run"]): Command =>
  Object.freeze({ name, usage, summary, positionals: pos, options, run });
const TIME = "<ms|ISO|+30m>";
type Rec = Readonly<Record<string, unknown>>;

const written = (what: string, result: WriteResult, extra: Rec = {}, lines: (s: Style, out: Lines) => void = () => {}): Outcome => ({
  json: { recorded: what, eventId: result.eventId, head: result.head, ...extra },
  render: (s, out) => {
    out.add(`RECORDED  ${what}`);
    out.add(`  ${s.paint("event", "secondary")}  ${result.eventId}`);
    out.add(`  ${s.paint("head ", "secondary")}  ${headLine(result.head)}`);
    lines(s, out);
  },
});

/** A command that reads format-2 records refuses an older file with a sentence, not an empty answer. */
function format2(r: Reader, what: string): ReplayState {
  if (r.state.format !== "irontrellis-event/2") throw new CliError("UNSUPPORTED_FORMAT", `${what} needs a format-2 history; ${r.path} is ${r.state.format} (migrate it with irontrellis migrate)`);
  return r.state;
}

// ---------------------------------------------------------------- runtime sessions (key files)

const SESSION_OPTIONS: readonly OptionSpec[] = [
  id("session", "string", "the admitted runtime session that signs (its agent is the actor)", { value: "<id>", required: true }),
  o("session-key", "string", "the session's private key file: the JSON file session admit --new-key writes, or a file holding only 0x + 64 hex", { value: "<file>", required: true }),
];

/** Reads a session key file (owner-only, a regular file) and checks it holds the admitted session's credential. */
function sessionSigner(state: ReplayState, session: string, file: string): SignHash {
  const record = state.runtimeSessions.get(session);
  if (record === undefined) throw new CliError("RUNTIME_NOT_CURRENT", `the history has no runtime session ${session}`);
  const path = resolve(file);
  let text: string;
  try {
    const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const st = fstatSync(fd);
      if (!st.isFile() || st.size > 4096) throw new CliError("KEY_UNAVAILABLE", `--session-key: ${path} is not a session key file`);
      if (process.platform !== "win32" && (st.mode & 0o077) !== 0) throw new CliError("KEY_UNAVAILABLE", `--session-key: ${path} has mode 0${(st.mode & 0o777).toString(8)}; it must be owner-only (chmod 600)`);
      text = readFileSync(fd, "utf8").trim();
    } finally { closeSync(fd); }
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError("KEY_UNAVAILABLE", `--session-key: ${path} cannot be read (${(error as { code?: string }).code ?? "error"})`);
  }
  let privateKey = text;
  if (text.startsWith("{")) {
    try { privateKey = String((JSON.parse(text) as { privateKey?: unknown }).privateKey); } catch { throw new CliError("KEY_UNAVAILABLE", `--session-key: ${path} is not valid JSON`); }
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) throw new CliError("KEY_UNAVAILABLE", `--session-key: ${path} holds no 0x-prefixed 32-byte private key`);
  const pair = keyPairFromPrivateKey(record.credentialScheme, record.credentialKeyId, privateKey);
  if (pair.credential.toLowerCase() !== record.credentialAddressKey.toLowerCase()) throw new CliError("KEY_MISMATCH", `--session-key: ${path} does not hold the key admitted for session ${session}`);
  return signHashWith(pair);
}

/** The runtime options of the owner profile in the file plus the named session. */
function runtimeOptions(r: Reader, g: Global, session: string, signHash: SignHash) {
  const profile = profileOf(r.state);
  const owner = g.owner ?? profile.owner;
  return { historyFile: r.path, domain: r.state.genesis.domain, owner, controller: g.controller ?? process.env.IRONTRELLIS_CONTROLLER ?? profile.controller ?? owner, now: () => Date.now(), session, signHash };
}

/** `authorize --record-refusal`: records the DENY / INDETERMINATE as a REQUEST_REFUSED signed by the actor's own session (SPEC §10.1.1). */
export async function recordRefusal(g: Global, p: Parsed, request: Readonly<Record<string, unknown>> & { actorId: string }): Promise<Rec> {
  const r = await openReader(g);
  writableFormat(r.store, "authorize --record-refusal");
  format2(r, "authorize --record-refusal");
  const session = need(p, "session");
  const runtime = openLocalRuntime(runtimeOptions(r, g, session, sessionSigner(r.state, session, need(p, "session-key"))));
  const result = await runtime.recordRefusal({ request: request as never });
  return "eventId" in result ? { recorded: true, eventId: result.eventId, head: result.head } : { recorded: false, reason: result.reason };
}
export const REFUSAL_OPTIONS: readonly OptionSpec[] = [
  o("record-refusal", "boolean", "when the answer is DENY or INDETERMINATE, record it in the history as a refusal signed by the actor's session (needs --session and --session-key; not with --at)"),
  id("session", "string", "with --record-refusal: the actor's admitted runtime session", { value: "<id>" }),
  o("session-key", "string", "with --record-refusal: the session's private key file", { value: "<file>" }),
];

// ---------------------------------------------------------------- budgets (SPEC §9)

const SUBJECT_OPTIONS: readonly OptionSpec[] = [
  id("actors", "list", "the agents the budget covers (default: any)", { value: "<a,b>" }),
  id("roles", "list", "the roles the budget covers: it follows whoever holds them (default: any)", { value: "<r1,r2>" }),
  id("actions", "list", "the actions it covers (default: any)", { value: "<a,b>" }),
  id("resources", "list", "the resources it covers (default: any)", { value: "<r1,r2>" }),
];
const CAP_OPTIONS: readonly OptionSpec[] = [
  o("amount-cap", "string", "the most the covered requests may spend per period, in the smallest unit", { value: "<integer>" }),
  o("count-cap", "number", "the most admitted requests per period", { value: "<n>" }),
  o("per-operation-cap", "string", "the most one request may spend", { value: "<integer>" }),
  o("expires", "string", "when the budget stops applying", { value: TIME }),
];
type Subjects = BudgetDeclaration["subjects"];
const SUBJECT_KEYS = [["actors", "actorIds"], ["roles", "roleIds"], ["actions", "actions"], ["resources", "resources"]] as const;
const subjectsOf = (p: Parsed, base?: Subjects): Subjects => {
  const out: Record<string, readonly string[] | null> = {};
  for (const [flagName, key] of SUBJECT_KEYS) out[key] = list(p, flagName) ?? base?.[key] ?? null;
  return out as Subjects;
};
const amountOpt = (p: Parsed, name: string): string | undefined => (str(p, name) === undefined ? undefined : parseAmount(str(p, name)!, name).toString());

/** Two selectors can match one request: every dimension is open on one side or the lists share a value, and the metrics agree. */
const overlaps = (a: Rec, b: Rec): boolean => {
  const sa = a.subjects as Subjects, sb = b.subjects as Subjects;
  const dims = SUBJECT_KEYS.every(([, key]) => sa[key] === null || sb[key] === null || sa[key]!.some((v) => sb[key]!.includes(v)));
  return dims && (a.metric === null || b.metric === null || a.metric === b.metric);
};
/** The warnings of `budget declare` (A-39.3, docs/API.md §1, A-25.1). */
function budgetWarnings(state: ReplayState, budgetId: string, witnessed: { bound: boolean; requireOnOpen: boolean }): string[] {
  const warnings: string[] = [];
  const declared = state.budgets.get(budgetId);
  if (declared !== undefined) {
    const overlapping = [...state.budgets.values()].filter((b) => b.status === "ACTIVE" && overlaps(b, declared)).length;
    if (overlapping > MAX_MATCHING_BUDGETS) warnings.push(`BUDGET_SET_TOO_LARGE: a request could match ${overlapping} active budgets; above ${MAX_MATCHING_BUDGETS} it is refused with BUDGET_SET_TOO_LARGE`);
  }
  if (!witnessed.bound) warnings.push("NO_WITNESS: no remote witness is bound, so an older copy of this history (with less usage) cannot be told apart from the latest one; bind one with irontrellis witness add --require-on-open");
  else if (!witnessed.requireOnOpen) warnings.push("WITNESS_NOT_REQUIRED_ON_OPEN: the witness policy does not ask the witnesses before reads, so a rolled-back copy restores spent budget until the next write; set --require-on-open");
  warnings.push("ADMITTED_ONLY: a budget is charged only by admitted operations (gateway jobs, gateway calls with recordCalls, run() callers); hook checks and per-call gateway checks are never charged");
  return warnings;
}

const budgetDeclare = command("budget declare", "budget declare <id> (--amount-cap <n> | --count-cap <n> | --per-operation-cap <n>) [--actors <a,b>] [--roles <r>] [--actions <a>] [--resources <r>] [--metric <name>] [--period-ms <n> [--origin <t>] [--carry-unused --carry-cap <n>]] [--not-before <t>] [--expires <t>]",
  "declare a budget: a spending, count or per-request limit over a group of requests, per period (format 2)", ["id"], [
    ...SUBJECT_OPTIONS,
    id("metric", "string", "the request metric it limits (default: every metric)", { value: "<name>" }),
    ...CAP_OPTIONS,
    o("period-ms", "number", "the length of one period in milliseconds (default: one period for the budget's whole life)", { value: "<n>" }),
    o("origin", "string", "with --period-ms: when period 0 starts (default: now)", { value: TIME }),
    o("carry-unused", "boolean", "with --period-ms: roll unused allowance into later periods, up to --carry-cap"),
    o("carry-cap", "string", "with --carry-unused: the most allowance that can roll over", { value: "<integer>" }),
    o("not-before", "string", "when the budget starts applying", { value: TIME }),
  ], async (p, g) => {
    const [budgetId] = positionals(p, ["id"]);
    const lengthMs = num(p, "period-ms");
    for (const name of ["origin", "carry-unused", "carry-cap"]) if (lengthMs === undefined && p.options.has(name)) throw new UsageError(`--${name} needs --period-ms`);
    if (flag(p, "carry-unused") !== (str(p, "carry-cap") !== undefined)) throw new UsageError("--carry-unused and --carry-cap go together");
    if (!["amount-cap", "count-cap", "per-operation-cap"].some((name) => p.options.has(name))) throw new UsageError("give at least one cap: --amount-cap, --count-cap or --per-operation-cap");
    const input: BudgetDeclaration = {
      budgetId: budgetId!, subjects: subjectsOf(p), metric: str(p, "metric") ?? null,
      period: lengthMs === undefined ? { kind: "NONE" } : { kind: "FIXED_WINDOW", lengthMs, originMs: str(p, "origin") === undefined ? Date.now() : parseTime(str(p, "origin")!, "origin"), carryUnused: flag(p, "carry-unused"), carryCap: amountOpt(p, "carry-cap") ?? null },
      amountCap: amountOpt(p, "amount-cap") ?? null, countCap: num(p, "count-cap") ?? null, perOperationCap: amountOpt(p, "per-operation-cap") ?? null,
      notBefore: str(p, "not-before") === undefined ? null : parseTime(str(p, "not-before")!, "not-before"), expiresAt: str(p, "expires") === undefined ? null : parseTime(str(p, "expires")!, "expires"),
    };
    const { result, warnings } = await write(g, async (w) => {
      writableFormat(w.reader.store, "budget declare");
      const done = await w.owner.declareBudget(input);
      const witness = w.owner.witnessStatus();
      const state = (await openReader(g)).state;
      return { result: done, warnings: budgetWarnings(state, budgetId!, { bound: (witness?.bound.length ?? 0) > 0, requireOnOpen: witness?.policy.requireOnOpen === true }) };
    });
    return written(`budget ${budgetId}`, result, { budget: input, warnings }, (s, out) => {
      for (const warning of warnings) out.add(warning.startsWith("ADMITTED_ONLY") ? s.paint(`  ${warning}`, "secondary") : s.strong(`  ${warning}`));
    });
  });

const budgetUpdate = command("budget update", "budget update <id> [--actors …] [--roles …] [--actions …] [--resources …] [--amount-cap <n>] [--count-cap <n>] [--per-operation-cap <n>] [--expires <t>] [--clear <names>]",
  "change an active budget from now on (usage so far is kept; rollover earned so far is frozen)", ["id"], [
    ...SUBJECT_OPTIONS, ...CAP_OPTIONS,
    o("clear", "list", "set these to none or any: actors, roles, actions, resources, amount-cap, count-cap, per-operation-cap, expires", { value: "<names>" }),
  ], async (p, g) => {
    const [budgetId] = positionals(p, ["id"]);
    const clear = new Set(list(p, "clear") ?? []);
    const known = ["actors", "roles", "actions", "resources", "amount-cap", "count-cap", "per-operation-cap", "expires"];
    for (const name of clear) {
      if (!known.includes(name)) throw new UsageError(`--clear: unknown name "${name}" (one of ${known.join(", ")})`);
      if (p.options.has(name)) throw new UsageError(`--clear ${name} and --${name} exclude each other`);
    }
    const result = await write(g, async (w) => {
      writableFormat(w.reader.store, "budget update");
      const current = w.reader.state.budgets.get(budgetId!) as Rec | undefined;
      if (current === undefined) throw new CliError("INVALID_INPUT", `the history has no budget ${budgetId}`);
      const base = current.subjects as Subjects, subjects = subjectsOf(p, base) as Record<string, readonly string[] | null>;
      for (const [flagName, key] of SUBJECT_KEYS) if (clear.has(flagName)) subjects[key] = null;
      const pick = <T>(name: string, given: T | undefined, now: T): T | null => (clear.has(name) ? null : given ?? now);
      return w.owner.updateBudget({
        budgetId: budgetId!, subjects: subjects as Subjects,
        amountCap: pick("amount-cap", amountOpt(p, "amount-cap"), current.amountCap as string | null), countCap: pick("count-cap", num(p, "count-cap"), current.countCap as number | null),
        perOperationCap: pick("per-operation-cap", amountOpt(p, "per-operation-cap"), current.perOperationCap as string | null),
        expiresAt: pick("expires", str(p, "expires") === undefined ? undefined : parseTime(str(p, "expires")!, "expires"), current.expiresAt as number | null),
      });
    });
    return written(`update of budget ${budgetId}`, result);
  });

const budgetClose = command("budget close", "budget close <id>", "close an active budget for good (it never reopens)", ["id"], [], async (p, g) => {
  const [budgetId] = positionals(p, ["id"]);
  return written(`closing of budget ${budgetId}`, await write(g, (w) => { writableFormat(w.reader.store, "budget close"); return w.owner.closeBudget({ budgetId: budgetId! }); }));
});

const capLine = (b: Rec): string => [
  b.amountCap === null ? undefined : `amount ${String(b.amountCap)}`, b.countCap === null ? undefined : `count ${String(b.countCap)}`, b.perOperationCap === null ? undefined : `per request ${String(b.perOperationCap)}`,
].filter((x) => x !== undefined).join(" · ");
const subjectLine = (b: Rec): string => {
  const s = b.subjects as Subjects;
  return SUBJECT_KEYS.map(([name, key]) => `${name} ${s[key] === null ? "any" : s[key]!.join(", ")}`).join(" · ") + ` · metric ${b.metric === null ? "any" : String(b.metric)}`;
};
const periodLine = (b: Rec): string => {
  const period = b.period as Rec;
  return period.kind === "NONE" ? "one period" : `every ${String(period.lengthMs)} ms from ${formatTime(period.originMs as number)}${period.carryUnused === true ? ` · unused rolls over, up to ${String(period.carryCap)}` : ""}`;
};
const headroomLines = (s: Style, out: Lines, h: Rec | null): void => {
  if (h === null) return;
  out.add(...rows(s, [
    ["active", h.active === true ? "yes" : "no"], ["period", h.periodIndex === null ? "not started" : String(h.periodIndex)],
    ["used", `${String(h.usedAmount)} (amount) · ${String(h.usedCount)} (count)`], ["rolled over in", String(h.carryIn)],
    ["remaining", `${h.remainingAmount === null ? "no amount cap" : `${String(h.remainingAmount)} (amount)`} · ${h.remainingCount === null ? "no count cap" : `${String(h.remainingCount)} (count)`}`],
  ]));
};

const budgetShow = command("budget show", "budget show [<id>]", "list the budgets (or one, with its headroom now or at --at)", [], [], async (p, g) => {
  if (p.positionals.length > 1) throw new UsageError(`unexpected argument "${p.positionals[1]}"`);
  const r = await openReader(g), state = format2(r, "budget show"), at = evaluationTime(g);
  const one = p.positionals[0];
  if (one !== undefined) positionals(p, ["id"]);
  const budgets = [...state.budgets.values()].filter((b) => one === undefined || b.budgetId === one);
  if (one !== undefined && budgets.length === 0) throw new CliError("INVALID_INPUT", `the history has no budget ${one}`);
  const shown = budgets.map((b) => ({ budget: b, headroom: headroom(state, b.budgetId as string, at) }));
  return {
    json: { at, budgets: shown },
    render: (s, out) => {
      out.add(`BUDGETS  ${plural(shown.length, "budget")} · evaluated at ${formatTime(at)}`);
      for (const { budget: b, headroom: h } of shown) {
        out.blank();
        out.add(`${String(b.status)}  ${String(b.budgetId)}  ${s.paint(capLine(b), "secondary")}`);
        out.add(`  ${s.paint(subjectLine(b), "secondary")}`);
        out.add(`  ${s.paint(periodLine(b), "secondary")}`);
        if (one !== undefined) headroomLines(s, out, h);
        else if (h !== null) out.add(`  ${s.paint(`remaining ${h.remainingAmount === null ? "—" : String(h.remainingAmount)} (amount) · ${h.remainingCount === null ? "—" : String(h.remainingCount)} (count)`, "secondary")}`);
      }
      out.blank();
      out.add(s.paint("Headroom is a view of the recorded usage; it is not permission to spend.", "secondary"));
    },
  };
});

const budgetHeadroom = command("budget headroom", "budget headroom <id> [--at <t>]", "what is left of a budget in the period at a time (default now): a view, not a permission", ["id"], [], async (p, g) => {
  const [budgetId] = positionals(p, ["id"]);
  const r = await openReader(g), state = format2(r, "budget headroom"), at = evaluationTime(g);
  const h = headroom(state, budgetId!, at);
  if (h === null) throw new CliError("INVALID_INPUT", `the history has no budget ${budgetId}`);
  return {
    json: { at, ...h },
    render: (s, out) => {
      out.add(`HEADROOM  ${budgetId} · at ${formatTime(at)}`);
      headroomLines(s, out, h);
      out.blank();
      out.add(s.paint("Headroom is a view of the recorded usage; it is not permission to spend.", "secondary"));
    },
  };
});

// ---------------------------------------------------------------- checkpoints (SPEC §7.3)

/** The recorded `STATE_CHECKPOINT`s, without their signatures. */
const checkpointsOf = (state: ReplayState) => state.events.flatMap((e, position) => {
  if (e.type !== "STATE_CHECKPOINT") return [];
  const { controlAuthorization: _signature, ...data } = e.data as Rec;
  return [{ position, eventId: e.id, timestamp: e.timestamp, ...data } as Rec & { position: number; eventId: string; timestamp: number }];
});

const checkpointCreate = command("checkpoint create", "checkpoint create [--id <id>]", "record a signed checkpoint of the state: head, state root, record count and projection head (format 2)", [], [
  id("id", "string", "the checkpoint id (default checkpoint:<position>)", { value: "<id>" }),
], async (p, g) => {
  positionals(p, []);
  const result = await write(g, (w) => { writableFormat(w.reader.store, "checkpoint create"); return w.owner.checkpoint(str(p, "id") === undefined ? {} : { checkpointId: str(p, "id")! }); });
  return written("checkpoint", result, { stateRoot: result.stateRoot, recordCount: result.recordCount, projectionHead: result.projectionHead }, (s, out) => {
    out.add(`  ${s.paint("root ", "secondary")}  ${result.stateRoot} · ${plural(result.recordCount, "record")}`);
    out.add(`  ${s.paint("proj ", "secondary")}  ${result.projectionHead ?? "off"}`);
  });
});

const checkpointList = command("checkpoint list", "checkpoint list", "the signed checkpoints recorded in the history", [], [], async (p, g) => {
  positionals(p, []);
  const r = await openReader(g), list = checkpointsOf(format2(r, "checkpoint list"));
  return {
    json: { checkpoints: list },
    render: (s, out) => {
      out.add(`CHECKPOINTS  ${plural(list.length, "checkpoint")}`);
      for (const c of list) out.add(`  ${String(c.position).padStart(6)}  ${String(c.checkpointId)}  ${s.paint(`covers position ${String((c.head as Rec).position)} · root ${String(c.stateRoot).slice(0, 18)}… · ${String(c.recordCount)} records · ${formatTime(c.timestamp)}`, "secondary")}`);
    },
  };
});

/** Every checkpoint against a full replay from the genesis: the stated root, record count and projection head recomputed at the position it covers. */
const checkpointVerify = command("checkpoint verify", "checkpoint verify", "replay the history from the genesis and check every checkpoint's root, record count and projection head (exit 1 on a mismatch)", [], [], async (p, g) => {
  positionals(p, []);
  const r = await openReader(g);
  format2(r, "checkpoint verify");
  const replayed = replay(r.state.events);
  if (replayed.status !== "ACCEPTED") throw new CliError("INVALID_HISTORY", `the history does not replay: ${replayed.code}: ${replayed.reason}`);
  const state = replayed.state;
  const results = checkpointsOf(state).map((c) => {
    // The replay itself refused any checkpoint whose root or record count differs from the state before it (SPEC §7.3);
    // the roots are recomputed here once more from the records at that position for the report.
    const at = (c.head as Rec).position as number, root = rootAt(state, at), proj = projectionHeadAt(state, at);
    const ok = root === c.stateRoot && proj === c.projectionHead;
    return { position: c.position, checkpointId: c.checkpointId, covers: at, ok, stateRoot: c.stateRoot, recomputedStateRoot: root ?? null, projectionHead: c.projectionHead, recomputedProjectionHead: proj ?? null };
  });
  const ok = results.every((x) => x.ok);
  return {
    json: { ok, mode: "FULL_REPLAY", checkpoints: results },
    render: (s, out) => {
      out.add(`${ok ? "VERIFIED" : s.strong("FAILED")}  ${plural(results.length, "checkpoint")} against a full replay`);
      for (const x of results) out.add(`  ${x.ok ? s.strong("OK      ") : s.strong("MISMATCH")}  ${String(x.checkpointId)} at ${x.position} ${s.paint(`(covers position ${x.covers})`, "secondary")}`);
      out.blank();
      out.add(s.paint("Each checkpoint's state root was recomputed from the records a full replay derives, never read from a cache.", "secondary"));
    },
    exit: ok ? 0 : 1,
  };
});

// ---------------------------------------------------------------- counterparties (SPEC §11)

const KEY_OPTION = o("key", "list", "a counterparty key as <keyId>=<ed25519 public key, 0x + 64 hex> (repeat or comma-separate; 1 to 16)", { value: "<id=0x…>", required: true });
const keysOf = (p: Parsed): CounterpartyKey[] => list(p, "key")!.map((entry) => {
  const at = entry.lastIndexOf("=");
  if (at <= 0) throw new UsageError(`--key: "${entry}" is not <keyId>=<public key>`);
  return { keyId: entry.slice(0, at), scheme: "ed25519", credential: entry.slice(at + 1) };
});

const counterpartyRegister = command("counterparty register", "counterparty register <id> --key <keyId>=<0x…> [--allow-key-rebind]", "register a counterparty whose signed receipts the history may record (format 2)", ["id"], [
  KEY_OPTION, o("allow-key-rebind", "boolean", "re-register a retired counterparty with a key id or key it used before"),
], async (p, g) => {
  const [counterpartyId] = positionals(p, ["id"]);
  const keys = keysOf(p);
  return written(`counterparty ${counterpartyId}`, await write(g, (w) => {
    writableFormat(w.reader.store, "counterparty register");
    return w.owner.registerCounterparty({ counterpartyId: counterpartyId!, keys, ...(flag(p, "allow-key-rebind") ? { allowKeyRebind: true } : {}) });
  }), { keyIds: keys.map((k) => k.keyId) });
});

const counterpartyRetire = command("counterparty retire", "counterparty retire <id>", "retire a counterparty: no further receipts from it are recorded", ["id"], [], async (p, g) => {
  const [counterpartyId] = positionals(p, ["id"]);
  return written(`retirement of counterparty ${counterpartyId}`, await write(g, (w) => { writableFormat(w.reader.store, "counterparty retire"); return w.owner.retireCounterparty({ counterpartyId: counterpartyId! }); }));
});

const counterpartyRotate = command("counterparty rotate", "counterparty rotate <id> --key <keyId>=<0x…> [--allow-key-rebind]", "replace a counterparty's keys: retire it and register it again with the new keys (its receipt chain continues)", ["id"], [
  KEY_OPTION, o("allow-key-rebind", "boolean", "keep a key id or key it used before"),
], async (p, g) => {
  const [counterpartyId] = positionals(p, ["id"]);
  const keys = keysOf(p);
  const done = await write(g, async (w) => {
    writableFormat(w.reader.store, "counterparty rotate");
    const current = w.reader.state.counterparties.get(counterpartyId!);
    if (current === undefined) throw new CliError("INVALID_INPUT", `the history has no counterparty ${counterpartyId}; register it first`);
    const retired = current.status === "ACTIVE" ? await w.owner.retireCounterparty({ counterpartyId: counterpartyId! }) : undefined;
    const registered = await w.owner.registerCounterparty({ counterpartyId: counterpartyId!, keys, ...(flag(p, "allow-key-rebind") ? { allowKeyRebind: true } : {}) });
    return { retired, registered };
  });
  return written(`new keys for counterparty ${counterpartyId}`, done.registered, { retiredEventId: done.retired?.eventId ?? null, keyIds: keys.map((k) => k.keyId) }, (s, out) => {
    if (done.retired !== undefined) out.add(`  ${s.paint("retire", "secondary")}  ${done.retired.eventId} (the old keys)`);
    out.add(s.paint("The receipt chain continues: the next receipt must name the last recorded one.", "secondary"));
  });
});

const counterpartyReceipts = command("counterparty receipts", "counterparty receipts <id>", "a counterparty's keys, status and the receipts the history recorded from it", ["id"], [], async (p, g) => {
  const [counterpartyId] = positionals(p, ["id"]);
  const r = await openReader(g), state = format2(r, "counterparty receipts");
  const c = state.counterparties.get(counterpartyId!);
  if (c === undefined) throw new CliError("INVALID_INPUT", `the history has no counterparty ${counterpartyId}`);
  const receipts = state.events.flatMap((e, position) => {
    if (e.type !== "COUNTERPARTY_RECEIPT_RECORDED") return [];
    const envelope = e.data.envelope as Rec;
    if (envelope.counterpartyId !== counterpartyId) return [];
    return [{ position, eventId: e.id, intentId: e.data.intentId, keyId: envelope.keyId, amount: envelope.amount, outcome: envelope.outcome, observedAt: envelope.observedAt, previousReceiptDigest: envelope.previousReceiptDigest }];
  });
  const view = { counterpartyId, status: c.status, keyIds: ((c.keys as readonly Rec[] | undefined) ?? []).map((k) => k.keyId), receiptCount: c.receiptCount, lastReceiptDigest: c.lastReceiptDigest ?? null, receipts };
  return {
    json: view,
    render: (s, out) => {
      out.add(`${String(c.status)}  counterparty ${counterpartyId}`);
      out.add(...rows(s, [["keys", view.keyIds.join(", ")], ["receipts", String(view.receiptCount)], ["last receipt", String(view.lastReceiptDigest ?? "none")]]));
      for (const x of receipts) out.add(`  ${String(x.position).padStart(6)}  ${String(x.outcome).padEnd(9)} ${String(x.amount)} for ${String(x.intentId)} ${s.paint(`observed ${formatTime(x.observedAt as number)}`, "secondary")}`);
      out.blank();
      out.add(s.paint("The amount and outcome are what the counterparty signed; the history binds them to the intent but does not prove them.", "secondary"));
    },
  };
});

// ---------------------------------------------------------------- duty policy (SPEC §13)

/** `{algorithm: "sha256", value}` of a document: `--<name> <file>` (hashed here) or `--<name>-digest 0x…`. */
function documentDigest(p: Parsed, name: string): Readonly<{ algorithm: "sha256"; value: ContentHash }> {
  const file = str(p, name), given = str(p, `${name}-digest`);
  if ((file === undefined) === (given === undefined)) throw new UsageError(`give --${name} <file> or --${name}-digest <0x…>`);
  if (given !== undefined) {
    if (!/^0x[0-9a-f]{64}$/.test(given)) throw new UsageError(`--${name}-digest: "${given}" is not 0x + 64 lowercase hex`);
    return { algorithm: "sha256", value: given as ContentHash };
  }
  const path = resolve(file!);
  if (!existsSync(path)) throw new CliError("FILE_NOT_FOUND", `--${name}: no file at ${path}`);
  return { algorithm: "sha256", value: `0x${createHash("sha256").update(readFileSync(path)).digest("hex")}` as ContentHash };
}
const SELECTION_OPTIONS: readonly OptionSpec[] = [
  o("incident", "string", "the incident document the investigation reviews (its sha256 is recorded, never its text)", { value: "<file>" }),
  o("incident-digest", "string", "or its sha256 directly", { value: "<0x…>" }),
  id("attester-role", "string", "the role whose holder attests the findings", { value: "<role>", required: true }),
];
const DIGEST_OPTIONS = (name: string, what: string): OptionSpec[] => [
  o(name, "string", `${what} (its sha256 is recorded, never its text)`, { value: "<file>" }), o(`${name}-digest`, "string", "or its sha256 directly", { value: "<0x…>" }),
];
const AUTHORITY_OPTIONS: readonly OptionSpec[] = [
  id("attestation-authority", "string", "the grant of ATTEST_DUTY_FINDING on duty:<descriptor hash> to the attester", { value: "<grant>", required: true }),
  id("disposition-authority", "string", "the grant of RECORD_DUTY_DISPOSITION on duty:<descriptor hash> to the session's agent", { value: "<grant>", required: true }),
  id("attester-session", "string", "a separate attester session that signs the finding (default: --session)", { value: "<id>" }),
  o("attester-key", "string", "with --attester-session: its private key file", { value: "<file>" }),
];
const CRITERIA = ["SOURCE_REVIEWED", "HISTORY_REVIEWED", "FINDING_RECORDED", "CONTROL_REVIEWED"] as const;

/** The duty writer for the named session (and attester), over the history `r`. */
function dutyWriter(r: Reader, g: Global, p: Parsed) {
  writableFormat(r.store, "duty");
  format2(r, "duty");
  const session = need(p, "session");
  const options = runtimeOptions(r, g, session, sessionSigner(r.state, session, need(p, "session-key")));
  const attester = str(p, "attester-session");
  if ((attester === undefined) !== (str(p, "attester-key") === undefined)) throw new UsageError("--attester-session and --attester-key go together");
  return openLocalDutyPolicy({ ...options, ...(attester === undefined ? {} : { attester: { session: attester, signHash: sessionSigner(r.state, attester, str(p, "attester-key")!) } }) });
}
/** The view in plain words (SPEC §13.3). */
const viewLines = (s: Style, out: Lines, view: Rec | null): void => {
  if (view === null) { out.add(s.paint("  no duty policy is active for this duty", "secondary")); return; }
  const last = view.lastRecordedDisposition as Rec | null;
  out.add(...rows(s, [
    ["state", String(view.dutyDisposition)], ["outstanding", view.outstanding === true ? "yes" : "no"], ["assignee", String(view.currentAssigneeId)],
    ["last finding", last === null ? "none" : `${String(last.disposition ?? last.dutyDisposition ?? "")} ${String(last.eventId ?? "")}`.trim()],
    ["reasons", (view.reasons as readonly string[]).join(", ") || "—"], ["outside result", String(view.externalOutcome)],
  ]));
};
const dutyOutcome = (what: string, result: Rec & { eventId: string; head: never; alreadyRecorded: boolean; view: Rec | null }): Outcome => ({
  json: result,
  render: (s, out) => {
    out.add(`${result.alreadyRecorded ? "ALREADY RECORDED" : "RECORDED"}  ${what}`);
    out.add(`  ${s.paint("event", "secondary")}  ${result.eventId}`);
    out.add(`  ${s.paint("head ", "secondary")}  ${headLine(result.head)}`);
    viewLines(s, out, result.view);
    if (result.alreadyRecorded) out.add(s.paint("The same request was recorded before under this id: nothing was signed or written.", "secondary"));
  },
});

const dutyDescribe = command("duty describe", "duty describe <duty> (--incident <file> | --incident-digest <0x…>) --attester-role <role> --session <id> --session-key <file>",
  "describe the investigation policy for an attempt duty: what the owner must grant before activate (writes nothing, grants nothing)", ["duty"], [...SELECTION_OPTIONS, ...SESSION_OPTIONS], async (p, g) => {
    const [duty] = positionals(p, ["duty"]);
    const r = await openReader(g);
    const d = dutyWriter(r, g, p).describe({ duty: duty!, incidentSourceDigest: documentDigest(p, "incident"), attesterRole: need(p, "attester-role") });
    const agent = r.state.runtimeSessions.get(need(p, "session"))!.agentId;
    const next = [
      `irontrellis grant <activation-grant> --to ${agent} --actions ${d.activationAction} --resources ${d.activationResource} --expires +1h`,
      `irontrellis grant <finding-grant> --to <attester agent> --actions ATTEST_DUTY_FINDING --resources duty:${d.descriptorHash} --expires +1d`,
      `irontrellis grant <disposition-grant> --to ${agent} --actions RECORD_DUTY_DISPOSITION --resources duty:${d.descriptorHash} --expires +1d`,
    ];
    return {
      json: { ...d, findingResource: `duty:${d.descriptorHash}`, next },
      render: (s, out) => {
        out.add(`DESCRIBED  duty policy for ${duty}`);
        out.add(...rows(s, [["descriptor", d.descriptorHash], ["activation", `${d.activationAction} on ${d.activationResource}`], ["findings", `duty:${d.descriptorHash}`], ["head", headLine(d.head)]]));
        out.blank();
        out.add("Next, as the owner (each grant must name exactly this resource, with no caps and no delegation):");
        for (const line of next) out.add(`  ${line}`);
        out.add(s.paint("This description grants nothing and writes nothing.", "secondary"));
      },
    };
  });

const dutyActivate = command("duty activate", "duty activate <id> --duty <duty> (--incident <file> | --incident-digest <0x…>) --attester-role <role> --authority <grant> --session <id> --session-key <file>",
  "activate the investigation policy on an attempt duty (signed by the session; needs the activation grant describe names)", ["id"], [
    id("duty", "string", "the attempt duty", { value: "<duty>", required: true }), ...SELECTION_OPTIONS,
    id("authority", "string", "the owner's grant of ACTIVATE_DUTY_POLICY on the described resource", { value: "<grant>", required: true }), ...SESSION_OPTIONS,
  ], async (p, g) => {
    const [activation] = positionals(p, ["id"]);
    const r = await openReader(g), duties = dutyWriter(r, g, p);
    const d = duties.describe({ duty: need(p, "duty"), incidentSourceDigest: documentDigest(p, "incident"), attesterRole: need(p, "attester-role") });
    const result = await duties.activate({ id: activation!, descriptor: d.descriptor, activationAuthority: need(p, "authority") });
    return dutyOutcome(`duty policy ${activation} on ${need(p, "duty")}`, { ...result, descriptorHash: d.descriptorHash } as never);
  });

const dutyDispose = command("duty dispose", "duty dispose <id> --duty <duty> --disposition COMPLETED_UNDER_POLICY|ESCALATED (--report <file> | --report-digest <0x…>) (--checklist <file> | --all-satisfied <reason>) [--next-step <text>] --attestation-authority <grant> --disposition-authority <grant> --session <id> --session-key <file>",
  "record a finding on an active duty policy: the attester signs the finding, then the session signs the disposition", ["id"], [
    id("duty", "string", "the attempt duty", { value: "<duty>", required: true }),
    o("disposition", "string", "COMPLETED_UNDER_POLICY or ESCALATED", { value: "<state>", required: true }),
    ...DIGEST_OPTIONS("report", "the local investigation report"),
    o("checklist", "string", "a JSON file: for each of SOURCE_REVIEWED, HISTORY_REVIEWED, FINDING_RECORDED, CONTROL_REVIEWED a {\"state\": SATISFIED|UNAVAILABLE|UNRESOLVED, \"reason\": text}", { value: "<file>" }),
    o("all-satisfied", "string", "mark all four criteria SATISFIED with this reason instead of --checklist", { value: "<reason>" }),
    o("next-step", "string", "what happens next (required with ESCALATED)", { value: "<text>" }),
    ...AUTHORITY_OPTIONS, ...SESSION_OPTIONS,
  ], async (p, g) => {
    const [disposition] = positionals(p, ["id"]);
    const state = need(p, "disposition");
    if (state !== "COMPLETED_UNDER_POLICY" && state !== "ESCALATED") throw new UsageError(`--disposition: "${state}" is not COMPLETED_UNDER_POLICY or ESCALATED`);
    if ((str(p, "checklist") === undefined) === (str(p, "all-satisfied") === undefined)) throw new UsageError("give --checklist <file> or --all-satisfied <reason>");
    let checklist: Rec;
    if (str(p, "all-satisfied") !== undefined) checklist = Object.fromEntries(CRITERIA.map((k) => [k, { state: "SATISFIED", reason: str(p, "all-satisfied")! }]));
    else {
      try { checklist = JSON.parse(readFileSync(resolve(str(p, "checklist")!), "utf8")) as Rec; } catch (error) { throw new CliError("INVALID_INPUT", `--checklist: ${(error as Error).message}`); }
    }
    const r = await openReader(g);
    const result = await dutyWriter(r, g, p).dispose({
      id: disposition!, duty: need(p, "duty"), disposition: state, checklist: checklist as never, reportDigest: documentDigest(p, "report"), nextStep: str(p, "next-step") ?? null,
      attestationAuthority: need(p, "attestation-authority"), dispositionAuthority: need(p, "disposition-authority"),
    });
    return dutyOutcome(`${state} finding ${disposition} on ${need(p, "duty")}`, result as never);
  });

const dutyContest = command("duty contest", "duty contest <id> --duty <duty> --target <disposition event> --reason <text> (--report <file> | --report-digest <0x…>) --attestation-authority <grant> --disposition-authority <grant> --session <id> --session-key <file>",
  "contest a recorded finding: the duty goes back to CONTESTED until a new finding", ["id"], [
    id("duty", "string", "the attempt duty", { value: "<duty>", required: true }),
    id("target", "string", "the event id of the finding contested (duty-disposition:<id>)", { value: "<event>", required: true }),
    o("reason", "string", "why the finding is contested", { value: "<text>", required: true }),
    ...DIGEST_OPTIONS("report", "the challenge document"), ...AUTHORITY_OPTIONS, ...SESSION_OPTIONS,
  ], async (p, g) => {
    const [contest] = positionals(p, ["id"]);
    const r = await openReader(g);
    const result = await dutyWriter(r, g, p).contest({
      id: contest!, duty: need(p, "duty"), targetDispositionId: need(p, "target"), reason: need(p, "reason"), reportDigest: documentDigest(p, "report"),
      attestationAuthority: need(p, "attestation-authority"), dispositionAuthority: need(p, "disposition-authority"),
    });
    return dutyOutcome(`contest ${contest} on ${need(p, "duty")}`, result as never);
  });

const dutyInspect = command("duty inspect", "duty inspect <duty>", "the investigation view of an attempt duty: its state, last finding and why it is or is not outstanding", ["duty"], [], async (p, g) => {
  const [duty] = positionals(p, ["duty"]);
  const r = await openReader(g), state = format2(r, "duty inspect");
  if (!state.attemptDuties.has(duty!)) throw new CliError("INVALID_INPUT", `the history has no attempt duty ${duty}`);
  const view = inspectDutyPolicyState(state, duty!) as Rec | null;
  return {
    json: { scope: "CAPTURED_HISTORY_ONLY", executionCapability: false, head: state.head, policy: view },
    render: (s, out) => {
      out.add(`DUTY  ${duty} · history ${headLine(state.head)}`);
      viewLines(s, out, view);
      out.blank();
      out.add(s.paint("This view reads the captured history only; it proves nothing about the outside result.", "secondary"));
    },
  };
});

// ---------------------------------------------------------------- export view (SPEC §15)

const VIEW_FLAGS = ["view", "from", "to", "records", "attestations"] as const;
const exportView = command("export", "export [--view | --from <n> --to <n>] [--records] [--attestations]",
  "print the events as a JSON array (bigints as {\"$continuity.bigint\":\"…\"} markers in older formats); with --view, --from or --to, the format-2 export view of a range, which export verify checks", [], [
    o("view", "boolean", "print the export view of the whole history (format 2)"),
    o("from", "number", "the export view from this position (default 0)", { value: "<n>" }),
    o("to", "number", "the export view up to this position (default the head)", { value: "<n>" }),
    o("records", "boolean", "with the view: include the state records at both ends, so a verifier can check both roots without the earlier events"),
    o("attestations", "boolean", "with the view: include the owner head attestations held for the two ends and the owner key events"),
  ], async (p, g) => {
    positionals(p, []);
    const r = await openReader(g);
    if (!VIEW_FLAGS.some((name) => p.options.has(name) && p.options.get(name) !== false)) {
      const text = g.json ? jsonStringifyWithBigints(r.state.events) : JSON.stringify(JSON.parse(jsonStringifyWithBigints(r.state.events)), null, 2);
      return { json: r.state.events, raw: `${text}\n`, render: (_s, out) => out.add(text) };
    }
    if (!(p.options.has("view") || p.options.has("from") || p.options.has("to"))) throw new UsageError("--records and --attestations go with --view, --from or --to");
    format2(r, "the export view");
    const from = num(p, "from") ?? 0, to = num(p, "to") ?? r.state.head.position;
    if (from > to || to > r.state.head.position) throw new UsageError(`--from ${from} --to ${to}: the range must satisfy 0 ≤ from ≤ to ≤ ${r.state.head.position}`);
    const records = flag(p, "records"), attestations = flag(p, "attestations");
    const pin = r.store.verify().pinnedHead?.attestation;
    const view = exportViewState(r.state, {
      fromPosition: from, toPosition: to,
      include: { referencedEvents: true, ...(records ? { fromRecords: true, toRecords: true } : {}), ...(attestations ? { attestations: true, keyEvents: true } : {}) },
    }, pin === undefined ? {} : { headAttestations: [pin] });
    const text = JSON.stringify(view, null, g.json ? undefined : 2);
    return { json: view, raw: `${text}\n`, render: (_s, out) => out.add(text) };
  });

const exportVerify = command("export verify", "export verify <file> [--genesis-event-hash <0x…>] [--expect-history-id <0x…>] [--expect-owner-key <0x…> | --expect-owner-keys <file>]", "check an export view file on its own: its history id against the value you give, the chain, both state roots, every event between them and what it carries, then its first owner keys against the values you give (exit 1 on any failure)", ["file"], [
  o("genesis-event-hash", "string", "the genesis event hash you trust for this history (default: the one the view states)", { value: "<0x…>" }),
  ...IDENTITY_OPTIONS(o),
], async (p, g) => {
  const [file] = positionals(p, ["file"], false);
  const path = resolve(file!);
  if (!existsSync(path)) throw new CliError("FILE_NOT_FOUND", `no export view at ${path}`);
  let view: unknown;
  try { view = JSON.parse(readFileSync(path, "utf8")); } catch (error) { throw new CliError("INVALID_INPUT", `${path} is not JSON: ${(error as Error).message}`); }
  const genesis = str(p, "genesis-event-hash");
  const expected = expectedIdentity(p);
  // Founder decision 4cb: the history id (of the genesis the view states, which the verification binds to the events) is
  // checked first, and a mismatch stops there; the first owner keys are compared once the verification has established them.
  const stated = view !== null && typeof view === "object" && typeof (view as Rec).genesisEventHash === "string" ? (view as Rec).genesisEventHash as string : undefined;
  let statedId: string | undefined;
  try { statedId = stated === undefined ? undefined : historyIdOfGenesisEventHash(stated); } catch { statedId = undefined; }
  const early = expected?.historyId === undefined ? [] : statedId === undefined
    ? [{ code: "HISTORY_ID_MISMATCH" as const, expected: expected.historyId, found: null, line: `HISTORY_ID_MISMATCH: the view states no valid genesisEventHash, so its history id is not the expected ${expected.historyId}` }]
    : mismatchesOf({ historyId: expected.historyId }, { historyId: statedId, ownerKeys: [] });
  const report = early.length > 0 ? undefined : verifyExportView(view, genesis === undefined ? {} : { genesisEventHash: genesis as ContentHash });
  const found = statedId === undefined ? undefined : report === undefined ? { historyId: statedId, ownerKeys: [] } : identityOfView(stated!, report.ownerKeyEpochs);
  const late = report?.ok === true && expected?.ownerKeys !== undefined && found !== undefined ? mismatchesOf({ ownerKeys: expected.ownerKeys }, found) : [];
  const mismatches = [...early, ...late];
  // The first owner keys are established only by a view that verified.
  const identity = identityView(expected, { historyId: statedId ?? null, ownerKeys: report?.ok === true && found !== undefined ? found.ownerKeys : null }, mismatches);
  const ok = report?.ok === true && mismatches.length === 0;
  const failures = [...mismatches.map((m) => m.line), ...(report?.failures ?? [])];
  void g;
  return {
    json: { ...(report ?? { notes: [] }), ok, ...(mismatches.length > 0 ? { code: mismatches[0]!.code } : {}), failures, identity },
    render: (s, out) => {
      out.add(`${ok ? "VERIFIED" : s.strong("FAILED")}  export view ${path}`);
      out.add(...rows(s, [
        ...identityRows(identity),
        ...(report === undefined ? [] : [
          ["from", `position ${report.from.position} · ${report.from.verified ? "root recomputed" : "not verified"} · ${report.from.authenticated ?? "not authenticated"}`] as const,
          ["to", `position ${report.to.position} · ${report.to.verified ? "root recomputed" : "not verified"} · ${report.to.authenticated ?? "not authenticated"}`] as const,
          ["events", String(report.eventCount)] as const,
        ]),
        ...(mismatches.length > 0 ? [["code", mismatches[0]!.code] as const] : report?.code === undefined ? [] : [["code", report.code] as const]),
      ]));
      for (const f of failures) out.add(`  ${s.strong("·")} ${f}`);
      for (const n of report?.notes ?? []) out.add(`  ${s.paint("·", "secondary")} ${n}`);
      out.blank();
      out.add(s.paint(ok ? "Every hash and root the view states was recomputed from what it carries. An end marked not authenticated is checked against the chain only, not against an owner signature."
        : "The view did not pass; treat what it states as unestablished.", "secondary"));
      out.add(s.paint(identityCaveat(identity), "secondary"));
    },
    exit: ok ? 0 : 1,
  };
});

/** Status lines for a format-2 history (SPEC §7.1–7.3). */
export function format2Status(state: ReplayState): Rec | undefined {
  if (state.format !== "irontrellis-event/2") return undefined;
  const root = stateRootOf(state);
  const checkpoints = checkpointsOf(state);
  const last = checkpoints.at(-1);
  return {
    stateRoot: root?.root ?? null, recordCount: root?.count ?? null, projectionHead: projectionHeadAt(state, state.head.position) ?? null,
    checkpoint: last === undefined ? null : { position: last.position, checkpointId: last.checkpointId, covers: (last.head as Rec).position, stateRoot: last.stateRoot },
    checkpoints: checkpoints.length, budgets: state.budgets.size, counterparties: state.counterparties.size, refusals: state.refusals.size, effects: state.effects.size,
  };
}

export const FORMAT2_COMMANDS: readonly Command[] = Object.freeze([
  budgetDeclare, budgetUpdate, budgetClose, budgetShow, budgetHeadroom,
  checkpointCreate, checkpointList, checkpointVerify,
  counterpartyRegister, counterpartyRotate, counterpartyRetire, counterpartyReceipts,
  dutyDescribe, dutyActivate, dutyDispose, dutyContest, dutyInspect,
  exportView, exportVerify,
]);

