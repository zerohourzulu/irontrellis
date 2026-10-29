/**
 * `irontrellis demo`: the zero-install story. A temporary history is created
 * and the standard scenario is played in-process through the core API — the
 * owner grants Bea read+collect on incident:42, admits her session, a duty is
 * recorded from a real (simulated) operation, Bea is replaced by Alex through
 * a succession rule, Alex's session takes the duty over — then the three
 * questions are answered from the file: WHY was Bea allowed, WHO is
 * responsible now, WHAT survives Bea. The history stays on disk so the reader
 * can run `verify`, `why`, `handover` on it. The head is anchored in the local
 * anchor log `<history>.anchors`, so `verify` has a log to compare with.
 */
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import {
  anchorHead, anchorsPathFor, commitTerms, createLocalDomain, createLocalOwner, generateKeyPair, loadOwnerKeyFile, openHistoryStore, openLocalRuntime, openLocalSimulation,
  ownerKeyPathFor, signHashWith, verifyHistory,
} from "@ramex-labs/irontrellis";
import { UsageError, flag, positionals, str, type OptionSpec, type Parsed } from "./args.ts";
import type { Command, Outcome } from "./commands.ts";
import { CliError, observe, openReader, queryAt, type Global } from "./history.ts";
import { dim, formatTime, type Lines, type Style } from "./output.ts";
import { handoverReport } from "./report.ts";
import type { HandoverReport } from "@ramex-labs/irontrellis";
import { headLine, renderHandover, renderResponsible, renderSurvives, renderWhy } from "./render.ts";

const OPTIONS: readonly OptionSpec[] = [
  { name: "dir", kind: "string", help: "directory for the demo history (default: a fresh temp directory)", value: "<dir>" },
  { name: "quiet", kind: "boolean", help: "print only the answers, not the steps" },
];

const HOUR = 3_600_000, DAY = 86_400_000;

/** Plays the scenario; returns the history path and the positions the questions refer to. */
export async function playScenario(dir: string, step: (text: string) => void): Promise<{ historyFile: string; leaving: HandoverReport; admissionPosition: number }> {
  const historyFile = join(dir, "history.jsonl");
  const now = Date.now(), domain = createLocalDomain();
  const config = { historyFile, domain, owner: "operations", controller: "operator", now: () => Date.now() };
  const owner = await createLocalOwner(config);
  step(`init          ${historyFile} (owner operations, controller operator, owner key beside it)`);
  for (const id of ["bea", "alex"]) await owner.createAgent({ id });
  await owner.createRole({ id: "reviewer" });
  await owner.declareSuccession({ id: "handover", from: "bea", to: "alex", role: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  step("structure     agents bea and alex · role reviewer · succession rule handover (bea → alex) · bea appointed reviewer, tenure shift:1");
  const keyBea = generateKeyPair("ed25519", "key:bea"), keyAlex = generateKeyPair("ed25519", "key:alex");
  await owner.admitRuntime({ session: "session:bea", agent: "bea", epoch: 1, key: "key:bea", credential: keyBea.credential, expiresAt: now + DAY });
  await owner.admitRuntime({ session: "session:alex", agent: "alex", epoch: 1, key: "key:alex", credential: keyAlex.credential, expiresAt: now + DAY });
  step("sessions      session:bea and session:alex admitted with fresh ed25519 credentials (private keys never enter the history)");
  await owner.grant({ id: "collect", to: "bea", actions: ["read", "collect", "OBLIGATE"], resources: ["incident:42"], expiresAt: now + 12 * HOUR });
  await owner.grant({ id: "review", to: "alex", actions: ["record-collection-disposition"], resources: ["duty:42"], expiresAt: now + 12 * HOUR });
  step("grants        collect → bea: read, collect, OBLIGATE on incident:42 · review → alex: record-collection-disposition on duty:42");
  const options = { ...config, session: "session:bea", signHash: signHashWith(keyBea) };
  // A raw intent id (A-37.2): the demo names its intent so the printed `why --intent operation:42` commands work.
  const op = { id: "operation:42", intentId: "operation:42", action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: "Incident 42 review" }) };
  const sim = openLocalSimulation(options);
  const ran = await sim.run(op);
  if (ran.status !== "SIMULATION_RESULT" || ran.invocation.status !== "SUBMITTED") throw new CliError("DEMO_FAILED", `simulated operation was not submitted: ${ran.status}`);
  const receipt = await sim.recordReceipt(op);
  if (receipt.status !== "RECEIPT_RESULT") throw new CliError("DEMO_FAILED", `receipt was not recorded: ${receipt.status}`);
  step("operation     bea reads incident:42 through session:bea (simulated adapter, signed receipt) — ALLOW on the recorded grant");
  const duty = await openLocalRuntime(options).obligate({ id: "duty:42", operation: op.id, description: "Review the collected material for incident 42.", deadline: now + 3 * DAY, succession: "handover", reviewAuthority: "review" });
  const admissionPosition = owner.exportHistory().findIndex((e) => e.type === "TRANSACTION_INTENT_ADMITTED");
  step(`duty          duty:42 recorded by bea from operation:42 (${duty.eventId}), deadline in 3 days, follows succession rule handover`);
  // The offboarding report at the moment bea leaves: what she holds, what will not follow.
  const leaving = handoverReport((await openReader({ history: historyFile, json: false })).state, "bea", Date.now());
  const handover = await owner.succeed({ id: "handover:42", rule: "handover", fromAgent: "bea", fromTenure: "shift:1", toAgent: "alex", toTenure: "shift:2", role: "reviewer", number: 2 });
  step(`succession    ${handover.status}: bea terminated, reviewer transferred to alex (tenure shift:2)`);
  await owner.grant({ id: "assign", to: "alex", actions: ["ASSIGN_PERFORMANCE"], resources: ["duty:42"], expiresAt: now + 12 * HOUR });
  await openLocalRuntime({ ...config, session: "session:alex", signHash: signHashWith(keyAlex) }).assign({ id: "assign:42", obligation: "duty:42" });
  step("assignment    alex's session takes duty:42 over under the succession rule; bea's grant collect does not follow");
  // Anchor the head in the local anchor log, as `irontrellis anchor` does, so verify can tell this copy from an older one.
  const signer = loadOwnerKeyFile(ownerKeyPathFor(historyFile));
  const store = openHistoryStore(historyFile, { signer });
  try {
    const anchoredAt = Date.now();
    const anchored = await anchorHead(store, signer, undefined, { id: `event:anchor:${anchoredAt}`, anchoredAt });
    await store.flush();
    step(`anchor        head position ${anchored.attestation.head.position} attested with the owner key and recorded in the local anchor log ${basename(anchorsPathFor(historyFile))}`);
  } finally {
    store.close();
  }
  return { historyFile, leaving, admissionPosition };
}

export const demo: Command = Object.freeze({
  name: "demo",
  usage: "demo [--dir <dir>] [--quiet]",
  summary: "play the standard scenario in a temporary history and answer WHY / WHO / WHAT",
  positionals: [],
  options: OPTIONS,
  async run(p: Parsed, g: Global): Promise<Outcome> {
    positionals(p, []);
    if (g.history !== undefined) throw new UsageError("demo creates its own history; do not pass --history");
    let dir: string;
    if (str(p, "dir") === undefined) dir = mkdtempSync(join(tmpdir(), "irontrellis-demo-"));
    else { dir = resolve(str(p, "dir")!); mkdirSync(dir, { recursive: true }); }
    const steps: string[] = [];
    const played = await playScenario(dir, (text) => steps.push(text));
    const local: Global = { history: played.historyFile, json: g.json };
    const reader = await openReader(local);
    const then = queryAt(reader, local, undefined, "operation:42");
    const request = then.request!;
    const nowQuery = queryAt(reader, local, undefined);
    const why = then.why(request), whyNow = nowQuery.why(request), responsible = then.responsible(request);
    const survivesResult = observe(reader, local).survives("bea");
    const report = played.leaving, after = handoverReport(reader.state, "alex", nowQuery.at);
    const verification = verifyHistory(played.historyFile);
    const quiet = flag(p, "quiet");
    const json = {
      history: played.historyFile, head: reader.state.head, steps, admissionPosition: played.admissionPosition, verify: {
        ok: verification.ok, failures: verification.failures, notes: verification.notes, chain: verification.chain, pinnedHeadStatus: verification.pinnedHeadStatus,
        pinnedAttestation: verification.pinnedAttestation ?? null, anchorLogStatus: verification.anchorLogStatus, controlSignatures: verification.controlSignatures,
      },
      why, whyNow, responsible, survives: survivesResult, handover: report, handoverAfter: after,
      commands: replayCommands(played.historyFile),
    };
    return {
      json,
      render: (s: Style, out: Lines) => {
        if (!quiet) {
          out.add("The scenario, played into a fresh history:");
          for (const line of steps) out.add(`  ${dim(s, "·")} ${line}`);
          out.blank();
          out.add(`${dim(s, "history")}  ${headLine(reader.state.head)}`);
          out.add(`${dim(s, "verify ")}  ${verification.ok ? "VERIFIED" : s.strong("FAILED")} · chain ${verification.chain} · pinned head ${verification.pinnedHeadStatus}${verification.pinnedAttestation === undefined ? "" : ` (${verification.pinnedAttestation === "VERIFIED" ? "owner-attested" : `attestation ${verification.pinnedAttestation}`})`} · witness ${verification.anchorLogStatus} · control signatures ${verification.controlSignatures}`);
          out.blank();
        }
        out.add(`${s.strong("WHY")} was bea allowed to read incident:42?  ${dim(s, `(as admitted at position ${played.admissionPosition}, ${formatTime(then.at)})`)}`);
        renderWhy(s, out, request, why, then.at);
        out.blank();
        out.add(`${dim(s, "And now?")} ${whyNow.epistemicStatus === "ESTABLISHED" ? `${whyNow.answer.authorization.decision}${whyNow.answer.authorization.decision === "DENY" ? ` (${whyNow.answer.authorization.code})` : ""}` : whyNow.epistemicStatus} — bea's termination ended her authority; the record of what was allowed then is unchanged.`);
        out.blank();
        out.add(`${s.strong("WHO")} is responsible for that action now?`);
        renderResponsible(s, out, request, responsible, then.at);
        out.blank();
        out.add(`${s.strong("WHAT")} survives bea?`);
        renderSurvives(s, out, "bea", survivesResult, nowQuery.at);
        out.blank();
        out.add(`${s.strong("HANDOVER")} — the offboarding report at the moment bea left:`);
        renderHandover(s, out, report);
        out.blank();
        const taken = after.openDuties.find((d) => d.id === "duty:42");
        out.add(`${dim(s, "After the handover:")} ${taken === undefined ? "duty:42 is not assigned to alex" : `duty:42 is ${taken.status}, assigned to alex, deadline ${formatTime(taken.deadline)}`}; alex holds ${after.liveGrants.map((x) => x.authorityId).join(", ") || "no grants"} — not bea's grant collect.`);
        out.blank();
        out.add(`The history is at ${played.historyFile}`);
        out.add(dim(s, "Ask it yourself:"));
        for (const line of json.commands) out.add(`  ${line}`);
      },
    };
  },
});

const replayCommands = (historyFile: string): string[] => {
  const base = `irontrellis --history ${historyFile}`;
  return [
    `${base} verify`,
    `${base} status`,
    `${base} why --intent operation:42`,
    `${base} responsible --intent operation:42`,
    `${base} survives bea`,
    `${base} handover bea`,
    `${base} handover alex`,
    `${base} authorize --actor alex --action read --resource incident:42`,
  ];
};
