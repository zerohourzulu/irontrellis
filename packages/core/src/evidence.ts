/**
 * The protected local evidence tool (port of Core 0.3 `evidence.ts`): a fixed
 * file-copy operation over a pre-selected input set into a protected output
 * directory. No caller paths, arbitrary adapter or tool dispatch.
 */
import { lstatSync, mkdirSync, realpathSync } from "node:fs";
import { FORMAT1_TEST_TOOLING, hasFormat1TestTooling } from "./format1-tooling.ts";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import type { TransactionAdapter } from "./coordinators.ts";
import { createPacketExecutor, selectInput, type EvidenceSelection, type PacketInspection } from "./adapters/packet-executor.ts";
import { commitTerms, openLocalExecution, type LocalExecutionOptions } from "./execution.ts";
import { captureData, identifier, record, requireCondition } from "./input.ts";
import { capturePolicy } from "./policy.ts";

export type { EvidenceSelection };
export type EvidenceToolOptions = LocalExecutionOptions & Readonly<{
  inputDirectory: string; outputDirectory: string; selection: EvidenceSelection; resource: string; role: string; tenure: string;
}>;
export type EvidenceRequest = Readonly<{ operationId: string; resource: string }>;

function directory(path: string): string {
  requireCondition(typeof path === "string" && path.length > 0);
  const selected = resolve(path);
  requireCondition(realpathSync(selected) === selected && lstatSync(selected).isDirectory());
  return selected;
}
/** Trusted setup only. Persist this selection; reopening must not select changed files. */
export function selectEvidence(inputDirectory: string): EvidenceSelection {
  return selectInput(directory(inputDirectory));
}

/** A fixed local evidence tool. No caller paths, arbitrary adapter or tool dispatch. */
export function openLocalEvidenceTool(options: EvidenceToolOptions) {
  const inputDirectory = directory(options.inputDirectory), outputDirectory = directory(options.outputDirectory);
  const resource = identifier(options.resource), role = identifier(options.role), tenure = identifier(options.tenure);
  const selection = captureData(options.selection) as EvidenceSelection;
  // The packet executor performs the complete selection schema/bounds check. Construct once against an existing directory, without reading source bytes.
  const termsCommitment = commitTerms({ tool: "continuity_collect_evidence", version: "1", resource, selection });
  const additionalPolicy = capturePolicy(options.additionalPolicy);
  const config: LocalExecutionOptions = {
    historyFile: options.historyFile, domain: options.domain, owner: options.owner, controller: options.controller, now: options.now, session: options.session, signHash: options.signHash,
    ...(options.ids === undefined ? {} : { ids: options.ids }), ...(options.signer === undefined ? {} : { signer: options.signer }),
    // A caller naming format 1 or legacy keeps that writer (SPEC §16.1; `LocalOwnerOptions.format`); `refusals` steers the automatic REQUEST_REFUSED.
    ...(options.format === undefined ? {} : { format: options.format }), ...(options.refusals === undefined ? {} : { refusals: options.refusals }),
    // A-185.3: the internal-format1 test-tooling mark travels with the options it was given.
    ...(hasFormat1TestTooling(options) ? { [FORMAT1_TEST_TOOLING]: true } : {}),
    ...(additionalPolicy === undefined ? {} : { additionalPolicy }),
  };
  const validated = createPacketExecutor({ inputDirectory, outputDirectory, selection, termsCommitment, resource, domain: config.domain, intentId: "configuration-validation" });
  const capture = (input: EvidenceRequest) => {
    const r = record(input, ["operationId", "resource"]);
    requireCondition(identifier(r.resource) === resource);
    // A-37.2: the tool supplies the raw intent id (= operationId; the packet and its folder are named by it) and owns
    // its collision risk; it does not use the derived id (KNOWN-ISSUES).
    const id = identifier(r.operationId);
    return Object.freeze({ id, intentId: id, action: "collect-evidence-packet", resource, role, tenure, termsCommitment });
  };
  const executor = (id: string, create = false) => {
    const attemptDirectory = join(outputDirectory, createHash("sha256").update(id).digest("hex"));
    if (create) {
      try { mkdirSync(attemptDirectory, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    }
    directory(attemptDirectory);
    return createPacketExecutor({ inputDirectory, outputDirectory: attemptDirectory, selection, termsCommitment, resource, domain: config.domain, intentId: id });
  };
  const inspect = (id: string): PacketInspection | Readonly<{ status: "NOT_STARTED" }> => {
    try {
      return executor(id).inspect();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return Object.freeze({ status: "NOT_STARTED" as const });
      return Object.freeze({ status: "OUTCOME_UNKNOWN" as const, reason: "Packet storage is unavailable." });
    }
  };
  const adapterFor = (id: string): TransactionAdapter => ({
    adapterProfile: validated.adapterProfile,
    // Directory creation and bounded packet writes happen only inside the coordinator's protected synchronous submit, after durable admission.
    submit: (submission) => executor(id, true).submit(submission),
    reconcile: (submission) => executor(id).reconcile(submission),
  });
  return Object.freeze({
    resource,
    /** Fresh admission or reconciliation of the same attempt; never a new-ID retry. */
    async collect(input: EvidenceRequest) {
      const op = capture(input), adapter = adapterFor(op.id);
      const result = await openLocalExecution(config, adapter, "LOCAL_PACKET").run(op);
      return Object.freeze({ result, packet: inspect(op.id) });
    },
    async recordReceipt(input: EvidenceRequest) {
      const op = capture(input), adapter = adapterFor(op.id);
      return openLocalExecution(config, adapter, "LOCAL_PACKET").recordReceipt(op);
    },
    /** Privileged application inspection. It is not an agent-facing tool. */
    inspect(input: EvidenceRequest) {
      return inspect(capture(input).id);
    },
  });
}
export type LocalEvidenceTool = ReturnType<typeof openLocalEvidenceTool>;
