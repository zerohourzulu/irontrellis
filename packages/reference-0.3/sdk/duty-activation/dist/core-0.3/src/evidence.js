import { capturePolicy } from "./policy.js";
import { mkdirSync, realpathSync, lstatSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { createPacketExecutor, selectInput, } from "./adapters/packet-executor.mjs";
import { openLocalExecution, commitTerms, } from "./execution.js";
import { captureData, identifier, record, requireCondition } from "./input.js";
function directory(path) {
    requireCondition(typeof path === "string" && path.length > 0);
    const selected = resolve(path);
    requireCondition(realpathSync(selected) === selected && lstatSync(selected).isDirectory());
    return selected;
}
/** Trusted setup only. Persist this selection; reopening must not select changed files. */
export function selectEvidence(inputDirectory) {
    return selectInput(directory(inputDirectory));
}
/** A fixed local evidence tool. No caller paths, arbitrary adapter or tool dispatch. */
export function openLocalEvidenceTool(options) {
    const inputDirectory = directory(options.inputDirectory), outputDirectory = directory(options.outputDirectory);
    const resource = identifier(options.resource), role = identifier(options.role), tenure = identifier(options.tenure);
    const selection = captureData(options.selection);
    // The packet executor performs the complete selection schema/bounds check.
    // Construct once against an existing directory, without reading source bytes.
    const termsCommitment = commitTerms({
        tool: "continuity_collect_evidence",
        version: "1",
        resource,
        selection,
    });
    const additionalPolicy = capturePolicy(options.additionalPolicy);
    const config = {
        ...(options.historyProfile === undefined ? { historyFile: options.historyFile } : { historyProfile: options.historyProfile, historyBinding: options.historyBinding }),
        domain: options.domain,
        owner: options.owner,
        controller: options.controller,
        now: options.now,
        session: options.session,
        signHash: options.signHash,
        ...(additionalPolicy ? { additionalPolicy } : {}),
    };
    const validated = createPacketExecutor({
        inputDirectory,
        outputDirectory,
        selection,
        termsCommitment,
        resource,
        domain: config.domain,
        intentId: "configuration-validation",
    });
    const capture = (input) => {
        const r = record(input, ["operationId", "resource"]);
        requireCondition(identifier(r.resource) === resource);
        const id = identifier(r.operationId);
        return Object.freeze({
            id,
            action: "collect-evidence-packet",
            resource,
            role,
            tenure,
            termsCommitment,
        });
    };
    const executor = (id, create = false) => {
        const attemptDirectory = join(outputDirectory, createHash("sha256").update(id).digest("hex"));
        if (create) {
            try {
                mkdirSync(attemptDirectory, { mode: 0o700 });
            }
            catch (error) {
                if (error.code !== "EEXIST")
                    throw error;
            }
        }
        directory(attemptDirectory);
        return createPacketExecutor({
            inputDirectory,
            outputDirectory: attemptDirectory,
            selection,
            termsCommitment,
            resource,
            domain: config.domain,
            intentId: id,
        });
    };
    const inspect = (id) => {
        try {
            return executor(id).inspect();
        }
        catch (error) {
            if (error.code === "ENOENT")
                return Object.freeze({ status: "NOT_STARTED" });
            return Object.freeze({
                status: "OUTCOME_UNKNOWN",
                reason: "Packet storage is unavailable.",
            });
        }
    };
    const adapterFor = (id) => ({
        adapterProfile: validated.adapterProfile,
        // Directory creation and bounded packet writes happen only inside the
        // coordinator's protected synchronous submit, after durable admission.
        submit: (submission) => executor(id, true).submit(submission),
        reconcile: (submission) => executor(id).reconcile(submission),
    });
    return Object.freeze({
        resource,
        /** Fresh admission or reconciliation of the same attempt; never a new-ID retry. */
        async collect(input) {
            const op = capture(input), adapter = adapterFor(op.id);
            const runtime = openLocalExecution(config, adapter, "LOCAL_PACKET");
            const result = await runtime.run(op);
            return Object.freeze({ result, packet: inspect(op.id) });
        },
        async recordReceipt(input) {
            const op = capture(input), adapter = adapterFor(op.id);
            return openLocalExecution(config, adapter, "LOCAL_PACKET").recordReceipt(op);
        },
        /** Privileged application inspection. It is not an agent-facing tool. */
        inspect(input) {
            const op = capture(input);
            return inspect(op.id);
        },
    });
}
