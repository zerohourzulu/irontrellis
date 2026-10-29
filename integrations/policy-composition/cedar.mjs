import { createHash } from "node:crypto";
import { isAuthorized, getCedarVersion } from "@cedar-policy/cedar-wasm/nodejs";

/** Trusted, pinned local policy text; no model-provided entities or context. */
export function cedarPolicy(source, record) {
  if (
    typeof source !== "string" ||
    Buffer.byteLength(source) > 65536 ||
    typeof record !== "function"
  ) {
    throw Error("INVALID_CEDAR_CONFIGURATION");
  }
  const version = getCedarVersion();
  const identity = `cedar:${version}:${createHash("sha256").update(source).digest("hex")}`;
  return Object.freeze({
    identity,
    record,
    evaluate(request) {
      const answer = isAuthorized({
        principal: { type: "Agent", id: request.actor },
        action: { type: "Action", id: request.action },
        resource: { type: "Resource", id: request.resource },
        context: {
          session: request.session,
          epoch: request.epoch,
          role: request.role,
          tenure: request.tenure,
          operationId: request.operationId,
          termsCommitment: request.termsCommitment,
          historyHead: request.historyHead,
        },
        policies: { staticPolicies: source },
        entities: [],
      });
      const errors =
        answer.type !== "success" ||
        answer.response.diagnostics.errors.length > 0;
      // Cedar can allow while skipping an errored policy. This application refuses it.
      const decision = errors
        ? "ERROR"
        : answer.response.decision === "allow"
          ? "ALLOW"
          : "DENY";
      const diagnostics = errors
        ? [
            "CEDAR_EVALUATION_ERROR",
            ...(answer.type === "success"
              ? answer.response.diagnostics.errors.map(
                  (e) => `${e.policyId}: ${e.error.message}`,
                )
              : answer.errors.map((e) => e.message)
            )
              .slice(0, 31)
              .map((s) => s.slice(0, 256)),
          ]
        : answer.response.diagnostics.reason
            .slice(0, 32)
            .map((id) => `CEDAR_POLICY:${id}`.slice(0, 256));
      return {
        identity,
        requestHash: request.requestHash,
        decision,
        diagnostics,
      };
    },
  });
}
