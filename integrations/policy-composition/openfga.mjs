import { createHash } from "node:crypto";
import { OpenFgaClient, ConsistencyPreference } from "@openfga/sdk";

export function fgaObject(type, id) {
  if (
    !["agent", "resource"].includes(type) ||
    typeof id !== "string" ||
    !/^[A-Za-z0-9:_-]{1,128}$/.test(id)
  )
    throw Error("UNSUPPORTED_RELATION_MAPPING");
  return `${type}:${Buffer.from(id, "utf8").toString("base64url")}`;
}

/** Trusted endpoint/store/model selection; caller-supplied contextual tuples are absent. */
export function openFgaPolicy({ apiUrl, storeId, modelId, record }) {
  const endpoint = new URL(apiUrl);
  if (
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    (endpoint.protocol !== "https:" &&
      !(endpoint.protocol === "http:" && endpoint.hostname === "127.0.0.1")) ||
    !/^[0-9A-HJKMNP-TV-Z]{26}$/.test(storeId) ||
    !/^[0-9A-HJKMNP-TV-Z]{26}$/.test(modelId) ||
    typeof record !== "function"
  )
    throw Error("INVALID_OPENFGA_CONFIGURATION");
  const selected = Object.freeze({
    apiUrl: endpoint.href.replace(/\/$/, ""),
    storeId,
    modelId,
    mapping: "base64url-agent-resource-collector/1",
  });
  const identity = `openfga:${createHash("sha256").update(JSON.stringify(selected)).digest("hex")}`;
  return Object.freeze({
    identity,
    record,
    async evaluate(request, signal) {
      if (
        request.action !== "collect-evidence-packet" ||
        !/^[A-Za-z0-9:_-]{1,128}$/.test(request.actor) ||
        !/^[A-Za-z0-9:_-]{1,128}$/.test(request.resource)
      ) {
        throw Error("UNSUPPORTED_RELATION_MAPPING");
      }
      const client = new OpenFgaClient({
        apiUrl: selected.apiUrl,
        storeId,
        authorizationModelId: modelId,
        retryParams: { maxRetry: 0 },
        baseOptions: {
          timeout: 4000,
          signal,
          maxRedirects: 0,
          maxContentLength: 65536,
          maxBodyLength: 65536,
          proxy: false,
        },
      });
      const result = await client.check(
        {
          user: fgaObject("agent", request.actor),
          relation: "collector",
          object: fgaObject("resource", request.resource),
        },
        {
          storeId,
          authorizationModelId: modelId,
          consistency: ConsistencyPreference.HigherConsistency,
        },
      );
      if (
        result.$response.headers["openfga-authorization-model-id"] !==
          modelId ||
        result.$response.headers["openfga-store-id"] !== storeId ||
        typeof result.allowed !== "boolean"
      )
        throw Error("INVALID_OPENFGA_RESPONSE");
      return {
        identity,
        requestHash: request.requestHash,
        decision: result.allowed ? "ALLOW" : "DENY",
        diagnostics: [
          `OPENFGA_STORE:${storeId}`,
          `OPENFGA_MODEL:${modelId}`,
          "HIGHER_CONSISTENCY",
          "NO_CONTEXTUAL_TUPLES",
        ],
      };
    },
  });
}
