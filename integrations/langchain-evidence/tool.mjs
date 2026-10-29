import { tool } from "langchain";
import * as z from "zod";
/** The application owns operationId. Model/tool-call IDs cannot mint retries. */
export function evidenceTool(client, { operationId, resource }) {
  if (
    typeof operationId !== "string" ||
    !operationId ||
    operationId.length > 128 ||
    typeof resource !== "string" ||
    !resource
  )
    throw Error("A fixed workflow operation and resource are required.");
  return tool(
    async (args) => {
      const result = await client.callTool({
        name: "irontrellis_collect_evidence",
        arguments: { operationId, resource: args.resource },
      });
      return JSON.stringify(
        result.structuredContent ?? {
          status: "UNAVAILABLE",
          details: result.content,
        },
      );
    },
    {
      name: "collect_evidence",
      description:
        "Ask the protected IronTrellis service to collect the selected evidence once. Refusal and uncertainty are results to report, not reasons to create a new operation ID.",
      schema: z.object({ resource: z.literal(resource) }).strict(),
    },
  );
}
