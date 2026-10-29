/** Framework interceptors: all effect authority remains inside the fixed backend record route. */
import { types } from "node:util";
import { hashCanonical } from "@ramex-labs/irontrellis/adapter";
import {
  assertGuard,
  capture,
  captureCall,
  type GovernedCall,
  type Route,
  type Guard,
} from "@ramex-labs/irontrellis-managed-agents";
import {
  ToolGuardrailFunctionOutputFactory,
  defineToolInputGuardrail,
  type RunContext,
  type ToolInputGuardrailData,
} from "@openai/agents";
import { interrupt } from "@langchain/langgraph";
export type Call = GovernedCall;
export interface ExecutionBackend<R> {
  decide(call: Call): Promise<Readonly<{ verdict: string }>>;
  record(call: Call, guards: Readonly<{ assertCurrent: Guard }>): Promise<R>;
}
/** Implement with the configured native observation writer/reconciler, never a second signed findings ledger. */
export type Observer = (
  event: Readonly<{
    kind: "HUMAN_REJECTED" | "RESULT_WITHHELD";
    call: Call;
    callHash: string;
    externalOutcome: "NOT_PROVEN";
  }>,
) => Promise<void>;
export const approvalHash = (call: Call): string =>
  hashCanonical(
    { domain: "irontrellis-shim-approval/1", call: capture(call) },
    "sha256",
  );
/** Why a call was blocked: IronTrellis's authority answer, or the person asked for approval (no approval, or not for this call). */
export type GovernanceBlockedReason = "AUTHORITY" | "HUMAN_REJECTED";
export class GovernanceBlocked extends Error {
  readonly reason: GovernanceBlockedReason;
  constructor(reason: GovernanceBlockedReason = "AUTHORITY") {
    super(reason === "HUMAN_REJECTED" ? "the person asked to approve this call did not approve it (rejected, no answer, or an answer for another call)" : "IronTrellis refused or could not determine authority");
    this.name = "GovernanceBlocked";
    this.reason = reason;
  }
}
export class ResultWithheld extends Error {
  constructor() {
    super("Tool result withheld after dispatch; do not retry the effect");
    this.name = "ResultWithheld";
  }
}
async function run<R>(
  backend: ExecutionBackend<R>,
  call: Call,
  guard: Guard,
): Promise<R> {
  assertGuard(guard);
  const decision = await backend.decide(call);
  assertGuard(guard);
  if (decision.verdict !== "ALLOW") throw new GovernanceBlocked();
  const result = await backend.record(call, { assertCurrent: guard });
  assertGuard(guard);
  return result;
}
/** Spread these options into the real SDK tool(). Binders read authenticated runner context, never argument identity. */
export function openAIToolShim<R, I, C>(
  raw: Readonly<{
    backend: ExecutionBackend<R>;
    route: Route;
    assertCurrent: Guard;
    executionCall(
      input: I,
      context: RunContext<C> | undefined,
      details:
        | Readonly<{ toolCall?: ToolInputGuardrailData<C>["toolCall"] }>
        | undefined,
    ): Call;
    guardrailCall(data: ToolInputGuardrailData<C>): Call;
  }>,
) {
  const options = { ...raw, route: capture(raw.route) };
  if (options.route.host !== "openai-agents-sdk")
    throw TypeError("OpenAI route required");
  return Object.freeze({
    needsApproval: true as const,
    inputGuardrails: [
      defineToolInputGuardrail<C>({
        name: "irontrellis_authority",
        async run(data) {
          const call = captureCall(options.guardrailCall(data), options.route);
          assertGuard(options.assertCurrent);
          const decision = await options.backend.decide(call);
          assertGuard(options.assertCurrent);
          return decision.verdict === "ALLOW"
            ? ToolGuardrailFunctionOutputFactory.allow()
            : ToolGuardrailFunctionOutputFactory.rejectContent(
                "IronTrellis authority check refused this call",
              );
        },
      }),
    ],
    async execute(
      input: I,
      context?: RunContext<C>,
      details?: Readonly<{ toolCall?: ToolInputGuardrailData<C>["toolCall"] }>,
    ): Promise<R> {
      const call = captureCall(
        options.executionCall(input, context, details),
        options.route,
      );
      return run(options.backend, call, options.assertCurrent);
    },
  });
}
/** Actual LangGraph interrupt escapes unchanged; resumed nodes capture and authorize the call again. */
export async function langGraphInterrupt<R>(
  raw: Call,
  options: Readonly<{
    backend: ExecutionBackend<R>;
    route: Route;
    assertCurrent: Guard;
    observe: Observer;
  }>,
): Promise<R> {
  const route = capture(options.route);
  if (route.host !== "langgraph") throw TypeError("LangGraph route required");
  const call = captureCall(raw, route),
    callHash = approvalHash(call);
  assertGuard(options.assertCurrent);
  const answer = capture(
    interrupt({ type: "irontrellis_approval", callHash, call }),
  ) as { approved?: boolean; callHash?: string };
  assertGuard(options.assertCurrent);
  if (
    !answer ||
    typeof answer !== "object" ||
    answer.approved !== true ||
    answer.callHash !== callHash
  ) {
    await options.observe({
      kind: "HUMAN_REJECTED",
      call,
      callHash,
      externalOutcome: "NOT_PROVEN",
    });
    assertGuard(options.assertCurrent);
    throw new GovernanceBlocked("HUMAN_REJECTED");
  }
  return run(options.backend, call, options.assertCurrent);
}
/** Withholding preserves the already incurred effect; failure to persist the observation also withholds. */
export async function releaseResult<R>(
  raw: Call,
  result: R,
  options: Readonly<{
    route: Route;
    assertCurrent: Guard;
    release: () => boolean;
    observe: Observer;
  }>,
): Promise<R> {
  const call = captureCall(raw, capture(options.route));
  assertGuard(options.assertCurrent);
  const released: unknown = options.release();
  if (types.isPromise(released))
    Promise.prototype.then.call(released, undefined, () => undefined);
  if (released === true) {
    assertGuard(options.assertCurrent);
    return result;
  }
  await options.observe({
    kind: "RESULT_WITHHELD",
    call,
    callHash: approvalHash(call),
    externalOutcome: "NOT_PROVEN",
  });
  assertGuard(options.assertCurrent);
  throw new ResultWithheld();
}
