import test from "node:test";
import assert from "node:assert/strict";
import {
  tool,
  Agent,
  Runner,
  RunContext,
  runToolInputGuardrails,
} from "@openai/agents";
import {
  ScriptedModel,
  assistantMessage,
  functionCall,
} from "@openai/agents/testing";
import {
  Annotation,
  StateGraph,
  MemorySaver,
  START,
  END,
  Command,
} from "@langchain/langgraph";
import { z } from "zod";
import {
  openAIToolShim,
  langGraphInterrupt,
  releaseResult,
  approvalHash,
  GovernanceBlocked,
  ResultWithheld,
} from "../dist/index.js";
import { setup, page, event } from "../../managed-agents/test/helpers.mjs";
function sdkTool(s) {
  const shim = openAIToolShim({
    backend: s.backend,
    route: s.route,
    assertCurrent: s.options.assertCurrent,
    executionCall(input, ctx, details) {
      return { ...s.call, callId: details.toolCall.callId, arguments: input };
    },
    guardrailCall(data) {
      return {
        ...s.call,
        callId: data.toolCall.callId,
        arguments: JSON.parse(data.toolCall.arguments),
      };
    },
  });
  return tool({
    name: "write",
    description: "Synthetic local notes",
    parameters: z.object({ text: z.string() }),
    ...shim,
  });
}
function graph(s, observe = async () => {}) {
  const state = Annotation.Root({ result: Annotation() });
  return new StateGraph(state)
    .addNode("effect", async () => ({
      result: await langGraphInterrupt(s.call, {
        backend: s.backend,
        route: s.route,
        assertCurrent: s.options.assertCurrent,
        observe,
      }),
    }))
    .addEdge(START, "effect")
    .addEdge("effect", END)
    .compile({ checkpointer: new MemorySaver() });
}

test("real Agents SDK runner approval pause resumes into native Core execution", async (t) => {
  const s = await setup(t, { route: { host: "openai-agents-sdk" } }),
    ft = sdkTool(s);
  const model = new ScriptedModel([
      [functionCall("write", { text: "hello" }, { callId: "call1" })],
      [assistantMessage("complete")],
    ]),
    agent = new Agent({ name: "offline", model, tools: [ft] }),
    runner = new Runner({ tracingDisabled: true });
  const paused = await runner.run(agent, "run the synthetic tool");
  assert.equal(paused.interruptions.length, 1);
  assert.equal(s.effects, 0);
  paused.state.approve(paused.interruptions[0]);
  const result = await runner.run(agent, paused.state);
  assert.equal(result.finalOutput, "complete");
  assert.equal(s.effects, 1);
  assert.ok(s.events().some((e) => e.type === "TRANSACTION_INTENT_ADMITTED"));
  model.assertComplete();
});
test("real Agents SDK guardrail denies revoked authority before tool dispatch", async (t) => {
  const s = await setup(t, { route: { host: "openai-agents-sdk" } }),
    ft = sdkTool(s);
  await s.revoke();
  const result = await runToolInputGuardrails({
    guardrails: ft.inputGuardrails,
    context: new RunContext(),
    agent: new Agent({ name: "offline" }),
    toolCall: functionCall("write", { text: "hello" }, { callId: "call1" }),
  });
  assert.equal(result.type, "reject");
  assert.equal(s.effects, 0);
});
test("real Agents SDK resumed approval rechecks revocation and does not dispatch", async (t) => {
  const s = await setup(t, { route: { host: "openai-agents-sdk" } }),
    model = new ScriptedModel([
      [functionCall("write", { text: "hello" }, { callId: "call1" })],
      [assistantMessage("refused")],
    ]),
    agent = new Agent({ name: "offline", model, tools: [sdkTool(s)] }),
    runner = new Runner({ tracingDisabled: true });
  const paused = await runner.run(agent, "request");
  await s.revoke();
  paused.state.approve(paused.interruptions[0]);
  await runner.run(agent, paused.state);
  assert.equal(s.effects, 0);
});
test("real LangGraph checkpointer interrupt and resume reauthorizes native record", async (t) => {
  const s = await setup(t, { route: { host: "langgraph" } }),
    g = graph(s),
    config = { configurable: { thread_id: "approved" } };
  const paused = await g.invoke({ result: null }, config);
  assert.equal(paused.__interrupt__.length, 1);
  assert.equal(s.effects, 0);
  const result = await g.invoke(
    new Command({ resume: { approved: true, callHash: approvalHash(s.call) } }),
    config,
  );
  assert.equal(result.result.status, "CORE_RESULT");
  assert.equal(s.effects, 1);
});
test("LangGraph stale approval after revocation fails closed", async (t) => {
  const s = await setup(t, { route: { host: "langgraph" } }),
    g = graph(s),
    config = { configurable: { thread_id: "revoked" } };
  await g.invoke({ result: null }, config);
  await s.revoke();
  await assert.rejects(
    g.invoke(
      new Command({
        resume: { approved: true, callHash: approvalHash(s.call) },
      }),
      config,
    ),
    GovernanceBlocked,
  );
  assert.equal(s.effects, 0);
});
test("LangGraph approval mismatch persists native observation and never dispatches", async (t) => {
  const s = await setup(t, { route: { host: "langgraph" } }),
    rec = s.makeRec();
  const observe = async (info) => {
    const result = await rec.reconcile(
      page(s, [event(info.kind, { actorId: info.call.actorId })]),
    );
    assert.equal(result.checkpointAdvanced, true);
  };
  const g = graph(s, observe),
    config = { configurable: { thread_id: "mismatch" } };
  await g.invoke({ result: null }, config);
  await assert.rejects(
    g.invoke(
      new Command({ resume: { approved: true, callHash: "wrong" } }),
      config,
    ),
    (error) => error instanceof GovernanceBlocked && error.reason === "HUMAN_REJECTED" && /did not approve/.test(error.message),
  );
  assert.equal(s.effects, 0);
  assert.equal(s.events().at(-1).type, "RECONCILIATION_OBSERVED");
});
test("output withholding writes native observation while original effect remains", async (t) => {
  const s = await setup(t, { route: { host: "langgraph" } }),
    rec = s.makeRec(),
    result = await s.backend.record(s.call);
  await assert.rejects(
    releaseResult(s.call, result, {
      route: s.route,
      assertCurrent: s.options.assertCurrent,
      release: () => false,
      observe: async (info) => {
        await rec.reconcile(
          page(s, [event(info.kind, { actorId: info.call.actorId })]),
        );
      },
    }),
    ResultWithheld,
  );
  assert.equal(s.effects, 1);
  assert.equal(s.events().at(-1).type, "RECONCILIATION_OBSERVED");
});
test("shim route cannot be selected by model arguments or rebound workflow", async (t) => {
  const s = await setup(t, { route: { host: "openai-agents-sdk" } }),
    shim = openAIToolShim({
      backend: s.backend,
      route: s.route,
      assertCurrent: s.options.assertCurrent,
      executionCall: () => ({ ...s.call, workflowId: "other" }),
      guardrailCall: () => s.call,
    });
  await assert.rejects(shim.execute({ text: "x" }), /route/);
  assert.equal(s.effects, 0);
});
