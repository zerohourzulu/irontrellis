# IronTrellis agent shims

IronTrellis (formerly Continuity) keeps a checkable record of who may act for whom, and which duties survive when an AI agent is replaced. This package, `@ramex-labs/irontrellis-agent-shims` 1.0.0-rc.2, connects the OpenAI Agents SDK (0.20.0) and LangGraph (1.4.21) to the [managed-agents adapter](../managed-agents/README.md). The framework's own approval or interrupt pauses a tool call; when it resumes, IronTrellis checks the agent's authority again before anything runs. An approval, or a resumed checkpoint, is never permission to run.

```sh
npm install @ramex-labs/irontrellis-agent-shims@next
```

The frameworks need `@langchain/core` and `zod` as peers; this release is tested with `@langchain/core` 1.2.12 and `zod` 4.6.5.

## A stale approval, caught

A model asks to call the tool `write`, and the OpenAI Agents SDK pauses the run for a person's approval. Before the person approves, the owner revokes the agent's grant. The run resumes with the approval; the shim asks the backend, the backend refuses, and the handler never runs. The tests play this story, and the same one in LangGraph, with the real frameworks offline.

## What it exports

| Export | What it does |
| --- | --- |
| `openAIToolShim(options)` | Real OpenAI Agents SDK tool options to spread into `tool({ name, parameters, ...shim })`: required approval, a tool-input guardrail (`irontrellis_authority`) and an execution callback |
| `langGraphInterrupt(call, options)` | Inside a LangGraph node: invokes the actual `interrupt`; when the graph resumes with an approval, authorizes and records the call |
| `releaseResult(call, result, options)` | Releases an already produced result, or withholds it |
| `approvalHash(call)` | Keeps the `irontrellis-shim-approval/1` SHA-256 digest; the new call type includes the workflow explicitly |
| `GovernanceBlocked`, `ResultWithheld` | Thrown when authority is refused or undetermined (or a LangGraph approval is rejected), and when a result is withheld |
| `ExecutionBackend`, `Observer`, `Call` | Types. The managed-agents `governed(options)` backend is an `ExecutionBackend` |

## OpenAI Agents SDK

| Step | What happens |
| --- | --- |
| Approval | The run pauses until a person approves in the SDK's approval state |
| Guardrail | After the approval, `decide` must answer ALLOW, or the tool input is rejected |
| Execution | `decide` again (anything but ALLOW throws `GovernanceBlocked`), then the backend's admitted `record`, with a synchronous live guard |

Your trusted binders (`executionCall`, `guardrailCall`) build the call from the authenticated runner context and call details; model arguments supply only the bounded tool input. The shim fixes tenant, actor, host (`openai-agents-sdk`), full workflow and session, so a call naming another route is refused. By default the SDK runs the guardrail only after the approval, so a person can be asked to approve a call IronTrellis then refuses; the runner option `toolExecution.preApprovalInputGuardrails: true` also runs it before the pause. See the [official OpenAI guardrail and approval guidance](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals) for the SDK boundary; effective authority enforcement belongs at tool execution.

## LangGraph

| Step | What happens |
| --- | --- |
| Pause | `interrupt({ type: "irontrellis_approval", callHash, call })`. Let the framework interrupt escape, so its checkpointer can persist it |
| Resume | Requires `approved: true` and the exact approval hash (`callHash`) |
| Rejected, or a wrong hash | `observe` is called with `HUMAN_REJECTED`, then `GovernanceBlocked` is thrown |
| Approved | The restarted node captures its fixed call and rechecks native authority before `record` |

The route's host must be `langgraph`.

## Withholding a result

`releaseResult` returns the result only if your `release()` returns `true` synchronously; otherwise it calls `observe` with `RESULT_WITHHELD` and throws `ResultWithheld`. It can withhold a result already produced, but it cannot undo its admitted effect.

Supply `observe` with a configured native writer or reconciler of `RECONCILIATION_OBSERVED` observations (event type 42), such as a managed-agents reconciler. Rejected approvals and withheld results do not use a second signed adapter ledger. A failed observation also withholds the output.

## Limits

These shims need a real, configured backend. They do not grant authority or implement chain finality, dispatch leases, external outcome proof or provider authentication themselves. Call and observer signatures changed to include fixed workflow routes and native observations; no legacy compatibility alias is claimed.

## Check it yourself

From a checkout of the repository:

```sh
pnpm install
pnpm -r build
pnpm --filter @ramex-labs/irontrellis-agent-shims test
```

The tests use @openai/agents 0.20.0's actual `Runner`, tool guardrails and approval state with its official offline `ScriptedModel`; no LLM endpoint is contacted. The LangGraph 1.4.21 tests use the actual `StateGraph`, `MemorySaver`, `interrupt` and `Command` resume against native Core execution. The offline model is a test fixture, not an authority. The managed-agents `test/verify-install.py` packs both packages and unchanged Core, checks them in a clean consumer, and instantiates both frameworks with strict installed types.

The test commands above are the package's own checks; this page does not report their results. Deployment boundaries and untested profiles are as stated above.

Apache-2.0. The package carries the repository NOTICE, with any required attribution appended.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
