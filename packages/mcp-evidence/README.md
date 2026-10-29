# IronTrellis Evidence MCP server

IronTrellis (formerly Continuity) keeps a checkable record of who may act for whom, and which duties survive when an AI agent is replaced.

`irontrellis-evidence` is a stdio MCP (Model Context Protocol) server with one tool, `irontrellis_collect_evidence`, that copies operator-selected files into a protected evidence packet if the configured agent still holds the authority in a format-2 IronTrellis history (format 2 is the history format this release writes). One operation id is one operation, so a retry reconciles the original attempt instead of copying again.

Need several approved tools, or tools the model may call repeatedly? Use [`@ramex-labs/irontrellis-mcp-gateway`](../mcp-gateway/README.md) (exactly-once jobs and per-call mode). This package is the smallest complete example of the same boundary: your application chooses the agent, the source files, the destination and the key before launching the server; none of them is a tool argument. Concepts: [docs/PRINCIPLES.md](../../docs/PRINCIPLES.md), [docs/GLOSSARY.md](../../docs/GLOSSARY.md).

This is 1.0.0-rc.2; install it from the `next` tag.

## What happens, call by call

The quickstart below builds this case and runs its first two steps: an agent, bea, holds a grant to collect the evidence packet for `incident:42`, and one input file is selected.

| Step | What the server does | The tool answers |
|---|---|---|
| bea asks for the packet, operation id `example:collection` | Checks bea's authority in the history, copies the selected file into a new packet and records the acknowledgment | `RECORDED`, `packetVerified: true` |
| bea repeats the same call | Inspects the original attempt; copies nothing; the history file is unchanged | `RECONCILIATION_ONLY` |
| The owner revokes the grant, and bea asks again under a new id | Copies nothing; bea's own session records the refusal in the history (code `REVOKED`) | `DENIED`, `reason: CORE_POLICY` |

## 60-second quickstart

```sh
npm install -g @ramex-labs/irontrellis-mcp@next   # provides irontrellis-evidence (alias irontrellis-mcp), -setup and -demo
irontrellis-evidence-setup /absolute/new-case     # synthetic input, disposable Ed25519 key, format-2 history, gateway.json
irontrellis-evidence-demo /absolute/new-case/gateway.json
```

Expected: `Tools: irontrellis_collect_evidence`, then a `RECORDED` packet on the first call and `RECONCILIATION_ONLY` on the repeat, with `packetVerified: true` both times. To connect another MCP client, configure it to launch `irontrellis-evidence --config /absolute/new-case/gateway.json` (stdio).

Keep the case directory private; setup refuses to overwrite an existing directory. All three commands take `--help` and `--version`. A refusal (an existing target, a missing parent, a configuration that is missing, not 0600 or not valid) is one JSON line on stderr with exit code 2, `{"status":"REFUSED","reason":<CODE>,"detail":<why>}` (the server's own line names `GATEWAY_CONFIGURATION_UNAVAILABLE` as its `reason` and may add the underlying `code`), where `detail` names the file, field or limit at fault and never echoes configuration values or keys.

## The tool

`irontrellis_collect_evidence { operationId, resource }`

| Argument | Rule |
|---|---|
| `operationId` | A stable, application-owned id, 1–128 characters. Repeating it reconciles the original attempt. |
| `resource` | Must equal the configured resource; the schema pins it with an `enum`. |

Annotations: `readOnlyHint: false`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`. It creates files and never deletes any; repeating an id copies nothing.

| Result | Meaning | MCP tool error |
|---|---|---|
| `RECORDED` | Admitted, copied, acknowledged in the history; `acknowledgment` is the recorded packet acknowledgment. | no |
| `RECONCILIATION_ONLY` | The original attempt was inspected; nothing was copied. If that attempt's acknowledgment was never recorded, it may be recorded now; `packetVerified` and `disposition` say what the attempt achieved. | no |
| `OUTCOME_UNKNOWN` | Admitted, but the copy or its acknowledgment is not confirmed (for example the selected input changed); `packetVerified` says whether the packet verified. Investigate; do not pick a new id. | yes |
| `DENIED` | `reason: CORE_POLICY` (no current grant): the agent's own session records the refusal in the history, unless an identical refusal was recorded in the last minute or the agent's refusals pass six a minute; the reply's `refusal` says which (`recorded: true` with the `eventId`, or `recorded: false` with the reason). `reason: ADDITIONAL_POLICY`: an additional policy supplied by an embedding host refused the call or could not answer; the history records no refusal for it, and the policy's own audit holds the decision. | yes |
| `REFUSED` | A bounded code: `INVALID_ARGUMENTS`, `RUNTIME_NOT_CURRENT` (retired or expired session), `OPERATION_CONFLICT`, `CAPACITY_CONTROL_ONLY`, … or `GATEWAY_UNAVAILABLE`. | yes |
| `BUSY` | One collection at a time; repeat the same call. | yes |

An MCP tool error is a reply with `isError: true`. `externalOutcome`, which `RECORDED`, `RECONCILIATION_ONLY` and `OUTCOME_UNKNOWN` replies carry, is always `NOT_PROVEN`: a packet proves which selected bytes were copied, not that their contents are true.

## Configuration

`gateway.json` (0600) has exactly these fields. Every choice is the operator's.

| Field | What it holds |
|---|---|
| `historyFile` | The format-2 history |
| `domain` | The history's authorization domain |
| `owner`, `controller` | The owner profile |
| `session` | The admitted runtime session |
| `role`, `tenure` | The agent's role and its current tenure |
| `resource` | The one resource the tool acts on |
| `inputDirectory`, `outputDirectory` | Where the selected files are read, and where packets are written |
| `selection` | From `selectEvidence(inputDirectory)`; reopening never re-selects changed files |
| `keyFile` | The session's private key, `0x` + 64 hex. The scheme is read from the session, and a key that is not the session's credential refuses startup. |

The copy is bounded: at most 8 files, 64 KiB each, 256 KiB in total, into `outputDirectory/<sha256(operationId)>/`.

## Embedding

`createEvidenceServer(loadEvidenceTool(configFile, { additionalPolicy? }))` returns an SDK `Server` (`@modelcontextprotocol/server`); `serveEvidence(tool)` serves it on stdio, to 2026-07-28 and 2025-era clients alike, behind a strict-JSON input guard (16 KiB frames, no duplicate keys, 5-second frame deadline, at most 1,024 messages in any 60 seconds). Input that breaks the guard never reaches the tool: the server stops with exit code 2.

The server refuses at startup rather than serving a configuration it cannot verify (`GATEWAY_CONFIGURATION_UNAVAILABLE`, exit 2). A legacy or format-1 history opens read only and the tool does not act on it; migrate it with `irontrellis migrate`.

## Limits

| Limit | What it means for you |
|---|---|
| The demo runs client and server under one user | A client with the same filesystem access can bypass the tool. A real boundary needs separate OS identities for the agent and the server, with the source, key, history and output directories reachable only by the server. |
| The server signs its records with the agent's session key, never the owner key | Those records stay unattested and unwitnessed until the owner's next write ([docs/SECURITY.md](../../docs/SECURITY.md)). |

## Check it yourself

From a clone of the repository:

```sh
pnpm install
pnpm -r build
pnpm --filter @ramex-labs/irontrellis-mcp test
```

The tests drive the server over stdio, through a real MCP client and with raw frames: a retry, a revoked grant, a retired session, a replaced key, attempts to substitute the actor, paths or resource, duplicate keys, oversized or unfinished frames, and a message flood. They check this package as it ships. They do not test your deployment, and the limits stated above still apply.

Dependencies: `@ramex-labs/irontrellis`, `@modelcontextprotocol/server` and `@modelcontextprotocol/client` (2.2.0, pinned exactly). Apache-2.0.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
