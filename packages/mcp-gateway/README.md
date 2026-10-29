# IronTrellis MCP Gateway

`@ramex-labs/irontrellis-mcp-gateway` **1.0.0-rc.2** puts the MCP tools you approve behind IronTrellis (formerly Continuity), which keeps a signed, replayable history of what each AI agent may do. Before a call reaches an upstream tool, the gateway checks the agent's current authority in that history (format 2); for exactly-once jobs and recorded calls, it also keeps the state of the attempt on disk. MCP client and server dependencies are pinned to **2.2.0**.

## What it is for

An agent that calls its tools directly can act on authority that was taken away a minute ago, or send the same request twice after a lost reply. The gateway sits between your MCP client and the upstream MCP servers you approve, and handles these cases:

| What goes wrong | What the gateway does |
| --- | --- |
| A grant is revoked while the agent runs | It reads the history afresh on every call, so new work under that grant answers `DENIED` |
| A reply is lost and the agent asks again | An exactly-once job answers from its original attempt and never forwards it again |
| An upstream tool's definition changes | It compares the tool with the approved definition before each new admission or per-call forward, and refuses a mismatch (`TOOL_CHANGED`) |

## Try it on a synthetic case

Install from the `next` tag, or use a verified packed installation; the 1.0.0-rc.2 build is not claimed publicly released.

```sh
npm install -g @ramex-labs/irontrellis-mcp-gateway@next   # provides irontrellis-mcp-gateway and irontrellis-mcp-ops
irontrellis-mcp-gateway setup /absolute/new-case           # a private synthetic case; add --mode per-call for the other mode
irontrellis-mcp-gateway --config /absolute/new-case/gateway.json   # serves stdio: put this command in your MCP client's settings
irontrellis-mcp-ops inspect --config /absolute/new-case/gateway.json
irontrellis-mcp-ops revoke  --config /absolute/new-case/gateway.json --authority write
```

`setup` creates a format-2 history with one worker agent, two local upstream servers (documents and tickets) and two jobs, `read_incident` and `create_incident_ticket` (two tools of the same names in per-call mode). The worker's grants and session expire after an hour. From your MCP client:

| You call | The gateway answers |
| --- | --- |
| `create_incident_ticket` | `RESPONSE_RETAINED`: forwarded once, and the reply kept on disk |
| `create_incident_ticket` again, with the same title | `RECONCILIATION_ONLY`: the retained reply; nothing is forwarded. A different title is refused (`OPERATION_CONFLICT`) |
| `create_incident_ticket` after the `revoke` | `RECONCILIATION_ONLY` with its retained reply, because it already ran. Had it never run, it would answer `DENIED`: the `write` grant covers this job |

The server speaks stdio and waits for an MCP client. The setup is a disposable case with local credentials and synthetic tools. Protect its private directory and never reuse its credentials in production. An unknown outcome needs investigation of the original business key, not a new key to force a retry.

## Choose an execution mode

| | Exactly-once jobs, `mode: "exactly-once"` (the default) | Per-call tools, `mode: "per-call"` |
| --- | --- | --- |
| One operation is | A fixed tool and business key | One call |
| A repeat | Reconciles the original attempt and never deliberately forwards it again; changed arguments conflict | Is a new call, checked again |
| Every call checks | The job's fixed schema and current authority; a new admission also checks the approved tool definition | Current authority and the configured tool definition |
| Admitted as an intent in the history | Every job, once | Each call, only with `recordCalls: true`: set it when each call must be admitted and charged through the recorded path |

The profile name is not a guarantee of exactly-once effects inside an arbitrary upstream service. A query-only ALLOW is not a dispatch permit.

`enforceFromReadOnlyHistory` (set by hand) keeps enforcing from a never-migrated legacy or format-1 history read-only: every open warns, and it serves only calls that need no record: a call that must be recorded is refused (`FORMAT_READ_ONLY` with a `remedy`) before anything is dispatched. Migrate to write.

Keep the authenticated history ID/domain, agent, runtime session, signers, role/tenure, trusted clock, upstream executable, business mapping and storage outside agent control. A model supplies only the bounded business arguments permitted by the fixed schema. Retiring or revoking authority cannot undo an effect already sent.

## Public imports

| Subpath | Purpose |
| --- | --- |
| root | `createGateway`, gateway/server integration and public types |
| `/operations` | Operator inspection, lease recovery, snapshots and revocation helpers |
| `/access-policy` | Trusted access-policy configuration |
| `/server` | MCP server integration |
| `/data` | The bounded private-file and canonical-data helpers the anchor outbox shares (`durableCreate`, `readPrivate`, `privateDirectory`, …) |
| **`/http`** | `serveGatewayHttp` for loopback evaluation; `serveGatewayRouter` and `serveGatewayBackend` for the explicit router/backend profile |
| **`/cooperative`** | `createCooperativeGateway`, with run, status, recover, cancel and observe over a pinned cooperative destination |
| **`/tasks`** | `createTaskManager` and `routeTaskRequest` for `io.modelcontextprotocol/tasks`, bound to the configured cooperative gateway and caller identity |
| **`/access-http`** | `createAccessVerifier`, binding issuer, resource, keys and the fixed caller/tenant/revision mapping |

The four subpaths in bold are separate capabilities; importing one does not enable another or establish a secure public deployment. Public HTTPS deployment is not part of this release. Each subpath has its compiled runtime and declaration exports and a `default` export key.

The loopback HTTP helper is an evaluation profile. The router/backend profile requires its explicit TLS/mTLS configuration, pinned private peer, channel-bound assertions, nonce storage and independent bearer/Core checks. Trusted `isActive` and current-access guards must remain effective across asynchronous work. A token or authenticated transport is not native authority to perform an operation. HTTP and Tasks do not turn an uncertain effect into a new attempt.

## Records and results

A refusal decided by the history is returned with its recording status; a recording failure cannot turn a refusal into ALLOW. Core and budget refusals are distinguished from connector reports. Upstream effect or receipt fields are assertions under the connector/counterparty profile; replay does not prove an external business outcome. Replies retain `externalOutcome: NOT_PROVEN` where applicable.

| Result | Operator interpretation |
| --- | --- |
| `RESPONSE_RETAINED` | An upstream reply was retained; inspect its error status and scope |
| `RECONCILIATION_ONLY` | Original retained attempt, with no new forwarding |
| `OUTCOME_UNKNOWN` | A dispatch start exists but the usable reply/outcome is not established |
| `DELAYED` / `NOT_DISPATCHED` / `STOPPED` | Dispatch has not started (anchoring, or an admission without a start record); inspect the reason and, with anchoring, the resume horizon |
| `FORWARDED` | Per-call forwarding occurred; inspect whether it was recorded |
| `DENIED` / `REFUSED` | Read the decision and the bounded refusal reason; do not bypass it |
| `BUSY` | Exclusion or a resource boundary prevents concurrent work |

Every message from the agent is checked before the MCP layer sees it: at most 16 KiB, strict JSON, and no more than 1,024 messages within any 60 seconds. A flood ends the gateway (`INPUT_REFUSED`); a long session of ordinary calls does not. Upstream servers are bounded the same way, and one that stops or floods is disconnected and started again, with its tool definition checked, on the next governed call to it.

Access is checked again after the attempt is durably retained and immediately before the call enters the upstream tool. A revocation at that point prevents the new effect, while an attempt already admitted keeps its uncertain state. No callback, old approval or retained result can replace that check.

Use [operations](docs/OPERATIONS.md), [recovery](docs/RECOVERY.md) and [access-policy](docs/ACCESS-POLICY.md) for operator procedures. Snapshot contents are sensitive; protect them as credentials/evidence until the chosen profile's exclusions are verified. Never clear a live lock or recovery journal to make a stuck operation run again.

## Optional anchoring barrier

Privileged hosts can configure the [live anchoring barrier](docs/LIVE-ANCHORING.md) through the programmatic API. It retains an admitted request while waiting for eligible protected reports, checks a stop latch, and resumes only while no dispatch start exists. The CLI setup does not enable anchoring.

Know its limits in 1.0.0-rc.2. This build includes no qualified report producer, and nothing in it verifies a chain anchor: `verifyAnchor` returns no report, `irontrellis verify` takes none, and the diagnostic connector reports cannot release this barrier. A production-profile barrier therefore never opens unless an external producer supplies reports, and it takes the mode a report declares, `CONSENSUS_VERIFIED` included, on that producer's word. No consensus-verified anchoring is claimed; the separate tools used for the demonstration anchoring records report `TRUSTED_NODE` only, never consensus-verified.

## Established and not established

The package's tests cover the real engine, crash and retry, transport, strict declarations and a packed install. The source tests are `src/http-test.test.mjs`, `src/cooperative-test.test.mjs` and `src/http-twohop-test.test.mjs`; the packed verifier is `src/http-verify-install.py` with the selected offline dependencies. These are the package's own tests; no separate review of the transport subpaths is claimed here.

This is not a hostile-code sandbox, distributed transaction manager, proof of downstream success or production chain/finality implementation. Upstreams share the configured host trust boundary. Cooperating destinations need their own checkpoint, fencing and deduplication contract. Whole-directory rollback, compromised administrators, a destination's unseen revocation and irreversible effects after dispatch remain distinct risks.

What the gateway records (admissions, refusals, effects, receipts) is signed with runtime session keys, not the owner key, so it stays unattested and unwitnessed until the next owner write; see [operations](docs/OPERATIONS.md#revoke). The attestation policy for PHL, Proof of Human Lineage (`ATTESTED`), ships in the 1.0.0-rc.2 core; transport test success does not establish every such policy combination.

Dependencies: `@ramex-labs/irontrellis`, `@ramex-labs/irontrellis-remote`, `jose`, `@modelcontextprotocol/server` and `@modelcontextprotocol/client` (jose 6.2.12 and the MCP SDK 2.2.0, pinned exactly). Apache-2.0.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
