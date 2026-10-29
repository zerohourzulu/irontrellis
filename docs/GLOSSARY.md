# Glossary

IronTrellis (formerly Continuity) keeps a signed, replayable history of who may act for whom. This page defines the words its records, answers and documents use, each in plain language with the limit that matters most. Identifiers in `code` keep their exact wire spelling.

Every definition says what a record or an answer claims. None of them establishes anyone's real-world identity, legal responsibility, that an action was carried out, or that an adapter's report is true. [Security](SECURITY.md) and the [history format](HISTORY-FORMAT.md) give the full boundaries. To see many of these words at work in one story, read the example at the top of [Principles](PRINCIPLES.md#a-short-example).

## The state words

| Word | Meaning |
|---|---|
| ALLOW | Permission established |
| DENY | Refused by the current rules |
| INDETERMINATE | Can't be decided from the evidence |
| OPEN | A duty still owed |

## People, agents and control

| Term | Meaning |
|---|---|
| **Principal, owner** | The party declared to own a history. Its grants can be recognized roots under `declared-principal-root/0.2`. Recognition is a recorded policy, not a check of anyone's real-world identity. |
| **Controller** | The supervisory identity on an agent and its control epochs. A `controllerId` grants no authority by itself. |
| **Agent** | A durable identity that can receive grants, occupy roles and owe duties. Termination ends its eligibility but erases none of its records. |
| **Runtime session** | One running instance admitted for an agent, with a credential, a control epoch and an expiry. Session-signed events bind the session and its key. Holding the key alone doesn't make the session current. |
| **Control epoch** | An agent's session generation. Advancing it fences earlier sessions, without deleting them or terminating the agent. |
| **Owner key epoch** | The owner keys, approval policy and next-key commitment that govern a span of history positions. A rotation is authorized by the epoch before it, and a check that depends on position must use the epoch in force there. |
| **Owner approval policy** | The `ownerPolicy`: a threshold for control events, with optional per-type thresholds, key classes, attestations and recovery. `M_eff` is the threshold that applies to an event; `M_rot` applies to a key rotation. Every supplied co-signature must verify, even one that doesn't count toward the threshold. See the [owner-policy reference](reference/owner-policy.md). |
| **Power-reducing event, `PR_eff`** | An event that reduces authority under the specified test of the state before it. Only such an event can use a lower threshold; having one of the listed event types isn't enough. |
| **PHL, Proof of Human Lineage** | The policy vocabulary for tracing authority to qualifying human-class approvals and attestation evidence. 1.0.0-rc.2 ships the PHL attestation policy (`humanFloor: "ATTESTED"`, with attesters and their signed statements); it ships no PHL query. It covers the recorded credentials and attester statements only: it doesn't prove a named person's identity, or an external action. |
| **Human floor** | `humanFloor: "DECLARED"` uses declared key classes. `"ATTESTED"` uses statements signed by the policy's attesters: a non-agent credential is `HUMAN` while its statement is valid, `LAPSED` after it expires, and `NONE` before it starts or without one. Which classes count depends on the event. |
| **Attester, attestation** | An authorized attester signs a statement about an owner credential, with an audience, profile, evidence digest and validity interval. The wire fields keep the names `attesters` and `attestations`. Trust in the attester, and the evidence behind its statement, sit outside signature verification. |
| **T1, T2, T3** | Time rules. Under attested policies, T1 stops runtime events from crossing a future statement expiry, and T2 limits how far a control event with at most one human-class counting signer can move time. When the genesis sets `sessionTimeHorizonMs`, T3 stops a session-signed event from carrying history time more than that horizon past the latest owner event that advanced it. These rules restrict the recorded timeline; they don't authenticate wall-clock time. The reference gives the exact order and exceptions. |
| **Restoration** | A restricted policy rotation that carries or renews attestation statements while keeping the specified keys, commitment and other policy fields. It lets qualifying lapsed credentials restore their attestations, under the restoration rules. |

## Roles and work

| Term | Meaning |
|---|---|
| **Role** | A durable office with one current tenure. Grants and duties can name the role, not only its occupant. |
| **Tenure, appointment** | One agent's numbered term in a role. Appointment opens it; unappointment or transfer ends it, under the replay rules. |
| **Succession rule, handover** | A succession rule records a predecessor, a successor and a role. A handover transfers the office and records the predecessor's departure. Grants don't follow just because duties survive. |
| **Intent** | A declared consequential operation, identified by an intent id and a nonce, with actor, action, resource, role and session binding, and an optional amount, counterparty and terms commitment. |
| **Admission** | The recorded authorization of an intent, at a particular pre-event head and evaluation time. Replay checks its full proof and runtime signature. It records permission, not completion. |
| **Adapter** | The component invoked for admitted work. Its profile and policy edition decide the acknowledgment, outcome and lifecycle rules. |
| **Acknowledgment, outcome** | The adapter's report of a submission or a result. A no-effect report says nothing was sent. An outcome record doesn't by itself prove a business result. |
| **Receipt** | An artifact that binds an admitted intent, its authorization and lifecycle evidence to a history prefix. Not the same as a remote witness receipt, which proves inclusion in a log. |
| **Effect record** | A signed measurement for an admitted intent (a metric, a unit and an amount), reported by a session, a connector or a counterparty. It records who claimed what, not that the effect happened. |
| **Counterparty receipt** | A receipt signed by a registered outside party for an admitted intent, and recorded by a session. Its amount and outcome are the counterparty's claim: the history binds them to the intent, but doesn't establish delivery or settlement. |
| **Obligation, duty** | Recorded unfinished work, with a durable obligor, a performance assignment and a status. Assignment changes who performs the work; it doesn't erase the obligation. |
| **Attempt duty, review** | Follow-up on an operation with an uncertain outcome, under the relevant adapter policy edition. Closing a review records the evidence digest and the disposition; it doesn't turn uncertain external evidence into certainty. |

## Authority and accounting

| Term | Meaning |
|---|---|
| **Grant, authority** | A permission with a grantor, a grantee and constraints. A recognized root starts a path; a delegation names its parent. |
| **Attenuation** | A child grant may narrow its parent's permission, never widen it. The rules cover action and resource sets, time, amounts, depth and required partners. |
| **Intersection** | Required partner authority (`requiredIntersectionIds`) that must take part in a valid permission path. Not the same as the owner-key threshold for signing control events. |
| **Controlling authorities** | The deduplicated union of the authorities on the selected main path and the required partner paths. A shared ancestor is charged once per accepted admission. |
| **Prohibition** | A recorded restriction, global or under a specified root. It can defeat an otherwise valid permission path. |
| **Revocation** | Ending an authority's eligibility. Paths that depend on it may stop working; independent paths may remain. Earlier usage and evidence stay recorded. |
| **Authority cap** | A grant's fixed per-transaction or cumulative amount limit. Not the same as a budget, which can be updated. The legacy capped `authorityUsage` and the format-2 all-controller `usage` are separate ledgers. |
| **Budget** | A separately declared limit that selects subjects and a metric, with caps, an active window and, optionally, fixed periods and carry-over. A budget can DENY a request that passes the authority checks; it never grants authority. |
| **Headroom** | A view of recorded budget usage and remaining allowance at a requested time, over the current records. It doesn't authorize work, and on its own it doesn't reconstruct a past state. |
| **Amount** | In format 2, a nonnegative bounded integer written as a canonical decimal string. Where a schema allows them, a missing amount, zero and `null` mean different things. |

## Answers and evidence

| Term | Meaning |
|---|---|
| **Decision** | ALLOW, DENY or INDETERMINATE, for a captured history, request and evaluation time. INDETERMINATE is never permission to proceed. The decision envelope carries `executionCapability: false`. |
| **Authorization proof** | The structured path, constraints, controlling authorities, usage and evidence that come with an ALLOW. The word "proof" here doesn't by itself mean a theorem-prover result or a zero-knowledge proof. |
| **Refusal record** | A session-signed `REQUEST_REFUSED` record of a DENY or INDETERMINATE. For a CORE or BUDGET refusal, replay decides the request again and must reach the same answer. A CONNECTOR refusal, recorded by an enforcement point such as the hook, shows only that the connector says so. For the hook and the gateway, recording is bounded and best effort: a hook that can't record in time still denies, and in 1.0.0-rc.2 the hook's protective-rule refusals aren't recorded at all. |
| **Reconciliation observation** | An admitted session's signed claim about one event from a provider's log: whether it matches an earlier admission or refusal by the same actor. Only the event's digest enters the history. It proves neither that every provider event was seen nor that an effect happened. |
| **WHY, RESPONSIBLE, SURVIVES** | Queries that explain a decision, attribute recorded roles and responsibilities, and describe what remains after a departure. Responsibility here is a claim about records, not a legal judgment. |
| **Epistemic status, scope assurance** | Whether an answer is established from the available evidence, and whether its state came from verified replay (`REPLAY_VERIFIED`) or from supplied scope (`SUPPLIED_SCOPE`). Keep the two apart. |
| **Evidence reference** | A deterministic reference to a supporting event and its history position. A bounded list of references isn't a complete external investigation. |

## Histories and verification

| Term | Meaning |
|---|---|
| **Format** | The version of a history's rules and bytes, fixed by its first line. Legacy histories (`continuity-event/0.2`, from Continuity) and format-1 histories (`irontrellis-event/1`) are read only; this release writes format 2 (`irontrellis-event/2`). Format 2 is released with the first public publication of 1.0.0-rc.2. After that, a later version reads a format-2 history exactly as 1.0.0-rc.2 does, or refuses it, and fixes to the rules come as a new format. |
| **Challenge profile** | The structure of what a session key signs. Format 2 as released means profile `g3`, the default, in which the signatures on intent declarations, refusals, effects and counterparty receipts also bind the event's id, type and timestamp. The `frozen-r2.3` profile exists only to verify the frozen format-2 conformance vectors. |
| **History, replay** | A sequence of JSONL events whose canonical record chain rebuilds the state. Formats have distinct schemas and hash domains; format-1 and legacy names don't describe format 2. |
| **History id** | In format 2, `historyId` and `genesisHash` name the genesis record-chain hash, `recordHash(0)`. `genesisEventHash` names the genesis event's own hash; never substitute one for the other. |
| **Head** | The identity of a history prefix: hash, position and canonical time. An admission head, a terminal head and a historical query head can be different valid prefixes. |
| **State root, projection** | Commitments to the specified canonical state records, or to the projection. A matching digest means something only with its exact schema, codec and claimed prefix. |
| **Pinned head, attestation** | The pin is the head selected in a side file beside the history (`<history>.head`); an attestation is the owner's signed statement of a head. An attestation can cover an earlier prefix than the latest pin, and that gap matters for rollback detection. Records written without the owner key, such as the refusals the hook and the gateway record, stay unattested until the next owner write. |
| **Anchor, anchor log** | A deposited head attestation and its receipt. A local anchor log protects against rollback only while a later trusted copy survives outside the attacker's control. Anchoring doesn't bind a witness. 1.0.0-rc.2 doesn't verify anchors on a public chain itself: its anchor check produces no report, and the separate tools used for the demonstration anchoring records report `TRUSTED_NODE` only ([known issues 54 and 71](records/KNOWN-ISSUES-r2.5.md)). |
| **Remote witness, binding** | A separate service that records owner-signed heads in a Merkle log. A signed binding in the history fixes the witnesses and their minimum policy; a side file on the host can't lower that minimum. Records written without the owner key aren't witnessed until the next owner write. |
| **Witness checkpoint, receipt, latest note** | Respectively: a signed Merkle-log root; evidence that an entry is in the log; a fresh, nonce-bound answer about a history's latest head. Inclusion alone doesn't prove freshness. These checkpoints aren't the in-history `STATE_CHECKPOINT` events. |
| **Equivocation, split view** | Conflicting owner-signed claims about a history, or inconsistent witness views. Remembered checkpoints and independent witnesses help detect them; evidence a reader never sees can't protect that reader. |
| **Next-key commitment, pre-rotation** | Committing to replacement keys before they're used, with proof of possession when they're revealed. It protects only while the next key stays outside the current key's compromise boundary. |
| **Capacity policy** | Bounds on history growth, with capacity reserved for control and lifecycle events. Physical file, memory and storage limits still apply. |
| **Migration** | Importing a source history under the target format's migration rules. Source signatures and their interpretation can be preserved; migration doesn't authenticate an untrusted source's past. |
| **Conformance, differential test** | Comparison with fixed expected vectors, or between implementations on the same inputs. Passing the listed cases is evidence for those cases, not proof that implementations are equivalent. |

*Last reviewed: 24 October 2026. This page is revisited at each release.*
