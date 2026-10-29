# Security and trust assumptions

IronTrellis (formerly Continuity) keeps a signed, append-only history of what AI agents may do: who granted what to whom, which session speaks for which agent, and what was refused. From that history it answers whether an action is allowed (ALLOW), refused (DENY) or cannot be decided (INDETERMINATE). This page says what a verified history proves, what each proof rests on, and where the protection stops.

One sentence carries most of it: **IronTrellis decides and explains; your hook, gateway or runtime enforces the decision.** A decision reads a captured history. It does not execute an operation, and it does not stop a host that bypasses it.

Read this page with [Custody](CUSTODY.md), [Witness](WITNESS.md), [Operator](OPERATOR.md) and the [owner-policy reference](reference/owner-policy.md).

## A short example

Ada runs a coding agent under the IronTrellis hook (`irontrellis-hook`), on her laptop, as her own OS user. She grants it `write-file` on the project for a week. During that week:

1. The agent edits files. IronTrellis finds each edit allowed, and the hook records nothing for them.
2. The agent runs `npm test`. It holds no `run-shell` grant, so the hook answers DENY and records the refusal, signed with the agent's session key.
3. The agent tries to edit `irontrellis-hook.json`, the hook's own configuration. A protective rule refuses the call before the history is even opened, so this refusal leaves no record.

A month later an auditor verifies the history against the history id and owner key that Ada published:

| The auditor can establish | The auditor cannot establish |
|---|---|
| That every change of power was signed as the owner policy in force required: Ada's owner key granted `write-file`, until a set date | Who held the keys, or what they intended: on one OS user the agent could have read Ada's key and signed a grant to itself, and that grant would verify clean |
| That each recorded admission, and each authority or budget refusal, reproduces on replay: the `npm test` refusal does | Every call the agent made, or what each call did: the file edits and the attempt on the hook's configuration left no record |
| That the copy contains the heads its pin, anchors and consulted witnesses vouch for | That it is the latest copy: until the next owner write (here, the next session the hook admits), the refusal record can be cut off and the copy still verifies |

The sections below explain each of these limits, and what to do about them.

## 1. What a verified history establishes

### Records and decisions

Replay checks the selected format's schemas, record chain, signatures and transitions. An edited, inserted or reordered event changes every later commitment.

Runtime authorization binds the request, the evaluation time, the pre-event head, the session, the epoch, the tenure, the intent and the nonce. Admission replay re-derives the recorded proof.

These checks establish a claim relative to the recorded prefix, its declared policies and the trusted cryptographic implementation.

### Owner control

Control events need the owner authorization that applies at their position. Format-2 owner policies can require several distinct credentials, per-type thresholds and a human-class floor. Every supplied signature must verify, including surplus signatures. A lower threshold for a power-reducing event depends on the event's actual pre-event-state conditions, not only on its type.

Credential separation, committed-key recovery and the lapse and restoration rules of attested policies are implemented. They do not remove the need to protect signers.

### Partial checks

A key-event verifier that does not replay the history checks only its stated subset. `stateChecked: false` means state-dependent credential separation was not judged there. Snapshot resume and export authentication have additional signer, epoch and threshold requirements; a valid isolated signature cannot replace them. Full replay remains the authority for state-dependent checks.

### Pins and witnesses

A pin (the latest head, recorded in a file beside the history) and its owner attestation provide evidence against truncation. Readers compare the file with the pinned prefix, and `verify` also reports the anchor and witness evidence it examined. A signature on an older head remains valid after a key rotation. So a valid chain and a valid old pin do not establish that the file is the latest copy.

A bound remote witness supplies evidence from another trust domain. Before signing a new statement, owner code checks that the witness's latest head is a prefix of the local history it is extending; a witness head ahead of that history, or conflicting with it, causes refusal. Clients verify checkpoints, inclusion proofs, consistency proofs and nonce-bound latest answers. The signed binding fixes the witness identities and the minimum policy, so a writable side file cannot lower those requirements.

### Same answers, now and later

Deterministic results require the same verified history, request, evaluation time and supported profile.

Publishing 1.0.0-rc.2 releases history format 2. A history it writes keeps its verdicts: later versions read it exactly as 1.0.0-rc.2 does, or refuse it, and rule fixes after 1.0.0-rc.2 come as a new format. Format 2 as released means challenge profile `g3`; the `frozen-r2.3` profile only verifies the frozen conformance vectors.

Conformance and differential tests provide evidence for their listed cases. Neither those tests nor the scoped Lean models establish that the production implementation is formally verified.

## 2. The host, the hook and the owner key

### The host is trusted

The host process, its operating system, filesystem, clock and crypto runtime are trusted. A hostile host can skip checks, alter JavaScript intrinsics, patch I/O or use any signer it can reach. Input capture accepts bounded data and refuses unsupported structures; it is not a sandbox against a process that controls the runtime.

### Only routed calls are checked

Hooks see only the calls routed through them. Subagents without hooks, unmediated scripts and credentials already available to an agent remain outside the check. The gateway sees only its routed calls, and its upstream programs run with the gateway's OS privileges. Exactly-once coordination is local to its supported execution path; it is not a universal claim about a remote business operation.

### One OS user is not a boundary

**A shell grant under the default shared-user layout can expose owner authority.** Keeping state outside the project, and matching protected paths or command strings, are useful tripwires, not isolation. Quoting normalization cannot cover arbitrary scripts, aliases, variable expansion or every host setting.

Use a different OS identity for the agent, or a signer the agent cannot read or drive. Keep the history, the owner configuration and the signer credentials outside the agent's writable area.

A key reference prevents theft only if it removes key material from the host. It prevents unauthorized use only if the signer has its own access gate. Do not pass the owner's `SSH_AUTH_SOCK`, Vault token or KMS credentials into the agent's environment. `irontrellis doctor --as-agent` tests access from the agent's OS identity; it supplements an operational review rather than proving isolation.

### The coding-agent hook needs the owner key beside the history

When it admits a new session, the hook signs its events with the one owner key beside the history (`<history>.owner-key.json`, a key file or a reference to its signer), and it cannot collect co-signatures. So in 1.0.0-rc.2 it cannot be used with a multi-signature owner policy or offline owner keys, and the same-user warning above applies in full ([Custody](CUSTODY.md) §9).

### Keys and what they sign

| Key | What it signs |
|---|---|
| Owner keys | Control events (every change of power) and head attestations |
| Session keys | Runtime events, within the session's admitted scope and expiry |

Keep keys dedicated to this protocol: format-2 Ed25519 signatures sign raw 32-byte hashes. Verify external signer responses against the selected public key. A read-only verifier does not need private keys.

### When a key leaks

A leaked current owner credential can authorize whatever the current policy permits until it is removed. With a threshold policy, compromise analysis must count independent credentials and the per-event threshold. A valid signature proves that a key was used, not that the intended person approved. After a suspected compromise, review the events and revoke unauthorized power.

A leaked session credential remains dangerous until it expires or is fenced. Advancing the agent's control epoch is the intended containment, subject to the applicable control authorization and storage conditions.

### 2.1 Pre-rotation and recovery

Pre-rotation commits to replacement keys before they are used. Revealing a committed key requires proof of possession, so a leaked current key alone cannot substitute an arbitrary successor. This protects recovery only while the next key is outside the current key's compromise boundary. Move a generated next-key file off the agent host promptly; each rotation creates a new custody obligation.

| Situation | What pre-rotation does |
|---|---|
| Current key leaked, committed next key safe | The thief cannot substitute a successor of their choosing |
| No commitment | An attacker holding enough current authority can rotate first |
| Current and next keys both compromised | The commitment alone gives no recovery advantage |
| Every case | Earlier signatures stay valid, and the current key can be misused until recovery |

Policy recovery and restoration have specific quorum, class and commitment rules. Use the [owner-policy reference](reference/owner-policy.md) rather than assuming that any lapsed key can rotate alone.

A witness protects a rotation only after it has received the required key-event evidence. A normal two-phase rotation coordinates the bound witnesses before it completes locally; an emergency rotation leaves a delivery obligation. Keep retired keys secure while a witness may still need a rotation-head statement signed by them.

Key-event bundles and qualified supersede handling are recovery mechanisms, not permission to erase lost history. A pending-rotation file must still pass replay and signature checks: planting one can obstruct progress, but must not grant signing authority.

## 3. Freshness and rollback

The strongest freshness claim is limited to the evidence actually consulted. A copy that verifies is consistent with itself; whether it is the latest copy depends on evidence held where an attacker cannot rewrite it.

### Hook and gateway records wait for the owner key

The hook's refusal records and the gateway's records are signed with session keys, not the owner key. A writer without the owner key cannot attest the new head: the pin carries the last owner attestation forward, and nothing is queued for the witnesses. The witness policy's limit on unwitnessed events (`maxUnwitnessedEvents`) refuses only owner writes, so it does not stop these records either.

So those records stay unattested and unwitnessed until the next owner write (for example, the next session the hook admits), which attests and witnesses a head that includes them. Sooner, `irontrellis repin` attests the current head and `irontrellis witness sync` brings the witnesses up to it; each does one of the two. Until then, a copy cut back to the last owner-attested head still verifies.

### Where freshness evidence falls short

| Gap | What it means, and what to do |
|---|---|
| Local copies | An attacker who restores a history, its old valid pin and every local anchor log can hide later events. Keep later evidence outside that attacker's control. An absent anchor log is not evidence that no later head existed. |
| Unattested tail | A runtime writer, or an asynchronous signer that has not answered yet, carries an earlier owner attestation forward. Events after that attested head are not protected by it. Await the documented flush or settlement path, inspect failures, and re-pin deliberately. |
| Witness tail | Events after the latest witnessed head are outside the witness's protection. Unreachable witnesses can allow bounded unwitnessed writing under policy, and verification can fail closed. A cached answer is only as fresh as its permitted cache interval. |
| Late binding | A copy that ends before the first witness binding contains no binding. Bind at creation where supported. For a history bound later, use an out-of-band minimum policy kept outside the agent's writable area. |
| Split views | A malicious witness may equivocate. Clients detect inconsistency against remembered checkpoints; independent witnesses and a quorum reduce dependence on one operator. Protect the distribution of verifier keys and the witness checkpoint keys. |
| Loss | A witness may hold a head that no surviving copy contains. Accepting a local rollback does not erase a remote finding. A supported owner-authorized loss acceptance records the loss; it does not reconstruct the missing events. |

### Transport and anchors

Witness transport should protect traffic and registration tokens. A signed, nonce-bound answer prevents an older answer from being replayed as fresh, but cannot prevent network denial of service. A refused registration, inconsistent registration evidence and an unreachable service are distinct failures.

An anchor receipt does not itself register a remote witness. The Rekor anchor is experimental and has not been exercised against a live log; do not treat it as a tested remote rollback service.

1.0.0-rc.2 doesn't verify chain anchors itself: its anchor check produces no report, and lists chain inclusion and finality as missing evidence. The MCP gateway's pre-dispatch barrier opens only on a report from an outside producer, and takes the mode that report declares, `CONSENSUS_VERIFIED` included, on its producer's word. The separate tools used for the demonstration anchoring records report `TRUSTED_NODE` only, never consensus-verified ([known issues 54 and 71](records/KNOWN-ISSUES-r2.5.md)).

### Reading `verify`

`verify` reports integrity, replay, pin, anchor and consulted-witness findings. Read its notes as well as its success flag: a carried earlier attestation or an unwitnessed tail limits the result.

The Python verifier does not consult pins, anchor logs or remote witnesses, and does not implement format 2. It cannot replace the store's operational freshness checks.

## 4. Availability

Availability is not guaranteed. Capacity reservations preserve specified control and lifecycle operations, but physical file caps, unavailable signers, storage errors, locks and memory exhaustion can still prevent progress. A bound input is not a host resource sandbox.

A stale lock left by a writer on another host is not automatically safe to reclaim; follow the [Operator](OPERATOR.md) procedures.

## 5. Time and budgets

Event timestamps and default evaluation times are host claims. A monotone replay rule detects regression behind the recorded head; it does not establish accurate real-world time. Protect the clock, and select evaluation times deliberately.

**Budgets follow event time (`EVENT_TIMESTAMP`).** Budget periods use the decision's `evaluationTime`, which for admissions and refusals equals the event timestamp, not the reader's wall clock. Fixed windows are half-open. A writer can advance event time into a later budget window; this is inherent in the time source.

Budget headroom is a view over current records, not an authorization or a historical replay. Restoring an older attested copy can restore prior usage and erase later refusals or receipts, unless independent freshness evidence detects the rollback.

Three replay rules bound the recorded timeline. They restrict it; they do not authenticate wall-clock time.

| Rule | When it applies | What it bounds |
|---|---|---|
| T1 | Attested owner policies | Runtime events that would cross a future statement expiry |
| T2 | Attested owner policies | Control-event time when too few human-class counting signers take part |
| T3 | The genesis sets `sessionTimeHorizonMs` | Session-signed time, to a horizon past the latest owner event that advanced time |

Replay bounds a session key's timestamp from above only by its session's `expiresAt`, by T1 under `ATTESTED` (statement expiries still ahead of the head), and by T3 when the genesis sets `sessionTimeHorizonMs`. A session-carried advance is permanent: `CONTROL_EPOCH_ADVANCED` does not reverse it. Without a horizon, a session key alone can move history time into later budget windows.

## 6. Recorded effects and refusals

An ALLOW proves neither dispatch nor completion. Receipt and outcome records establish what the recorded signer or adapter claimed. `externalOutcome: NOT_PROVEN` or `SIMULATED`, and `LOCAL_ONLY` finality, must remain visible. A connector classification identifies the source of an observation; replay does not independently discover which real-world actors are trustworthy connectors.

**A proof-size refusal (`OUTPUT_LIMIT_EXCEEDED`) is not a denial of authority.** A lowered-threshold or lapsed-key revocation or termination can remove an oversized winning path and let a smaller granted path produce a proof; that authority was granted, and left unrevoked, at the ordinary quorum. To stop an actor, use a prohibition, a zero-cap budget, a fence or a termination, never a proof-size limit.

### Refusals are scoped evidence

**The hook does not record its protective-rule refusals.** The protective rules guard IronTrellis's own files and control commands, and the hook checks them before it opens the history. So in 1.0.0-rc.2 such a refusal leaves no record: the call is still refused, but the history does not show the attempt. The hook records a refusal only when the grants decide DENY, or when an agent without a current session tries a side-effecting call (through the hook's own connector session, when it has one), and only in format 2.

A hook's recorded refusal describes its mapping of a routed call, not necessarily an agent-signed request. A hook or gateway that cannot record in time still denies; bounded best-effort recording is not a complete census of all denied calls. Shared identifier namespaces can be occupied first by another session: use unpredictable or properly scoped identifiers, and keep replay's refusal handling.

### PHL, Proof of Human Lineage

PHL statements bind credentials, audiences, profiles, evidence digests and validity intervals. Their signatures establish that selected attesters made those statements. They do not establish a named person's identity, the quality of an attester's ceremony, or external execution.

Declared classes and attested classes provide different assurance. Review attester independence, credential separation, expiry and setting-time validity, rather than reading a class label alone.

## 7. Storage, privacy and older formats

Histories are plaintext. Grants, resources, identifiers and descriptions may expose sensitive information. Minimal query disclosure filters answers, not the stored file. Keep secrets and arbitrary tool input out of permanent resource names and descriptions. Commit to terms by digest where appropriate, and protect the external terms separately. A digest is not access control, nor a guarantee against guessing low-entropy content.

The documented local store uses private file and directory modes; platform support and parent-directory permissions still matter. Never commit real histories, owner keys, session keys or signer credentials to source control. Back up the history, pin, anchors and relevant witness state together, with a protected, independent copy of freshness evidence. Do not restore past a witness's known head without following the explicit recovery procedure.

A failed append may report `WRITE_UNCONFIRMED` with `mayHaveCommitted: true`, and a signer or flush failure can occur after events became durable. Re-read and verify rather than retrying blindly. Torn lines require the documented recovery process; ordinary replay must not silently repair them.

Legacy histories have weaker guarantees, including unsigned control events and unattested pins. Migrating a source signs its recorded contents; it does not establish that an unpinned or tampered source was authentic. Preserve the source archive, and inspect any explicit acceptance of an unpinned source. Older runtime signing support includes a development-oriented secp256k1 signer that is not claimed to be constant-time. Prefer supported production custody arrangements and the current default suite.

## 8. What is not covered

- Enforcement against a hostile host.
- Universal freshness. The frozen Python verifier does not read pins, anchor logs or witnesses, so a truncated but valid prefix can pass it (§3 above, and [Operator](OPERATOR.md)).
- External spending or effects.
- Confidentiality of stored histories.
- Liveness during an outage.
- Equivalence between the formal models and the TypeScript implementation.
- Constant-time signing with the older development secp256k1 signer (§7 above).

Scoped formal models and test results keep their own assumptions, source pins and exclusions; no theorem count substitutes for that boundary. No external cryptographic audit or user study has been reported. Historical internal reviews belong under [`docs/history/`](history/README.md) and do not automatically certify later changes.

## 9. Before you deploy

Check each of these, and check them again when hosts or policies change:

| Check | Where to start |
|---|---|
| Signer isolation | [Custody](CUSTODY.md) §8, and `irontrellis doctor --as-agent` |
| Session expiry and incident fencing | [Operator](OPERATOR.md) §6 |
| Independent freshness evidence | §3 above, and [Witness](WITNESS.md) |
| Restore procedures | [Operator](OPERATOR.md) §2 |
| Routed-call coverage | §2 above |
| Handling of uncertain writes | §7 above, and [Operator](OPERATOR.md) §6 |

## 10. Reporting a vulnerability

Report vulnerabilities privately through the repository's Security tab, following the root [security policy](../SECURITY.md). Do not include real keys or private histories in a report.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
