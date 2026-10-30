---
title: "Replayable Authority Histories for Auditing Automated Agents"
abbrev: "Agent Authority History"
category: info

docname: draft-rampertab-audit-agent-authority-history-00
submissiontype: IETF
consensus: false
v: 3
ipr: trust200902
area: "Security"
workgroup: "Network Working Group"
keyword:
 - agent
 - audit
 - delegation
 - authorization
 - refusal
 - SCITT

pi: [toc, sortrefs, symrefs]

author:
 -
    ins: R. Rampertab
    fullname: Ramesh Rampertab
    organization: RAmEx Labs
    country: United States of America
    email: ramesh.rampertab@ramex.com

normative:
  RFC2119:
  RFC8174:

informative:
  RFC9943:
  RFC7942:
  RFC6962:
  RFC9162:
  RFC8032:
  RFC8693:
  RFC9052:
  RFC9334:
  RFC9591:
  RFC9942:
  I-D.izmaylov-agent-permission-receipts:
    title: "Signed Permissions and Action Receipts for Automated Agents"
    author:
      - ins: P. Izmaylov
    date: 2026-10-24
    seriesinfo:
      Internet-Draft: draft-izmaylov-agent-permission-receipts-01
    target: https://www.ietf.org/archive/id/draft-izmaylov-agent-permission-receipts-01.txt
  I-D.kuehlewind-audit-architecture:
    title: "An Architecture for Auditing Agent Delegation and Interactions"
    author:
      - ins: M. Kuehlewind
      - ins: H. Birkholz
    date: 2026-09-07
    seriesinfo:
      Internet-Draft: draft-kuehlewind-audit-architecture-01
    target: https://www.ietf.org/archive/id/draft-kuehlewind-audit-architecture-01.txt
  I-D.birkholz-verifiable-agent-conversations:
    title: "Verifiable Agent Conversation Records"
    author:
      - ins: H. Birkholz
      - ins: T. Heldt
      - ins: O. Steele
    date: 2026-08-31
    seriesinfo:
      Internet-Draft: draft-birkholz-verifiable-agent-conversations-01
    target: https://datatracker.ietf.org/doc/html/draft-birkholz-verifiable-agent-conversations-01
  I-D.ietf-wimse-arch:
    title: "Workload Identity in a Multi System Environment (WIMSE) Architecture"
    author:
      - ins: J. Salowey
      - ins: Y. Rosomakho
      - ins: H. Tschofenig
    date: 2026-07-06
    seriesinfo:
      Internet-Draft: draft-ietf-wimse-arch-08
    target: https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch-08
  I-D.ietf-oauth-transaction-tokens:
    title: "Transaction Tokens"
    author:
      - ins: A. Tulshibagwale
      - ins: G. Fletcher
      - ins: P. Kasselman
    date: 2026-07-30
    seriesinfo:
      Internet-Draft: draft-ietf-oauth-transaction-tokens-11
    target: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11
  AUDIT-BOF:
    title: "BoF request: Agent Use of Delegation and Interaction Traceability (AUDIT)"
    author:
      -
        ins: M. Kuehlewind
      -
        ins: H. Birkholz
      -
        ins: P. Dingle
    date: 2026-10
    target: https://datatracker.ietf.org/doc/bofreq-kuhlewind-audit-agent-use-of-delegation-and-interaction-traceability/

  IRONTRELLIS-DISCLOSURE:
    title: "IronTrellis Commissioning Disclosure"
    author:
      - org: RAmEx Labs
    date: 2026-10
    target: https://github.com/zerohourzulu/irontrellis/blob/v1.0.0-rc.2/docs/COMMISSIONING-DISCLOSURE.md
    refcontent: "Informative operational guidance only"
  IRONTRELLIS-CHECKLIST:
    title: "IronTrellis Install Checklist"
    author:
      - org: RAmEx Labs
    date: 2026-10
    target: https://github.com/zerohourzulu/irontrellis/blob/v1.0.0-rc.2/docs/INSTALL-CHECKLIST.md
    refcontent: "Informative operational guidance only"
  IRONTRELLIS-RATIONALE:
    title: "Why IronTrellis, Why Now, What is the Long Horizon"
    author:
      - org: RAmEx Labs
    date: 2026-10
    target: https://github.com/zerohourzulu/irontrellis/blob/v1.0.0-rc.2/docs/WHY-IRONTRELLIS.md
    refcontent: "Informative rationale only"
  IRONTRELLIS-LEAN:
    title: "Why We Check IronTrellis With Lean"
    author:
      - org: RAmEx Labs
    date: 2026-10
    target: https://github.com/zerohourzulu/irontrellis/blob/v1.0.0-rc.2/docs/FORMAL-VERIFICATION.md
    refcontent: "Informative note on what was machine-checked, what it caught, and its limits"
  IRONTRELLIS-LEAN-PROOFS:
    title: "Selected Lean proofs, IronTrellis 1.0.0-rc.2"
    author:
      - org: RAmEx Labs
    date: 2026-10
    target: https://github.com/zerohourzulu/irontrellis/tree/v1.0.0-rc.2/verification/SelectLeanProofs
    refcontent: "Lean 4 sources of the headline theorems, with premises and rebuild commands"
  IRONTRELLIS-REPO:
    title: "IronTrellis 1.0.0-rc.2"
    author:
      - org: RAmEx Labs
    date: 2026-10
    target: https://github.com/zerohourzulu/irontrellis/tree/v1.0.0-rc.2
    refcontent: "Open-source implementation, release candidate"
  IRONTRELLIS-RELEASE:
    title: "IronTrellis 1.0.0-rc.2 release downloads"
    author:
      - org: RAmEx Labs
    date: 2026-10
    target: https://github.com/zerohourzulu/irontrellis/releases/tag/v1.0.0-rc.2
    refcontent: "Packages, checksums, documents and the zero-knowledge demonstration download"

  WEBAUTHN3:
    title: "Web Authentication: An API for accessing Public Key Credentials, Level 3"
    date: 2026-08-25
    target: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
  VC-DM2:
    title: "Verifiable Credentials Data Model v2.0"
    date: 2025-05-15
    target: https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/

  I-D.helixar-hdp-agentic-delegation:
    title: "Human Delegation Provenance Protocol (HDP): Cryptographic Chain-of-Custody for Agentic AI Systems"
    author:
      - ins: A. Dalugoda
        org: Helixar Limited
    date: 2026-10-06
    seriesinfo:
      Internet-Draft: draft-helixar-hdp-agentic-delegation-03
    target: https://www.ietf.org/archive/id/draft-helixar-hdp-agentic-delegation-03.html

  RFC6973:
  I-D.irtf-cfrg-bbs-signatures:
    title: "The BBS Signature Scheme"
    author:
      - ins: T. Looker
      - ins: V. Kalos
      - ins: A. Whitehead
      - ins: M. Lodder
      - ins: G. Bernstein
    date: 2026-10-29
    seriesinfo:
      Internet-Draft: draft-irtf-cfrg-bbs-signatures-14
    target: https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-14.html
  GROTH16:
    title: "On the Size of Pairing-based Non-interactive Arguments"
    author:
      - ins: J. Groth
    date: 2016-05-31
    seriesinfo:
      Cryptology ePrint Archive: "2016/260"
    target: https://eprint.iacr.org/2016/260
  FHE-INTEGERS:
    title: "Fully Homomorphic Encryption over the Integers"
    author:
      - ins: M. van Dijk
      - ins: C. Gentry
      - ins: S. Halevi
      - ins: V. Vaikuntanathan
    date: 2010-06-08
    seriesinfo:
      Cryptology ePrint Archive: "2009/616"
    target: https://eprint.iacr.org/2009/616
  DWORK-ROTH:
    title: "The Algorithmic Foundations of Differential Privacy"
    author:
      - ins: C. Dwork
      - ins: A. Roth
    date: 2014
    seriesinfo:
      DOI: "10.1561/0400000042"
    target: https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf
  SEAL-SECURITY:
    title: "Microsoft SEAL: Correct Use and Security Guidance"
    author:
      - org: Microsoft
    refcontent: "Mutable project security guidance; inspected 11 October 2026."
    target: https://github.com/microsoft/SEAL/blob/main/SECURITY.md


--- abstract

Software agents act on authority that changes while they run: permissions are granted and revoked, running instances are replaced, and some requests are refused. Activity logs record what a system reports it did, but they do not by themselves show what an agent was allowed to do when it acted, and the operator can edit them. This document specifies a model for an authority history: an append-only, signed record of who granted what to whom, which actions were admitted, which requests were refused, and which unfinished duties survive when one agent replaces another. Given independently authenticated owner keys and history identity, a verifier can replay the history and recompute its recorded authorization decisions while trusting neither the agent nor the operator. The document states what such a verifier can and cannot establish. Optional profiles cover external anchoring, federated operation, human-attested keys and zero-knowledge disclosure. An informative appendix describes one encoding.

--- middle

# Introduction {#intro}

This section sets out the problem, the approach and an example, and relates the model to existing work. The specification begins in {{terminology}}.

## The question {#problem}

Consider an organization that lets a software agent buy supplies on its behalf. During the month the agent's running instance is replaced after a fault, a larger order is refused, and a second agent takes over the purchasing role. Weeks later an auditor, a regulator or a supplier asks about one purchase: was this agent allowed to make it, at the moment it made it, and on whose authority?

Today that question is usually answered from logs kept by the system being audited. Logs record what the system reports it did. They rarely carry the authority state from which the answer could be recomputed, and whoever operates the host can edit them. The answer therefore rests on trust in the operator, the very party an audit is meant to check.

Automated agents make the question both more common and harder to answer, for three reasons:

* **Authority changes during execution.** Grants are issued, narrowed and revoked while agents run. The Agent Use of Delegation and Interaction Traceability (AUDIT) BoF request names "how permissions evolved during execution" as a question audits must answer {{AUDIT-BOF}}.
* **The actor is not one thing.** A running instance, the durable agent it belongs to, and the office that agent holds can each be replaced independently. Authority attached to the wrong one is either lost on replacement or wrongly inherited.
* **What did not happen matters too.** An auditor needs to know which requests were refused and why, and what work was left unfinished when an agent was replaced.

This document proposes that a system record its authority, not only its activity: as an append-only, signed history from which its authorization decisions can be recomputed by a party that trusts neither the agent nor the operator that runs it.

## The approach {#approach}

{{fig-approach}} shows who signs which records and who checks them.

~~~ ascii-art
   Owner keys, authenticated out of band
         |
         | every change of power is owner-signed
         v
   +---------------------------------------------------+
   | Authority history (append-only, hash-chained)     |
   |   grants, revocations, sessions, roles, tenures,  |
   |   admissions, refusals, duties, handovers         |
   +---------------------------------------------------+
         ^                              |
         | sessions sign admissions,    | export
         | refusals and outcomes        v
   +--------------+         +-----------------------------+
   | Agent and    |         | Verifier                    |
   | its host     |         | trusts neither agent nor    |
   | (untrusted)  |         | operator; replays the range |
   +--------------+         | and recomputes decisions    |
                            +-----------------------------+
~~~
{: #fig-approach title="Who signs what, and who checks it"}

Three properties carry the design:

* **Authority is recorded as signed data.** Every creation or withdrawal of power (a grant, delegation, prohibition, revocation, session admission, role transfer or termination) is a control record that must satisfy the owner's approval policy in force at its position ({{control-records}}). A delegation can narrow the grant it derives from, never widen it.
* **Decisions are reproducible.** A decision is ALLOW with a proof (the permission path from a root grant of the owner to the actor), DENY with a code, or INDETERMINATE. A consequential action is recorded as an admission that names the head (the position, hash and time of the history prefix) on which it was decided; refusals are recorded as well. Replay re-derives every admission and every authority or budget refusal, and rejects a history whose recorded decision does not reproduce ({{decisions}}).
* **Verification does not depend on the operator.** Given owner keys and a history identity authenticated by independent means, a verifier can check an export without the agent, the operator, the writer software or network access to the host ({{export}}). Showing that an export is the latest state needs evidence held outside the host: signed heads held by others, witnesses or external anchors ({{rollback}}, {{external-anchoring}}).

The rest of the model follows from taking these properties seriously: separate records for the agent, its runtime sessions and its office ({{separation}}); duties that survive a handover while grants do not ({{duties}}); observations of calls that bypassed the decision point ({{reconciliation}}); and an explicit statement of what a verifier can and cannot conclude ({{establishes}}).

## A short example {#intro-example}

{{tab-example}} follows the purchasing scenario above through one history. It is illustrative and simplified; {{worked}} gives a fuller sequence.

| Step | Record | Signed by | What a verifier later concludes |
|---|---|---|---|
| 0 | Genesis: owner keys, policy identifiers | None (the genesis is unsigned) | The history's identity, once authenticated out of band |
| 1 | Create agents A1 and A2, a purchasing role R and a succession rule for R; register supplier X's receipt key | Owner | The parties, the office, and whose receipts count |
| 2 | Appoint A1 to R (tenure 1); admit runtime session S1 for A1 | Owner | Who holds the office, and which key speaks for A1 |
| 3 | Grant G to A1: purchase from supplier X, total at most 500, valid until 31 October | Owner | The authority A1 holds |
| 4 | Admission: A1 buys 200 from X | S1 | ALLOW, recomputed, with proof path owner to G to A1 |
| 5 | Supplier's signed receipt for that purchase | S1, wrapping X's signature | X claims delivery; the claim is authenticated, the delivery is not |
| 6 | S1 fails; advance A1's control epoch, which retires S1, and admit session S1b | Owner | Any record S1 appends after this point is rejected on replay |
| 7 | Refusal: A1 asks to buy 400 | S1b | DENY, recomputed: amount exceeded (200 + 400 > 500) |
| 8 | Duty: pay X for the step 4 purchase by 15 November, owed by role R under the succession rule of step 1 | S1b | Open work attached to the office, not to A1 |
| 9 | Handover: terminate A1, transfer R to A2 (tenure 2); admit session S2 | Owner | The duty stays open under R; grant G does not pass to A2 |
| 10 | Refusal: A2 asks to buy 50 | S2 | DENY, recomputed: no authority |
{: #tab-example title="One purchasing history and what a verifier learns from it"}

Weeks later an auditor receives an export of the whole history and obtains the owner's public keys from a source the operator does not control. Without contacting the operator, the auditor can establish that the purchase at step 4 was authorized, and by which grant; that two requests were refused, on which heads and why; that the payment duty is still open under the purchasing role, and that no signed assignment of it to A2 has been recorded; and that A2 received none of A1's power. The auditor cannot establish from the export alone that the goods arrived, that every purchase passed through the decision point, or that the export ends at the latest record.

## What a verifier can and cannot conclude {#intro-limits}

| Question an auditor asks | Established from an export? | What the answer rests on |
|---|---|---|
| Was this action authorized by the recorded authority at the head it names? | Yes | Replay; owner signatures on every change of power |
| Which requests were refused, when, and with which code? | Yes, for recorded refusals. Authority and budget refusals are recomputed; refusals by an external enforcement point are attested, not recomputed. A history need not record every refused attempt. | Session signatures; replay |
| Who owed which unfinished work after a handover, and did any power pass with the role? | Yes | Replay of roles, tenures and duties |
| Did the owner approve each change of power? | That the required keys signed; not who held them, nor what they intended | The owner approval policy; key custody |
| Did the action have its effect in the world? | No: only who claimed it, and on which head | Signed outcomes and counterparty receipts are claims |
| Did every action pass through the decision point? | No. Reconciliation observations report matched and unmatched calls, without a completeness guarantee. | Placement of the decision point; reconciler coverage |
| Is this the latest state of the history? | Only with evidence held outside the host | Held heads, witnesses, external anchors |
| Are the timestamps true? | No; history time is the writers' claim | Writers' clocks; see {{sec-host}} |
{: #tab-limits title="What a verifier can and cannot establish"}

{{establishes}} states these conclusions precisely, and {{sec-summary}} lists each adversary with its residual limit.

## How this relates to existing work {#intro-related}

Several existing mechanisms each answer part of the question. The model is intended to complement them, not replace them.

| Work | What it provides | What this document adds |
|---|---|---|
| Activity logs and tracing | A record of what a system reports it did | The authority state needed to recompute whether it was allowed, under owner signatures that an operator without the owner keys cannot forge |
| OAuth Token Exchange {{RFC8693}}; Transaction Tokens {{I-D.ietf-oauth-transaction-tokens}} | Delegation and context carried in tokens for the duration of a request | A durable history in which a token's underlying grant, and its revocation, can be recorded and replayed |
| Workload Identity in a Multi System Environment (WIMSE) architecture {{I-D.ietf-wimse-arch}} | Identifiers and short-lived credentials for workloads | A session admission can bind a WIMSE credential's key; the history records what that identity was allowed to do over time |
| Certificate Transparency {{RFC6962}} {{RFC9162}}; Supply Chain Integrity, Transparency and Trust (SCITT) {{RFC9943}} | Append-only, auditable logs; evidence that a statement was registered | Replay of authority-state transitions. Registration does not establish that a statement is true or complete. |
| Remote Attestation Procedures (RATS) {{RFC9334}} | Evidence about the environment that produced a record | References to such evidence; this model checks authority and signer claims, not environments |
| AUDIT architecture {{I-D.kuehlewind-audit-architecture}} | Cross-domain record generation, collection and audit context | A local, replayable authority-state component that such an architecture could carry |
| Signed permissions and action receipts {{I-D.izmaylov-agent-permission-receipts}} | Passkey permissions, attenuating delegation, signed action receipts | Replayed actor, session and epoch state; role tenures and surviving duties; admissions that must reproduce ALLOW |
{: #tab-related title="How this model relates to existing work"}

These pieces compose. A deployment could issue OAuth tokens under grants recorded in the history, bind WIMSE credentials to admitted sessions, and anchor the history's heads in a transparency service or public ledger. {{related}} and {{scitt}} give the detail.

## Relation to AUDIT, and questions for discussion {#audit-relation}

The AUDIT BoF proposal identifies evolving authorization as an auditing concern {{AUDIT-BOF}}. The architecture draft {{I-D.kuehlewind-audit-architecture}} addresses cross-domain record generation and collection. This document proposes a local replayable authority-state component; identity mapping and cross-domain context propagation require separate profiles. Referenced Internet-Drafts are work in progress, and this individual submission implies no working-group adoption.

The author would particularly welcome views on four questions:

1. Is a replayable authority-state component, as distinct from record collection and context propagation, useful work for AUDIT?
2. Should refusals, and duties that survive replacement, be first-class audit records?
3. Does the separation of agent, runtime session, office and authority ({{separation}}) align with the vocabularies of OAuth and WIMSE, or should it be reconciled with them?
4. Which concrete encoding would be most useful first: a COSE statement profile suitable for SCITT ({{scitt}}), or a JSON encoding such as the one in {{example}}?

The model is drawn from IronTrellis, an implementation in development. {{status}} reports what has been built and independently checked, and {{formal}} what has been machine-checked in Lean and which proof paths were chosen.

## Scope and how to read this document {#scope}

The model addresses four questions: what authority supported a request at a captured head; what requests were refused; what work survives replacement; and what supplied host calls have no matching decision. Its proposed requirements apply to a complete model instantiation. A concrete interoperability profile MUST specify closed schemas, canonical encoding, signature challenges, transition and error precedence, identifiers, time semantics, limits, and exact decision and evidence ordering. This document alone does not define byte-level interoperability.

| Section | What it specifies | Of most interest to |
|---|---|---|
| {{terminology}}, {{model}} | Vocabulary; the parties and what each is trusted for | Everyone |
| {{authority}}, {{records}} | The records, and how they are signed, chained and replayed | Implementers of a writer or verifier |
| {{decisions}} to {{duties}} | Decisions, refusals, budgets, receipts, duties, handover, lineage queries | Builders of agent runtimes and gateways |
| {{continuation}}, {{reconciliation}} | Recovery of uncertain execution; calls that bypassed the decision point | Operators of long-running agents |
| {{export}} | Exports, what they prove, and keeping a history fresh: local anchors, witnesses, public chains | Auditors |
| {{owner-approval}}, {{human-attestation}}, {{federated-operators}}, {{selective-disclosure}} | Optional profiles | Deployments that need them |
| {{security}}, {{privacy}} | Threats, responses and residual limits | Security and privacy reviewers |
| {{example}}, {{status}}, {{formal}} | One encoding; what is built, proved and machine-checked | Anyone judging maturity |
{: #tab-roadmap title="How this document is organized"}

Out of scope: the semantics of actions and resources (these are application identifiers), the policy language used to express constraints beyond the structural ones named here, the content of prompts and responses (see {{I-D.birkholz-verifiable-agent-conversations}}), a concrete remote-attestation format for the executing environment or biometric ceremony (see {{RFC9334}}), a record or signing-ceremony transport protocol, and any claim about the business outcome of an action in the world.

IronTrellis's rationale manuscript {{IRONTRELLIS-RATIONALE}} is separate informative material. It does not supply protocol requirements or interpretation rules.


# Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

BCP 14 requirements apply to profiles claiming this proposed model, not to all agent-auditing systems. An Informational document can state such requirements without claiming an IETF standard. A deployment claim is an assertion to be assessed under stated trust assumptions, not a theorem supplied by this document.

Identifiers are opaque strings assigned by the application; the model constrains their relations, not their form. {{tab-terms}} defines the terms used throughout.

| Term | Meaning |
|---|---|
| Principal (owner) | The party a history belongs to and the root of every power in it. Holds the owner keys that sign control records. |
| Controller | The identity under which agents are created and their sessions managed. A label, not a holder of grants. |
| Agent | A durable identity that can hold grants, occupy roles and owe duties. After termination its requests are refused; its record stays. |
| Runtime session | One running instance of an agent, admitted with its own public key, a control epoch and an expiry. Signs session records. |
| Control epoch | A per-agent counter. Advancing it retires every session admitted under an older epoch without terminating the agent. |
| Role | A durable office held by one agent at a time, in numbered tenures. Transferring a role does not transfer grants. |
| Succession rule | Who follows whom in a role, and which record kinds the succession may produce. |
| Handover | The predecessor's termination and the transfer of the role to the successor's new tenure, recorded as one atomic operation. |
| Grant (authority) | A permission with a grantor, a grantee and constraints. A grant made by the principal is a **root**. |
| Delegation | A grant issued by an agent under a grant it holds. Always **attenuated**: it may narrow its parent, never widen it. |
| Prohibition | A rule forbidding a subject from specified actions on specified resources. |
| Revocation | A control record that ends a grant, delegation or prohibition. Revoking a parent cascades to its delegations. |
| Control record | A record that creates or withdraws power. Signed by owner keys in force at its position. |
| Session record | A record signed by a session key: intent, admission, consumption, outcome, receipt, refusal, effect or observation. |
| Decision | ALLOW with a proof, DENY with a code and evidence, or INDETERMINATE with a code and evidence. |
| Refusal record | A session-signed record of a DENY or INDETERMINATE, with the request, evaluation time, head and code. |
| Duty (obligation) | Unfinished work owed under a role, with a deadline, status, performer and optionally a succession rule. |
| Reconciliation observation | A signed record that a call was observed at a host boundary and matched, or not, to a decision. |
| Head | The identity of a history prefix: chain hash, position and time of the last record. |
| Export | A self-contained view of a history, or a range of it, checkable without the writer. |
| Verifier | A party that checks an export, trusting neither the agent nor the operator. Needs authenticated history identity and owner trust anchors. |
| Witness | A service in another trust domain keeping an append-only log of owner-signed head statements, accepting only extensions. |
| Human-attested key | A key for which a verification profile holds signed evidence binding the exact key to a human at an enrollment ceremony. Not uniqueness, legal identity or continuing control. |
| Voucher | A human who signs a scoped statement about another subject's enrollment. Evidence only; no authority. |
| Budget | An owner-declared stop rule over a group of requests, charged by admissions ({{budgets}}). |
| State checkpoint | An owner-signed commitment to the state root at a position ({{state-commitment}}). |
| Counterparty | An external party whose registered key signs receipts ({{counterparty-receipts}}). |
| Head attestation; anchor | An owner-signed head kept beside the history, deposited in a log its writers cannot rewrite, or recorded as an owner-signed anchor control record ({{rollback}}). |
| Attester | A party named in the policy whose signed statement classes a key as human ({{human-attestation}}). |
{: #tab-terms title="Terms"}

# Model {#model}

## Parties and trust {#parties}

| Party | Trusted for | Not trusted for |
|---|---|---|
| Principal | Owner keys are the authority trust anchor, once authenticated by an independent mechanism | Being independent of the operator; a signature is a key claim |
| Operator (host) | Nothing. Can read and write every file, including the history | Anything; the model detects changes that conflict with authenticated commitments |
| Agent and sessions | Nothing. A session signature shows that an admitted session made a claim at a head | That the claim is true in the world |
| Verifier | Nothing; it relies only on owner public keys it has authenticated, and MAY rely on witness keys | Needs no access to, and places no trust in, the agent, operator, writer or host |
{: #tab-trust title="Who is trusted for what"}

A verifier MUST authenticate the expected history identity and initial owner keys through an independent trust mechanism: an attacker can generate a consistent substitute history with its own keys, so keys in an untrusted genesis authenticate nothing. Later keys are established from verified rotations. The model does not prevent an operator from editing a history; it detects edits that conflict with authenticated signed commitments. Removal of an unattested suffix, or restoration of an older copy with its older genuine commitments, can remain undetected; {{rollback}} bounds that risk.

## The history {#history}

A history is an ordered, append-only sequence of records starting with a **genesis** that fixes the domain, the first owner keys, the policy identifiers governing replay and any capacity limits; the genesis hash identifies the history. Each record has a unique identifier, a type, a non-decreasing timestamp and type-specific data under a closed schema, and commits to its predecessor by hash ({{chain}}). The state at position p is a deterministic function of records 0 through p. Decisions are computed from that state and explicit request inputs, including evaluation time ({{determinism}}). Operational identity, clock-skew and freshness gates are separate from replay and may reject access even when replay is valid.

## Five things kept apart {#separation}

~~~ ascii-art
   principal ---owns---> history
       |
       | creates, grants, appoints
       v
     agent (durable) ----occupies----> role (office, tenure n)
       |                                   |
       | runs as                           | owes
       v                                   v
   runtime session (key, epoch, expiry)   duties (survive handover)
       |
       | holds, through grants
       v
   authority (root grants, delegations, prohibitions)
~~~
{: #fig-separation title="The principal, agent, session, role and authority are separate records"}

An agent can be terminated while its role, tenure history and duties stay on record. A session can be fenced by advancing the epoch without touching the agent. A role can be transferred without the successor inheriting the predecessor's grants.

## Four rules the rest depend on {#model-rules}

- **Powers and obligations need not pass together.** An instantiation MUST preserve unfinished duties across an applicable succession and MUST require an authorized signed assignment before changing their performer. It MUST NOT transfer the predecessor's grants merely because a role transfers. Duties and role occupancy MUST NOT be accepted as permission to act.
- **Interpretation is not authority.** An instantiation MUST evaluate authority from the captured history, the explicit request and the evaluation time. It MUST NOT accept a language model's interpretation as authority evidence. Results MUST distinguish ALLOW, DENY and INDETERMINATE and carry scope and evidence ({{decisions}}).
- **Everything ends, and withdrawal is never blocked by a quota.** A profile MUST specify the end conditions of each grant, session and duty, including whether a grant may omit expiry. A capacity rule MUST keep a declared-limit bypass for valid power-reducing controls while reporting absolute storage and signature failures ({{capacity}}).
- **Evidence is legible.** An instantiation MUST return stable, typed evidence references for each decision and query conclusion, each identifying its captured history and evaluation scope. A historical answer MUST NOT be presented as present execution permission ({{query-scope}}).

# The authority history {#authority}

## Control records {#control-records}

A conforming history MUST support the control record kinds in {{tab-control}}. Each carries owner authorization satisfying the policy in force at its position ({{control-signature}}, {{owner-approval}}).

| Kind | Names |
|---|---|
| PRINCIPAL_CREATED | A principal. Recorded principals are identities under the one owner key set; a profile must distinguish them from the history owner and specify root recognition. |
| AGENT_CREATED | A new agent, its principal, controller and initial epoch |
| ROLE_CREATED | A new role and its principal. Roles are exclusive: one current tenure at a time. |
| SUCCESSION_RULE_DECLARED | A rule: predecessor, successor, role, trigger (the predecessor's termination) and the record kinds the succession may produce |
| AGENT_APPOINTED | A tenure: agent, role, tenure identifier and number, optional succession rule |
| AGENT_UNAPPOINTED | The end of a tenure without a successor |
| ROLE_TRANSFERRED | The end of one tenure and the start of the next for another agent (succession or reassignment) |
| RUNTIME_SESSION_ADMITTED | A running instance: session, agent, controller, epoch, key identifier, public credential, expiry |
| CONTROL_EPOCH_ADVANCED | An agent's next epoch; fences every session under an older one |
| AUTHORITY_GRANTED | A permission or a prohibition ({{grants}}) |
| AUTHORITY_REVOKED | The end of a grant, delegation or prohibition, naming the revoker |
| AGENT_TERMINATED | The end of an agent, with the succession rule, role and tenure when a handover applies |
| OWNER_KEYS_ROTATED | The owner key set from the next position on ({{owner-keys}}) |
{: #tab-control title="Control record kinds"}

An instantiation MUST support owner-signed anchors and witness binding and unbinding as control capabilities ({{rollback}}). A deployment MAY select its anchoring and witness policy; supporting the capability alone establishes no independent anchor. Budget, checkpoint, counterparty, anchor, and witness binding and unbinding records are also control records ({{budgets}}, {{state-commitment}}, {{counterparty-receipts}}, {{rollback}}).

## Grants, delegations and prohibitions {#grants}

A **permission** has a grantor, a grantee, a root, optionally a parent, a flag saying whether it stands alone or exists only as a partner for another grant, and constraints: actions, resources, an optional validity window, optional per-operation and cumulative amount ceilings, an optional transaction count, a maximum delegation depth, and required partner grants that must be live at the same time. A root permission is issued by the principal; a delegation is issued by an agent under a grant it holds and inherits the parent's root.

| Constraint | A delegation, relative to its parent |
|---|---|
| Actions, resources | MUST be subsets |
| Validity window, amount ceilings | MUST fit inside |
| Delegation depth | MUST be strictly smaller |
| Required partners | MAY add, MUST NOT remove |
{: #tab-attenuation title="Attenuation: a widening delegation is a replay rejection, not a warning"}

A conforming replay MUST reject a delegation that is not attenuated as in {{tab-attenuation}}. A delegation is evaluated against its delegator's status at evaluation time: a terminated delegator or a revoked parent yields no authority, revocation cascades to delegations, and independent paths to the same authority survive.

A **prohibition** with ROOT scope is attached to a root grant and must fit inside it; one with GLOBAL scope is issued by the global policy source named in the genesis and applies across roots. Profiles MUST define path selection when several independent grants exist; a root-scoped prohibition must not be presented as overriding unrelated roots. An unrevoked root-scoped prohibition keeps its effect, within its own validity window, while its **anchor path** is live: it loses effect when a grant in its ancestry is revoked or when an actor on that path (its grantor, or the grantor or grantee of a grant in its ancestry) is terminated. A GLOBAL prohibition has no anchor path and no lifecycle term: it loses effect only by revocation or outside its own validity window.

## Sessions and epochs {#sessions}

A session-signed record MUST be rejected on replay if the signing session is unknown, if its epoch is not the agent's current epoch at that position (the **epoch fence**), if the agent is not active, or if the record's timestamp is not before the session's expiry. Under an attested owner floor ({{human-attestation}}), a session-signed or administrative record MUST also be rejected if its timestamp is at or past the expiry of an owner attestation that was unexpired at the preceding head: only an owner-signed record carries history time across such an expiry. A genesis MAY set a **session-time horizon**; when it does, a session-signed or administrative record outside a migrated prefix MUST also be rejected if its timestamp is more than that horizon after the latest owner-signed record that advanced history time (or after the genesis, if there is none).

Advancing an epoch is the intended response to a session key that may have leaked: it retires every earlier session at once, and declared capacity limits MUST NOT refuse it ({{capacity}}).

## Owner keys and pre-rotation {#owner-keys}

~~~ ascii-art
  epoch 1: keys {K1}, commitment D = H(K2)     (fixed by genesis)
      |
      | rotation: reveals K2, proves possession, commits H(K3)
      v
  epoch 2: keys {K2}, commitment H(K3)
      |
      x  a thief holding only K1 cannot rotate: K2 is kept elsewhere
~~~
{: #fig-prerotation title="Pre-rotation: the next key is committed before it is needed"}

The genesis declares the first owner keys; an OWNER_KEYS_ROTATED record, authorized by the policy in force before it, replaces the set from the next position on. A retired key identifier MUST NOT be re-bound or return, and a retired credential MUST NOT return under another identifier. Every owner signature is judged by the keys in force at the position it covers.

A history SHOULD carry a **next-key commitment**, fixed by the record that opens the epoch. A rotation out of a committed epoch MUST either reveal at least one committed key and commit again, or, where it keeps every key and changes only the approval policy, carry the commitment unchanged. A revealed key MUST be proved by its own signature over the rotation, its digest MUST be in the commitment, and under a policy every revealed key MUST carry its own possession proof, which no quorum of current keys can substitute; a rotation that keeps every key and changes nothing MUST be refused. The converse is a stated limit: no quorum of current keys can replace or drop a commitment, so a quorum holding no committed key can change the policy and reduce power but can never add, remove or replace a key.

## Owner approval policies {#owner-approval}

An instantiation MAY require separate signatures from M of N enrolled owner keys, with a global threshold and per-type overrides. A selected profile MUST define distinct credential identity, eligible membership, effective thresholds, duplicate handling, policy-update authorization and recovery. The rules below are the ones everything else rests on.

- **Pre-event authority.** The effective policy and membership MUST be selected from the accepted pre-event state. New keys, new classifications and a proposed policy MUST NOT authorize their own adoption. A rotation MUST satisfy at least the greater of the preceding global threshold and its rotation threshold. A policy change with an unchanged key set is itself a rotation (a **policy rotation**): authorized by the pre-event policy with agent keys counting zero, effective from the next position, unable to add, remove or re-key, and carrying any commitment unchanged.
- **One owner signature, always.** Every covered control record MUST retain at least one owner signature. A user-interface selection of zero extra co-signers MUST NOT be encoded or verified as zero owner authorization. Under a policy, enrolled credentials MUST be pairwise distinct, and a key's class MUST be a function of its credential, never of its identifier. A writer MUST NOT silently reset a non-default policy when a rotation omits one.
- **Recovery is opt-in and never free.** Where the policy opts in to **recovery through committed next keys**, a committed key that a rotation reveals, with its proof of possession, counts toward that rotation's threshold as if in force; it is admissible on no other record, never lowers the threshold, and MUST be custodied as a current key. Without the option, loss of every current key is permanent: no unsigned, agent-only or emergency route exists, and a profile MUST NOT silently lower M on loss of availability. The profile MUST define the effective-threshold and signer-eligibility rules for recovery; a deployment enabling recovery with a rotation threshold above one MUST commit at least that many next keys or accept that recovery needs the difference in surviving current keys.
- **Reducing power may need fewer signatures; adding it never does.** A per-type threshold below the global one MAY be declared only for the record types in {{tab-prtypes}}, and applies only when the record **reduces power by effect**, decided from its content and the pre-event state before any signature is counted. Such a record MUST NOT make any request pass the authority procedure (judged before the proof-size preflight, {{sec-rest}}), or any session live, that did not before it, at any evaluation time at or after the record, and MUST NOT change owner keys, commitment, policy or bound witnesses. A lowered threshold MUST NOT exceed the number of non-agent credentials, so that no agent key is ever needed to reduce power.
- **Agents never own.** A profile permitting registered agent keys as co-signers MUST require at least one eligible human-class owner signature on every covered control event and MUST exclude agent signatures from policy and owner-key changes. Under the **declared** floor, human class is a label set by the owner quorum. Under the **attested** floor ({{human-attestation}}), a key counts as human only while an attester's statement embedded in the policy covers the record's time.
- **Credentials have one job.** Under a policy, owner keys, committed keys, attesters, session credentials and counterparty credentials MUST be pairwise distinct; a credential recorded as a session or counterparty credential MUST NOT become an owner, attester or committed key while a policy is in force, and conversely. A commitment carried into a policy epoch that names such a credential MUST NOT be revealed while the policy is in force. The rule cannot catch a credential the history never recorded.

| Reduces power by effect | Needs the ordinary quorum |
|---|---|
| Revoking a permission; advancing an epoch; terminating or unappointing an agent; declaring a new budget; tightening a budget; retiring a counterparty; a checkpoint | Revoking a prohibition; revoking a permission that an unrevoked prohibition has in its ancestry; terminating an agent on an unrevoked prohibition's anchor path ({{grants}}); unappointing an agent a live role budget could match; raising a cap; narrowing a budget's subjects; ending a budget earlier; tightening a budget that carries unused allowance forward |
{: #tab-prtypes title="Which records may use a lowered threshold"}

The profile MUST reject, when a policy is set, a configuration that cannot satisfy its own human and threshold rules. A strict profile MUST NOT be disabled by omission of fields; any downgrade requires the preceding policy's authorized change. A history that never selects a policy MUST replay exactly as it did without these rules. Remote signers MAY take part through an encrypted ceremony that authenticates the parties, binds history, head, epoch, action and exact challenge, protects responses, and rejects expired, replayed or mismatched responses; it MUST provide the signer with the effect being approved and preserve uncertainty across retries. Transport encryption never replaces owner authorization, human eligibility or effect-boundary checks, and voucher participation in enrollment grants no owner vote.

## Proof of Human Lineage attestation {#human-attestation}

An instantiation MAY support a Proof of Human Lineage (PHL) attestation profile to decide which signing keys qualify as human-attested for a selected policy. The claim concerns the origin and assessment of a key's enrollment evidence, not authorship of content and not a guarantee that an agent will never use the key later. Biometric verification, key possession, identity, uniqueness, live presence and informed intent are distinct properties.

A selected profile MUST define its biometric assurance, authenticator and verifier trust roots, exact-key binding, vouching requirements, bootstrap, validity and status rules, disclosure dependencies and a deterministic acceptance predicate. A generic user-verification result MUST NOT be described as biometric evidence when the mechanism also permits a PIN without distinguishing the method. WebAuthn {{WEBAUTHN3}} supplies useful authenticator evidence; attesting its credential does not attest a separate history-signing key. The proposed enrollment combines a method-qualified biometric ceremony, possession and explicit adoption of the exact signing key, and, for a remote subject, at least one other qualified human's signed vouch; the vouch MUST bind the same subject key, ceremony and assurance context, state what was observed, and be verifiable under the selected voucher trust policy. A circular chain of new vouches MUST NOT be accepted as a bootstrap. Verifiable credentials {{VC-DM2}} can carry claims; they do not establish their truth. An instantiation claiming replay enforcement MUST bind sufficient authenticated eligibility evidence into the replay input; a mutable registry lookup MUST NOT silently decide historical validity, and missing evidence MUST NOT silently qualify a key as human. Evidence MUST identify the key, profile, enrollment, issuer, voucher, time and status context and limitations; a profile MUST specify whether the verifier checks trusted admission statements or also revalidates their underlying evidence; missing required evidence MUST be reported as incomplete or unverified.

Under the attested floor, a key's class is a function of the policy in force, its credential and the record's timestamp ({{tab-class}}). An **attester** is a party named in the policy in force. Its **statement** is a signed assertion bound to the exact credential, to the history's domain and, after the genesis, to the history's identity, with a validity interval; it is embedded in the policy and removed only by the owner quorum, never by the attester alone, and its subject MUST be an enrolled key or a committed next key not classed as an agent.

| Class | When | May count toward |
|---|---|---|
| HUMAN | An attester's statement covers the record's time | Everything the policy allows |
| LAPSED | The epoch's statement for the key has expired | Only a record that reduces power by effect, a state checkpoint, or a **restoration** |
| AGENT | So classed by the policy | Ordinary actions; never the floor, policy changes or rotations |
| NONE | Otherwise | Nothing |
{: #tab-class title="Key classes under the attested floor"}

A restoration is a policy rotation that keeps every key, the commitment and every other field and only carries each statement as written or renews it; a renewal MUST name the same credential, MUST have started by the record's timestamp and after the epoch opened, and MUST extend the expiry. Lapse never removes a key: a carried expired statement MUST be kept through every rotation that keeps the key; a restoration MUST NOT add or remove a subject, and no subject's class may drop; a lapsed key never counts on a recovery rotation. A statement removed by the quorum is final. The policy MUST name at least two attesters; it MUST be refused when set unless at least a rotation quorum of its keys have valid statements and every lowered threshold is within the count of keys with started statements.

The attested floor bounds history time: a control record whose counting signatures include at most one human-class credential MUST keep the preceding head's time or advance it no further than the **attestation horizon**, the latest expiry among the policy's statements, and MUST NOT reach the maximum representable time; two or more human-class signers MAY set any legal time. A committed next key MAY be attested before it is revealed; that is the only way a recovery signer counts as human.

Three limits are stated and known not to hold: under the declared floor, class is a label; an attester's honesty and independence are not verified; and a key that can authorize a record alone chooses its timestamp, bounded only by the horizon under the attested floor and not at all under the declared one. Enrollment establishes a bounded prior association; a profile claiming fresh human approval of a particular action MUST bind a fresh biometric approval to the exact action challenge and displayed effect. Profiles MUST specify renewal, suspension and revocation, including the consequences of voucher or issuer misconduct, MUST distinguish historical acceptance under the committed evidence cutoff from current risk, and MUST keep later adverse evidence inspectable without rewriting yesterday's replay. A single key's head attestation MUST NOT be taken as proof of the human floor for its preceding history, and a head attestation signed by a lapsed, agent or unclassed key MUST NOT seed an abbreviated replay; nor may any single-key head attestation where the policy requires more than one signature for a checkpoint. A checkpoint recorded in the history under its own quorum MAY seed one. A profile supporting abbreviated replay MUST specify and validate an adequate starting-state authentication policy; otherwise full replay is required.

## Capacity {#capacity}

A history MAY declare size limits. A declared limit MUST NOT refuse a control record that reduces power (revocation, epoch advance, termination, unappointment, witness unbinding). Absolute format or storage caps, unavailable durable storage or inability to sign may still prevent append; a history at an absolute terminal cap is extended by a successor history with its own genesis, which is distinct from same-case continuation ({{continuation}}). A profile MUST define both operational and terminal limits and distinguish their failure reports.

# Records and their verification {#records}

## The chain and the head {#chain}

~~~ ascii-art
  pos:   0         1         2               p
       +-----+   +-----+   +-----+         +-----+
       | gen |<--| r1  |<--| r2  |<-- ... <-| rp  |
       +-----+   +-----+   +-----+         +-----+
  hash  h0=H(0,gen) h1=H(h0,r1) h2=H(h1,r2)  hp=H(h(p-1),rp)
  head at p = (hp, p, timestamp_p)
~~~
{: #fig-chain title="Each record commits to its predecessor; the head names a prefix"}

A conforming encoding MUST define a record hash at each position as a function of the previous hash and the record's content, under a collision-resistant hash with domain separation. The head at p is the triple (hash, position, timestamp), compared field by field. An edit, insertion or reordering changes every later hash; a fully rehashed substitute is detected only by a conflicting authenticated signature or held commitment, and removal of a complete suffix is not detectable from the chain alone ({{rollback}}). A profile MUST distinguish internal consistency from authenticity.

## Control signatures {#control-signature}

Every control record after the genesis MUST carry at least one valid owner signature and satisfy the selected approval policy. Each counting signature MUST be made by an admissible owner key (one in force at that position, or, on a recovery rotation, a committed key the rotation reveals with its possession proof) over a challenge that binds at least:

- the history's domain, so the record cannot be replayed into another history;
- the record's identifier, type and timestamp;
- the head before the record, so the record cannot be moved;
- a hash of the record's effect, under profile-defined exclusions for the authorization containers themselves.

A replay MUST reject a control record with absent, malformed, out-of-epoch or invalid required signatures, or whose eligible distinct signatures do not satisfy its effective policy. A multi-signature profile MUST define surplus, duplicate and ineligible entries and the exact container exclusions; an exclusion MUST NOT allow unsigned effect changes. Which threshold applies, and whether a record is a restoration or a recovery rotation, MUST be decided from the record, the signers' identifiers, the epoch record and the pre-event state alone, before any signature is verified, so the verdict never depends on verification order.

## Session signatures {#session-signature}

Every session record MUST carry a session binding and a type-specific signature. Profiles MUST specify exactly which bytes are authenticated; a generic claim that all envelopes are signed is insufficient. Records constructed after the final envelope is fixed SHOULD bind identifier, type, timestamp, preceding head, binding and effect. In the example encoding, declarations, refusals, effects, lifecycle events and counterparty wrappers bind their envelope; admissions instead sign the decision-time challenge (request, evaluation time, preceding head and session, role, intent and nonce bindings), and the admission's own identifier is committed by a later owner attestation. Migrated prefixes keep their source authorization. Session checks occur in each type's validation stage: find the session and credential, check the epoch fence, active agent, binding, expiry, challenge hash and signature. An admission additionally carries the authorization proof; replay MUST re-derive it from the pre-admission state and recorded inputs and require canonical byte equality. A missing or mismatched credential is not a fence failure.

## Replay and determinism {#determinism}

A reader reconstructs state by replaying every record from genesis under the profile's fixed check order; the profile MUST specify chain, schema, authorization, transition and capacity precedence. A rejected record leaves the state unchanged, the rejection names the position, and a history containing a rejected record is invalid as a whole. Given the same history, request and evaluation time, every conforming implementation MUST produce the same decision, proof and evidence list; evaluation time is an explicit input, never the reader's clock, and evidence lists MUST be ordered deterministically. A specification instantiating this model SHOULD publish conformance vectors and SHOULD have at least two independent implementations pass them; passing a finite set is bounded evidence, not universal correctness.

## Evidence references {#evidence}

Every claim a decision or query makes MUST be supported by an evidence reference naming a record by identifier, type, position and history hash. Further kinds MAY name an authority by its grant record, a credential by its admission, a receipt by content hash and record, or an external attestation by type, reference and attester. Evidence is bounded; a result whose evidence would exceed the bound is INDETERMINATE with an explicit code, never silently truncated.

## State commitment {#state-commitment}

A conforming encoding MUST define a **state root** committing to the complete set of state records at a position, such that matching roots commit to matching record sets. Inclusion needs a verified path, leaf index and tree size; sorted non-membership additionally needs authenticated adjacent indices and boundary proofs and an authenticated commitment whose ordering and uniqueness were validated; two arbitrary inclusion paths are insufficient. A Merkle tree over the sorted state records in the manner of {{RFC6962}} satisfies this. An instantiation MUST support owner-signed checkpoints and root-bearing head attestations, distinguishing the state before a checkpoint from the state including it. A reader resuming from a cache MUST recompute the root and compare it with an owner-signed root at exactly that position, falling back to full replay on mismatch; a mismatch alone does not establish owner-key misuse. A signed starting state is an owner assertion unless independently replayed.

# Decisions and refusals {#decisions}

## The decision procedure {#procedure}

A **request** names an actor, an action, a resource and a claimed time, and optionally an amount, a counterparty and a commitment to terms. A decision is one of the results in {{tab-decision}}.

| Result | Meaning | Carries |
|---|---|---|
| ALLOW | Authority exists | A proof: the root, the permission path from root to actor, intersections satisfied, effective constraints after attenuation, the controlling authority identifiers, usage snapshot of every capped grant, authority evidence, prohibitions checked |
| DENY | Authority does not exist or is overridden | A code and a sorted list of failures with evidence. Codes MUST at least distinguish: action not allowed, no authority, revoked, expired, not yet valid, prohibited, agent inactive, session fenced, missing intersection, amount exceeded |
| INDETERMINATE | The history or request cannot support a decision (unverifiable relation, invalid causal time, evidence over the bound) | A code and evidence. MUST NOT be treated as ALLOW; an enforcement point that must choose MUST treat it as a refusal |
{: #tab-decision title="The three decision results"}

The procedure MUST evaluate, in order: domain and policy identifiers; causal time (evaluation time not before the head's time); the actor's lifecycle; the session binding when the request is consequential; candidate permission paths from recognized roots; delegation status along each path; required intersections; prohibitions; per-grant limits including cumulative usage. Budgets ({{budgets}}) are consulted only after an ALLOW and can only turn it into a DENY. Every result MUST state, as constant values, that it is a reading of the captured history and not a capability to execute anything.

## Consequential requests and admissions {#admissions}

A request intended for consequential execution is **consequential**. The runtime declares an **intent** (actor, action, resource, role and tenure, the adapter that will carry it out, optional amount, counterparty and terms commitment, and a nonce); the engine records an **admission** carrying the evaluation time, the expected head and the proof. After an admission the record may show a **consumption** (the adapter's signed acknowledgment), an **outcome** (confirmed, failed, disputed or unknown), a **receipt** (a compact artifact checkable against a supplied prefix), and **effects** (measurements reported by a session, connector or counterparty). None establishes that the world changed; each establishes that a signer claimed something at a head. A job with an uncertain submission stays outcome-unknown until reconciled; exactly-once effects require executor idempotency and recovery, which a signed history cannot supply by itself.

## Budgets {#budgets}

An instantiation MUST support **budgets**: owner-declared stop rules over a group of requests selected by actors, roles, actions, resources and metric, with a cap per period, per operation or in count, and bounded carry-over. A budget selected by role MUST follow the role across a handover. Budgets are charged by admissions only, never by refusals or effects; a matching selector alone does not meter effects.

## Refusals as records {#refusals}

A conforming history MUST support a **refusal record**, session-signed, with the fields in {{tab-refusal}}.

| Field | Rule |
|---|---|
| Source | The authority procedure (CORE), a budget, or a **connector** (an enforcement point outside the engine) |
| Request | As evaluated |
| Evaluation time | MUST equal the record's timestamp |
| Expected head | MUST be the head immediately before the record |
| Decision and code | DENY or INDETERMINATE; the budget identifier for a budget refusal; connector identifier, code and detail digest for a connector refusal |
| Signer | For CORE and budget refusals the signing session's agent MUST be the request's actor; for a connector refusal, the connector's own admitted agent |
{: #tab-refusal title="The refusal record"}

For CORE and budget refusals, replay MUST re-run the decision on the state before the record and MUST reject the record unless decision, code and budget identifier are reproduced; a refusal the state would have allowed is a replay rejection. A connector refusal is **attested, not re-derived**: the engine cannot reproduce a decision it did not make. A reproduced DENY establishes the recorded denial at that head; INDETERMINATE establishes that the inputs could not support ALLOW; an attested refusal proves only that an admitted connector claimed to have refused. An expired, fenced, terminated or never-admitted actor cannot sign its own CORE or budget refusal; a live connector session can attest the mapped attempt instead.

Refusals never change usage counters. A writer SHOULD coalesce identical refusals per actor within a short window and SHOULD rate-limit them, and MUST report whether a refusal was recorded and, if not, why; the history therefore need not enumerate every attempt. A deployment that wants refusals enforced as well as recorded MUST place the decision point where the action is executed ({{coverage}}).

# Counterparty receipts and external policy {#counterparty}

## Counterparty receipts {#counterparty-receipts}

An instantiation MUST support owner-authorized registration and retirement of counterparty verification keys and session-recorded counterparty receipts, distinguishing a local issuer receipt, a commitment to an artifact, and a separately counterparty-signed artifact; a digest alone MUST NOT be reported as authenticated counterparty evidence. A receipt MUST bind the history identity, counterparty and key, the earlier admitted intent and its declaration digest, and the reported effect and time; its wrapper MUST bind the recording session and preceding head. Replay MUST require an ACTIVE counterparty with the named key at the wrapper position and verify the envelope signature before the wrapper authorization. Retirement MUST NOT invalidate an earlier accepted wrapper; new wrappers during retirement MUST be rejected. Re-registration may replace keys while preserving the receipt chain; a credential replaced this way leaves the history's records and the one-job rule ({{owner-approval}}) can no longer see it. A profile MUST specify uniqueness, duplicate and reference-ordering rules and the consistency of duplicated receipt and effect fields; a wrapper referencing an earlier envelope MUST carry or reference it so an exporter can supply the dependency. Verification MUST report artifact authenticity, historical authority, canonical inclusion and current usability separately. A counterparty's signature establishes its claim, not settlement, delivery or legal effect.


## External policy composition {#policy-composition}

An instantiation MUST support composition with an application-selected external decider (Cedar and OpenFGA are examples) through a profile-defined interface. The application MUST bind both decisions to the same captured actor, action, resource, arguments or their commitment, and contextual inputs. For a required external policy, the broker MUST admit a new effect only when the model returns ALLOW and the decider returns an authenticated, supported ALLOW under the configured policy identity; denial, error, missing evidence and an unavailable required decider MUST prevent dispatch. An external ALLOW MUST NOT override a model denial or create a grant, duty discharge or succession power. The profile MUST identify policy, model and store versions, input provenance, freshness, error handling and restart behavior, and MUST distinguish a pinned policy model from mutable relationship data. The application MUST durably retain the external result before admission and link it to the captured request, and MUST recheck current history, authority and clock after asynchronous evaluation or signing. Post-admission external-policy liveness MUST be checked at the executor boundary or the enforcement claim refused; a profile MUST NOT advertise cross-service atomicity merely because both decisions allowed at admission.

# Duties, handover and lineage {#duties}

## Duties {#obligations}

An instantiation MUST support durable obligations and attempt duties with signed creation, assignment and status records. A duty is created from a recorded operation and its receipt, by an administrative session record, and carries its identifier, source intent, causal receipt, durable role, tenure, description, deadline, status, beneficiary, terms commitment, current performance assignee, optional succession rule and transition policies. Statuses are OPEN, OUTCOME_UNKNOWN, DISPUTED, DISCHARGED and IMPOSSIBLE_OR_ESCALATED; a status change and a performance assignment are each signed administrative records. An **attempt duty** preserves follow-up responsibility for an uncertain operation; a profile MUST distinguish its creation rules, and an investigation review MUST NOT be interpreted as fulfillment or automatic discharge.

## Succession and handover {#handover}

When a predecessor is terminated under a succession rule, the writer MUST provide a specified atomic handover operation; profiles MUST define crash recovery and the visibility of intermediate prefixes, since two adjacent valid events alone do not prove atomic storage. {{tab-handover}} states what MUST hold across a handover.

| What | Across a handover |
|---|---|
| Open duties under the applied rule | Belong to the role; stay OPEN and are reported as surviving until the successor records a signed performance assignment |
| Grants | Do **not** follow. The report MUST list every live grant of the predecessor, each marked as not following |
| Delegations the predecessor issued | Evaluated against the predecessor's status; after termination they yield no ALLOW |
| Budgets selected by the role | Follow the role |
| The predecessor's sessions | Cease to authorize requests while the agent is inactive; credentials are not deleted and the epoch is not advanced |
{: #tab-handover title="Handover rules"}

## Queries {#queries}

A conforming instantiation MUST support the queries in {{tab-queries}}, each answered from the captured history with evidence references and an explicit epistemic status: established from a verified replay, or not established and why.

| Query | Answers |
|---|---|
| WHY | For a request: which grants, in which order, under which constraints, from which root, in which session and tenure |
| RESPONSIBLE | For an action: who is attributable at the time (actor, session, role, principal, mandator, authority source, controller) and who holds the duty afterwards. A statement about the records, not a legal judgment |
| SURVIVES | For an agent: lifecycle status, tenures, duties that outlive it, assignments, unresolved intents, reported outcomes, and authority dependencies its termination invalidates |
| LINEAGE | For an authority, admission or request: the capability roots and grant paths that support it, including required intersections and issuance authorizations, with any established human-lineage assessment. Confers no permission |
{: #tab-queries title="The four queries"}

## Proof of Human Lineage {#human-lineage}

A PHL lineage query verifies recorded authority lineage and stated human-evidence predicates under selected policies. It MUST identify its selector, authenticated history identity, evaluated head and time, interpretation and assessment policies, disclosure scope and path-selection rule; an admission query MUST use the replay-reproduced decision path with all required intersections. The **capability root** is the root permission a path descends from; it is distinct from the history owner, the owner keys in force at the root-grant event and the grantor named there, and an answer MUST identify these separately. A valid owner signature on a grant establishes the recorded edge; it MUST NOT by itself be reported as human evidence for the grantor or grantee.

For a root issued under several owner approvals the answer MUST distinguish (a) whether its actual counting quorum contains a qualifying human-attested credential, (b) whether every quorum permitted by its policy requires one, and (c) any assessment of the named grantor; "human-authorized capability root issuance" denotes (a), judged in the root-grant event's frozen context. Counting MUST use the policy in force before the event. A query MUST distinguish established-true, established-false and unknown; missing or withheld evidence MUST NOT be treated as non-human; verification MUST terminate within declared limits and report partial coverage; and for several roots the answer MUST name its quantifier and MUST distinguish alternative paths from required partner paths. An authority-only query MUST distinguish provenance and liveness from action-specific authorization, and each returned path MUST keep its own root and result. Per-edge assessments MUST carry evidence references and MUST distinguish assessment at the edge's event, at query time and as current risk; under the attested floor a lapsed class MUST be reported as lapsed, and later expiry or revocation MUST NOT silently rewrite an established event-time conclusion. An unknown required branch prevents an established-true all-required-roots conclusion; an established-false required branch can establish a false one despite another unknown branch. A limited or redacted view MUST NOT assert an exhaustive all-path or total-count conclusion. Invalid supplied evidence MUST be distinguished from evidence unavailability. Ordinary authority validity and PHL attestation assurance MUST be reported separately unless the selected authority profile makes the latter an acceptance condition. A human signature in one observed quorum MUST NOT establish proposition (b); a genesis key set MUST NOT be presented as an inferred root-grant signing quorum; actor binding MUST NOT be counted as an owner approval. Counts MUST state their unit, deduplicate exact credentials, exclude evidence-only vouchers (a human-associated credential count MUST include only credentials whose assessment is established and report counting-authorization and actor-binding sets separately, and a count under a uniqueness policy MUST name that policy's domain, issuer assumptions and incomplete coverage), and MUST NOT present distinct keys as distinct humans; absent an authenticated uniqueness policy, a distinct-human count is reported as not established. A declared HUMAN class or omitted-class default MUST NOT be reported as a verified assessment. Disclosure MAY hide identities through a reviewed selective-disclosure profile whose public proof binds the same predicate, scope and context.

## Query scope and investigation {#query-scope}

A query result MUST bind the exact domain, genesis identity, interpretation versions, disclosure scope, evaluated head and time, and MUST distinguish a replay-derived conclusion from unavailable evidence, unsupported interpretation or unverified freshness; missing evidence MUST NOT be relabeled as DENY, and a caller-supplied proof or serialized state MUST NOT acquire established status from matching metadata alone. A query about an earlier prefix MUST report whether the supplied history's head is the same prefix, a verified strict extension (later position and matching commitment) or unverified. A historical ALLOW remains an answer about that prefix; present consequential use requires a separate current authorization. Commitment integrity, inclusion, finality, availability, historical authorization, freshness and external outcome MUST be reported as distinct axes. A private or commitment-only deployment MUST NOT claim a publicly reconstructible undisclosed graph. Public reconstruction MUST require independently obtainable bodies, schemas, policies and opening material; an unexplained root alone is insufficient. An indexer, cache or explanation interface MUST NOT be accepted as an authority source because it displays the records.

An instantiation MUST support a prospective, duty-scoped investigation policy, an authorized evidence-bound disposition and a durable contest. Activation MUST identify one existing duty, its rules commitment, the activating actor and the prior head, and MUST NOT rewrite earlier meanings or grant general upgrade power; the profile MUST specify one-activation and compatibility rules, signer purposes, authority prerequisites and finite disposition and contest allowances. A disposition MUST distinguish the attester's signed finding from the performer's authorization to record it; replay MUST check each purpose-bound signature, role and session binding, authority and exact evidence commitment; the same actor MAY fill both roles only if both powers and both signature purposes are checked; the writer MUST re-evaluate fresh eligibility of both after each asynchronous signature and again under the writer lock, with the head unchanged, fresh time at or after the signed time and both authority routes unchanged, without altering signed challenges. Assignment, a restored resource, a reported APPLIED outcome or a reviewed report MUST NOT alone close the duty. The duty view MUST distinguish OPEN, COMPLETED_UNDER_POLICY, ESCALATED, NEEDS_REVIEW and CONTESTED, keep the original creation status, apply the profile's review-freshness rule on new evidence or assignment, and report accepted contests until an explicit adjudication resolves them. Completion under a local policy MUST NOT be reported as external proof or legal discharge, and old readers MUST return an explicit unsupported result rather than a misleading status.

# Execution recovery and continuation {#continuation}

## Admission, dispatch and uncertain outcomes {#recovery}

An instantiation MUST support distinct intent, admission, submission attempt, consumption, outcome, observation and receipt states. A configured executor profile MUST bind target identity, schema and version, captured arguments, enforcement mode, business identity and idempotency identity before signing the intent; untrusted request data MUST NOT select callbacks, credentials or destinations outside the configured profile.

~~~ ascii-art
  intent --> admission --> [submit] --> consumption --> outcome
                              |                          |
                              | timeout / crash          | unknown
                              v                          v
                   keep original identity,      reconcile via status
                   reserved allowance,          and evidence route;
                   outcome UNKNOWN              never re-dispatch on
                                                an empty lookup
~~~
{: #fig-recovery title="An uncertain submission keeps its identity; it is never silently repeated"}

A broker MUST durably record the admitted submission identity before sending. After a timeout, lost response or crash it MUST preserve the original identity, reserved allowance and unknown outcome, MUST NOT dispatch again merely because a lookup is empty, and MUST recover through the original identity and a status or evidence route. A new operation, compensation or restoration MUST obtain its own current authority; a late report MUST be recorded as evidence under current recording authority without manufacturing a receipt, releasing allowance or granting execution permission. The profile MUST state its rollback, full-state-loss and host-trust limitations. A cooperating destination MUST authenticate the coordinator, accept checkpoints only as exact history extensions, durably acknowledge the effective fence and recheck the admission's control tuple and required authority liveness, under the declared time and policy assumptions, at its commit boundary; cancellation and application MUST share the profile's durable ordering boundary; a cancellation after APPLIED MUST be reported as too late; staging a new checkpoint MUST NOT be reported as an acknowledged fence. Atomic effect-and-idempotency commitment MUST be one durable transaction; missing or corrupt restart state MUST fail closed and MUST NOT silently reinitialize a destination; retention of attempt identities and tombstones MUST be bounded and MUST refuse growth rather than forget replay protection.

## Same-case continuation {#same-case}

An instantiation MUST provide an explicit continuation mechanism. A same-case storage profile MUST preserve the original domain and genesis, canonical bytes and global positions, interpretation versions, signatures, usage, revocations, nonce state, reservations, attempts and open duties; a suffix-only replay or a fresh genesis MUST NOT be represented as a continuation. A segmented profile MUST reconstruct from genesis or an authenticated starting state, commit immutable segments before publishing their manifest, acknowledge only after the required durable barriers, and reconcile uncertain writes against the committed manifest; conditional append MUST check the storage generation and canonical head under an exclusive writer boundary, and orphan data MUST NOT silently become canonical or cause fallback to an older head. Migration MUST be explicit, preserve the originals and existing attempts, usage, identities and capacity obligations, verify the source and prevent concurrent use of the old write path; destination transfer MUST independently validate the transferred complete history before acknowledging its checkpoint; an exact same-history retry MUST preserve the original durable result and MUST NOT create another effect or reset allowance. A storage manifest is integrity evidence under host assumptions, not finality.

## Interfaces and service boundaries {#interfaces}

An instantiation MUST expose separate read-only inspection, authorization evaluation and controlled write interfaces. CLI, SDK, Model Context Protocol (MCP) and agent-framework bindings are application interfaces, not authority sources; an authenticated caller binding MUST map a connection to the configured actor, session and tenure; untrusted caller parameters MUST NOT select another actor's privilege; and read-only handles MUST NOT become execution capabilities. A protected-resource profile MUST identify the trusted host, custody and access boundary; restoration requires separate authorization and MUST NOT discharge the investigation duty. A service MUST bound its resources, capture one consistent observation per composite query and apply an explicit disclosure policy; a natural-language explanation interface MUST retain the typed result and evidence links and MUST NOT upgrade an unverified conclusion. A durable-job interface MUST persist an opaque handle bound to the original attempt before launch, check caller access and permission on every poll, inspection or cancellation, and MUST NOT infer an effect retry from reconnection; a handle MUST NOT confer authority, and a cancellation acknowledgment MUST distinguish stopping later outgoing phases from cancellation at the destination and from rollback of an applied effect. An authenticated HTTP binding MUST validate issuer, audience, token type and lifetime, MUST reject token-supplied discovery keys or URLs outside the configured trust policy, MUST NOT forward bearer credentials upstream or retain them in records, MUST recheck caller access around asynchronous signing, dispatch and disclosure, and MUST NOT interpret a disconnect, expired token or refusal as cancellation or proof of no effect. A public service profile MUST specify HTTPS and custody boundaries. Access loss after an effect MUST preserve the attempt while withholding disclosure under current policy.

# Reconciliation {#reconciliation}

## Why a decision point is not enough {#coverage}

No decision point sees every call: a host may execute a tool without asking, a sub-agent may run without the hook, a script may call a service directly, and a token the agent holds may be used outside any gate. A history that records only what passed through the decision point proves what the decision point saw and decided, not what the agent did. A deployment claiming coverage under this model MUST publish an assessed coverage table (scope, version, period, assessor, known unknowns) classifying every identified effect path as in {{tab-coverage}}. A claim that an agent is "governed" without this table is not supported by the model.

| Class | Meaning |
|---|---|
| enforced | The decision point both decides and performs, or holds the only credentials, with assessed controls that prevent the effect on DENY: credential isolation, protected executors, stale-decision checks, fail-closed behavior. Holding a credential on a hostile host is insufficient |
| recorded | The effect can occur without a decision, but an observation feed with documented coverage and loss guarantees is reconciled against the history ({{observations}}) |
| open | Neither enforced nor observed |
{: #tab-coverage title="Coverage classes for an effect path"}

## Reconciliation observations {#observations}

An instantiation MUST support RECONCILIATION_OBSERVED as a session-signed finding. The signer MUST be an admitted session whose agent equals the recorded reconciler; an owner signature MUST NOT be accepted in its place. Each observation MUST carry a unique identifier, the reconciler, the source stream and event reference with a digest, the observed call fields with explicit unsupplied-field markers under profile-defined optional-field and absence rules, a MATCHED or UNMATCHED result, the immediately preceding head, the session binding and a purpose-specific signature. A MATCHED reference MUST identify an earlier admission or refusal whose actor equals the observed actor; a match to a refusal MUST NOT be treated as permission or as an effect claim, and the verifier MUST list fields that differ from the matched request and observations whose reconciler equals the observed actor.

A later observation whose digest equals an accepted one for the same stream and reference MUST be rejected as a duplicate; one whose digest differs, if accepted, MUST carry an equivocation reference to the earliest, which verification lists without invalidating the history. Replay MUST validate schema, session authorization with its fence precedence, reconciler binding and preceding head, then the match and duplicate rules, before capacity. Replay MUST NOT infer provider completeness or re-create undisclosed source bytes from the digest; a cursor keyed by reconciler and stream MUST track the last accepted reference, and opaque source references MUST NOT be assumed ordered. Under the writer lock the writer MUST match at the append head, sign and durably append before advancing its collection checkpoint, recovering a crash through the original source identity without recording twice. A verifier MUST present unmatched, equivocation and mismatch listings as signer claims about supplied feed events: they prove neither complete coverage nor an external effect. Legacy ledger migration MUST append each observation at the current head and MUST NOT back-date history records. Collection intervals, feed loss and matching criteria MUST be reported as deployment evidence.

# Export, verification and freshness {#export}

## The export view {#export-view}

An export MUST carry at least: the domain, the concrete profile identifier, authenticated history identity and the genesis event hash, distinguished from the genesis record-chain hash; the heads at both ends of the range; every record in the range with its hash; every owner key rotation at or before the end; where state roots are defined, the roots at both ends, the full state at the start and audit paths for requested records; the owner attestations and witness receipts held for both heads; and the dependency closure of earlier bodies read by transitions. A verifier MUST authenticate its trust anchors and identity first, then signatures and transitions. A later starting state requires full prefix replay or an authenticated starting-root commitment, and the export MUST report starting-state authentication separately from transition validity.

## What a verifier establishes {#establishes}

Given an export and the owner public keys, a verifier that trusts neither agent nor operator can establish: **chain integrity**; **control-record authenticity** (every change of power satisfies the policy in force, bound to position and effect); **session-record authenticity** under each type's rules; **decision reproduction** (every admission was authorized at the head it names and every CORE or budget refusal reproduces); **captured authority** at any position and explicit evaluation time; **refusals**, including which were attested rather than reproduced; **duties and handovers**, including that no grant followed; **reported observations** with their results; **state equality** where an owner-signed root is available; and, where selected, **human-eligibility evidence** against the named policy.

It does **not** establish that an action had its effect in the world, that every call passed through the decision point, that timestamps are true, that an owner key was held by the right person, or that the export is the latest state unless freshness evidence from outside the host is available ({{tab-limits}}).

## Rollback and freshness: local anchors, witnesses and public chains {#rollback}

Chain hashing cannot distinguish a history from the same history with a valid suffix removed. {{tab-anchors}} lists the mechanisms, from a file beside the history to a public chain; they differ in who must be compromised to roll the history back undetected.

| Mechanism | Where the evidence lives | Defeats | Does not defeat |
|---|---|---|---|
| Head attestation | A file beside the history, written after each owner-attested write | Truncation by anyone who cannot rewrite the attestation | An operator who restores an older copy with its older genuine attestation |
| Local anchor log | An append-only log the history's writers cannot rewrite | Truncation past any logged head | Restoration of a copy from before the logged head; an administrator of both |
| Remote witness | A Merkle-committed log of owner-signed head statements in another trust domain, one linear chain per history | Rollback to any head the witness holds; records equivocation evidence | A copy from before the first binding; the window while unreachable; an administrator of host and witness |
| Public chain anchor | A commitment to the head, published to a public, permissioned or hybrid ledger ({{external-anchoring}}) | Rollback or fork of any anchored prefix, for anyone who can read the chain | Unpublished work after the last anchor; a hidden fork; chain-side finality and availability limits |
{: #tab-anchors title="Freshness mechanisms, weakest to strongest"}

A conforming instantiation MUST support head attestations and the witness protocol; a deployment MUST configure at least one of the two and SHOULD use an independent witness when its claim requires protection against restoration of all local side files. The deployment MUST report the attested position and the unauthenticated tail, and a reader MUST refuse a copy that lacks an attested head it knows of. A witness accepts a head statement only if it is signed by an owner key in force at that head and its stated previous head is exactly the latest the witness holds; owner code signs only after obtaining the witness's latest head and checking it is a prefix of the history being extended. Every answer is signed over a fresh client nonce and validated within a deadline, and is the witness's claim at response time, not proof of unsubmitted work. Clients verify checkpoints with an out-of-band key and check consistency with earlier ones; gossip or independent comparison is needed to reveal disjoint views. Witnesses SHOULD be bound in the history by a control record, and an external identity or creation policy SHOULD require that binding. A witness sees only the genesis, key rotations and head hashes.

## External anchoring profiles {#external-anchoring}

An instantiation MAY publish authenticated history commitments to a public, permissioned or hybrid ledger. Anchoring commits a particular prefix; it does not establish the truth of records, complete capture or the absence of a later prefix, and it does not replace {{rollback}}'s mechanisms or ordinary replay.

~~~ ascii-art
  history head ---> anchor statement ---> outbox (durable, journaled)
   (owner side)     (publisher-signed)         |
                                               v
                                        chain connector --> ledger
                                               |
            barrier: ELIGIBLE / DELAYED <------ finality verifier
            (effects may wait for a label)      (labels, below)
~~~
{: #fig-anchoring title="Anchoring: statement, outbox, connector, finality, barrier"}

A selected profile MUST identify its chain and trust bootstrap, commitment encoding, publisher authorization, destination and upgrade policy, inclusion and successful-execution checks, finality rule, freshness and availability policy, and behavior on timeout, outage or conflicting evidence. A commitment MUST bind the intended history and authenticated genesis, the exact committed head and state-root semantics, the profile and its predecessor commitment, with an explicit absent-predecessor form for the first; it MUST NOT accept an arbitrary restart as continuation. Owner authentication remains distinct from the publisher's key. A verifier MUST check that a successor's prefix extends the previously accepted committed head rather than accept an increasing sequence number as continuity; a contract accepting a hash proves neither validity nor extension.

The profile MUST distinguish independently validated consensus evidence from reliance on a named node; agreement among RPC responses is not a consensus proof, and for layered chains execution and settlement MUST be distinguished. As an informative example, not part of the model, {{tab-finality}} shows the labels the reference connector uses for a rollup settling on a layer-1 chain, and the three verification modes it reports.

| Label (ordered) | Meaning |
|---|---|
| SUBMITTED | The transaction left the outbox; inclusion unknown |
| L2_INCLUDED | Included in a rollup block reported by the connector's node |
| L1_POSTED | The rollup batch containing it was posted to the settlement chain |
| L1_FINAL | The settlement chain has finalized that batch (about 12 s on the example chain) |
| CEMENTED | The rollup commitment has passed its refutation period (about two weeks) |
{: #tab-finality title="Informative: the reference connector's finality labels, weakest to strongest; its modes are CONSENSUS_VERIFIED, TRUSTED_NODE and UNVERIFIED"}

Deployments MUST report the latest verified commitment, committed position, known unanchored tail, and the assurance and freshness of chain evidence, and MUST state whether external effects wait for finality or may occur within an exposure window. A timeout is an uncertain submission; retries MUST preserve commitment identity and MUST NOT authorize repeated effects. A profile requiring finality before dispatch MUST recheck current authority at the effect boundary. Public, private and hybrid are deployment descriptions, not assurance levels: a permissioned profile MUST disclose membership, quorum, fault assumptions and governance; a hybrid one MUST say whether it mixes validators, publicly anchors a private commitment, or both. It MUST NOT claim required external participation if an entirely internal quorum can commit; data-availability participation alone is not consensus over the history.

Three opt-in tiers are defined, in increasing exposure: **anchoring** of heads (the reference implementation's default); **persistence** of complete record bodies on the chain, which makes the history public and MUST be disclosed as such; and **on-chain execution or verification** of the authority rules, in which the chain is a second implementation that MUST agree with replay and is never an authority over it: no certificate, inclusion proof or quorum can admit an event that replay refuses or refuse one it admits.

## Federated operators {#federated-operators}

A deployment MAY distribute operation of one history among a consensus committee. Ordering hash publications alone is federated anchoring; federated execution additionally requires participants to validate the record profile and agree on exact bytes, order and resulting commitments. The profile MUST specify membership and epochs, quorum and fault assumptions, deterministic execution, canonical publication, checkpoint and bootstrap rules, available bodies, recovery and membership change; its evidence MUST bind predecessor, ordered records and resulting roots at the heights where they are authenticated, and a pre-state commitment MUST NOT be presented as a post-state one. Several processes under one administrator MUST NOT be described as independent trust domains.

Committee membership grants no owner or session authority; every record MUST still satisfy its ordinary rules, and a quorum certificate is not an owner signature. A committee MAY hold a co-signing key enrolled in the AGENT class: it is never sufficient alone, never counts on a rotation or policy change, can never block a power reduction, and can be rotated out by the human-class holders. Replicated execution MUST NOT itself perform external effects; a deployment claiming governed dispatch MUST specify a separate executor boundary, leadership fencing and a retry policy, including how uncertain outcomes are handled. Under its honest-quorum assumptions, federation prevents one operator from replacing committed history and evidences conflicting commits; it does not prevent valid acts signed by a compromised owner, prove exclusive routing, or make false reports true.

# Optional zero-knowledge proofs {#selective-disclosure}

An instantiation MAY provide zero-knowledge proofs over an authenticated history, so that a useful fact can be checked while the records establishing it stay private: a disclosed field authenticated, a private delegation chain shown to satisfy an authority or lineage predicate, or an aggregate shown to follow from committed histories. This document selects no mandatory proof system. A proof result MUST identify its evidence scope and MUST NOT itself grant execution authority; a verifier MUST NOT substitute an unspecified proof for required replay evidence.

**Relation and statement.** A profile MUST specify a relation R(x, w) with public statement x and private witness w, its permitted record kinds, encodings, bounds, commitments, predicate, outputs and soundness and privacy assumptions. Every value used to satisfy the predicate MUST be constrained to the corresponding committed record; hash-to-field encodings MUST be injective, so reducing a 256-bit digest modulo a smaller field is insufficient. The statement MUST bind the relation and version, the intended history and full head, the state root or projection head and count, the subject or selection rule, the question and context, the disclosure policy, the audience, and an explicit non-execution result; the verifier MUST obtain the expected anchor and verifying key independently of the prover. An existential predicate does not identify the verifier's intended subject; universally quantified claims require coverage of their whole domain. A root-membership proof relates to a commitment; a claim over accepted signed histories MUST say how identity, keys, signatures, ordered transitions and resulting roots are verified, and MUST report whatever is assumed rather than proved. A claim relying on absence, revocation status, intersecting authority or accumulated usage MUST cover every record that can change the answer, by complete replay, authenticated exhaustive ranges or another specified completeness relation; an inclusion proof for a granting record alone does not establish the absence of a prohibition. The profile MUST say which witness components are private, public or checked outside the relation; a membership relation MUST bind the canonical record, its leaf, path and anchor; a projection relation MUST bind its encoding, range and projection head and its verifier MUST NOT report omitted transitions as verified; a subject-specific profile MUST bind the selected subject, or a hiding commitment opened inside the relation, to the record used for the predicate.

**Profiles.** Selective disclosure MAY reveal chosen fields or predicates of a hidden record, binding them to the same canonical record and anchor; selective-disclosure signatures such as {{I-D.irtf-cfrg-bbs-signatures}} are a building block, not a replacement for transitions, and ordinary Merkle openings MUST NOT be labeled zero-knowledge. A private authority profile MAY prove that a request met a named predicate at a head while keeping delegators and terms private; its relation MUST evaluate session, lifecycle, edges, attenuation, intersections, prohibitions, revocations and selected budgets under the same request and state. A private human-lineage profile MUST give distinct identifiers to its predicates (the named root actor, human participation in the actual issuance quorum, or a policy requiring one), MUST keep lapsed distinct from human and unknown from non-human, and proves satisfaction of the evidence rules, not biological truth. An aggregate profile MUST define the population's enrollment and inventory commitment, selection and deduplication rules, the unit counted, treatment of unknowns, and the statistic; the verifier MUST authenticate the inventory independently, and the relation MUST account for every eligible item. An illustrative result such as 62 established-true of 100 paths with 10 unknown is a statement about that declared population and denominator, not about non-human remainder. A selective-disclosure-signature profile MUST specify issuer trust, message-to-record binding and history relationship and MUST NOT reinterpret an existing signature under another scheme. A private lineage relation MUST bind each classification to the signing credential, its issuer and voucher, the assessment-policy version and the status context, evaluated under the policy in force before the event. A private budget relation MUST bind its inputs to the same admitted operations, periods, policy and carry state and enforce exhaustion and ordering; a continuation MUST NOT substitute recaptured inputs under an old identity.

**Privacy and lifecycle.** Zero knowledge limits disclosure beyond the public statement; it does not conceal the statement. A profile MUST list observable outputs and metadata, assess low-entropy guessing and linkage, and specify cohort, suppression and repeated-release rules; a verifier MUST NOT label an exact aggregate differentially private because its computation is proved. Any differential-privacy mechanism MUST be separately specified and bound to the proved computation ({{DWORK-ROTH}}). The verifier MUST report the predicate proved, the assurance axes covered, proof-system and setup trust (for example {{GROTH16}}), external checks and remaining unproved axes; STATE, BUDGET and BOTH modes keep their meanings; multi-stage proofs MUST bind each stage's anchors, program and counters and reject joins across unrelated states. A deployment MUST version relations, circuits and keys and state which it accepts historically. Fully homomorphic encryption {{FHE-INTEGERS}} is named as a forward path for computing selected statistics over encrypted inputs; an FHE profile MUST specify who encrypts, evaluates and decrypts, exact or approximate arithmetic and its error bound, and the integrity mechanism, since confidentiality alone does not show the right inputs were used ({{SEAL-SECURITY}}). {{status}} reports what has been proved so far. A differential-privacy profile MUST define adjacency, the protected unit, contribution bounds, sensitivity, mechanism, parameters, randomness and an accountant for repeated releases, and MUST include public commitments and auxiliary outputs in its analysis. An FHE profile with several key holders MUST specify its key-sharing, threshold or multi-key construction, and a combined FHE/ZK profile MUST bind ciphertexts, keys, program, input commitments and result across every component and assess output, size and access-pattern leakage.

**Rules that hold across every profile.** Failure, unsupported profiles and absent required evidence MUST remain distinguishable from verified success. A composed verifier MUST compare the shared statements of its components and require every selected component check and every proof dependency; two valid proofs alone are insufficient. A profile MUST define empty-input and missing-evidence behavior, and its verifier MUST reject a success obtained by omitting a required subject, range or dependency. An owner signature on a root alone MUST NOT be reported as proof of accepted replay. A hidden-record inclusion result MUST NOT be reported as authority, revocation freshness, budget compliance, duty closure, complete capture or external truth unless those checks are covered by its relation and authenticated context. STATE, BUDGET and BOTH modes MUST retain their declared meaning. Counting qualified credentials MUST NOT be reported as counting distinct people without a separately verified uniqueness mechanism. An aggregate over an empty population MUST return an explicit no-data result rather than a percentage; a profile selecting a non-default denominator MUST disclose its exclusions; any external inventory certification or participant-selection assumption MUST appear in the result. A deployment relying on a trusted setup MUST identify the ceremony, custody and compromise assumptions it accepts; provers MUST use fresh proof randomness where the system requires it; unknown or retired versions MUST be rejected under the stated acceptance policy. An FHE profile MUST NOT silently use approximate equality for an exact authority predicate, and encryption confidentiality alone MUST NOT be reported as proof that the right inputs were used. A profile MUST identify its proof system, verifying-key and parameter identities, circuit bounds and the configuration that provides zero knowledge in every wrapper; MUST specify opening retention, prover access, key-compromise response and treatment of unavailable evidence; and, where it claims hiding commitments, MUST identify the hiding construction, entropy assumptions and custody of openings.

# Applicability beyond AI agents {#beyond-agents}

The separation of authority, actor, session, office and effect applies wherever an actor is a process or a credential subject ({{tab-beyond}}). A profile using these mappings MUST preserve the distinction between a recorded grant, evidence of a request's authorization, and mediated execution.

| Setting | Mapping | Stated limit |
|---|---|---|
| Processes and operating systems | Each process an agent, each instance a session, inter-process operations requests under grants; epochs fence old instances | Recording a process as an agent provides no isolation, memory safety or truthful device reports; a profile claiming mediation MUST publish its coverage under {{coverage}} |
| Revocable credentialing | The history records an issuer's grants to people or agents, their scope and withdrawal; a profile MUST distinguish subject, issuer and owner and define presentation (authenticated subject-to-key binding and presentation proof, audience, purpose, replay resistance), expiry, suspension and revocation | Offline verification of an old status cannot show that no later revocation exists; a credential is not permission to act without an explicit policy |
| Lineage of non-human and embodied actors | The succession of models, services or robots recorded under the same history; a lineage answer MUST derive from signed creation, appointment, handover and revocation records | Recorded heritage, not identical behavior or physical integrity |
| State authority roots | A root class for authority asserted by a public body under law, with public key ceremonies and rotations; a relying party MUST report whether a chain terminates at such a root, elsewhere, or cannot be resolved | No claim of legal validity or enforceability; participation is voluntary and no registry is defined |
{: #tab-beyond title="Other settings the model applies to"}

In addition: a process profile claiming that all interaction is mediated MUST identify and enforce its execution boundaries, including privileged calls, shared memory, device access, background tasks and administrative bypasses; a credentialing verifier MUST state the captured status position, evaluation time and freshness policy it used, and renewals MUST preserve linkage without silently restoring withdrawn authority; an actor-lineage profile MUST state how a successor is bound to its predecessor's records, which predicate classifies an actor as non-embodied or embodied, and how unknown or unverifiable links are reported; a state-authority profile MUST identify the issuing body and its legal basis, MUST create and publish the root's keys through a public ceremony recorded in a publication of record, MUST make rotation and revocation equally public, MUST define how a history references the root and authenticates that reference, and an unresolved chain MUST NOT be treated as state authority.

# Security Considerations {#security}

## Threat model {#sec-summary}

Operational guidance that complements this section is described in {{status}}.

The verifier distrusts agents, the writer and the operator; an execution claim separately depends on a disclosed executor boundary. Cryptographic conclusions assume authenticated trust anchors, correctly implemented profile rules, collision-resistant hashes and unforgeable signatures. No language model is a proof or policy authority. {{tab-threats}} lists each adversary, the response and the residual limit.

| Adversary | Ability | Verification or deployment response | Residual limit |
|---|---|---|---|
| Host/operator | Bypass hooks, alter files/clock/configuration, withhold bodies | Authenticate trust anchors; replay; compare held/witnessed heads; classify effect paths | Unseen effects, withheld evidence, and unattested tails remain unproved |
| Agent/session thief | Propose false claims, sign with an admitted session, or advance history time up to the session's expiry, the next owner-attestation expiry under the attested floor, or, where the genesis sets a session-time horizon, that horizon past the latest time-advancing owner-signed record | Epoch/expiry/lifecycle fences, authority re-derivation, purpose-specific signatures; a writer that checks session timestamps against a trusted clock ({{sec-host}}); a session-time horizon | Valid key claims need not be true externally |
| File writer without signing keys | Edit, rehash, splice or truncate a store | Check signatures, chain, exact heads and external commitments | A previously valid prefix with all old local side files can be restored |
| Owner-key thief | Satisfy a compromised control quorum, or the separate head-signature rule | Eligible distinct-key thresholds where selected, dedicated keys, committed-next possession, rotation and incident review | A valid signature/quorum does not prove human intent; head and control policies can differ |
| Compromised or manipulated agent co-signer key | Contribute one signature toward a threshold on non-policy control events | Policies requiring at least one human-class signature; exclusion of agent signatures from owner-key and policy changes; rotation | Cannot authorize alone or alter owner keys or policy; its one contribution still counts where the policy permits |
| Holder of a stolen or escrowed committed next key | Under the recovery option, sign the rotation that reveals it; otherwise withhold it and freeze the key set | Rotation threshold of two or more with distinct custodians per committed key; leaving recovery absent and relying on key-material backup; custody of each committed key as a current key | Under a rotation threshold of one it takes the history alone; without recovery, loss of every current key is permanent by design |
| Sole authorizer of a control record | Choose the record's timestamp: lapse co-owners, expire sessions, budgets and dated grants, or pin time | Attestation-horizon bound on a single human-class signer under the attested floor; rotation threshold of two or more | A single signer still sets time up to the horizon; two human-class signers set any time; under the declared floor there is no bound; the model has no clock |
| Coerced or colluding attester | Attest an agent-held key as human, or refuse renewal | Statements inert until the owner quorum embeds them; two attesters required; the quorum removes attester and statement by policy rotation; lapsed keys keep power reduction, checkpoints and restoration | Collusion between quorum and attester is indistinguishable from consent; with no cooperating attester, keys, attesters, thresholds and floor stay frozen |
| Witness or witness-key thief | Withhold replies or serve disjoint views | Pinned keys, nonce/deadline, inclusion/consistency checks, remembered checkpoints and independent comparison | A nonce alone does not stop split views; unsubmitted work is invisible |
| Provider/counterparty | Omit, rewrite or fabricate reports | Retain digest/issuer evidence, list equivocation and match differences | Signatures authenticate the reporter, not effect or complete coverage |
| Reconciler | Mis-map calls, omit observations, self-observe | Admitted-session binding, explicit absent fields, source identity, duplicate/equivocation lists | No completeness theorem; matching actor alone does not establish execution binding |
| External decider/destination | Change policy, disappear, return stale results | Same-request policy binding, fail-closed required policy, acknowledged fence/status recovery | Cross-service atomicity and full destination rollback require a stronger profile |
| Anchor publisher or chain-facing RPC | Withhold or misreport publication; submit a stale or conflicting commitment | Authenticate chain/profile and intended history; validate execution, finality and committed-prefix continuity; retain independent checkpoints | Unpublished work/forks remain invisible; fees, outage and stale bootstrap can stop freshness |
| Federation member or coordinator | Propose invalid order/state, withhold bodies, equivocate or censor | Independent deterministic replay, authenticated membership/quorum, actual post-state commitment evidence and retained bodies | Corrupt quorum, common administration, unavailable evidence or unsafe membership change can defeat the profile |
| Dispatcher or former leader | Repeat an external call or execute after authority changes | Fresh effect-boundary checks, committed attempt identity, leadership fencing and downstream idempotency/status | Consensus alone supplies neither external atomicity nor exactly-once effects |
| Agent using a human's device or key | Reuse enrolled credentials, automate prompts or sign after unlock | Exact-key enrollment binding; qualified custody; fresh action approval where required | Enrollment alone does not prove current human participation; an unlocked/exported key can be misused |
| Dishonest voucher or Sybil ring | Certify fabricated relationships or agent-controlled keys | Authenticated bootstrap, another-person checks, scoped signed vouches, diversity and prospective status handling | Colluding roots or real humans can lie; distinct keys are not necessarily distinct people |
| Coercer or deepfake attacker | Manipulate the subject or impersonate live interaction | Independent contact, context-bound live checks, in-person option and incident recovery | No biometric/signature proves voluntary intent; remote presence tests remain fallible |
| Authenticator or attestation issuer compromise | Falsify biometric/key-protection evidence | Qualified method-specific profiles, pinned metadata/trust and status evidence, re-attestation | Verification still depends on the device, issuer and assessment process |
| Registry/status operator | Hide revocation, replay old good status or correlate subjects | Committed historical cutoffs, current freshness checks, private evidence, independent checkpoints | Availability and unseen later status remain separate; hashes may still enable correlation |
{: #tab-threats title="Threat model"}

The cryptographic basis is: chain hashing for integrity within the record; owner signatures over position and effect for every change of power; type-specific session signatures; re-derivation of non-migrated admissions and CORE/BUDGET refusals on replay, while CONNECTOR, reconciliation and external-decider findings remain signer claims; and, for freshness, owner-attested heads held outside the host.

## The host is trusted by the engine, not by the verifier {#sec-host}

The engine runs inside the host with the host's permissions; a host can skip the check, patch the clock or read key files. The model confines what the host can do undetected rather than pretend otherwise. Unhooked calls are not seen ({{coverage}}); a verifier assessing a completeness claim MUST obtain and report the coverage table. A decision is point-in-time. History time is the writers' claim: a clock set forward expires grants early, a clock set backward is caught only when it would precede the head. Deployments SHOULD use a monotone, trusted clock, readers SHOULD refuse a head unreasonably ahead of their own clock, and where grants and budgets depend on time a deployment SHOULD identify a trusted-time or witness-receipt-time binding and its uncertainty. A single signer's control over time is bounded only as {{human-attestation}} states. A session key has similar control. A session record carries a timestamp chosen by its signer. Replay rejects it if that time is at or past the session's expiry, and, under the attested floor, at or past the expiry of an owner attestation that was still valid at the preceding head ({{sessions}}). Someone who steals a session key and can add records directly can therefore move history time forward to just before the earlier of those limits. Advancing the epoch stops further records but does not move time back. Deployments SHOULD accept session records only through their own writer, which checks each timestamp against the deployment's trusted clock; a verifier cannot tell afterwards whether that writer was used. A history whose genesis sets a session-time horizon ({{sessions}}) bounds this in replay itself: a session key can then move history time no further than that horizon past the time of the latest owner-signed record that advanced history time. The cost is operational: once the horizon is reached, sessions cannot record until an owner writes such a record, so an unattended deployment needs scheduled owner records and therefore an owner key that is available.

## Key compromise {#sec-keys}

| Key | What its thief can do | Response | Limit |
|---|---|---|---|
| Owner (enough to meet the policy) | Produce valid control records and attestations | Rotation; pre-rotation keeps a thief holding only current keys from locking the owner out, provided the committed key is kept off the host | Signatures establish which keys signed, not who authorized; one key suffices in a single-key profile; a retired key still signs a copy cut back to before its rotation, and only later-head evidence tells that copy from the real one |
| Committed next key | Under recovery, co-sign the revealing rotation; otherwise freeze the set by withholding | Custody as a current key; rotation threshold of two with distinct custodians | Under a threshold of one, its holder takes the history alone; the threshold counts keys, not custodians |
| Session | Sign admissions, refusals, receipts and duties until expiry or epoch advance; advance history time up to its expiry, the next owner-attestation expiry under the attested floor, or a set session-time horizon past the latest time-advancing owner-signed record, if its records bypass the deployment's writer ({{sec-host}}) | Epoch advance, which bypasses declared limits; finite session expiry | Can still fail at absolute caps or on unavailable storage |
| Witness | Equivocate: show different logs to different clients | Remembered checkpoints; several independent witnesses | Cannot forge owner statements or alter contents it never sees |
| Reconciler session | Mis-map or omit observations | Admitted-session binding, listing rules | Admission does not certify honesty or independence |
| Chain publisher, validator, dispatcher | Stall progress or publish invalid commitments; repeat a call | Verifiers check validity and prefix continuity; committee fault threshold; fencing and idempotency | None can forge owner authorization; a hidden fork stays hidden |
{: #tab-keys title="Key compromise"}

A key used under this model SHOULD sign only domain-separated challenges defined by its profile, so that it cannot serve as a signing oracle for another protocol. Distinct committed keys SHOULD be held by distinct custodians; profiles SHOULD require finite session expiry outside migrated prefixes; and the incident procedure SHOULD review the compromise interval, append revocations and advance epochs. FROST {{RFC9591}} or another threshold scheme may produce an ordinary profile-valid signature; that is distinct from a policy requiring separate signatures by several enrolled keys. A deployment with more than one human key SHOULD require at least two signatures for a key rotation, and with a threshold of two or more SHOULD set the power-reducing types to one so that one present human can always stop an agent. Uninstall, upgrade and file-deletion restrictions are operating-system controls, not consequences of the signature scheme.

## Rollback, refusals, delegation, availability, claims {#sec-rest}

**Rollback.** Without evidence outside the host, a rollback to any head the owner once attested is undetectable. A reachable witness bound to the history closes this; what remains is a copy from before the first binding, the window while the witness is unreachable, the administrator of both host and witness, and the records after the last witnessed head. A deployment MUST state which apply. Anchors and committee checkpoints add known-head evidence; a fresh reader needs an authenticated bootstrap; a hidden fork remains hidden.

**Unsigned records and refusals.** Only control records carry an owner signature; a party who can write the file but holds no admitted session cannot add admissions, refusals or observations. Instantiations SHOULD sign intent declarations, so that a file writer cannot squat identifiers. A denied agent cannot fill the history with refusals: they are session-signed, coalesced and rate-limited, bounded by declared capacity that never refuses power-reducing controls, and a CORE or budget refusal the state would have allowed is rejected on replay. CONNECTOR claims can still be false.

**Delegation and prohibition.** Attenuation is a replay rule, prohibition scope and path selection decide what is overridden, and required intersections need live partners; these three let a verifier bound the maximum authority any actor could have had from the history alone. Retiring a counterparty does not deny consequential requests that name it; stop them with a prohibition, a budget or at the connector. A proof-size refusal is not a denial of authority: a power-reducing revocation or termination can remove an oversized winning path and let a smaller granted path produce a proof, turning that refusal into an ALLOW. To stop an actor, use a prohibition, a zero-cap budget, a fence or a termination, never a proof-size limit.

**Availability.** Declared capacity preserves withdrawal; absolute caps, disk failure, a stale lock or signer failure can still stop revocation and termination, so an independent executor stop channel is a deployment requirement where safety depends on withdrawal. Deployments MUST plan for a history's terminal state and a successor, MUST choose and document whether a witness outage stops gated owner writes or permits them up to a bound, and must keep a separate emergency stop boundary when effects are finality-gated.

**Receipts and outcomes are local claims.** A receipt establishes that a session signed a claim at a head; an effect, that a measurer reported a quantity; an outcome, that an attester reported a status. Deployments MUST NOT describe a history as proof of what an agent did, as opposed to what the decision point saw and decided and what signers claimed.

**Cryptographic agility.** The model names no mandatory algorithm. An instantiation MUST specify its hash, signature suites and canonical encoding, MUST bind the suite to each key when the key is declared, and SHOULD require strict signature verification (for Ed25519 {{RFC8032}}: canonical encodings, no small-order keys, cofactorless verification).

# Privacy Considerations {#privacy}

A history records who was allowed to do what, who was refused and who owes what; it is not confidential by construction. Deployments SHOULD keep secrets out of identifiers and descriptions, SHOULD commit to terms by digest and hold content elsewhere, and SHOULD limit disclosure and retention. Encryption requires a profile defining what is committed and how auditors recover it. The model provides no erasure: a record needed for replay cannot be removed, so identifiers that must later be erasable SHOULD be pseudonymous or held outside the history under a salted commitment. Observation call fields, effects and counterparty receipts import third-party data into the history and SHOULD be minimized to what matching and verification need. Query answers MAY withhold fields under a disclosure policy; that policy does not protect the file. Refusal records deserve particular care, since they record what a person's agent attempted and was denied; access to them SHOULD be governed at least as strictly as access to admissions.

A witness or transparency service learns that a history existed and advanced at given times; the witness design exposes only genesis, rotations and head hashes, while registration of records exposes their content unless by hash, and even hash-only registration reveals cadence. Unsalted hashes of low-entropy names permit guessing. Public anchors reveal publication cadence, account and commitment metadata; the persistence tier makes the history public. Cross-history correlation is possible wherever an identifier recurs; deployments that need unlinkability SHOULD use pairwise identifiers and SHOULD avoid registering raw identifiers with a shared service. Selective disclosure cannot remove transitions needed for replay, and a redacted view must state which conclusions remain verifiable.

A PHL attestation profile should retain only minimal signed verification and vouching facts, keeping biometric templates and media out of the history and registry. Device identifiers and vouch graphs can still reveal identities and relationships; a digest is not anonymization, and hashes alone MUST NOT be described as anonymity. Optional proofs keep the public-statement and aggregate-release limits of {{selective-disclosure}}: computing an aggregate correctly does not establish unbiased enrollment, and a private lineage predicate does not establish physical humanity beyond its evidence policy. RFC 6973 {{RFC6973}} describes the correlation and identification threats that apply.

# IANA Considerations {#iana}

This document has no IANA actions. A future wire profile may register media types for exports and head statements, and COSE header parameters or CBOR Web Token (CWT) claims for the SCITT mapping; those registrations belong to the profile.

--- back

# Example encoding: an append-only JSON Lines history {#example}

This appendix is informative. It describes the "format 2" history of the IronTrellis implementation, to show that the model is implementable and to fix vocabulary. Format 2 was released with the first public release candidate; later rule changes are a new format, and format-2 histories keep their verdicts. Nothing here is normative for the model.

## Store, chain and state {#ex-chain}

A history is a UTF-8 file with one JSON object per line: a version literal, the previous record hash, the event `{id, type, timestamp, data}` with `data` canonically encoded (keys in UTF-8 byte order, integers only, amounts as decimal strings), and the line's own record hash:

~~~
recordHash(p) = SHA-256( "irontrellis-record/2" || 0x00 || prev
                         || SHA-256(canonical(event_p)) || be64(p) )
~~~

with `prev` thirty-two zero bytes at p = 0. The head is `{hash, position, canonicalTime}` and `recordHash(0)` identifies the history. After every event the state is a sorted set of closed records (event, genesis, owner key epoch, principal, agent, role, tenure, succession, session, authority, usage, nonce, intent, receipt, obligation, duty, anchor, witness binding and policy, budget, counterparty, refusal, effect, observation, reconciliation cursor); leaves are `SHA-256(0x00 || kind || 0x00 || key || 0x00 || SHA-256(canonical(record)))` sorted by (kind, key), and the root follows {{RFC6962}}'s recursion. A checkpoint at c commits to the state after c-1.

## Record kinds and signatures {#ex-kinds}

| Class | Types (42 in all, codes 0 to 40 and 42; code 41 is unassigned) | Signed by |
|---|---|---|
| Genesis | 1 | Unsigned; identity authenticated out of band |
| Control | Principal, agent, role, succession rule, appointment, unappointment, transfer, session admission, epoch advance, grant, revocation, termination, anchor, owner key rotation, witness binding and unbinding, budget declaration, update and close, state checkpoint, counterparty registration and retirement | Owner key(s) in force, over the control challenge |
| Session | Intent declaration, admission, consumption, outcome, receipt, refusal, effect, counterparty receipt wrapper, reconciliation observation | The admitted session's key |
| Administrative | Obligation creation, performance assignment, status change, outcome observation, attempt-duty creation, assignment and review, investigation activation, disposition, contest | A session, under an administrative authorization carrying its own authority proof |
{: #tab-exkinds title="Event classes in format 2"}

A control event carries `controlAuthorization = {keyId, signature}` over the SHA-256 of

~~~
{ "version": "irontrellis-control-authorization/2",
  "domain": <genesis domain>, "eventId", "eventType", "timestamp",
  "previousHead": {"hash": recordHash(p-1), "position": p-1},
  "effectHash": SHA-256(canonical(data without the authorization
                                      containers)) }
~~~

Owner key epochs are `[{fromPosition, keys, nextKeyDigests}]`; a rotation out of a committed epoch reveals a committed key with its proof of possession over the same challenge and commits again. Optional distinct-key policies add a global threshold, per-type thresholds, agent and human classes, pre-event quorum checks and a second authorization container excluded from the effect hash; a history without these fields replays unchanged. Session events carry `{runtimeSessionId, credentialKeyId, controlEpoch}` and a type-specific challenge; admissions sign the decision-time challenge of {{session-signature}}.

## Refusals, duties, export, witness {#ex-rest}

A refusal is `REQUEST_REFUSED` with `refusalSource` CORE, BUDGET or CONNECTOR, the request, `evaluationTime`, `expectedHistoryHead`, `decision`, `code`, optional `budgetId` or `connector: {connectorId, refusalCode, detailDigest}`, the session binding and `refusalAuthorization`. Replay re-runs CORE and BUDGET refusals and rejects the event with `REFUSAL_NOT_REPRODUCED` on any difference; a CONNECTOR refusal carries `CONNECTOR_REFUSED`. A handover is the operation `succeed`: `AGENT_TERMINATED` then `ROLE_TRANSFERRED`, sealed by a `STATE_CHECKPOINT`, with a report listing open duties, live grants each marked as not following, sessions, tenures and the SURVIVES answer.

The export view `irontrellis-export/2` carries the domain, genesis hash, heads, roots and counts at both ends of a range, every event with its hashes, checkpoints, optional full record sets, requested inclusion paths, every rotation at or before the end, held attestations and the complete earlier-body dependency closure. Type 42 `RECONCILIATION_OBSERVED` carries the observation fields of {{observations}} under the challenge `irontrellis-reconciliation-authorization/2`; its error order is schema, session and fence, reconciler binding, preceding head, match, duplicate or equivocation, uniqueness, capacity.

The witness protocol `irontrellis-witness/1` keeps per history a chain of statements `{version, historyId, domain, head, previous | null}`, accepted only if signed by a key in force at the head and `previous` is the witness's latest. Entries (`REGISTERED`, `HEAD`, `ROTATED`, `EQUIVOCATION`, `SUPERSEDED`) are leaves of an {{RFC6962}} tree with {{RFC9162}} proofs; checkpoints are signed notes; every latest-head answer is signed over a client nonce. The anchor statement for the public-chain tier, `irontrellis-anchor-statement/1`, has a frozen field list and canonical rule; its first vector (1,076 bytes, chain `eip155:42793`) has been reproduced independently.

# Implementation status {#status}

This appendix is informative, in the spirit of {{RFC7942}}, and reports documentary evidence as of 29 October 2026. It is not a certification of conformance. The IronTrellis implementation was released as open source on 29 October 2026, as the release candidate 1.0.0-rc.2 {{IRONTRELLIS-REPO}}. The release tag is signed with a hardware-held key, and the eleven npm packages built from it were published by the repository's release workflow with provenance statements linking each package to that build; the downloads, checksums and documents are listed with the release {{IRONTRELLIS-RELEASE}}. It connects to coding agents through hooks for Claude Code, OpenAI Codex CLI and Cursor, and to agent frameworks through shims for the OpenAI Agents SDK and LangGraph; the repository's quick start is the easiest way to try the model.

The implementation pairs this model with two operational documents. A commissioning disclosure {{IRONTRELLIS-DISCLOSURE}}, which every party commissioning an installation reads and signs, states each critical failure mode (time base, anchoring, witnesses, key custody, host compromise, unhooked paths, the limits of replay, federation, privacy and outages) in three parts: what can go wrong, what the implementation does about it, and what the installation itself must do. Where a duty could fall between the two, it is named on both sides, and protections the current release does not yet provide are marked as such. An install checklist {{IRONTRELLIS-CHECKLIST}} turns these duties into steps for a single experimenter and for an organisation, with an optional external review before commissioning. Both are informative; this document does not require them.

| Part of the model | Specified | Built | Independently checked | Machine-checked (see the next appendix) |
|---|---|---|---|---|
| Authority history, decisions, refusals, replay | Yes | Yes, TypeScript | Yes: an engine-free Python checker written from the text alone agrees with the engine on 446 of 460 checks of the regenerated suite (253 vectors) and on all 446 checks of three further suites, including the 86 frozen vectors; the other 14 checks exercise a later rule (the session time horizon) that the checker predates. It checks admission proofs for consistency and does not re-derive the decision procedure itself | Decision procedure, including revocation monotonicity at the stage before the final checks; admission accounting |
| Owner approval policies, attested floor, recovery, restoration | Yes | Yes | Yes: 89 owner-policy and 68 human-attestation vectors, 157 of 157 | Yes, two independent models |
| Duties, handover, investigation, continuation | Yes | Yes | Partly (within the suites above) | Export record machine; observation uniqueness |
| Reconciliation observations | Yes | Yes | 28 engine-derived vectors; independent batch pending | Uniqueness only |
| Witness protocol | Yes | Yes | Within the suites above | Anchor-verifier continuity (model) |
| Public-chain anchoring (tier 1), outbox, barrier | Yes | Outbox, barrier, finality verifier and raw-byte statement contract built and locally tested; live publication deferred (see below) | Statement vector reproduced; contract: 174 author and 428 independent checks | Anchor-verifier continuity |
| Persistence and on-chain execution (tiers 2 and 3) | Yes | Design and partial prototype; a predecessor project deployed its engine as a contract on a test network | No | Tier separation within anchor-verifier continuity (model) |
| Federated operation | Yes | No | No | Committee is not an owner; committee time rule |
| Zero-knowledge profiles | Yes | Experiment; seven demonstration proofs on synthetic histories are published with the release, see below | Yes for those seven: two separately built verifiers accepted them and refused tampered copies; whether the proved program implements this model is under review | No |
| PHL enrollment and lineage queries | Proposed | No | No | No |
{: #tab-status title="Implementation status"}

On 29 October 2026 the reference writer's test suite passed on a Linux host for the release commit: 1,810 tests, 1,797 passing, none failing, and 13 skipped because they need a secrets service, administrator rights or an earlier release build that the host did not provide. On the repository's hosted Linux runners the same suite passed under Node.js 22 and 24, and the published `irontrellis` package ran its demo on a clean host. The hosted macOS and Windows jobs did not pass for this release; Windows is not yet a supported platform. Running the suite on faster hosted runners before the release found a race in the coding-agent hook: two copies of the hook deciding the same call could refer it to the user instead of refusing it, because one read the clock before the other's refusal was recorded; the hook never allowed such a call on its own. It was fixed before the release tag, with regression tests. One engine defect, in the encoding of a succession record, was found by a separate conformance exercise; it has been fixed, with regression tests. The TypeScript verifier shares code with the writer and is not independent of it; the Python checker is advisory and is not a writer. In the one checker comparison that found disagreements, all seven were the checker lagging rulings already in force. No external cryptographic audit is claimed.

**Public-chain anchoring.** The release candidate does not itself verify chain anchors: its anchor check produces no report and lists chain inclusion and finality as missing evidence. Separate tools in its repository record histories on Etherlink Shadownet (chain 127823) under a test profile, and on 25 October 2026 they recorded a first worked history on Etherlink mainnet (chain 42793); those tools report finality in TRUSTED_NODE mode, from nodes the operator chose ({{tab-finality}}). Anchoring in CONSENSUS_VERIFIED mode, which needs an independently administered, validating Tezos node to confirm finality, is defined and partly vectored, and is not part of this release candidate; when it comes, it adds to these records rather than correcting them.

**Zero-knowledge proofs.** Seven zero-knowledge proofs are published with the release as a demonstration {{IRONTRELLIS-RELEASE}}, one for each of the seven synthetic workloads (revocation, three-period, count, cumulative, exhaustion, handover of both, handover of state). They were produced on 29 October 2026 with a pinned build of the implementation's segmented proof program, made on Linux, on synthetic histories; rebuilding that program byte for byte from published source is future work (below). The download holds the root proofs, the root verification key, the proof program with its configuration, and a small verifier that can be built from the public OpenVM source. Before publication, two verifiers built and run separately, one written independently against the published OpenVM library, accepted all seven and refused tampered copies, and the program's commitments and verification key were regenerated from the published program and configuration and matched. Each proof shows only that the program's checks passed for one small synthetic history, within the rules the program supports; the proofs are not production-qualified, whether the program implements this model faithfully is under review, and they establish neither authority, completeness nor freshness. A research experiment produced and verified Groth16/BN254 proofs of hidden principal-record membership under an actual format-2 state root (arkworks 0.5.0, single-party setup, eight-event fixture), with signatures and replay outside the circuit. In October 2026 an earlier edition of the implementation's segmented proof program was also proved on seven synthetic workloads; that program followed an earlier edition of the rules and could not be rebuilt byte for byte on Linux, so those proofs are not published. A larger proof run is in progress and has not yet completed.

# Formal verification: what was chosen, what it proves, what it does not {#formal}

This appendix is informative. IronTrellis does not model every path through the implementation; it chose the paths where a mistake would hurt most and wrote each as a model in Lean 4, stating properties the model must satisfy and letting the kernel check them. {{tab-lean}} lists each path, and {{IRONTRELLIS-LEAN}} explains the choices for a general reader. A selection of these proofs is published with the release {{IRONTRELLIS-LEAN-PROOFS}}: a self-contained Lean project of 32 source files and 15 headline theorems covering the decision procedure, revocation, owner keys and attestation, spending accounting, committees and anchoring, with each theorem's exact premises and the commands that rebuild them and print the axioms each one relies on. Every result listed passed under one gate: Lean 4.34.1 with core and Std only, no `sorry`, `admit`, `native_decide` or custom axioms, with `#print axioms` recorded for every theorem. The integrated edition of 17 October 2026 (186 modules, 2,048 theorems) was rebuilt from source on separate hardware with an independently installed Lean, and every theorem in it depends only on Lean's three standard axioms. A rebuild checks the proofs, not whether each model states the rules faithfully; that is reviewed separately. The models are being brought up to the current edition of the rules: the 17 October edition predates the optional session-time horizon ({{sessions}}), so its results hold for histories that set none.

| Path chosen | Why it was chosen | What is proved | Limits |
|---|---|---|---|
| The authority decision procedure ({{procedure}}) | Every ALLOW rests on it; delegation paths, intersections, prohibitions and caps interact | A model of path selection, attenuation, intersections, prohibitions and caps; the model and the engine agree on 120,000 generated cases. Revocation is monotone at the authority-verdict stage: revoking a permission never turns a request that was not allowed into one that is allowed, before the proof-size preflight. This is proved for the executable procedure model under a valid record set, when no unrevoked prohibition has the revoked permission in its ancestry (the revocation entries of {{tab-prtypes}}), and rebuilt independently; terminating an agent is proved likewise | A model of the rules, not the code; agreement on cases is evidence, not proof. Monotonicity of the final verdict is not claimed: the proof-size preflight can still differ ({{sec-rest}}) |
| Owner approval and the attested floor ({{owner-approval}}, {{human-attestation}}) | The owner's keys are the trust anchor; the rules for lapse, restoration and recovery are easy to get subtly wrong | Two independently written models prove: a one-signature floor, pre-event authority, commitment conservation, lapsed keys limited to power reduction, checkpoints and restoration, separation of owner, committed, attester, session and counterparty credentials, the single-signer time bound, and non-expansion of power-reducing records relative to five stated assumptions about the decision procedure, the first of which (revocation monotonicity) is itself proved for the procedure model (previous row) | Several results are assumption-relative; one of the two models still states the termination rule in its earlier, grantor-only form, which the procedure model proves in its current form; two liveness claims in the companion property list were found false and withdrawn |
| Admission accounting ({{admissions}}) | Shared ancestors on a path could be charged twice or not at all | Under immutable caps and one serialized order, every controlling authority is charged once per accepted admission and recorded usage never exceeds its cap; rejection atomicity, admission-time epoch fencing and the capacity census are proved alongside | Budgets have only a conditional bound |
| A committee is not an owner ({{federated-operators}}) | Federation must never turn a committee into the principal | A committee co-signing key is never sufficient alone, never counts on a rotation or policy change, can never block a power reduction, can always be rotated out by the human-class holders, and is never human under the attested floor without a statement | Rotation out assumes the human-class holders still exist and can sign, and that an attester named in the policy issues their renewal statements |
| Checkpoint availability under committee loss | A counterexample was found | The counterexample is accepted: a policy requiring the committee for checkpoints blocks them until a rotation; the rule's wording was corrected | A wording result, not a replay change |
| Anchor-verifier continuity ({{external-anchoring}}) | A public anchor is only as good as the rule that accepts it | Accepted heads always form a prefix chain, so the modelled verifier never accepts a rollback or fork; a strictly increasing sequence number with valid linkage is not sufficient without the prefix check (counterexample given); two statements for one predecessor are always detected; a wrapper requiring both a certificate and replay acceptance never admits what replay refuses nor refuses what replay admits on certificate grounds | Chain finality and availability are outside the model |
| Committee time and the attested floor | Time is the writers' claim; the vote rule and the time bound must compose | The vote rule composes with the attested-floor bound; a history violating the vote rule replays identically, so the rule is evidence, not replay; committed timestamps are bounded under an honest-quorum hypothesis | The hypothesis is stated, not discharged |
| Renewal, restoration and removal under the attested floor (ongoing) | The largest remaining surface of the owner rules | Several hundred typed-model statements across the renewal, restoration, selective removal and reachable-successor cases, kernel-checked, and rebuilt independently as part of the 17 October edition | Restoration and removal results assume that an attester named in the policy issues the renewal statements; no native-signature or replay-correspondence result |
{: #tab-lean title="Proof paths chosen, and their limits"}

**What the proofs caught.** A signed twelve-event history in which revoking a grant turned a clear DENY into an ALLOW, because the engine checked a cumulative cap after choosing a path; the rule was moved. A single-signature termination of an agent in the middle of a delegation chain that would have silently switched off a prohibition depending on it; the rule was tightened. A null-expiry session from a migrated prefix that could still attest a duty finding; the rule now expires it. Two liveness promises of the "you can always do X" kind that were false in edge cases, such as a policy where one key is enough.

**What they do not show.** The proofs are about models of the rules, not the TypeScript that runs; the two are connected by testing on large case sets, which is strong evidence, not proof. Cryptography is assumed: signatures cannot be forged and hashes do not collide. A proof shows exactly the statement written down. Some results hold only under named assumptions, and each is listed. Nothing shows that a person meant to approve something or that a report from the world is true. The largest open piece is a proof that replaying any history always rebuilds exactly the same state.

**Where this is going.** Each rule change is followed by re-checking the proofs it touches. The selection published with the release rebuilds with two commands, so that a reader can rerun it rather than take this appendix's word; the full editions, a claims ledger naming every theorem with its assumptions and exclusions, the counterexamples that changed rules, and the scripts that compare the models with the engine are to follow in the same way. The zero-knowledge demonstration of {{status}} is to be completed the same way: the source of the proof program with a pinned recipe for rebuilding it, the EVM verifier contract and its proof, and the questions and results for each synthetic history.

# Relation to other work {#related}

**Signed Permissions and Action Receipts** ({{I-D.izmaylov-agent-permission-receipts}}, revision -01) specifies passkey permissions, attenuating delegation, signed action receipts, acknowledged cancellation and signed tree heads, and maps its records onto the AUDIT architecture's record types; its verifier separates malformed evidence from sound records reporting actions outside permission, whereas this model rejects admissions that do not reproduce ALLOW. Replayed actor, session and epoch state, role tenures and surviving duties are not specified there. Neither design proves complete execution history from agent-generated records alone.

**AUDIT** ({{I-D.kuehlewind-audit-architecture}}, revision -01) organizes cross-domain record generation, audit context and auditing services, including delegation and authorization transition records, and keeps real-time enforcement outside its post-hoc scope. This document supplies a proposed state-transition component; duties and reconciliation are proposals for discussion, not adopted work items.

**OAuth and WIMSE.** Token exchange {{RFC8693}} and transaction tokens {{I-D.ietf-oauth-transaction-tokens}} carry delegation inside tokens for a request; the WIMSE architecture {{I-D.ietf-wimse-arch}} gives workloads identifiers and short-lived credentials. A session admission can bind a WIMSE credential's key, a grant can be the authority behind a token issuance, and a token's claims can reference the grant identifier; the record of authority is the history, the token a derived credential whose issuance and revocation can themselves be recorded.

**RATS** {{RFC9334}} can establish properties of the environment that produced a record; this model carries evidence references for that purpose and does not define attestation.

**Human delegation provenance** ({{I-D.helixar-hdp-agentic-delegation}}) describes session-bound human authorization and a signed delegation chain with optional proof-of-humanity credentials. Overlapping concerns do not imply wire interoperability or identical assurance.

# SCITT mapping {#scitt}

This mapping is informative. Registering IronTrellis signatures does not automatically create SCITT Signed Statements or Receipts. A future profile could wrap an owner head attestation, export digest, control record or session claim in a newly signed COSE_Sign1 statement {{RFC9052}}, defining payload canonicalization, issuer identity and key discovery; reusing a raw signature as a COSE signature is invalid because the signing inputs differ. SCITT requires protected `iss` and `sub` claims on statements and Receipts {{RFC9943}} {{RFC9942}}; a profile could scope the subject to a history identity. The witness evidence of {{rollback}} is analogous but has no compliant COSE mapping. Registration does not establish statement truth or issuer completeness, and submitted-head chaining cannot detect an unsubmitted suffix.

# Worked model example {#worked}

This informative sequence is illustrative, not a conformance fixture.

1. An authenticated owner creates two agents and an exclusive purchasing role, admits their sessions, and declares a succession rule. Only the current agent receives a bounded purchasing grant.
2. A purchase is admitted under the current head. A separately signed counterparty report is recorded. An uncertain submission preserves its original identity and allowance; the replacement may observe its result but does not dispatch it again.
3. A request exceeding a grant or budget produces a reproduced refusal. A supplied provider event is separately recorded as MATCHED or UNMATCHED; matching the refusal does not authorize the reported call.
4. An investigation duty remains attached to the role. Handover terminates the predecessor, transfers the tenure and reports surviving work and non-transferring grants. The successor needs fresh authority for performance assignment, resource restoration and disposition.
5. A prospective policy permits a purpose-bound finding and authorized disposition. A contest remains visible. Segmented continuation preserves the same genesis, usage, pending identity and duties.
6. An auditor authenticates the intended history and export boundaries, replays the range with its dependencies, and reports authority, claims, inclusion, freshness and outcome assurance separately. An optional hidden-record proof establishes only its pinned predicate.

# Acknowledgments {#ack}
{:numbered="false"}

The model draws on the IronTrellis design and its predecessor and the cited AUDIT proposals. The author thanks the AUDIT BoF proponents for the problem statement and the author of {{I-D.izmaylov-agent-permission-receipts}} for a clear prior design against which to state the differences.
