# Principles

IronTrellis (formerly Continuity) keeps a signed, replayable history of who may act for whom, and of which duties survive when an AI agent is replaced. This page sets out the ideas behind that design: what each one means in practice, and where it stops. The principles guide the product. A change to behavior still needs an [RFC](RFC.md), a reviewed implementation and evidence.

## A short example

The demo that comes with the CLI plays this story into a real history:

1. The owner appoints an agent, bea, to the role `reviewer`, and grants it the right to read and collect on `incident:42`.
2. A read of `incident:42` by bea is ALLOW. Then bea records a duty, `duty:42`: review the collected material.
3. The owner replaces bea with alex through a handover: bea is terminated, and the role passes to alex in a new tenure.
4. Under an assignment the owner authorized, alex's session takes `duty:42` over.

| Afterwards, ask | The history answers |
|---|---|
| Why was bea allowed to read `incident:42`? | WHY traces the grant behind that decision, at the head where it was made. That record doesn't change. |
| Can bea act now? | No. A new request by bea is DENY, because bea is terminated. |
| Did bea's grant pass to alex? | No. The handover report marks it as not following. |
| Is `duty:42` still owed? | Yes. It survived the handover, and alex performs it under a recorded assignment. |

Anyone holding the history and the owner's published keys can replay it and check every one of these answers. To watch it happen, run `node packages/cli/bin/irontrellis.mjs demo` in a built checkout. Each answer follows from one of the principles below.

## Separate the actor from the office

Five things that are easy to blur are kept as separate records:

| Record | What it is |
|---|---|
| Principal | The owner of the history, and the root of its grants |
| Agent | A durable identity that can hold grants, occupy roles and owe duties |
| Runtime session | One admitted running instance, with its own key, control epoch and expiry |
| Role tenure | One agent's numbered term in an office |
| Grant | A permission, with a grantor, a grantee and limits |

Replacing a process need not erase an office or its obligations. A session's key and control epoch identify one admitted runtime. If bea's running process misbehaved, the owner could advance bea's control epoch. That session would be fenced, and a request through it would get DENY (`SESSION_FENCED`), while bea, the role, the grant and the duty stayed as they were.

## Separate powers from unfinished work

Succession records how a role passes and which duties survive. A successor needs its own session and fresh authority: a surviving duty never silently carries over the predecessor's keys or grants.

Read the handover report and each duty's current status. Don't treat a termination as the work being done. The exact transition and recovery rules are in the [history format](HISTORY-FORMAT.md) and the [API guide](API.md).

## Models propose; signed rules decide

A model can interpret a request and propose an action. It can't create authority by describing its intent. Replay and authorization evaluate the captured inputs under the selected rules, and every answer keeps its evidence and its uncertainty:

| Answer | Meaning |
|---|---|
| ALLOW | Permission established, with a proof |
| DENY | Refused by the current rules, with a code and evidence |
| INDETERMINATE | Can't be decided from the evidence. It is never permission to proceed. |

The evaluation time, and the head of the history that the answer must concern, have to be explicit at the interface that asks.

The rules of a released format don't drift. Format 2 is released with the first public publication of 1.0.0-rc.2. From then on, a later version reads a format-2 history exactly as 1.0.0-rc.2 does, or refuses it, so the history keeps its verdicts. Fixes to the rules come as a new format.

Conformance suites and independent checks give bounded evidence about implementations; they don't establish that every implementation agrees on every format. The packaged Python verifier covers legacy and format-1 histories. The separate format-2 checker and the selected Lean model proofs each have their own stated scope.

## Plan for expiry, revocation and replacement

- Grants and sessions have lifetimes. Duties can stay open after a runtime is gone.
- An unknown external outcome stays unknown until supported evidence resolves it. Retrying with a new business identifier can make the same effect happen twice.
- Control operations, physical storage limits and owner-policy requirements have to be understood together. A promise in software to accept a revocation can't make a full disk writable.

## Keep human governance explicit

Prefer bounded delegation, separate credentials, recoverable key custody and evidence a person can inspect.

- Owner approval policies set thresholds per type of change, and allow a lower threshold only for an event that really reduces power.
- The PHL, Proof of Human Lineage, attestation policy states which human-lineage evidence a history accepts, including how that evidence lapses and is restored. It is not a general test of humanity.
- RESPONSIBLE describes the supplied records. It is not a legal judgment.

Privacy needs deliberate choices about what to keep and what to disclose: an authenticated history can still contain sensitive data. External policy engines, witnesses and cooperating services each add their own checks and trust boundaries; none of them replaces replay.

## What ships today, and what doesn't

1.0.0-rc.2 supplies these signed-history primitives and policy rules. Autonomous institutions, agent estates, public-benefit arrangements and wider chain capabilities need designs, and deployment evidence, of their own. The founding Constitution, Continuity's original statement of vision, is historical context: it adds no runtime policy, and it doesn't claim that those future systems ship today. [Security](SECURITY.md) records what the current mechanisms don't establish.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
