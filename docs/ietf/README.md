# IronTrellis at the IETF

*RAmEx Labs · 29 October 2026*

The model behind IronTrellis is written up as an **Internet-Draft**: a public proposal to the [Internet Engineering Task Force (IETF)](https://www.ietf.org/), the open standards body that develops many of the Internet's core protocols. An Internet-Draft is a working document that anyone can read and comment on. It isn't a standard, and posting one implies no endorsement.

| | |
|---|---|
| Title | *Replayable Authority Histories for Auditing Automated Agents* |
| Name | `draft-rampertab-audit-agent-authority-history-00` |
| Posted | 29 October 2026, as an individual submission, intended status Informational |
| Read it | [The draft on the IETF Datatracker](https://datatracker.ietf.org/doc/draft-rampertab-audit-agent-authority-history/), the authoritative copy, with the current revision and its history |
| Discuss it | The [AUDIT mailing list](https://mailman3.ietf.org/mailman3/lists/audit.ietf.org/), audit@ietf.org ([archive](https://mailarchive.ietf.org/arch/browse/audit/)) |

## What the draft proposes

An authority history is an append-only, signed record of who granted what to whom, which agent actions were admitted, which requests were refused, and which unfinished duties survive when one agent replaces another. A verifier who holds the owner's keys can replay the history and recompute each recorded decision, without trusting the agent or its operator. The draft also states what such a verifier cannot establish.

It is offered to the IETF's **AUDIT** effort (Agent Use of Delegation and Interaction Traceability). AUDIT is a proposal for a future working group, discussed on the mailing list above; it isn't a working group yet, and nothing has been adopted. Section 1.6 of the draft asks four questions on which the author would welcome views.

## What is in this folder

| File | What it is |
|---|---|
| `draft-rampertab-audit-agent-authority-history-00.md` | The source, in [kramdown-rfc](https://github.com/cabo/kramdown-rfc) Markdown |
| `draft-rampertab-audit-agent-authority-history-00.xml` | The XML exactly as submitted; it is byte-for-byte the file the IETF archive serves |

The Datatracker copy is authoritative. Later revisions (`-01` and on) are posted there first and copied here.

## How the draft relates to this repository

The draft describes the model; this repository is one open-source implementation of it. The draft's appendices report what was built and independently checked as of the release candidate 1.0.0-rc.2, and which parts of the model were machine-checked in Lean ([the published Lean proofs](../../verification/SelectLeanProofs/)).
