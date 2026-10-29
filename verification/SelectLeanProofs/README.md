# Selected Lean proofs

*RAmEx Labs, 2026-10-27. The machine-checked proofs published with 1.0.0-rc.2.*

This folder holds a small, self-contained Lean project: 32 source files and 15 headline theorems, chosen from larger checked editions because they cover the parts of IronTrellis where a mistake would hurt most. It uses Lean 4.34.1 and its core and Std libraries, without Mathlib or other external packages. For why we use Lean at all, see [Why we check IronTrellis with Lean](../../docs/FORMAL-VERIFICATION.md).

Every theorem here is about a **model** of the rules, written in Lean, and not about the TypeScript code that runs. We connect the model and the code by testing them against each other, which is strong evidence, not proof.

## What is proved

| Topic | What the theorems say, in the model | Theorems |
|---|---|---|
| The allow/deny decision | An "allow" passes the path checks and the modeled failure checks; every required co-approver is present; and the fixed search limit is enough, given a valid history and a validated path. | `Authority.authorizeState_soundness`, `Authority.authorizeState_every_required_partner`, `Authority.selectGraph_fuel_sufficient` |
| Revocation | Revoking a permission cannot create a new "allow" at the stage before the final checks: an allow after the revocation implies an allow before it. | `Authority.G65.revocation_algebra_nonexpansion`, `Authority.G65.revised_allow_revocation_nonexpansion` |
| Owner keys and attestation | Accepted control events use distinct keys and credentials and meet the required quorum. A valid attestation is bound to its audience, subject, attester, validity period and place in the history. | `IronTrellis.I06_distinct`, `IronTrellis.I07_quorum`, `IronTrellis.I18_attestation_binding` |
| Spending accounting | With a fixed registry, the accounting preserves the cap-safety property it starts with and rebuilds both usage ledgers exactly from the accepted events, revocations included. | `Faithful.aggregate_with_revocations` |
| Committees | In the stated committee profile, the committee's credential cannot authorize anything alone and does not count toward a key rotation; under an attested policy, classifying a key as a human's requires a valid attestation. | `Committee.human_requires_statement`, `Committee.committee_never_alone`, `Committee.committee_never_counts_rotation` |
| Blockchain anchoring | Under its stated premises, the anchor checker refuses a history that forks from the one it has seen and a head that moves backward. Runs from an empty start only ever accept histories that extend one another. | `Anchor.fork_refused`, `Anchor.rollback_refused`, `Anchor.no_fork_after_run` |

Each theorem has exact premises; read them in the source before relying on a sentence in this table.

## Check it yourself

You need Lean 4.34.1, the version named in `lean-toolchain`. The project has no other dependencies. From this folder:

```
lake build
lake env lean AxiomQuery.lean
```

The first command checks all 32 source files; it should finish with no errors. The second prints each of the 15 theorems with the axioms it depends on. Each should list only Lean's three standard axioms (`propext`, `Classical.choice`, `Quot.sound`) or a subset of them: `Committee.human_requires_statement` uses only `propext`, and `Committee.committee_never_alone` uses `propext` and `Quot.sound`. If any theorem lists `sorryAx` or another axiom, the proof is incomplete or relies on an assumption, and we'd like to hear about it.

## Who checked it

The editions these files come from were rebuilt independently, by an agent other than the proofs' author, on a separate Linux virtual machine with an independently installed copy of Lean. The retained records do not establish separate physical hardware, and this was not an external security review. This selected project was then built from clean on its own on 27 October 2026, on a Linux virtual machine, with Lean 4.34.1 and no other libraries, and its axiom output matched the earlier independent records for all 15 theorems. That build was made by the agent that assembled the project.

## Limits

- **Not the final answer for revocation.** The revocation theorems stop before the final checks, which can still change the outcome. They do not show that a final "no" can never become a "yes".
- **A model, not the code.** Nothing here proves that the TypeScript engine, or any deployed system, matches the model in every case.
- **No cryptography or biology.** Signatures and credentials are abstract fields in the model. Nothing here proves that a signature is secure, that a hardware key was used, or that an attester is a human.
- **Not everything.** Many parts of IronTrellis have no model here, and some committee properties (construction, availability) are not proved.

For everything else that was done to check IronTrellis, see [How IronTrellis was tested](../../docs/TESTING.md).
