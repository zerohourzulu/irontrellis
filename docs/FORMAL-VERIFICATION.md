# Why we check IronTrellis with Lean

*RAmEx Labs · October 2026*

---

IronTrellis (formerly Continuity) keeps a signed, tamper-evident history of what AI agents are allowed to do: who granted an agent authority, what it was permitted to do, what was refused, and what was later taken away. Anyone holding the history and the owner's published keys can replay it and get the same answer to "was this action allowed?" That answer has to be right every time, because people will rely on it to keep agents in check.

## The problem

The input is a history and a request, and the output is allow, deny, or "can't decide". In between, authority can reach an agent along several delegation paths, with prohibitions, budgets and required co-approvals applied along the way. Revoking one grant can quietly change which path wins, so the obvious promise, "revoking something never gives anyone more power", needs real checking. Owners can require two of three keys for big changes but one key for emergency changes that only reduce power, so "reduces power" has to be defined exactly. Under an attested policy, a key counts as a human's only while an attester vouches for it, and what still works when that vouching lapses is easy to get wrong.

## What Lean caught

Lean is a proof assistant: you write the rules down as a precise model, state what should always hold, and a small trusted checker confirms or refuses each proof. Writing a proof forces every case into the open; the cases that won't go through are the bugs. One finding was a signed, 12-event history in which revoking a grant turned a clear *deny* into an *allow*: the engine checked a spending limit too late, after it had already picked a path. Another: terminating an agent in the middle of a delegation chain, with a single signature, could silently switch off a prohibition that depended on that chain, so the rule was tightened. A third: two promises of the "you can always do X" kind were false in edge cases, and were withdrawn before anyone relied on them.

After the first finding was fixed, we went back and proved the core of the promise: in the model of the decision procedure, revoking a permission never widens the permissions still in force, at the stage where the model works them out. The final answer comes after further checks, and the proof does not yet cover those, so it does not yet show that a "no" can never become a "yes".

## What we checked, and what we didn't

We have not modeled every path through IronTrellis; we chose the ones where a mistake would hurt most.

The table lists only what the theorems published with this release show.

| What we checked | What the published theorems show | What they do not cover |
|---|---|---|
| The allow/deny decision | An "allow" passes the path checks and the modeled failure checks, every required co-approver is present, and the fixed search limit is enough, given a valid history and a validated path. Revoking a permission never widens the permissions still in force (proved for the stage before the final checks). Model and engine agree on 120,000 generated cases. | Agreement with the code is tested, not proved. The revocation proof stops before the final checks, so it does not show that the final answer can never flip from no to yes. |
| Owner keys and human vouching | Accepted changes to the owner's keys use distinct keys and credentials and meet the required quorum. A valid attestation is bound to its audience, subject, attester, validity period and place in the history. | Signatures are abstract in the model: nothing here proves a signature secure or an attester human |
| Spending limits | With a fixed registry, the accounting preserves the cap-safety property it starts with and rebuilds both usage ledgers exactly from the accepted events, revocations included. | Assumes a fixed registry and a safe starting state |
| Committees | The committee's credential cannot authorize anything alone and does not count toward a key rotation; under an attested policy, classifying a key as a human's requires a valid attestation. | Holds in the stated committee profile; how committees are formed or kept available is not proved |
| Blockchain anchoring | The anchor checker refuses a fork of the history it has seen and a head that moves backward; runs from an empty start only accept histories that extend one another. | Rests on a stated premise about the earlier anchor; says nothing about whether the chain itself is final or online |

The full editions behind this selection hold more results, for example about committee timestamps and renewing vouching. They are not part of this release's published selection, so we don't claim them here.

We also had the proofs checked from scratch by someone other than their author. The October 17 edition, 2,048 theorems in all, was rebuilt on a separate Linux virtual machine with an independently installed copy of Lean, and every theorem depends only on Lean's three standard axioms; the revocation proof was rebuilt the same way after it was added. The retained records do not establish separate physical hardware, and this was not an external security review. A rebuild shows that Lean's checker accepts the proofs. Whether each model states the rules faithfully is a separate question, which we answer with reviews, not proofs.

As IronTrellis grows we add rows, and when a rule changes we re-check the proofs it touches. We think checked models like these will become a normal part of programming, and we want to help bring that future sooner.

## The honest limits

Our proofs are about a model of the rules, not the TypeScript code that runs; testing the two against each other is strong evidence, not proof. The models follow the rules as they stood in mid-October and are being brought up to date: the optional limit on how far agents can move a history's clock, for example, is not yet modeled, so those results hold for histories that do not use it. We assume the cryptography works: signatures can't be forged and hashes don't collide. A proof shows exactly the statement written down, so if we state the wrong property, Lean will happily prove the wrong thing. Nothing here can show that a person truly meant to approve something, or that a report from the outside world is true. Some of our checks cover large but finite sets of cases rather than all possible inputs. And the biggest open piece is still open: a proof that replaying any history always rebuilds exactly the same state.

## See for yourself

With this release we publish a selection of the proofs in `verification/SelectLeanProofs/`: the Lean sources of the theorems in the table above, with their exact premises, and the commands to rebuild them and print the axioms each one relies on. The full editions, the counterexamples that changed our rules and the scripts that compare the model with the engine are not yet published. Don't take our word for it. Run it, read the claims, and tell us what we missed.

*Last reviewed: 27 October 2026. This is a living document: it grows as the proofs grow.*
