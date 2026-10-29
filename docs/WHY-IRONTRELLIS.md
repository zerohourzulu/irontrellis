# Why IronTrellis™, Why Now, What is the Long Horizon

*RAmEx Labs · October 2026*

---

IronTrellis (formerly Continuity) is an open record of authority for AI agents. When software acts for people, buying, signing, paying, or handing work to other software, IronTrellis keeps a signed history of who allowed it, within what limits, what was refused, and what was left unfinished. Anyone holding that history, and the owner's published keys, can replay it and reach the same answer to the question "was this allowed?", without having to trust the agent or the company that runs it. This essay explains why we built it, why we think the moment is now, and where we believe it leads.

# Why IronTrellis

## An agent buys something, then disappears

Alice wants one plush toy, a Cheshire Cat, and she is happy to spend up to $25 within the next week. She does not want to shop for it herself, so she gives the job to a purchasing agent, which we will call Mr. Hatter. Mr. Hatter may ask a research agent, White Rabbit, to compare sellers, but White Rabbit may only research. It may not pay.

White Rabbit finds the toy for $19.99. Along the way it tries to pay a $5 deposit to hold one, and the attempt is refused: five dollars is less than twenty-five, but the question was never the amount. White Rabbit was given permission to look, not to spend. Mr. Hatter then buys the toy. The payment goes through. And then, before the parcel arrives, Mr. Hatter's software crashes and is not restarted.

Nothing dramatic has happened. But a set of plain questions now has no obvious owner. Someone has to check that the parcel arrives, or ask for a refund if it doesn't. Was Mr. Hatter actually allowed to make that purchase, at that price, on that day? Who told him to? Was the refused deposit a bug, or the system working? Who is now responsible for the unfinished part of the job, and what power, if any, do they have to finish it?

The software that could have answered is gone. Its logs, if they exist, sit on a machine run by someone else, and whoever runs that machine can edit them. The questions do not disappear when the process does. They become harder to answer at exactly the moment someone needs the answer.

IronTrellis begins with this ordinary problem. Software can now act quickly and leave consequences that last far longer than the program that caused them. We want those consequences to have a record that people can read, check, and use to finish the work.

## People solved this once, for themselves

Human beings are temporary, and we built a world that is not. A person can resign, retire, or die, and still the company continues, the office is filled by someone else, the contract is honoured, the debt is paid, and the estate is settled. Authority can be delegated and taken back. Powers can be limited. Records outlive the people who wrote them. A dispute can trace who did what, and on whose say-so.

None of this is technology in the usual sense. It is centuries of practice: offices that are separate from the people who hold them, signatures, ledgers, successors, the idea that a power has to come from somewhere. These practices are what let short-lived individuals create long-lived institutions.

Software agents have almost none of this by default. An agent can be started in seconds, copied, renamed, moved to a new model, handed a payment card or a password, allowed to start other agents, and switched off without anyone taking over its work. Each of these is useful. Together they produce a fog: lots of activity, and very little that can later be explained.

IronTrellis tries to give agents a small, precise version of the structure that people already rely on.

## Power has a history

A cryptographic key proves that someone controls a credential. It does not prove that they were allowed to use it for this. Mr. Hatter's payment card could buy almost anything; Alice's instruction allowed one toy, under $25, this week. The gap between what a credential *can* do and what its holder *may* do is where most of the trouble lives.

IronTrellis records that gap. Every grant of power is an entry in a signed, append-only history: who granted it, to whom, for what, with which limits, and on whose earlier authority. When an agent acts, the history shows the path the power took to reach it, and every step on that path has to be valid at that moment. A few rules follow, and each one is there because its absence causes real harm:

- **Power can be narrowed, never widened, as it is passed on.** Mr. Hatter can give White Rabbit research rights, but he cannot give away more than he holds, and he cannot turn his spending limit into a shared wallet. Creating ten helpers does not multiply a budget by ten.
- **A prohibition is not defeated by another permission.** It applies to everything that descends from the same original grant, and an owner can make one apply everywhere. If finance approves the amount and security forbids the supplier, the purchase is refused.
- **Taking power back works through the whole chain.** When a grant is revoked, everything that rested only on it ends too, while a separate valid path is still judged on its own terms.
- **Refusals are records, not silence.** The refused $5 deposit is written down with the reason. A clear "no" shows where the boundary is while the work is still happening, which is when it is most useful.

## Three questions

The purpose of IronTrellis fits in three questions that people already ask about each other:

| Question | What the history can answer | What it does not settle |
|---|---|---|
| Why was this allowed? | The path from the original grant to the action, the limits on each step, and the state of the history when it was checked. The same holds for a refusal. | Whether the purchase was wise, whether the seller told the truth, or what the agent "intended" |
| Who is responsible? | Separate, named roles: who instructed, who acted, who approved, who controlled the running software, who owes the unfinished work | Legal liability or moral blame. A path through a record is evidence, not a verdict |
| What survives if this actor disappears? | Open duties, roles that continue, authority that ends with the agent, and anything handed on by an explicit, signed decision | Promises nobody recorded, lost private files, or events in the outside world that nobody observed |

The right-hand column matters as much as the middle one. A system earns trust when it says plainly what it checked and what it did not. "Allowed at this point in the record" and "allowed right now" are different claims, and IronTrellis keeps them apart. Evidence that is missing, stale, or disputed stays marked as such; it is never quietly rounded to a convenient yes or no.

## Duties outlive the actor

When Mr. Hatter bought the toy, he created a small obligation: make sure it arrives, or get Alice her money back. In IronTrellis that duty belongs to the purchasing *role*, not to Mr. Hatter's running program. This is the old distinction between the person and the office. The office stays when the person leaves.

So when Mr. Hatter's software dies, the duty is still there, still open, still pointing at the same order. Alice can appoint a successor, Dormouse, to finish it. But a duty never carries power with it by accident. Assigning Dormouse to chase the refund does not hand Dormouse a purchasing budget; any power Dormouse needs to finish the job has to be granted separately and has its own limits. If the power is missing, that gap is reported, rather than invented because finishing the task seemed like a good idea.

Ordinary language blurs things that IronTrellis keeps distinct: restarting the software, changing who controls it, ending an agent's authority, and appointing someone else. Each is a different decision, made by someone, for a reason. Treating them all as "a restart" would hide decisions from the people whose money and work are affected.

## Recovery starts with knowing what changed

Failures are rarely clean. A program can stop answering and still be running. A network can split two healthy machines. A supervisor can take over, and then the old instance comes back.

IronTrellis gives each takeover a numbered generation. Once a new generation is recorded, any system that checks the history will reject consequential requests from the old one, even if the old software can still produce a perfectly valid signature. It cannot stop the old program from running; it makes the old program's requests refusable wherever the rules are enforced.

It also refuses to guess. Suppose the seller accepted Mr. Hatter's order, but the confirmation never arrived. A replacement that assumes failure might buy a second toy; one that assumes success might hide the problem. IronTrellis gives the purchase a lasting identity, so a retry can be recognized as the same intent and checked, and an unknown outcome stays visibly unknown until there is evidence. Recovery succeeds when the next actor can tell what it knows from what it still has to find out.

## Trusting neither the agent nor the operator

The point of an audit is to check the party being audited. If the only evidence is a log kept by that party, the audit is a conversation with the suspect.

An IronTrellis history is built so that an outsider can check it alone. The owner of an account publishes keys through a channel the operator does not control. Every entry is signed and linked to the one before it, so removing or reordering entries breaks the chain. A verifier who has the history and the owner's keys can replay it from the start and recompute every recorded decision: each "allowed", each "refused" by the rules themselves, each open duty. If the operator altered the record, the replay disagrees.

One weakness remains: an operator could hide the newest entries and present an older, shorter history as if it were complete. To close that gap, IronTrellis can *anchor* the history, which means publishing a small fingerprint of the latest entry somewhere the operator cannot quietly rewrite. The anchoring point can be local or public, and the trade-offs are worth seeing side by side:

| Anchoring point | What it protects against | What it costs or leaves open |
|---|---|---|
| A local anchor log kept beside the history | Accidental damage and casual tampering | Still under the operator's control |
| An independent witness that co-signs each head | An operator showing different histories to different people | Depends on the witness staying honest and available |
| A public blockchain | Anyone, including the operator, quietly rewriting or truncating the past | Fees, delay until the chain's own finality, and the chain's own assumptions |

By default, only fingerprints go on a public chain. Prompts, personal data, contracts, private memory and secrets do not belong in a permanent public record, and a fingerprint is not automatically a privacy shield either: timing, amounts and who-dealt-with-whom can reveal a great deal. So privacy is part of every choice about what to publish, from the start.

## What a record cannot show

We would rather say this clearly than have a reader discover it. A history of authority shows what was recorded and whether the recorded rules were followed. It cannot show that every action passed through the checkpoint: an agent with a raw vendor password might go around it, which is why each deployment has to say what is enforced and what is merely observed. It cannot prove who a person really is, or that a parcel really arrived. A timestamp is the writer's claim, not a trusted clock. And an AI model's eloquent explanation is never treated as proof: decisions come from deterministic rules and signatures, which anyone can recompute.

These limits do not make the record weak. They make it usable, because a person relying on it knows exactly where its answers stop.

# Why Now

## Agents are learning to act

For most of their short history, AI systems talked. Now they act. They call services, fill in forms, move money, sign up for things, and increasingly start and instruct other agents. The step from "talk" to "act" changes the question people need answered. When a system only advised you, you could check its advice. When it acts, you need to know afterwards what it was allowed to do, and that need grows with the amount of money and responsibility that flows through software.

## The pieces around the gap are arriving

The good news is that serious people are building the surrounding infrastructure. There are emerging standards for agent identity, for signed mandates that capture what a user asked for, for machine-to-machine payment, for agent commerce, and for passing narrowed capabilities from one service to another. Each answers a real question: who is this, how does value move, what was requested, what was granted.

IronTrellis does not compete with these. It asks a different question that sits between them: how did this authority change over time, what did its use commit someone to, and what happens next? Identity, payments and mandates each describe a moment. IronTrellis is about the sequence of moments, and about what remains when the actor is gone.

## Auditors are asking the same question

In 2026 the Internet Engineering Task Force, the body that maintains many of the Internet's core protocols, approved a working session on auditing the actions of automated agents. Its proposal names the need to establish "how permissions evolved during execution." That is almost word for word the problem IronTrellis was built to solve.

We are submitting IronTrellis's model to the IETF as an individual Internet-Draft, *Replayable Authority Histories for Auditing Automated Agents*. A draft is an invitation, not an endorsement: it puts the idea where the people who build the Internet's plumbing can examine it, argue with it, and improve it. Even if it never becomes a standard, it may bring the right eyes to a problem that will not wait.

## Conventions harden early

There is a moment, early in the life of any infrastructure, when the conventions are still soft. Later they harden into whatever happened to ship first. Our founding vision put the risk this way:

> The infrastructure deciding how authority, responsibility and benefit flow through such systems should not be invented accidentally by a handful of closed platforms after autonomous agents become economically indispensable.

If the record of who allowed what lives inside one company's servers, then that company decides what the record says, who may read it, and whether it survives the company. We think the record should be open, inspectable, portable, and difficult for any single intermediary to rewrite. That is far easier to establish now than to retrofit later.

## The tools are ready, and we have used them

Two kinds of tools have become practical at the same time as agents, and we have used both seriously.

**Machine-checked proofs.** A proof assistant called Lean lets us write the rules down as a precise model, state what must always hold, and have a small trusted checker confirm or refuse each proof. We did not model all of IronTrellis; we chose the paths where a mistake would hurt most: the allow-or-deny decision, the rules for changing an owner's keys, spending limits, committees, and blockchain anchoring. The proofs paid for themselves. One found a signed twelve-event history in which revoking a grant turned a clear "deny" into an "allow", because a spending limit was checked too late; the rule was fixed. Since then we have proved, for that model, that revoking a permission never widens the permissions still in force, at the stage where the model works them out. That is not yet a proof about the final answer: the checks that run after that stage are outside it. The proofs are about a model of the rules rather than the running code; we connect the two by testing them against each other (120,000 generated cases for the decision rule alone), which is strong evidence, not proof.

**Zero-knowledge proofs.** These let a computer prove that it ran a program correctly without anyone having to re-run it. We have made such proofs internally for seven authority workloads, including revocation, limits on how much a grant may spend, and a handover between agents. They used an earlier edition of our rules and a program built on macOS, and our Linux rebuild did not reproduce that program byte for byte, so we are not publishing them. For this release we are preparing a new edition of the program with a pinned Linux recipe that anyone can rerun, with the synthetic test histories regenerated and signed under the current rules; the proofs will be published as soon as they are verified. Each will show that the program's checks passed for one small synthetic test history, within the bounded set of rules the program supports. That is not a claim about every IronTrellis rule or about production data, and a review of whether the program matches the rules exactly is still under way. A proof over a full hundred-event history did not finish on our workstation; we will run it on hardware built for the job. Our first implementation is also slower than it needs to be, partly because it does not use the fast hashing an earlier prototype already had; after this release we will assess how to make it faster, reusing what we can. Each published proof will be pinned together with the exact code that produced it, so every claim stays tied to what actually ran.

Here is where the work stands, in plain terms:

| Status | What |
|---|---|
| Built and independently checked | The signed history, decisions, refusals and replay. An engine-free checker, written only from the specification, agrees with the engine on 446 of 460 checks of the current test suite; the other 14 test a later rule, the session time horizon, which the checker predates. The owner-approval and human-attestation rules pass all 157 of their test cases. |
| Machine-checked | The decision procedure (including that revoking a permission never widens the permissions still in force, at the stage before the final checks), owner keys and human attestation, spending accounting, committees, and the rule that an anchor checker never accepts a rollback or a fork. The proofs were rebuilt independently on a separate Linux virtual machine. |
| Being produced | Zero-knowledge proofs of seven authority workloads on synthetic test histories, for a new edition of the program, to be built with a pinned recipe that anyone can rerun; published when verified. A hundred-event history comes later |
| Built, with one example on the main network | Anchoring to a public blockchain. The first release can record histories on a public test network. One example history has already been written to the Etherlink main network with an experimental tool, the chapter 1 record that anyone can check; production anchoring there, with finality checked independently, comes after the first release. |
| Designed, with early experiments, not yet built | Federated operation, selective disclosure with zero-knowledge proofs, and queries about human lineage |

With this first release, the sources, the specification, the test suites and the Lean proofs are published together, and the zero-knowledge summary proofs with the program that checks them follow as soon as they are verified, so that anyone can rerun them rather than take our word for any line of that table. No external security audit has been done yet, and we will say so until one has.

# What is the Long Horizon

The first job of IronTrellis is deliberately small: let a person give an agent bounded power, refuse what goes beyond it, record what happened, and keep unfinished work from vanishing. If that works, much larger structures become possible. They are not built into the protocol; they can be assembled from its pieces. What follows are possibilities, not products or predictions.

## From agents to institutions

The lasting object may not be the agent at all. It may be the institution.

An institution can persist while its models change, its agents retire, its people come and go, and its keys rotate. In such a structure, the institution holds roles; roles carry authority; agents occupy roles for a while; instructions direct their work; duties keep its commitments; successors keep it going; and the history keeps the evidence. This is close to how durable human organizations already work, rebuilt from small parts that a machine can check.

From those parts one can imagine a long-lived research group whose agents keep running experiments for years, a family's household agent that handles the heating contract through many winters, a cooperative of agents that share work and income, or a small company whose back office is mostly software but whose every delegated power can be traced to a person who granted it.

## Effects outlive their makers

Agents will create things of value, and relationships and obligations, that outlast the software that made them. When an agent is permanently switched off, someone has to settle what it leaves behind: authority ends, permissions that cannot be passed on disappear, open obligations are assigned, and anyone with a declared interest receives it. We call this an agent's estate. The phrase is not meant to treat software as a person. It recognises a plain fact: economic effects can outlive the process that caused them, and the world will need orderly ways to handle that.

## A human at the root

As agents start other agents, which start others, it will matter more and more whether a human being stands at the root of a power. IronTrellis's model includes a way to show that the keys behind a grant were enrolled under a human-attestation process, and that an agent's key alone can never change the owner's keys. We call the wider idea Proof of Human Lineage. It has firm limits, and we state them: a key is not a person, possessing a key is not the same as meaning to approve something, and two keys are not proof of two humans. Within those limits, being able to ask "is there a person behind this power, and by what evidence?" may become one of the most important questions in an automated economy.

## Privacy that can still prove

Today, proving that an agent was allowed to act usually means showing the whole record. In the future, it should be possible to prove a narrow fact, such as "this purchase was within an authorized budget", without revealing who authorized it, the rest of the budget, or anything else in the history. Zero-knowledge proofs make that possible in principle, and our experiments show it working on a small scale. The long-term goal is a world where accountability and privacy stop being a trade-off: where you can show what a relying party needs, and nothing more.

## Checked by machines, judged by people

We believe machine-checked proofs will become a normal part of building software that people depend on, and that AI assistance will make them far cheaper to produce. IronTrellis was itself built by a team of people and AI systems, and its most important rules were checked by a proof checker that does not care who wrote the proof. That combination, fast help from AI and a small, trusted checker that refuses anything unproven, is one we expect to spread.

The same principle runs through the product. A model can help a person write an instruction, read a graph, or understand an explanation. It never decides whether something was allowed. Decisions come from rules that anyone can recompute, and approvals come from people or from the agents they have explicitly empowered.

## What IronTrellis will not try to be

A clear vision includes clear refusals. IronTrellis is not a wallet, an identity system, a payment network, or a framework for building agents; it works alongside those. It does not judge fairness, settle legal liability, or decide how the benefits of automated work should be shared. It does not need a catalog of everything people might buy or agree to; it records the authority, terms and evidence of whatever the parties declare. And it should never quietly take a fee from every agent descended from it. People should be able to read the specification, take their history elsewhere, and check it with software we did not write.

## The human principle

Behind all of this is one idea. IronTrellis does not exist to make machines more powerful for its own sake. It exists to make machine power legible to the people it affects, and governable by them. Where there is a choice, we prefer:

- bounded authority over unlimited access;
- explicit delegation over shared passwords;
- recovery planned in advance over hoping nothing fails;
- traceability where responsibility matters, and privacy everywhere else;
- open formats over platform lock-in;
- explanations a person can read over policies nobody can see;
- many independent authorities over one global one.

If autonomous systems come to do a large share of useful work, people will need ways to create, sponsor, inherit, govern and benefit from long-lived machine activity, much as they now own a business or a piece of land. Some of that activity will serve families; some will fund research; some will direct part of its output toward the public good. How authority, responsibility and benefit flow through those systems is a decision too important to leave to accident.

## The next problem

The Internet learned how to identify machines. Blockchains learned how to give machines assets. AI learned how to give machines agency. The next problem is to give autonomous action structure through time.

Identity without authority is not enough. Authority without limits is dangerous. Action without a history is ambiguous. Delegation without responsibility is fragile. And autonomy without succession is gone the moment the process stops.

An agent should never be merely a process that happens to be running. It should live inside a structure that can explain where its power came from, what it may do, what it owes, who stands behind it, and what remains when it is gone.

That is what IronTrellis is for. When it is published, read the specification, run the proofs, replay a history yourself, and tell us what we missed.

*Last reviewed: 23 October 2026. This essay is kept up to date as the work changes.*
