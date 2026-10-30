# Origin of IronTrellis™

*Ramesh Rampertab · October 2026*

---

IronTrellis (formerly Continuity) began as a document, not as code. At the end of August 2026 I wrote a founding vision for a project with the working title Continuity, and within two days I had corrected it four times. It was written in the language of a constitution, with numbered articles, "ratified" amendments and a great many musts. This is the same set of ideas, retold in plain words: where they came from, why they mattered, and what became of them.

One thing first. This document is not a rulebook, and nobody who contributes to IronTrellis signs up to it. The rules IronTrellis actually follows live in its specification, which anyone can read, test, question and propose to change. What you will find here is the reasoning that started the project. If you think some of it is wrong, you are exactly the reader it was written for.

# The problem we started from

## An agent that can act is not yet an actor anyone can account for

By 2026 software agents could do real things. They could send messages, negotiate, call paid services, run wallets, change infrastructure, hire other agents, and keep going with no person watching. The founding vision began from a simple observation: being able to act is not the same as being a responsible actor inside an organization.

An agent can have an identity without having legitimate authority. It can hold money without permission to spend it. It can finish a task without leaving any lasting evidence of why it was allowed to. It can hand work to another agent without clearly passing on, or limiting, the authority it was working under. And it can disappear while the contracts, duties, funds, promises and debts it created are still very much alive.

So the vision set out to make a short list of questions answerable by a machine, for any consequential action an agent takes:

- Who is this actor?
- Who empowered it, and how did that authority reach it?
- What exactly may it do, and which limits travel with that power?
- What has it committed itself, or the person behind it, to do?
- Who is accountable?
- What happens to its duties and powers if it disappears?

## People solved this once, for themselves

People are temporary, and we have built a world that is not. Someone resigns, retires or dies, and the company carries on. The office is filled by someone new. The contract is still honored, the debt still paid, the estate settled. Authority can be delegated and taken back, powers can be limited, records outlive their authors, and a dispute can trace who did what and on whose say-so.

None of that is technology in the usual sense. It is centuries of practice that lets short-lived people build long-lived institutions. Agents, by default, have almost none of it. An agent can be started in seconds, copied, renamed, moved to a different model, given a payment card, allowed to start other agents, and switched off with no one taking over its work. Each of those is useful. Together they produce activity that is very hard to explain afterwards, and the more money and responsibility flows through software, the more that matters.

The founding vision put the real question this way. The question is not how to make agents autonomous; that is already happening. The question is how to make autonomous action **durable, bounded, attributable and governable**.

## Fill the gap, don't rebuild the neighbourhood

When the vision was written, a lot of good infrastructure for agents was arriving at once: standards for agent identity and reputation, signed mandates that capture what a user asked for, machine-to-machine payments, agent commerce, and several efforts at the IETF on agent identity and delegation. It would have been easy to build yet another wallet, identity token, payment rail or agent framework.

The vision argued for the opposite: work alongside all of these, and answer the question none of them answers. Identity standards say who you are. Payment protocols say how value moves. Mandates say what the user requested. Delegation systems say what capability was granted. The missing question was where a given piece of authority lives inside a lasting structure, what relationships and duties using it created, and what happens next.

# The ideas at the center

## Power has provenance

The most important idea in the founding vision was what it called power provenance: no consequential action should stand alone. Take a small purchase:

> Alice sets up Company X. Company X creates a purchasing office. The office appoints Agent A, with a mandate to spend up to $500. Agent A delegates a limited capability to Agent B. Agent B spends $23.70.

That $23.70 should not merely show that Agent B held a private key. It should be possible to show that Agent B acted because Agent A delegated the capability, because Agent A held the purchasing office, because that office had purchasing authority, because Company X created it, and that the purchase met every limit along the way.

A private key proves control of a credential. Provenance shows that an action was legitimate inside a declared system of authority. That difference is the whole project in one sentence, and everything else grew from it.

## Three questions

The vision boiled the purpose down to three questions people already ask about each other, and proposed that every autonomous system should be able to answer them:

- **Why was this allowed?** The actor, its role, the mandate, the path the authority took, the limits that applied, the policy version, who approved it, and the evidence.
- **Who is responsible?** The chain of responsibility from the acting agent up to the people or organizations behind it.
- **What survives if this actor disappears?** Its open obligations, outstanding contracts, roles, unexpired mandates, the agents it created, the consequences of revoking it, its successors and its unfinished work.

The vision guessed that the third question might turn out to be the project's most distinctive contribution. We still think so.

A day later, after an outside review, one of the four corrections sharpened all three. An answer is evidence about a particular history, not an all-knowing verdict. It has to say which history it looked at and at which point, under which rules, what it could not see, and what it assumed. "Why was this allowed?" does not establish motive, wisdom, fairness or legal validity. "Who is responsible?" names who instructed, acted, approved, controlled or benefited; it is not a finding of legal liability or blame. And when the evidence is missing, stale or disputed, the answer has to say so rather than round it to a convenient yes or no.

## Keep the actor apart from the office

Humans learned long ago that a person and an office are different things. The vision applied the same lesson to software and stopped treating an agent as the container for everything associated with it. An agent's identity may end; the role it held need not. A running program may crash; its obligations should not vanish with it. A model may be replaced while the organization stays the same.

So the vision drew distinctions that ordinary language blurs:

| Kept apart | Why it matters |
|---|---|
| The principal: the person or organization that power ultimately comes from | Valuable authority should trace back to someone, and experiments without a human root should be visibly labeled as such |
| The agent: a lasting identity | It can survive model upgrades, new machines, restarts and key changes, much more like an office-holder than a running process |
| The runtime: one running instance of that agent | "Process death is not identity death." A crash is not the end of an agent |
| The role: a lasting office with powers and duties | When one agent leaves, another can take the office |
| Authority, mandate and obligation | What may be done, a bounded instruction issued under that power, and what must still be done |
| The succession rule | Who takes over, and which powers and duties pass. Powers and duties need not pass together |
| The receipt | Compact evidence of who acted, under which role and mandate, from which authority, under which rules, when, and with what result |

"Powers and obligations need not pass together" may be the most important line in the whole original document. When an agent is replaced, its unfinished work should survive; its spending power should not quietly travel with that work. The later corrections made it sharper still: a duty never brings power with it. A successor gets only the authority that is separately and explicitly granted, with its own limits.

## Authority has a shape, and it has negative space

Several ideas followed about the shape of authority.

- **Power narrows as it is passed on.** A delegation can never create power its parent did not have. Creating ten helpers does not multiply a budget by ten.
- **Some actions need more than one yes.** Real institutions often require finance and security and the customer to agree. The vision called this authority intersection and pointed out that authority is a graph, not a simple family tree.
- **Prohibitions are first-class.** "May spend up to $500" and "must not deal with addresses on this blocklist" are different kinds of statement. Writing down what is forbidden is stronger than hoping it can be inferred from what was not granted.
- **Taking power back reaches everything built on it.** If Alice revokes the grant she gave Agent A, everything that rested only on that grant ends too. But if Agent C has a separate, valid path to its authority, that path survives. Validity is worked out from the graph, not assumed from ownership. That also makes possible a very practical question to ask before revoking anything: what will break if I do this?

## Identity is not ownership

If an agent has entered contracts, earned a reputation, run up obligations, done work and created other agents, then selling the token that represents it cannot rewrite its history. The vision separated five things that are easy to merge: identity, the controller of the identity, the role, the authority, and who benefits economically. Moving one of them should never silently move the others. Each change needs its own explicit, recorded step.

## Keep a history, not a table

Rather than overwriting the current state each time something changes, the vision proposed keeping an append-only history of events, such as an agent appointed, authority granted, an obligation created, authority revoked, an agent terminated, and working out the present state from that history. A history gives provenance, the ability to reproduce any past state, audits, disputes that can be examined, and a graph that can be rebuilt by someone else.

That choice turned out to carry the most weight of anything in the vision. It is why an outsider can now replay an IronTrellis history from the beginning and check each recorded decision, instead of trusting whoever runs the machine.

# The four corrections

The original vision was dated 27 August 2026. Within two days it had four amendments. Each one corrected something the first draft had gotten too narrow, too optimistic or too vague. They are worth retelling, because the corrections are where the vision learned to be honest.

## Anything people can agree to, not just software

The first draft's examples kept describing purchases of software, data or paid services. That was an accident of the examples, not a principle, and the first amendment said so. A transaction is any consequential event in which people or agents create, change, perform, transfer, settle or end authority, value, rights, duties, assets or relationships. It can be physical goods, labor, money, energy, a license, a contract, a recurring delivery. IronTrellis does not need a catalog of everything people might buy or agree to; it records the authority, terms and evidence of whatever the parties declare.

It also added relationships that last. A household's winter heating arrangement might authorize an oil delivery every few weeks. Each delivery, invoice, payment, missed delivery or refund is an event inside one continuing relationship, and that relationship, with its unresolved duties, can outlive any single agent that handles it.

This is also where the project's example acquired its characters. Alice wants one Cheshire Cat plush toy and will spend up to $25 within the week. Mr. Hatter, her purchasing agent, may delegate research to White Rabbit but not the power to pay. White Rabbit's attempt to pay a $5 deposit is refused, because looking is not spending. Mr. Hatter buys the toy, then his software stops before it arrives, and Dormouse is appointed to finish the job with only the authority it needs. That small story has been the test case ever since.

## The record must not depend on us

The second amendment dealt with durability. If the promise is that the history of authority outlasts the agents in it, that promise cannot depend on any account, server, database, explorer or company that we run, including the project itself. Its strongest form rests on public blockchains that no participant controls, used for the minimum evidence needed: identifiers, signatures, the key transitions of authority, and fingerprints of everything else.

It drew a distinction that has saved us from overclaiming more than once: **integrity is not availability**. A fingerprint on a public chain can prove that a document you hold is the one that was committed. It cannot bring back a document that has been lost everywhere. So a deployment has to say plainly which layer protects what: the chain for commitments, some form of storage for public content, controlled custody for confidential content, and replaceable conveniences such as explorers and indexers, which present the record but never own it.

And it asked for honest claims. Not "permanent", which no system can promise, but something more useful and checkable:

> No Continuity account, server, company, agent, vendor, or counterparty is the sole keeper of the finalized public record.

## Failure is messy

The third amendment faced the fact that failures are rarely clean. A program that stops answering may still be running. A network can split two healthy machines. A backup supervisor takes over, and then the original comes back. Two copies of a program may both believe they are the agent.

The answer was to separate things that look alike when you are in a hurry: restarting the software, handing control of it to someone else, and replacing the agent with a different one. Each is a different decision with different consequences, and none should be disguised as another. Each takeover gets a new numbered generation, and once it is recorded, requests from the older generation can be refused wherever the rules are checked, even though the old program's signatures are still mathematically valid. Silence is evidence that something is unavailable, not proof that it is gone.

It also refused to pretend that anything happens exactly once. If a purchase was sent and the reply never came, the outcome is unknown, and it stays visibly unknown until there is evidence. A retry has to be recognizable as the same intent, never treated as fresh permission to buy a second toy. The amendment summed up what the system can honestly promise, and it is still the best summary of the design:

> Durable authority and responsibility do not depend on one process continuing to run. Current control can be distinguished from stale control; recovery and succession follow declared rules; consequential actions can be rejected when their authority is superseded; unresolved external effects remain visible for reconciliation; and the history explains what happened.

## Answers with a scope, and one history at a time

The fourth amendment, written after an outside review, closed several gaps at once. Answers carry their scope, as described above. A duty never implies power. Rebuilding a history from public evidence needs the event data itself to stay available, not just its fingerprint. Each history has exactly one line of descent at a time: a test network, a mirror or a copy is a separate history, not a second truth. And rules are never applied backwards: every event is read under the rules in force when it was accepted, and later corrections are added going forward instead of rewriting the past.

# What it refused to be

A clear vision needs clear refusals, and the founding document had several.

- **It does not create legal personhood.** An agent does not become a legal person because a record says so. IronTrellis produces evidence of identity, authorization, provenance, commitments and declared relationships; what that means in law depends on the jurisdiction.
- **It is not an AI model, a payment network or an agent framework.** It works alongside all of them.
- **It is not a reputation system.** Reputation asks whether an agent is trustworthy. Authority asks whether it is empowered. A highly reputable agent may have no authority to spend my money, and a brand-new agent may have entirely legitimate authority. Confusing the two is a serious mistake.
- **It is not an ontology of civilization.** The first version was to contain only a few composable pieces, from which richer arrangements can grow.

And one refusal deserves its own line: **a language model is never the source of authority.** A model can help a person express an instruction, read a graph or understand an answer. But the founding vision was blunt about the order of things: the AI interprets, people or explicitly authorized agents sign, a deterministic engine checks, and the history remembers. It called that distinction non-negotiable, and of everything in the original document, it is the line we have held most strictly.

# Open by design

The vision was firm that the project should be aggressively open: code under the Apache License 2.0, chosen for its explicit patent grant, and specifications published so that anyone can implement them. The protocol has to be usable without paying its creator. Any business around it should come from operating it well, not from taxing it.

That extended to money that flows between agents. The original intuition that agents might generate value for their creators or communities stayed, but the vision refused to build in any hidden fee on every agent descended from another. Economic relationships, such as a share to a creator, a maintenance pool or a public-benefit fund, should be explicit, visible, consensual, bounded in time and separate from identity. It even imagined, as an option and never a requirement, that a person or organization could direct a small part of what their agents earn to public goods. The same structure that traces authority can trace benefit.

On standards, it was modest. Do not begin by declaring a universal standard. First make something useful, then build bridges to the standards around it, then learn from the people who implement it, and only then pursue formal standardization. The goal is not to own a standard; it is to create a small piece that other standards find useful enough to reference. Submitting IronTrellis's model to the IETF as an individual draft is the start of that last step, and an invitation, not a claim.

It also chose its critics in advance. The first community was not to be only enthusiasts. The vision named identity and security engineers, distributed-systems engineers, cryptographers, payment developers, lawyers who work on electronic agency, and people hostile to blockchain, "especially the last group". If a skeptic agrees that a particular step really benefits from a public, durable record, we have learned something.

# The longer horizon

The first job was deliberately small. The founding vision listed nine things a first implementation had to show: that a principal can create an agent; that authority can be granted with explicit limits; that it can be delegated but not enlarged; that unauthorized action is refused; that authorized action can happen; that the action leaves verifiable evidence; that an obligation outlives the actor that created it; that someone else can take over that obligation under declared rules; and that the whole history can be rebuilt and understood. "If those nine things work," it said, "we have something real."

Beyond them it sketched larger possibilities, built from the same small pieces rather than hard-coded: institutions that persist while their models, agents, people and keys change; agents that run research for years; a family's household agent that looks after the heating contract through many winters; cooperatives of agents; and, strangest of all, an agent's estate, an orderly way to settle what an agent leaves behind when it is switched off for good. That idea is not meant to treat software as a person. It simply recognizes that economic effects can outlast the process that caused them, and that the world will need orderly ways to deal with that.

Behind all of it was what the vision called the human principle. IronTrellis does not exist to make machines more powerful for its own sake. It exists to make machine power legible to the people it affects, and governable by them. Where there is a choice, it prefers bounded authority to unlimited access, explicit delegation to shared passwords, recovery planned in advance to hoping nothing fails, traceability where responsibility matters and privacy everywhere else, open formats to platform lock-in, explanations a person can read to policies nobody can see, and many independent authorities to one global one.

The essay *Why IronTrellis, Why Now, What is the Long Horizon* follows these possibilities further.

# What became of the vision

Two months on, the name has changed, from Continuity to IronTrellis. Much of the rest has been built, some of it differently from how the vision first imagined it, and some of it is still only an idea.

**Built, and checkable by anyone with the history and the owner's keys:** a signed, append-only history of authority; grants that narrow as they pass on, prohibitions, required co-approvals and revocation that reaches everything built on a grant; refusals recorded with their reasons; duties that belong to a role and survive a handover while grants do not; numbered generations that fence off an agent's older running copies; and replay, so that an outsider can recompute each recorded decision without trusting the operator.

**Built differently than first imagined:** the vision expected small smart contracts on a blockchain to be the registry. In IronTrellis the history lives as a signed file that anyone can replay, and a public chain is used where it is strongest: as an independent place to anchor a fingerprint of the latest state, so that an older copy cannot quietly be passed off as the latest. The first release can do this on a public test network; live anchoring on the main network comes after it.

**Checked by machine:** the rules where a mistake would hurt most have been written as models in the Lean proof assistant and checked by its small trusted kernel, and some of those proofs found real mistakes in the rules, which were then fixed.

**Not yet part of IronTrellis:** the graph explorer that would light up an authority path on screen, the agent charter, interoperability profiles for the payment and mandate standards the vision named, federated operation, and the estate. They remain worth building.

We have also learned where the original was too confident, and the four corrections were only the beginning. Every claim about IronTrellis now has to say what it rests on and where it stops. That habit is perhaps the vision's most important descendant.

# Why it still matters

The founding document ended with a passage that has stayed at the heart of the project ever since:

> The Internet learned how to identify machines. Blockchains learned how to give machines assets. AI learned how to give machines agency. The next problem is to give autonomous action structure through time.

Identity without authority is not enough. Authority without limits is dangerous. Action without provenance is ambiguous. Delegation without responsibility is fragile. Autonomy without succession disappears the moment the process stops.

An autonomous actor should never be merely a process that happens to be running. It should live inside a structure that can explain where its power came from, what it may do, what it owes, who stands behind it, and what remains when it is gone.

That was the starting point. The specification, the code, the tests and the proofs are where it is being worked out in public. Read them, run them, and tell us where the vision, or the work, falls short.

*Last reviewed: 23 October 2026.*
