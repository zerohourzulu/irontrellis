# IronTrellis Commissioning Disclosure

*RAmEx Labs · For IronTrellis 1.0.0-rc.2 · Last reviewed: 28 October 2026*

---

## Before you sign

IronTrellis (formerly Continuity) keeps a signed history of what AI agents were allowed to do: who granted each power, within what limits, what was refused, and what was left unfinished. Anyone holding that history and the owner's public keys can replay it and check every recorded decision, without trusting the agent or whoever runs the machine.

But the record is only as trustworthy as the installation around it. This document lists the most serious ways an installation can be compromised or misread, what IronTrellis does about each, and what your installation must do. Where a duty could fall between the two, we name it on both sides on purpose: overlap is better than a gap.

**This document describes the release it ships with, not the finished design.** IronTrellis 1.0.0-rc.2 is a release candidate, and some protections the design calls for are not built yet. Where that is so, a line marked **Not in this release** says what is missing. Until it is built, your installation has to supply that protection itself, or knowingly accept the gap.

Everyone who commissions an installation signs: the one person setting up a home lab, or every signatory at an organization's key ceremony. Your signature says you were told. This document is published with each IronTrellis release, and the release fixes its exact text. When you sign, record the release version and this file's SHA-256 fingerprint, so anyone can later check exactly which words you saw. IronTrellis does not yet show you this document or record your acknowledgement for you; you keep the signed copy under your own rules.

## Disclosures

### 1. This is pre-release software

**What can go wrong.** IronTrellis 1.0.0-rc.2 is a release candidate. It has a large test suite and machine-checked proofs of selected rules (which cover models of the rules, not the running code), and during development an independent checker, written only from the specification, has been run against the engine. It has had no external security audit. A bug could weaken any protection below.

**What IronTrellis does about it.** It states its status plainly and publishes its sources and tests for others to rerun. It will say "no external security audit" until one has been done.

**Not in this release:**
- a shipped independent checker for this release's history format (the Python verifier in the repository reads only the older formats).

The Lean proof sources are published in the repository, in verification/SelectLeanProofs/.

**What this installation must do.** Where money, safety or legal duties are at stake, keep your existing controls. Record the version installed and read its release notes and known issues.

### 2. Owner keys: custody, pre-rotation and recovery

**What can go wrong.** Whoever holds enough owner keys can grant any power, change the approval rule, and choose the time on what they sign; with the next key as well, they can replace the keys. A signature proves which key signed, not who held it or what they meant. If every current owner key is lost and recovery is not possible, the history can never be changed again: there is no back door. A key you retired can still sign an old copy of the history, cut off just before the change that retired it. Only evidence that the history went on (a witness, an anchor, a later copy) shows which copy is real.

Whoever holds the committed next key is as dangerous as whoever holds today's key. The approval rule counts keys, not people: two keys in one custodian's hands are one custodian. If you use the option that requires a named attester to vouch that each owner key belongs to a person, a key whose attestation has lapsed can still stop things, write checkpoints and help restore attestations, but nothing more; and if no attester will cooperate, your keys, rules and attesters stay frozen. Collusion between an attester and key holders looks like consent.

**What IronTrellis does about it.**
- **Pre-rotation.** `irontrellis init` commits the history to the fingerprint of a *next* owner key, and only that next key can replace today's. By default `init` writes the next key as a file beside the history, `<history>.owner-next-key.json`, to be moved off the machine. Until you move it, a thief with the machine holds both keys.
- **An approval rule (M of N).** The history format can require separate signatures from several owner keys. At least one owner signature is always required. Agent keys may co-sign some actions, never alone, and never on key or policy changes. Under a one-signature rule, today's key alone can also change the approval rule.

**Not in this release:**
- multi-signature rules from the command line: the `irontrellis` command holds one owner key and signs with it alone. Adding a second owner key and collecting a second signature are possible only through the programming interface;
- even there, under a rule needing two signatures, some records are still signed with one key and refused: binding or removing a witness, the handover step, a key change through the witness-first path, and adding a next-key commitment under a key-change rule of two or more (known issue 22). A co-signed key change is written locally first and given to the witness afterwards;
- a command to perform a recovery rotation (replay accepts one, but no shipped tool writes it).

**What this installation must do.** Keep owner keys in a signer, never as files on the IronTrellis machine (see 3). Move the next key off the machine as soon as the history is created, to a different place and custodian (a safe, or law-firm escrow), and guard it exactly as a current key. With several key holders, decide the approval rule deliberately, knowing the limits above (a rule needing two signatures means working through the programming interface), and let one signature stop an agent. Where two signatures are needed to change keys, make sure the two keys have two different custodians. Use each owner key for IronTrellis only: a key that also signs email, code or logins can be tricked into signing an IronTrellis record through the other system.

### 3. Where the owner keys live

**What can go wrong.** Every later owner key is authorized by the one before it, so a history started with weak or exposed keys keeps that weak root for its whole life. Anyone who could copy that first key can produce records indistinguishable from yours.

**What IronTrellis does about it.** By default `irontrellis init` creates the owner key as a file next to the history (readable only by its owner). You can instead keep it in a signer from the start:
- `--signer ssh-agent`, with the key held by an SSH agent. A hardware key such as a YubiKey is documented to work through gpg-agent's SSH support (not yet tested with a real card). FIDO security keys (`sk-` key types) are refused.
- `--signer vault-transit`, with the key held by a HashiCorp Vault Transit engine.
- `--signer command`, with an external program that signs.

The Claude Code route (`irontrellis-hook init`) creates its key files under `~/.irontrellis/projects/` and warns that the same user can read them. `irontrellis doctor` warns when an owner key file sits on the machine (`OWNER_KEY_FILE_ON_HOST`) and says how to move it into a signer.

**Not in this release:** a guided key-setup step during installation, an offer of hardware or protected-chip keys, and a separate signed risk statement for proceeding without them.

**What this installation must do.** For real use, create the history with a signer from the very first command. A history whose first key ever existed as a file on the machine should be treated as untrusted: use it for experiments only, label it so, and start a new history with proper keys before anything is at stake.

### 4. Publishing the owner keys and the history's identity

**What can go wrong.** Anyone can produce a complete, internally consistent history signed with keys of their own. A verifier who takes the owner keys from the history itself has checked nothing.

**What IronTrellis does about it.** The model requires the history's identity and first owner keys to be confirmed through an independent channel before anything else is checked. The history identifier is a hash of the first record, which holds the first owner keys, so a reader configured with the expected identifier (the Claude Code hooks, the gateway) refuses any other file, and that also fixes the first owner keys. `irontrellis export verify` can take the expected first-record hash. But `irontrellis verify` itself takes no expected identifier: it reads the first owner keys from the history file.

**Not in this release:** a `verify` option that takes the expected history identifier and owner public keys and refuses a history that does not match them (planned).

**What this installation must do.** Publish the history identifier (the `historyId` that `init` prints) and the owner public keys through a channel the machine's operator does not control, and tell auditors where to find them. Auditors must check the history against the published identifier (for example with `irontrellis export verify` and the expected first-record hash) before they rely on any verification result.

### 5. Agent session keys and their expiry

**What can go wrong.** Each running agent signs with a session key. A thief can sign records as that agent until the key expires or is retired, and can push history time forward (6). Its claims about the outside world need not be true.

**What IronTrellis does about it.** Each session is admitted by an owner-signed record with an expiry; replay rejects records signed after expiry or by a retired session. Advancing the agent's epoch, a counter, retires all its earlier sessions at once, and no configured size limit can block it, though the format's hard limits, a full disk or an unavailable signer still can (14). Every action is re-checked against the authority the owner granted. On the Claude Code route, sessions last 24 hours by default.

**What this installation must do.** Give sessions a short expiry. Keep session keys away from the agent's own tools where you can. Advance the epoch as soon as a leak is suspected, then review what was signed meanwhile.

### 6. Time and the trusted clock

**What can go wrong.** IronTrellis has no clock of its own; each record's time is its writer's claim, and `init` takes the host's clock. A clock set forward expires grants early; one set backward is caught only if it falls before the latest record. A sole owner key holder chooses the time on what they sign. A stolen session key whose records skip your installation's writer (the IronTrellis process that appends records) can push history time forward to just before the session's expiry. Retiring the session does not move time back, and afterwards nobody can tell whether your writer was used.

**What IronTrellis does about it.**
- Replay rejects records whose time goes backward, or that reach their session's expiry.
- `irontrellis verify` lists any agent record that moves history time forward by more than five minutes (a fixed limit).
- An optional **session-time horizon**, set when the history is created (`irontrellis init --session-time-horizon <ms>`; off by default), stops agent records from running more than that far ahead of the latest owner-signed record that moved time forward. Once the horizon is reached, agents cannot record until an owner writes such a record, for example a checkpoint, so an unattended installation needs scheduled owner records. The Claude Code route's `irontrellis-hook init` does not offer it.

**Not in this release:** flagging records whose time is ahead of the public-chain block that anchors them.

**What this installation must do.** Use a trusted time source that never runs backward, and record which. Accept agent records only through your own writer, which checks each time against it. Decide whether to set a session-time horizon, and if so, schedule the owner records it needs.

### 7. External anchoring, and what is lost without it

**What can go wrong.** A chain of hashes cannot tell a history from the same history with its newest records cut off. Without evidence held outside your machine, whoever controls it can restore an older copy and nobody can tell.

**What IronTrellis does about it.** `irontrellis anchor` records the latest position of the history in a local anchor log, and experimentally in the public Sigstore Rekor transparency log (never yet tried against the live log); `verify` checks those anchors. For public blockchains, a durable outbox and an on-chain statement contract are built and tested, and host software can use them through the programming interface. In this release that path supports a test profile on Etherlink Shadownet, a public test network (chain 127823). On 25 October 2026 an experimental tool in the repository also wrote one example history to Etherlink mainnet (the chapter 1 record, in docs/examples), with finality reported by nodes we chose. Production anchoring on mainnet, with finality checked against the chain's consensus, is designed and partly tested, and deferred to a later release. Where it is used, only fingerprints are published, never the records themselves.

**Not in this release:** anchoring to a public chain by default; a command-line option for it; a shipped finality checker; a product command that shows chain anchors (an experimental reader in the repository checks the chapter 1 record); production mainnet anchoring (the chapter 1 record is an example written with an experimental tool).

**What this installation must do.** Treat a local anchor log as protection against accidents and casual tampering only: it lives under the operator's control. In this release, rollback protection rests mainly on an independent witness (8); bind one. If you integrate the Shadownet test profile, describe it as test-network anchoring, never as public mainnet anchoring. Record which anchoring you use, and what it does not protect. An anchor proves the history up to that point existed by then, not that it is true or complete; work after the last anchor, and a hidden fork, stay invisible.

### 8. Independent witnesses and auditors

**What can go wrong.** Evidence kept by the same administrator as the history can be rolled back with it. A witness can go offline, or show different readers different views. A witness closes rollback only from the moment it is bound. It cannot catch a copy taken before that, a rollback during an outage, an administrator who runs both the host and the witness, or records written after the last witnessed one.

**What IronTrellis does about it.**
- **Binding.** `irontrellis witness add` (or `init --witness <url>`) binds a remote witness, a separate service. It co-signs the newest owner-signed head of the history and refuses one that does not extend what it holds. Records written by agents are covered when the owner next writes, or when you run `irontrellis witness sync`.
- **Fresh answers.** Answers are signed over a fresh challenge, so an old answer cannot be replayed.
- **Split views.** A reader catches contradictions it receives itself. A witness showing *different* readers different views is caught only when readers compare what they received, and nothing in IronTrellis makes them compare.
- **Outages.** Owner writes continue while the witness is unreachable until a set number of events are unwitnessed (default 1,000; set with `irontrellis --history <history> witness add <url> --verifier-key <key> --max-unwitnessed <n>`, an option of `witness add`, not of `init`), then stop. Revocations, epoch advances, terminations, unappointments, budget updates and closures, counterparty retirements, witness removals and checkpoints are exempt, so you can still stop an agent.
- **Alarms.** If the witness reports a rollback or a split view, or a witness-first key change is left unfinished, every owner write is refused, including those that stop an agent, until the alarm is dealt with.
- **What the witness learns.** The witness receives the full first record, including the owner public keys and the deployment identifier, the full key-change records, and the fingerprints, positions and times of later heads. Its list of entries can be read without a token.

**What this installation must do.** Configure at least one witness run by someone other than the host's administrator. Set `--max-unwitnessed` (on `witness add`) to the number of unwitnessed events you can tolerate. Keep an independent way to stop agents for the case of a witness alarm (14). Treat what the witness learns as public. Give your auditor an export, the published keys (4) and the witness's public key by a route the operator does not control, and arrange for auditors to compare what they receive. Write down which of the four gaps above apply to you.

### 9. Host compromise

**What can go wrong.** The engine runs with the host's permissions. Whoever controls the host (an administrator, malware, a cloud provider) can skip the check, change the clock, read keys stored there, withhold records, or stop IronTrellis.

**What IronTrellis does about it.** A verifier trusts the host for nothing except, in this release, the owner keys in the history's first record unless they are confirmed from outside (4). Replay catches edits that conflict with signed records, and witnesses limit rollback.

**What this installation must do.** Use a patched, minimal machine for this alone, with few administrators and no owner keys. Ceremony rules on who may uninstall, upgrade or delete files are enforced by the operating system, not by signatures; configure them there.

### 10. Actions that bypass IronTrellis

**What can go wrong.** IronTrellis sees only what passes through its decision point. An agent holding a raw password, token or payment card, a helper agent started without IronTrellis's check, or a script calling a service directly acts unseen.

**What IronTrellis does about it.**
- **Admissions.** Actions that run through IronTrellis's recorded execution path (the programming interface's run path, or the MCP gateway with call recording turned on) are recorded as admissions. The Claude Code hooks check each side-effecting tool call they receive (tools set as read-only are not checked, and a check that times out does not block the call), but do not record each call in the history.
- **Refusals.** Refusals are recorded too, with limits: by default, a repeat of the same refusal within 60 seconds is skipped, and at most six per minute are recorded for each agent. The programming interface and the gateway report when a refusal was not recorded; the Claude Code hooks do not.
- **Reconciliation.** A reconciler you run can record observations of calls seen at a provider, each marked matched or unmatched against the history. IronTrellis does not read provider logs itself.

**What this installation must do.** List every way your agents can cause effects, mark each enforced, recorded or open, and publish that table with its scope, the version and period it covers, the assessor, the known unknowns, and the date. A path counts as enforced only when the decision point holds the only credentials and the executor is protected; a credential sitting on a hostile host is not enforcement. If a path is recorded through a log feed, document the feed's coverage, collection interval and loss. Let the decision point, not the agent, hold credentials. Do not call your agents "governed" without that table.

### 11. What replay can and cannot prove

**What can go wrong.** People read more into a verified history than it holds. Replay proves the record is intact, every change of power carried the required owner signatures, and every admitted action was authorized at the point it names. It does not prove that an action had its effect, that every action passed through the decision point, that times are true, who held a key, or, without outside evidence, that a copy is the latest.

**What IronTrellis does about it.** Verification reports these separately, keeps missing evidence marked, and treats receipts and outcomes as signed claims. Its verdicts come from deterministic rules; no AI model takes part in deciding them.

**What this installation must do.** Never describe the history as proof of what an agent did. In reports, say which conclusions rest on replay and which on outside evidence.

### 12. Federation limits

**What can go wrong.** Sharing operation among a committee helps only if members are truly independent and enough are honest. Even then, it cannot stop acts signed with a stolen owner key, prove every action went through it, make false reports true, or guarantee an outside action happens exactly once.

**What IronTrellis does about it.** Federated operation is designed, not built. In the design a committee is never the owner: its key only co-signs, never alone, and human key holders can remove it. The label "federated" is reserved until independent hosts pass their tests.

**What this installation must do.** Do not call your installation federated.

### 13. Privacy, and the lack of erasure

**What can go wrong.** The history records who allowed what, who was refused and who owes what; it is not confidential by construction. Records needed for replay cannot be deleted. Hashes are not anonymity, anchors reveal when you publish, and a witness learns the owner public keys and key changes (8).

**What IronTrellis does about it.** It can record a fingerprint of terms while the content lives elsewhere. Where chain anchoring is used, only fingerprints are published.

**Not in this release:** the optional mode that stores full records on a public chain (which would make the history permanently public).

**What this installation must do.** Keep secrets and personal data out of names and descriptions; use pseudonyms or salted fingerprints for anything that may need erasing. Restrict access to refusal records, which show what someone's agent tried. Feed in only the fields matching needs: provider logs, effects and receipts put third-party data into a record that cannot be erased. Set a retention and access rule for the whole history file, not only refusals; a query that hides fields does not protect the file. Check data-protection duties with counsel.

### 14. Stopping agents, outages, and the end of a history

**What can go wrong.** A failed disk, a stuck lock, an unavailable signer, full storage, a witness reporting a rollback or split view, or an unfinished key change can stop a revocation from being written (8). The history format also has hard limits (1,048,576 state records, or a 1 GiB file) that refuse every further write, including a revocation. An emergency cannot wait for chain finality (the point after which the chain will not change its mind).

**What IronTrellis does about it.** No size limit that you configure can refuse a revocation, epoch advance or termination, and failures are reported, not hidden. On the recorded execution path (10), if an outside action times out or the machine crashes mid-way, IronTrellis keeps the attempt open as "outcome unknown" and never repeats it on its own.

**What this installation must do.** Keep a way to stop your agents' effects that does not depend on IronTrellis. Back up the history, never with the keys. Plan for the history's end and its successor before it nears the format's limits. Provide a way to find out what happened at an outside destination after a timeout, and make repeated calls safe on the destination's side. A signed history cannot make an action happen exactly once.

## Legal notices

**No warranty, no liability.** IronTrellis is free, open-source software under the Apache License 2.0. It is provided "AS IS", without warranties or conditions of any kind, and to the fullest extent the law allows, RAmEx Labs and the contributors are not liable for any damages arising from its use (LICENSE, sections 7 and 8, which govern). Signing this acknowledgement does not change that.

**If harm occurs.** If the installation contributes to damage to property, data or people, the installation takes prompt, effective action to stop it and limit further harm, preserves the history and its evidence, and reports any security weakness to RAmEx Labs privately (SECURITY.md).

**Export control and sanctions.** RAmEx Labs is a United States company and operates under U.S. law. Each installation is responsible for complying with the export control and sanctions laws that apply to it, including the U.S. Export Administration Regulations and the sanctions programs of the Office of Foreign Assets Control (OFAC). Do not use, export or re-export IronTrellis in violation of those laws.

**Help us make it stronger.** Privacy, legal and operational security requirements differ by country and industry. We welcome contributions that strengthen IronTrellis's security and integrity, and help adapting it to local requirements (CONTRIBUTING.md).

## Acknowledgement

**Document:** IronTrellis Commissioning Disclosure, for IronTrellis 1.0.0-rc.2

**Fingerprint:** sha256: ______________________________________ (the SHA-256 of this file as shipped in that release)

**Installation:** ______________________________________ (installation name or deployment identifier)

**History identifier:** ______________________________________ (the historyId printed by `irontrellis init`)

**Owner key custody:** ☐ signer (SSH agent, gpg-agent hardware key, Vault Transit or command signer) ☐ key files on this machine (experiments only)

By signing, I confirm that I have read disclosures 1 to 14 and the legal notices of the document identified above, including every "Not in this release" line, and understand what this installation is responsible for.

Name: ______________________________ Role: ______________________________

Signature: __________________________ Date: ______________________________

Signed by hand, or with the e-signature tool: ______________________________

Name: ______________________________ Role: ______________________________

Signature: __________________________ Date: ______________________________

Signed by hand, or with the e-signature tool: ______________________________

This release has no built-in signing step. Sign a printed copy by hand, or use your organization's own electronic signature tool; either way, the signature applies to the document with the fingerprint above. The organization decides where the signed copy is kept, under its own operating rules.

*This document is not legal advice.*
