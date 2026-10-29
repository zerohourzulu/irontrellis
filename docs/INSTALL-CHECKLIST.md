# IronTrellis Install Checklist

*RAmEx Labs · For IronTrellis 1.0.0-rc.2, with the Commissioning Disclosure of the same release · Last reviewed: 28 October 2026*

---

This checklist covers commissioning an IronTrellis (formerly Continuity) installation: before, during and after. A note like (D6) points to item 6 of the Commissioning Disclosure, which gives the reason. Commands are those of IronTrellis 1.0.0-rc.2; `<history>` stands for your history file.

- **Light path:** one person, a home lab, nothing important at stake. You still read and sign the disclosure.
  *What this path gives up:* with no witness and no independent publication of your keys, nothing outside your machine shows which copy of the history is the latest or which keys are real. With no trusted time source, every time is only your machine's claim. With no coverage table, the record shows what passed through IronTrellis, not what your agents did. That is why it is for experiments only.
- **Standard path:** an organization, or anything touching money, customers, safety or legal duties. The signed disclosure is kept under your own operating rules.
- **Optional external pre-commission audit:** an outside party checks your plan first.

Read every **Not in this release** line in the disclosure before you start: each is a protection your installation has to supply, or knowingly go without.

---

## Light path (single experimenter)

### Before
- [ ] Read the Commissioning Disclosure in full. Note the release version and the file's fingerprint (`shasum -a 256 COMMISSIONING-DISCLOSURE.md`) (Before you sign).
- [ ] Use a separate machine or virtual machine, not your everyday computer (D9).
- [ ] Decide what the agents may touch. Keep real payment cards and production passwords away from them (D10).
- [ ] Install: `npm install -g irontrellis@next` (Node 22.18 or later). For Claude Code, also `npm install -g @ramex-labs/irontrellis-hooks@next`.

### During
- [ ] Create the history: `irontrellis init --history <history>`, or for Claude Code, `irontrellis-hook init --agent claude-code` and then either enable the IronTrellis plugin or run `irontrellis-hook install claude-code --write`. This keeps the owner key as a file on the machine, which is acceptable for experiments only (D3).
- [ ] Move the next owner key off the machine straight away (`<history>.owner-next-key.json`), even if only to a USB stick in a drawer (D2).
- [ ] Label this history "experimental, untrusted" (D3).
- [ ] Optionally record a local anchor now and then: `irontrellis --history <history> anchor`. It protects against accidents, not against whoever runs the machine (D7).
- [ ] Keep session expiry short (D5).
- [ ] Sign the disclosure (Acknowledgement section).

### After
- [ ] Save the signed disclosure, the history identifier (`historyId`, printed by `init`) and your owner public keys somewhere off the machine (D4).
- [ ] Run `irontrellis --history <history> verify` once, and read what it says it cannot establish (D11).
- [ ] Run `irontrellis --history <history> doctor` and read its warnings about key files (D3).
- [ ] Before using the setup for anything real, move to the standard path with a new history (D3).

---

## Standard path (organization)

### Before
- [ ] Name an installation owner and an incident lead.
- [ ] Send the disclosure to every signatory in good time (your rules set how many days); record its fingerprint and the release version (Before you sign).
- [ ] **Keys.** Decide the number of owner keys, their custodians, and the signing rule (how many signatures for which actions) (D2).
- [ ] Choose the signer that will hold each owner key from the very first command: an SSH agent (a hardware key works through gpg-agent's SSH support; FIDO `sk-` keys are refused), a Vault Transit key, or a command signer (D3).
- [ ] Create the next owner key away from the IronTrellis machine, so that only its public key is ever on the machine (D2).
- [ ] Read the disclosure's limits on signing rules: the `irontrellis` command holds one owner key and signs alone, so any rule needing two signatures has to run through the programming interface, where some records are still refused (known issue 22). Decide your signing rule with that in mind (D2).
- [ ] Arrange separate custody for each next key, for example a safe or law-firm escrow, and guard it as a current key (D2).
- [ ] Where two signatures are needed to change keys, the two keys have two different custodians (D2).
- [ ] Owner keys are used for nothing else (D2).
- [ ] **Host.** Prepare a minimal, patched machine used only for IronTrellis, with named administrators (D9).
- [ ] Decide which operating-system controls enforce who may uninstall, upgrade or delete files (D9).
- [ ] **Time.** Choose a trusted time source that never runs backward, and document it (D6).
- [ ] Confirm that agent records will be accepted only through your own writer (D6).
- [ ] Decide whether to set a session-time horizon, and if so, how owner records (for example checkpoints) will be scheduled so agents can keep recording (D6).
- [ ] **Witnesses.** Arrange at least one witness run by a different administrator, with its URL and verifier key (D8).
- [ ] Decide how many unwitnessed events you will tolerate during an outage (`--max-unwitnessed` on `witness add`, default 1,000) (D8).
- [ ] **Anchoring.** Decide whether you need anything beyond the witness and the local anchor log. Public-chain anchoring in this release is a test-network profile for host software. The one mainnet example so far, the chapter 1 record, was written with an experimental tool in the repository. If you integrate anchoring, describe it as what it is (D7).
- [ ] **Coverage.** List every way agents can cause effects, and mark each as enforced, recorded or open; record scope, version, period, assessor and known unknowns (D10).
- [ ] Move credentials from agents to the decision point where possible (D10).
- [ ] **Privacy.** Agree naming rules that keep secrets and personal data out of records; treat what the witness learns as public; consult counsel (D8, D13).
- [ ] **Stopping.** Set up an independent way to stop agents' effects (D14).
- [ ] Plan how the history will end and what succeeds it, well before the format's limits (D14).
- [ ] Choose the electronic-signature protocol and where the signed disclosure will be kept (Acknowledgement).

### During (the ceremony)
- [ ] Confirm every signatory is present or authenticated remotely.
- [ ] Check the disclosure shown against the fingerprint recorded for the release (Before you sign).
- [ ] Each signatory signs the disclosure.
- [ ] Create the history with the owner key in its signer, the next key's public key only, and the witness bound from the first write, for example:
  `irontrellis init --history <history> --signer ssh-agent --public-key <owner key> --next-public-key <next key> --witness <url> --verifier-key <key>`
  Add `--session-time-horizon <ms>` if you chose one (D2, D3, D6, D8).
- [ ] Run `irontrellis --history <history> doctor` and confirm it reports no owner key file on the machine (D3, D9).
- [ ] If you chose a limit other than 1,000 unwitnessed events, set it now, before any multi-signature rule: `irontrellis --history <history> witness add <url> --verifier-key <key> --max-unwitnessed <n>` (it rebinds the same witness with the new limit) (D8).
- [ ] Set the signing rule. A rule needing more than one signature has to be set through the programming interface; the command-line tool cannot collect a second signature (D2). For a one-key rule: `irontrellis --history <history> owner rotate-key --owner-policy <file> --next-key-ref <file> --new-next-public-key <key>`, so that the new next key is also created off the machine (D2).
- [ ] Set session expiry (D5) and the clock source (D6).
- [ ] Record the history identifier.

### After
- [ ] Publish the history identifier and owner public keys through a channel the operator does not control, and tell auditors where to find them (D4).
- [ ] File the signed disclosure under your operating rules.
- [ ] Run `irontrellis --history <history> verify` and read its limits (D11). Then check the history against the published identifier: `irontrellis --history <history> export --view > view.json`, then `irontrellis export verify view.json`, and compare the view's `historyId` with the published one, since `verify` does not take an expected identifier in this release (D4).
- [ ] Run `irontrellis --history <history> witness status` and confirm the witness holds the latest owner-signed head (D8).
- [ ] Publish the coverage table with date and assessor (D10).
- [ ] Test the stop channel (D14) and advancing an agent's epoch (retiring its sessions) on a test agent: `irontrellis --history <history> epoch advance <agent> --from <n> --to <n+1>` (D5).
- [ ] Rehearse the key-change procedure on a throwaway history, never on the real one; the first real rotation is a scheduled ceremony (D2).
- [ ] Schedule reviews of release notes and known issues, verify's time listings, witness status, and the coverage table (D1, D6, D8, D10).
- [ ] Write the incident plan: who advances epochs, who changes keys, who reviews the affected period (D2, D5).
- [ ] Agree the reporting rule: every report says which conclusions rest on replay and which on outside evidence (D11).
- [ ] Do not describe the installation as federated (D12).
- [ ] Set up backups of the history, stored apart from every key. After restoring an older copy, expect the witness to refuse it as a rollback until you restore a later copy or record the loss (`irontrellis --history <history> witness remove <url> --accept-loss --reason <text>`); never present a restored copy as current (D8, D14).
- [ ] Give the auditor an export (`irontrellis --history <history> export`), the published keys and the witness's public key by a route independent of the operator, and write down which rollback gaps remain (D4, D8).

---

## Optional external pre-commission audit

**Who might do it.** An independent security firm, an audit team inside the organization, separate from the people running the host, a law firm with technical support, or a qualified reviewer from the IronTrellis community. They should not administer the host or hold an owner key.

**What they check.**
- [ ] The release version and disclosure fingerprint match what will be installed, and the installation has a plan for every "Not in this release" line (Before you sign, D1).
- [ ] Key custody: signers, custodians, next-key separation, signing rule and its key-change limit; owner keys used for nothing else; next keys guarded as current keys (D2).
- [ ] No owner key has ever existed as a file on the machine: `irontrellis doctor` shows none now, and the ceremony record (the `init` command and its output) shows the key was in a signer from the start; or the reason is documented (D3).
- [ ] The publication channel for owner keys is outside the operator's control, and auditors know to compare against it (D4).
- [ ] Session expiry and the epoch-advance procedure (D5).
- [ ] The time source, any session-time horizon, and that agent records go only through the installation's writer (D6).
- [ ] What anchoring is used, and that it is described accurately (D7).
- [ ] Witness independence, the unwitnessed-event limit, and the written list of remaining rollback gaps (D8).
- [ ] Host hardening, administrator list and operating-system controls (D9).
- [ ] The coverage table: completeness of effect paths, credential placement (D10).
- [ ] Any planned public claims, against what replay can prove (D11, D12).
- [ ] Privacy and naming rules (D13).
- [ ] The stop channel, backups and end-of-history plan (D14).

**What they hand back.**
- [ ] A dated report naming the scope, version and evidence examined.
- [ ] Findings ranked by severity, each tied to a disclosure number.
- [ ] A list of what was not checked.
- [ ] A signed statement of their independence from the host and the key holders.
- [ ] Optionally, the report's fingerprint, to be filed with the signed disclosure.

An audit of your installation's plan is not an audit of IronTrellis's code (D1).
