# SPEC: IronTrellis Anchoring Profiles — r1 (companion to Core EFFECTIVE r5)

`SPEC-IRONTRELLIS-ANCHORING-PROFILES-r1.md` — part 1 of 2 (§P, §1–§10). Part 2 carries §11–§21.

## Preamble

**P.1 Status.** This document is the companion to `SPEC-IRONTRELLIS-CORE-v2-EFFECTIVE-r5` that Core A-186.4 names (Core P.9; Core §7.4, the informative anchoring paragraph). It is **normative for anchoring profiles, gateways, connectors and the anchoring listings of `verify`**: the evidence those listings consume, the objects the profiles exchange, and the ceremony, writer, outbox and report-level rules of A-94.1 and Core Appendix G that are not Core text. Its text is not r5 text. Core carries only the pointers Core P.9 lists: the §7.4 paragraph, the §18 listings this document feeds (A-140.1, A-151.2, A-181), Appendix G G.6 (the TEST-profile operator rules, A-183.2 (v)) and Appendix E E-32…E-39. Nothing here touches Core replay: no replay rule, no refusal code, no field, no record kind and no vector of Core. Where this document and Core differ about a Core rule, Core governs. [A-186.4]

**P.2 Precedence.** As in Core r5 P.1 and P.7: **AS01-PART2 > AS01 > G6.10 > G6.9 > G6.8 > G6.7 > G6.6 > G6.5 > G6.4 > G6.3 > G6.2 > G6.1 > G6 > G5 > G4 > r4.** Only the latest text of every chain is integrated (A-186.3). Founder note 4am took its final text as A-181 and ranks with `ADDENDA-AS01.md`, not with its G1-family number. `ADDENDA-AS01-PART2.md` (A-187…A-191) contains no ruling for this document; it ranks above everything it would amend.

**P.3 Rulings applied, by addendum file.**
- `ADDENDA-G6.6-FEDERATION.md`: A-140, A-141, A-142, A-143, A-144, A-145 (part 1).
- `ADDENDA-G6.7.md`: A-150 (part 1).
- `ADDENDA-G6.8.md`: A-151.0 (the §2.6 chain note), A-151.1 and A-151.2 (part 1, as amendments to A-140.5 and A-140.6; A-151.3 is Core Appendix F F.7), A-154, A-155 (part 1).
- `ADDENDA-G6.9.md`: A-158, A-159, A-160, A-161, A-162, A-163, A-164, A-165 (part 2); A-165.1 extends A-140.2's list (§2.3).
- `ADDENDA-G6.10.md`: A-167, A-168, A-169 (part 2).
- `ADDENDA-AS01.md`: A-181.1, A-181.2 and A-181.4 as amendments to A-142.1 (part 1, §4; the listing itself is Core §18), A-181.3 (part 2, §14), A-182 (part 1), A-183 (part 1), A-185.2 (part 2); A-186.4 and A-186.5 (this preamble).
- `A-ANCHORING-AND-FEDERATION-DESIGN.md` (11 Oct) is the engineering proposal A-140–A-145 ruled on. It is background only: where it differs from a ruling, the ruling governs, and nothing in it is text unless a ruling adopts it.

**P.4 Conventions.** MUST, MUST NOT, SHOULD, MAY are RFC 2119. Each passage carries the tag of its final ruling, `[A-n.m]`; where a later ruling amends an earlier one, both are named: `[A-145.1 as amended by A-182.1]`. Core is cited by its r5 section number ("Core §7.4"); Core rules are pointed to, never restated. Where two rulings conflict, or something a section needs is not ruled, the text says `[GAP: …]` and nothing is resolved silently. Items the rulings hold open carry a status line in italics naming the ruling. "PHL" is Proof of Human Lineage. "IronTrellisLiveChainAnchor" (the milestone at which IronTrellis anchors histories on a live public chain in consensus-verified mode; A-182.1's "LIVE-1", renamed by founder decision 4br) is the post-rc.2 live-anchoring milestone [A-193.1]. "LiveChainFinalized" (the word a verifier report prints for an anchor found final in consensus-verified mode under a PRODUCTION-class profile) is §7.1's headline word, a printed label and never a field [A-193.2] [A-193.3]. `ADDENDA-AS02.md` (A-192…A-198) ranks above `ADDENDA-AS01-PART2.md` and rules for this document through A-193 (§7, §14, this paragraph) and A-195 (§8.2, §10, §19.3). Shadownet is chain 127823 (A-183). Dates are UTC.

**P.5 Open holds recorded here, not ruled.** [A-186.5] [A-182.1] A-144.4 (the CometBFT commit certificate, §6.4), A-145.2 (federation labels, evidence-gated, §7.4), A-150.2's live evidence and A-161's founder-run node evidence (IronTrellisLiveChainAnchor, §8.3 and §14; A-182.1), A-159's opt-in label and A-160's tier-3 label (§12, §13; A-159.0, A-160.0, unchanged by A-182.1), and A-163's resume default (stands as A-168 ruled; founder decision 4bo). E-32…E-39 are deferred and not adopted (§21).

**P.6 Contents of both parts.**

Part 1 (this file):
- §1 Scope, the Core boundary and terms
- §2 Committee co-signing key: class, separation, custody (A-140; A-140.5 as amended by A-151.1; A-140.6 with A-151.2; the N3 theorem by pointer to Core Appendix F F.7)
- §3 Committee time bound (A-141; A-141.2 as amended by A-155.1)
- §4 Anchor-time bracketing: the evidence `verify` consumes (A-142.1 as amended by A-181.1, A-181.2, A-181.4)
- §5 Anchored PHL status registry (A-143)
- §6 `irontrellis-anchor-statement/1` (A-144; A-144.4 open)
- §7 rc.2 scope, IronTrellisLiveChainAnchor and labels (A-145.1 as amended by A-182.1; A-182.2; A-145.2 open; A-145.3)
- §8 Etherlink finality for the launch connector (A-150; A-150.2 open)
- §9 The replay verdict and the certificate barrier are two outputs (A-154)
- §10 Profile classes, the Shadownet TEST profile and path B (A-183)

Part 2 (job 69; section numbers continue):
- §11 `irontrellis-anchor-namespace/1`: one immutable instance, discovery, migration (A-158)
- §12 Persistence tier: closures, descriptors, `availability` literals (A-159)
- §13 Tier-3 resumable staging; `MIRROR_ACCEPTED` is evidence only (A-160)
- §14 Connector qualification and `irontrellis-anchor-verify-report/1`, with `finality.l1BlockTime` (A-161; A-181.3)
- §15 Comparison editions (A-162)
- §16 Outbox resume after a crash; the barrier chain (A-163 as amended by A-168)
- §17 rc.2 ships without fee replacement (A-164)
- §18 Operator-signed outbox clearance; `keyExposure`; `CONFLICT_RESOLVED` (A-165 as amended by A-169)
- §19 `irontrellis-profile-manifest/1` and the trust root (A-167)
- §20 The outbox signer test (A-185.2)
- §21 Core Appendix E pointers E-32…E-39

---

## 1. Scope, the Core boundary and terms

**1.1 Boundary.** Anchoring and federation are outside Core; the Core-side statement of that boundary, the SECURITY sentences, the pre-dispatch barrier as a host/writer policy with no Core refusal code, and the rule that a committee holding an owner key holds one signature toward `M` are Core §7.4 [A-94.0] [A-94.1] [A-94.2] and are not repeated here. Every rule of this document is a deployment-profile, writer, ceremony, outbox, connector or report-level rule in the sense of A-94.1 and Core Appendix G. A history that violates any of them replays identically. [A-140] [A-141.0]

**1.2 Terms.** *Committee co-signing key*: an owner key (`{keyId, scheme: "ed25519", credential}` in `K`) whose signature is produced by a committee under a disclosed quorum rule (threshold custody per Core §6.4, or a remote signer per Core §6.5.8 [A-92.4]). *Validator vote key*: a key that signs consensus votes or commits of the federation engine. *Chain-publisher key*: Core §7.4 [A-94.2]. `τ(p)`, `hc(e)`, `PR_eff`, `cls`: as in Core §6.5.1 and §6.5.3. *Operator key*: §18 [A-165.1]. [G6.6 terms]

**1.3 Report-level means report-level.** Every `verify` listing this document feeds is report-level and never a refusal; every barrier state it defines (`ELIGIBLE`, `DELAYED`, the finality labels) is a report state, never a Core refusal code (§9, Core §7.4 [A-94.1]).

## 2. Committee co-signing key: class, separation, custody

Extension B of the 11 Oct proposal. Profile and ceremony rules; no replay change.

**2.1 Ruling.** [A-140.0] A committee key MAY be a member of `K` under Core §6.5.2–§6.5.3 exactly as built. It holds one signature toward `M_eff` (Core §7.4 [A-94.2]). It is classed **`AGENT`**; the agent rules (Core Appendix F F.2 invariants 8 and 9; the resume-root rule of Core §7.4; T2's `hc` of Core §6.5.6) are its guardrails and are what make "a committee is not an owner" mechanical. No third key class is introduced.

**2.2 Class (ceremony MUST; `verify` listing).** [A-140.1] A deployment that enrols a committee co-signing key MUST set `keyClasses[keyId] = "AGENT"` for it in every policy that names it. Under `ATTESTED` no attester MAY issue a statement whose `subject` is a committee key (the predicate of Core §6.5.5 is false of a committee; Core refuses the contradiction with an `AGENT` class by Core §6.5.2 attestation validity rule 3 and otherwise classes the key `NONE`). The listing — every `AGENT`-classed key whose label (Core §6.5.2 `labels`) names a committee, and every policy with no `AGENT` entry in which a label names a committee — is Core §18's (report-level, never a refusal).

**2.3 Separation (ceremony MUST).** [A-140.2] The committee co-signing key MUST be distinct from every validator vote key of the federation engine (a vote key signs arbitrary bytes and would be a signing oracle for the Core §6.1 challenge; Core §6.3 dedicated-key rule), from the chain-publisher key (Core §7.4 [A-94.2]), and from every session and counterparty credential (the owner-key rule of Core §6.5.4 refuses the adopting rotation otherwise). It MUST NOT be the sole signer of a pin or anchor-log entry that the deployment relies on as a resume root (Core §7.4: an `AGENT`-signed `/2` attestation validates a prefix and serves rollback detection, never a resume). The operator key of §18 is likewise distinct from the committee key, as from every owner key, the publisher, vote keys and session and counterparty credentials [A-165.1].

**2.4 Commitments and recovery (ceremony MUST).** [A-140.3] A committee key MAY be committed as a next key and revealed by an ordinary rotation (the Core §3.3 key test and `nextKeyAuthorizations` of Core §6.1 apply as to any key). It MUST NOT be a recovery signer: under `DECLARED` a revealed recovery signer is `HUMAN` by declaration (Core §6.5.4), which a committee cannot honestly be; under `ATTESTED` it cannot count (no statement). A deployment with `recovery` set MUST NOT commit a committee key.

**2.5 Power reduction and rotation (restated consequences, no new rule).** [A-140.4] A committee key may appear in `S(e)` and count on a `PR_eff` event (Core §6.5.3) but is never required for one (invariant 32; Core §6.5.2 rule 10) and never the floor (invariant 8). It never counts on `OWNER_KEYS_ROTATED` (invariant 9). Hence: a committee can neither reduce power alone nor block a reduction, and `M_rot` human-class keys can always rotate a dead or hostile committee out. The exact form of "can always rotate it out" is the N3 theorem, **Core Appendix F F.7** [A-151.3]: removal under H0 with `≥ M_rot` current `HUMAN` holders and, out of a committed epoch, a held committed key revealed with its proof of possession; `LAPSED` contributes nothing; restoration is a separate capability. This section's claim is read as F.7 (a) under its premises and never as a claim for `LAPSED` holders or outside H0.

**2.6 Quorum loss (SECURITY; writer).** [A-140.5 as amended by A-151.1] Loss of committee quorum is a ceremony failure of one signer (Core §6.5.8 [A-92.4]), never a relaxation of `M`. Types whose `M_eff` the remaining qualifying keys cannot meet are blocked until a rotation. A `PR_eff` event is never blocked by the committee's loss: invariant 32 bounds `byType[T]` for `T ∈ PR_types` by the non-agent credentials, so a counting set without the committee exists whenever the human-class holders of L3/L4/L9 (Core Appendix F F.3) exist. A `STATE_CHECKPOINT` is available exactly when a counting set without the committee meets `M_eff(STATE_CHECKPOINT)`, the floor (one `HUMAN` or `LAPSED` entry) and T2 at the intended timestamp (Core §6.5.8 [A-119.3]); Core §6.5.2 rule 10 does not bound `byType.STATE_CHECKPOINT`, so a valid policy with `byType.STATE_CHECKPOINT = N` makes the committee necessary for checkpoints and blocks them until a rotation changes the policy. A rotation removing the committee is available to `M_rot` current `HUMAN` holders under H0 (Core Appendix F F.7); under `ATTESTED` with fewer than `M_rot` current `HUMAN` holders the only type-26 event is a restoration, which keeps every key. A writer holding only the committee key reports `CHECKPOINT_SUPPRESSED {reason: NO_SIGNER}` for automatic checkpoints; a federated writer MUST hold, or be able to reach, a human-class signer for `M_eff(STATE_CHECKPOINT)`.

*Chain note.* A-140.5's second sentence as first written ("`PR_eff` events, `STATE_CHECKPOINT` and every rotation are not [blocked]") was accepted as a wording defect by A-151.0: `STATE_CHECKPOINT ∈ LOW_types` but `∉ PR_types`, so rule 10 does not bound it, and `byType.STATE_CHECKPOINT = N` is a valid policy under which the committee is necessary for every checkpoint. For `PR_eff` events the claim is a theorem (invariant 32); for rotations it holds only with `M_rot` current `HUMAN` holders. No replay rule, code or policy-validity rule changes. [A-151.0]

**2.7 Recommended shape (SHOULD).** [A-140.6] [A-151.2] `threshold: 1`; `byType.OWNER_KEYS_ROTATED ≥ 2`; at least two human keys; `byType[T] ≥ 2` on the types the committee is to co-sign; `byType[T] = N` where the committee's signature is to be necessary for `T` (accepting that any one unavailable key then blocks `T`). "One human plus the committee at `threshold: 2`" is refused at policy time (Core §6.5.2 rule 6), correctly. `byType.STATE_CHECKPOINT` SHOULD be `1` (Core Appendix G G.2 (8)) and SHOULD NOT exceed the number of non-`AGENT` credentials of `K`: the committee's signature SHOULD never be necessary for a checkpoint, which adds no authority (Core §6.5.3). `byType[T] = N` is for types the committee is to gate, never for `STATE_CHECKPOINT`. The listing of every policy whose `byType.STATE_CHECKPOINT` exceeds the number of non-`AGENT` credentials of its epoch is Core §18's (report-level, never a refusal; it joins the §2.2 listings). Extending rule 10 to `STATE_CHECKPOINT` is **E-34** (Core Appendix E): post-rc.2, not adopted, non-additive, since a policy valid today would become invalid. Expressing "the committee plus any one human" without `byType[T] = N` is **E-32** (§7.5).

**2.8 Code, stage and tests.** [A-140] [A-151.2] None in replay; the writer pre-check is unchanged (`CONTROL_AUTHORIZATION_INVALID {required, present}`, `CHECKPOINT_SUPPRESSED`, Core §6.5.8); report-level listings in `verify`. Additive: yes (no Core rule; the key is an ordinary `AGENT` credential). Vector impact: none. Builder tests: (i) a policy with an `AGENT` committee key at `byType.AUTHORITY_GRANTED = 3`, `N = 3`: grant with all three accepted; with two humans refused; rotation removing the key by two humans accepted with the committee's signature listed as non-counting. (ii) The probe's policy (`threshold 1`, `OWNER_KEYS_ROTATED 2`, `STATE_CHECKPOINT 3 = N`, `C` `AGENT`): checkpoint by H1, H2 refused `CONTROL_AUTHORIZATION_INVALID {required: 3, present: 2}` and `CHECKPOINT_SUPPRESSED {reason: NO_SIGNER}` reported by a writer holding H1, H2; rotation by H1, H2 removing `C` accepted; `verify` lists the policy.

## 3. Committee time bound

Extension C of the 11 Oct proposal. A federated-profile vote rule; no Core clock.

**3.1 Ruling.** [A-141.0] A federated profile MAY bound committed timestamps without giving Core a clock, as a **vote rule** of each member, not as a replay rule. It has no refusal code (the A-94.1 pattern: the pre-dispatch barrier, Core §7.4). A history that violates it replays identically; the bound is a property of the profile's evidence, not of the history.

**3.2 Rule (profile MUST, where selected).** [A-141.1] A member MUST NOT vote for a batch containing a ◆ event `e` at `p` unless `e.timestamp = τ(p)` or `e.timestamp ≤ now_member + δ`, where `now_member` is the member's own clock at vote time and `δ` is the profile's disclosed tolerance (milliseconds). A profile MAY apply the same rule to ◇ and ▲ events. The `= τ(p)` clause keeps the `max(now, head.canonicalTime)` write of Core §6.1 [A-22.3] admissible after an earlier advance and mirrors T2's form (Core §6.5.6). The rule MUST be mechanical and disclosed so that a well-formed owner event is never permanently refused: a writer whose event fails it re-prepares at an admissible time (the two-phase write of Core §6.5.8; the challenge binds `previousHead`, so no stale consent is re-signed).

**3.3 What it claims and does not.** [A-141.2 as amended by A-155.1] [A-155.0] The operative predicate of §3.2 is `timestamp = τ(p) ∨ timestamp ≤ now_member + δ`: an **upper** bound against each voter's **vote-time** clock with the head-time exception; "within `δ`" adds no lower proximity requirement. Claim: *under the disclosed assumption that every commit contains `q` distinct honest voters who apply §3.2, each committed covered timestamp equals its prior head time `τ(p)` or is at most each such voter's vote-time clock plus `δ`. The same upper bound holds against a voter's commit-time clock reading only when that reading is no smaller than its vote-time reading (a per-member nondecrease the profile may disclose as an assumption). No lower proximity bound and no real-time bound follows (Core Appendix F F.2 item 37; Core Appendix E E-23). `q` counts distinct honest voters, not every member of a quorum that may contain faulty voters.* Not claimed: real time (item 37 stands; Core has no clock, E-23); anything about a history whose canonical publication is not the committee's commit; protection against a common clock fault. No additional clock or commit relation is part of the disclosed profile by default; a profile MAY disclose a per-member clock relation as an **assumption**, never as a vote or replay rule. Under `ATTESTED` the rule composes with T2 (both hold); under `DECLARED` it is the only bound and it is evidence.

*Chain note.* A-141.2's first claim sentence ("within `δ` of `q` members' clocks at commit, or equal to the head's") overstated the rule twice, two-sided and commit-time, and is replaced by the claim above; `VoteClockBoundary.lean` is accepted. [A-155.0]

**3.4 Code, stage and tests.** [A-141] [A-155.2] None; federation wrapper, vote stage. Additive: yes. Vector impact: none. Builder test (P5 lane): a ◆ event at `now + 2δ` is not committed; the same event re-prepared at `now` is; a `PR_eff` event at `τ(p)` with `τ(p) > now + δ` is committed. The `now + 2δ` example is read with `δ > 0` and `timestamp ≠ τ(p)`; at `δ = 0` or at the head time the predicate decides as written and the example does not apply.

## 4. Anchor-time bracketing: the evidence `verify` consumes

Construction H of the 11 Oct proposal. The listing itself — "event time ahead of its anchor", `T(p) = min{T_i : h_i ≥ p}`, the fixed `δ = TIME_LISTING_SKEW_MS = 300,000` ms, unbracketed tails — is **Core §18** [A-181.1] [A-181.2] [A-181.4] and is not restated. This section fixes what the profiles supply to it.

**4.1 Inputs.** [A-181.4] [A-181.2] `A` is the set of verified anchors in **`CONSENSUS_VERIFIED`** mode supplied to `verify`: each is an `irontrellis-anchor-statement/1` (§6) verified per §6.3 together with its `irontrellis-anchor-verify-report/1` (§14), with head position `h_i = statement.head.position` and block time `T_i = report.finality.l1BlockTime` (§14 [A-181.3]: the header timestamp of the L1 block at `l1Level`, from the independently administered validating L1 node of §8.3 (ii); `null` unless `mode = CONSENSUS_VERIFIED`). Only anchors verified in `CONSENSUS_VERIFIED` mode bracket; `TRUSTED_NODE` anchors are listed separately as "trusted-node evidence (not bracketing)" and never make a tail bracketed. Monotone anchor sequences are not assumed: a §11 migration (A-158.5) restarts `sequence` under a new instance, which is why `T(p)` is a minimum over every anchor whose head is at or past `p`, not the anchor whose interval contains `p`.

**4.2 Chain time is evidence.** [A-142.1] [A-181.3] Chain time is evidence about when a prefix became public; it is never used in replay and never changes a verdict (Core §7.4 [A-94.1]). `l1BlockTime` is chain evidence, never a clock reading; the L2 block time is not used (sequencer-controlled; refutable until `CEMENTED`, §8.4).

**4.3 TEST anchors.** [A-183.2 (iii)] [A-181.2] `verify` brackets with TEST-class anchors (§10) under the label "bracketed (test chain)", never as production bracketing. A TEST anchor brackets only when its report is in `CONSENSUS_VERIFIED` mode against the test chain's L1 (§10.2 (ii)); a TEST anchor in `TRUSTED_NODE` mode is trusted-node evidence like any other and carries no `l1BlockTime`. [E-M3, erratum candidate (decision 4ct)] `TRUSTED_NODE` anchors never bracket, whatever the class.

*Chain note.* [A-181.1] [A-181.2] [A-181.4] A-142.1 as first written listed ◆ events only, read `δ_r` as a reader option defaulting to `maxClockSkewMs`, admitted anchors "labelled consensus-verified or trusted-node", and listed events with `timestamp < T_{i−1} − δ_r`. A-181 gives one rule for ◆, ◇ and ▲ with a fixed `δ` (A-180.1's constant), narrows the evidence class to `CONSENSUS_VERIFIED` (founder 4am; §8.2), adopts the builder's earliest-anchor rule, and **withdraws** the "behind" clause: an event written between an anchored head and that anchor's inclusion legitimately carries a time earlier than the inclusion time, so the clause reported expected behaviour, not an anomaly.

**4.4 Code and stage.** [A-142] [A-181] None; report (Core `verify`) plus the external codec of §14. Additive: yes. Vectors: none in Core; external report vectors gain `l1BlockTime`.

## 5. Anchored PHL status registry

Extension E of the 11 Oct proposal. A ceremony-profile rule.

**5.1 Rule.** [A-143.1] A PHL attestation profile MAY anchor its evidence registry's status log under the `external-anchoring` profile rules. The registry remains outside replay and export (Core §6.5.5 [A-93.5] unchanged). The anchored commitment MUST be a salted, registry-wide commitment (per-subject digests MUST NOT be published on a public chain: cadence correlates subjects, the row-20 ability). What it supports: a status asserted at time `t` can be checked against the committed cutoff then in force; a withheld revocation is detectable only under an append-only, anchored log with a stated freshness policy.

**5.2 Code and stage.** None; ceremony profile. Additive: yes. Vector impact: none. [A-143]

## 6. `irontrellis-anchor-statement/1`

The external contract's first half: bindings and canonical rule frozen. [A-144]

**6.1 Encoding.** [A-144.1] Closed schema. Canonical text per Core §3.1; digest = `hashCanonical(statement)` (Core §3.2). Every optional field is written as explicit `null`, never omitted (the Core §7.2 convention; the `policy?` exception of Core §7.2 does not apply here). Scalars per Core §3.3. The statement carries no owner signature and is never a Core event, challenge or record (Core §7.4 [A-94.0]); the owner's object is the `/2` head attestation (Core §7.4), bound by digest and retained off-chain with the evidence bundle; the chain transaction authenticates the publisher (Core §7.4 [A-94.1]). Key order is fixed by canonical sorting and is irrelevant to safety; the distinct `version` literal is what keeps the bytes disjoint from every `irontrellis-*/2` challenge and attestation.

**6.2 Fields (all required unless `| null`).** [A-144.2]
```
{ version: "irontrellis-anchor-statement/1",
  domain: <genesis domain as written>,
  historyId: ContentHash,                       // recordHash(0)
  genesisEventHash: ContentHash,                // eventHash(e0), §3.2 glossary
  profile: { id: Identifier, manifestHash: ContentHash },
  head: { hash: ContentHash, position: U53, canonicalTime: U53 },
  stateRoot: ContentHash,
  projectionHead: ContentHash | null,           // null iff the genesis turned the projection off
  attestationDigest: ContentHash,               // hashCanonical(the /2 attestation object as written)
  sequence: U53,
  predecessor: ContentHash | null,              // digest of statement sequence−1; null iff sequence = 0
  previousHead: { hash: ContentHash, position: U53 } | null,   // predecessor's head, short; null iff sequence = 0
  chain: { id: ProtocolString, destination: ProtocolString },
  evidence: { manifestDigest: ContentHash | null, certificateDigest: ContentHash | null, checkpointEventId: Identifier | null },
  availability: Identifier }
```
`profile.manifestHash` is read with the manifest of §19 (A-167); `evidence.manifestDigest` is not the profile manifest's hash and is unchanged (§19.4 [A-167.4]); the `availability` literals are §12.5 (A-159.4: `ANCHOR_ONLY` | `BODIES` | `BODIES_AND_ARTIFACTS`); `sequence` restarts at `0` under a new instance (§11, A-158.5).

**6.3 Verifier obligations (restated from `external-anchoring`).** [A-144.3] `predecessor`/`previousHead` consistency; the Core prefix at `head` extends `previousHead` (replay or an approved extension proof; a rising `sequence` proves nothing); `attestationDigest` resolves to a `/2` attestation that verifies per Core §7.4 at `head`; `stateRoot`/`projectionHead` equal `rootAt`/projection head at `head.position` (Core §7.1, §12). Transaction hashes and fee replacements are outbox records, outside the statement (§16–§18).

**6.4 Status of the contract.** [A-144.4] *Open; A-186.5.* **Not frozen:** the federated commit-certificate bundle (pending CometBFT qualification; the `h`/`h+1` relation stays a certificate fact) and any contract bytes. Of what A-144.4 listed as still needed: the profile-manifest schema is §19 (A-167); outbox states and assurance labels are §16–§18 (A-163/A-168, A-165/A-169) and §8 (A-150); per-connector chain rules are §8 (A-150) and §14 (A-161); the `availability` literals are §12.5 (A-159.4). The builder-produced statement vector with its digest reproduced by the independent checker is external (`anchor-statement/v1/*`, builder-pinned, checker-reproduced) and, like every external vector, unfrozen until the live claim (Core P.8).

**6.5 Code and stage.** None in Core; external contract. Additive: n/a (outside Core). Vector impact: none in Core. [A-144]

## 7. rc.2 scope, IronTrellisLiveChainAnchor and labels

**7.1 IronTrellisLiveChainAnchor, the live public anchoring milestone.** [A-145.1 as amended by A-182.1] The minimum honest scope of live recording, kept as the **definition of the "live public anchoring" milestone IronTrellisLiveChainAnchor**, which is post-rc.2: A-144 frozen and vectored (§6); durable outbox with stable submission identity (§16–§18); at least one public mainnet connector in consensus-verified mode (trusted-node is a separately labelled weaker profile, never a fallback; §8); pre-dispatch barrier as the default governed-effect path with a separate emergency-stop boundary; verifier reports with continuity check and FINALIZED mode label (§14); installer responsibility statement; test networks never satisfy a production profile (§10). `ANCHOR_RECORDED` stays optional (Core §7.4). *Status: post-rc.2 (founder decision 4bn, A-182.1); IronTrellisLiveChainAnchor is not an rc.2 gate.*

**The headline word.** [A-193.2] [A-193.3] A-145.1's "FINALIZED mode label" is the headline word **LiveChainFinalized** (founder decision 4br): a report of §14.2 earns it iff (a) its `(chainId, profileId)` derives class `PRODUCTION` under §10.1; (b) `finality.mode = CONSENSUS_VERIFIED`; (c) `finality.label` is at or past `L1_FINAL` in §8.1's order (`L1_FINAL` or `CEMENTED`); (d) `continuity.contradiction = false`. The §8.4 sentence is printed beneath it unchanged. No `FINALIZED` literal exists in any schema; §8.1's literals are unchanged. It is a printed or listing label only (§14.2 "Printed headline"), never a field of the `/1` report, the barrier record, the statement, the manifest payload or the trust root; a field would be a `/2` report revision (Core Appendix E E-43, not adopted). TEST-class profiles never print it (§10.2 (iv)).

**7.2 What rc.2 ships.** [A-182.1] The live Etherlink mainnet connector is deferred past rc.2 (4bn, overriding 4w's launch default). *"IronTrellisLiveChainAnchor is not an rc.2 gate (founder 4bn). rc.2 ships: A-144 frozen and vectored; the durable outbox (A-165, A-169); the pre-dispatch barrier code path; the A-158 namespace and A-159 persistence semantics; the mainnet production profile **defined** and vectored where no mainnet evidence is needed; and the Shadownet TEST profile of A-183 exercised live (4aq). rc.2 makes no production-anchoring claim: installations run local-only, or Shadownet-test anchoring under A-183."* Readings fixed for part 2 by the same ruling: A-161.0's "rc.2-required" reads "required for IronTrellisLiveChainAnchor"; A-161's founder-run node evidence and the `l1-final-consensus-verified` positive vector move to IronTrellisLiveChainAnchor (A-161's negatives stay rc.2); A-158.0's "rc.2 … because the rc.2 default tier needs a destination" reads "rc.2 (the TEST profile needs a destination; IronTrellisLiveChainAnchor the production one)". A-145.2 and A-159/A-160's withheld labels are unchanged.

**7.3 rc.2 claim wording (for README, IETF status and the DevTrack report).** [A-182.2 as restated by A-193.4] *"rc.2 records histories on Etherlink Shadownet (chain 127823) under a test profile and reconstructs them publicly; live public anchoring on Etherlink mainnet in consensus-verified mode (the IronTrellisLiveChainAnchor milestone, whose verifier reports will print the headline LiveChainFinalized) is defined, partly vectored, and deferred past rc.2."* [E-M1, erratum candidate (decision 4ct)] One founder-run demonstration record on Etherlink mainnet under the production id, cited with its `TRUSTED_NODE` report mode, is neither live public anchoring nor the milestone; §8.2's TEST-only rule is the barrier mode, not the report mode.

**7.4 Federation labels.** [A-145.2] "Federated anchoring" is claimable only with P4 exit evidence on independently administered hosts; "federated execution" only with P5 exit evidence. Until then the label is withheld. The witness quorum of `WITNESSES_BOUND` (`policy.quorum`) is available today and is described as what it is: a quorum of witnesses. *Status: open; gated on P4/P5 exit evidence (A-145.2; A-186.5); unchanged by A-182.1.*

**7.5 E-32.** [A-145.3] `ownerPolicy.required?: { [eventType]: [keyId] }` — named keys that must be among the counting set for a type, so that "the committee plus any one human" is expressible (today only `byType[T] = N` makes a key necessary, at the cost of needing every key). Post-rc.2, additive, guarded; not needed for rc.2. Carried as **Core Appendix E E-32** (§21). E-18 and E-20 unchanged.

**7.6 Code and stage.** None (ruling; text). Vectors: A-161's negatives stay rc.2; the positive and the founder-node evidence move to IronTrellisLiveChainAnchor. [A-145] [A-182]

## 8. Etherlink finality for the launch connector

Per-connector chain rule (A-144.4); founder decision: Etherlink first. [A-150]

**8.1 Labels.** [A-150.0] Finality labels, strictly ordered: `SUBMITTED` (sent to the sequencer) < `L2_INCLUDED` (in an Etherlink block) < `L1_POSTED` (the blueprint/inbox message carrying the transaction is in a Tezos L1 block) < **`L1_FINAL`** (that L1 block is Tenderbake-final: at least two L1 blocks built on it, which is ~12 s per the founder, not the ~6 s single-block "layer-1 confirmation" of the Etherlink docs) < `CEMENTED` (the rollup commitment covering the L2 block is cemented after the refutation period). Mode labels, orthogonal: `CONSENSUS_VERIFIED`, `TRUSTED_NODE`, `UNVERIFIED` (Continuity's historical label). Continuity's `TRUSTED_OWN_NODE_DIRECT_CHECKPOINT_TIP` maps to `TRUSTED_NODE`. Shadownet (chain 127823) evidence never satisfies a production profile (§7.1, §10.1); the launch connector is Etherlink **mainnet**. Label and mode literals are closed; the report that carries them is §14.

**8.2 Barrier.** [A-150.1] The pre-dispatch barrier waits for **`L1_FINAL` in `CONSENSUS_VERIFIED` mode**. `CEMENTED` is a second, later label written to the report when observed; it is not waited for (two weeks is not a dispatch latency). `TRUSTED_NODE` never satisfies the barrier of a production profile and is never a fallback (§7.1). `L1_FINAL` stays the rule for every `CONSENSUS_VERIFIED` barrier, TEST profiles included; 4av's post-rc.2 "IronTrellis-defined finality" changes nothing here (§10.2). A TEST-class profile that declares the trusted-node barrier mode of §10.2 (ii) marks `ELIGIBLE` at `L1_FINAL` in `TRUSTED_NODE`; that mode exists for the TEST class only and never reaches a production profile [A-195.1].

**8.3 What makes `L1_FINAL` consensus-verified.** [A-150.2] All of: (i) an Etherlink EVM node tracking a rollup node answers `eth_getBlockByNumber("finalized")` at or past the L2 block, and the rollup node yields the L1 level and operation hash at which that block's blueprint/inbox message was included; (ii) an **independently administered, validating Tezos L1 node** (different administrative control from the node in (i); a full validator, not an RPC relay or explorer) reports that L1 block at that level in its chain with level ≤ its head − 2, and the inbox message at that level and operation hash contains the expected bytes (or their hash); (iii) both node identities (chain id, protocol, software commit, operator) are recorded in the report with the L1 level, block hash and operation hash. (i) alone, or a public RPC/explorer, is `TRUSTED_NODE`. Own rollup-node re-execution is **not** a substitute for (ii): it re-derives L2 state, which stays refutable, and is under the installer's own administration; it is welcome as extra evidence under its own label `OWN_ROLLUP_REEXECUTED`. The founder's live production Tezos node is not touched without the founder's explicit go-ahead; if used, it counts as (ii) only if it is not also the node of (i). The node of (ii) is also the source of `finality.l1BlockTime` (§4.1, §14).

*Status: the definition is in force for every `CONSENSUS_VERIFIED` barrier. Its live evidence — an installation shown to meet (i)–(iii) on Etherlink mainnet, the founder-run node evidence and the `connector/etherlink/l1-final-consensus-verified` positive vector — is **open; IronTrellisLiveChainAnchor, post-rc.2** (A-150.2 with A-161; A-182.1; A-186.5). Where no independently administered validating Shadownet L1 node exists, the TEST profile runs `TRUSTED_NODE` and says so (§10.2 (ii)).*

**8.4 Refutation residual, disclosed.** [A-150.3] At `L1_FINAL` the **inclusion and order of the transaction bytes in the Tezos inbox are final**; the **L2 execution** (contract state, receipts, the Etherlink block itself per the docs) remains refutable until `CEMENTED`. The report MUST carry `finality: {label: "L1_FINAL", mode: "CONSENSUS_VERIFIED", l1Level, l1BlockHash, operationHash, refutationResidual: "OPEN", cementedAt: null}` and the FINALIZED-mode sentence: *"L1-final; the rollup commitment covering this block may still be refuted until approximately <L1 level + refutation period>; execution-dependent facts are not final."* `cementedAt` and `refutationResidual: "CLOSED"` are written only on observed cementation. The full report shape, `cementedAt` as an L1 level, and `l1BlockTime` are §14 (A-161.1, A-181.3).

**8.5 Genesis `finality`.** [A-150.4] Unchanged: `finality: "LOCAL_ONLY"` describes Core (no external finality in replay, Core §5.1). Connector finality lives in the profile manifest (§19) and the report (§14). A genesis `finality` literal naming a connector finality class is **Core Appendix E E-33** (post-rc.2, format minor, not adopted; nothing needs it; §21).

**8.6 Code, stage and vectors.** [A-150] None in Core; connector profile, outbox and report. Additive: n/a (outside Core). Vector impact: none in Core; one external connector vector `connector/etherlink/l1-final-consensus-verified` (report bytes, checker-reproduced; moved to IronTrellisLiveChainAnchor by A-182.1) and one negative `…/trusted-node-not-final` (rc.2).

## 9. The replay verdict and the certificate barrier are two outputs

Samurai N4; `CertificateSeparation.lean` accepted. [A-154]

**9.1 Ruling.** [A-154.0] Core §7.4 [A-94.1] is read as Astra reads it: the Core replay verdict is **certificate-invariant**, and the pre-dispatch barrier is an **external** decision that requires both replay acceptance and the certificate. The N4 task sentence's "never refuses one replay admits on certificate grounds alone" is **withdrawn as an unconditional property**: `wrapped(true, false) = false` while the Core verdict is `true`. The barrier never *refuses* in the Core sense; it **delays**.

**9.2 Wording (profile text).** [A-154.1] *"The replay verdict and the dispatch eligibility are two outputs. (1) Core replay accepts or refuses an event from the history alone; no certificate, anchor or quorum is an input to it (Core §7.4 [A-94.1]). (2) The external barrier marks an event `ELIGIBLE` iff replay accepted it and a valid certificate (or the connector's finality per §8) is held, and `DELAYED` otherwise; `DELAYED` is a report state, never a Core refusal code. Soundness: the barrier never marks `ELIGIBLE` an event replay refuses. Completeness is conditional: the barrier's eligible set equals the replay-accepted set iff every replay-accepted event in the covered range holds a valid certificate (certificate completeness); A-94.1 does not supply that premise, and the outage barrier of the anchoring design is exactly its failure. A verifier compares only the statements it is given; a conflicting anchor it has not seen is outside its knowledge (A-94.1's first sentence)."* Off-chain judging under path B (§10.3) is replay under these two outputs.

**9.3 For the formalizers.** [A-154.2] Expose `coreVerdict` and `eligible = coreVerdict ∧ certificate` as two functions; prove soundness unconditionally and completeness under the named premise `∀ e, replay e → certificate e`; keep the `(false, true)` counterexample as a regression. No premise that the certificate is available is asserted anywhere.

**9.4 Code and stage.** None; federation wrapper and report. Additive: yes. Vector impact: none. [A-154]

## 10. Profile classes, the Shadownet TEST profile and path B

AR-07. [A-183]

**10.1 Classes.** [A-183.1] Every anchoring profile has a **class**, `PRODUCTION` or `TEST`, derived at rc.2 from a closed table of `(chain.id, profile.id)` pairs in the gateway and `verify` (no manifest field; a `class` field is E-39): `(eip155:42793, <the production profile id R9 pinned>) → PRODUCTION`; `(eip155:127823, <that id with the segment `etherlink-shadownet-test` in place of its mainnet segment>) → TEST`. The builder states both literals in DEVIATIONS. Any other pair is `TRUST_ROOT_INVALID` (§19). `LIVE_ANCHOR_CHAIN` becomes this table. §8.1's "Shadownet never satisfies a production profile" and the `shadownet-chain-refused` vector of §14 stand for the PRODUCTION profile (production id with chain 127823, or chain 127823 under any PRODUCTION id → `TRUST_ROOT_INVALID`). The table binds every loader of a trust root, the outbox included: it is check (T6) of §19.3, held in one shared module used by the outbox, the gateway and `verify`, and the outbox's enqueue-time chain check is the §19.4 equality `statement.chain.id = T.manifest.chain.id` against the loaded, classified trust root, never "any `eip155:` chain" [A-195.2]. The production id is the literal R9 pinned if the coordinator produces that record; otherwise `irontrellis-anchoring-profile/etherlink-mainnet/1`, with the TEST id `irontrellis-anchoring-profile/etherlink-shadownet-test/1` by the substitution above [A-195.3].

**10.2 TEST profile rules.** [A-183.2] [A-195.1] (i) A TEST profile satisfies the pre-dispatch barrier **only** under an explicit gateway opt-in `anchoring.allowTestProfile: true` (CLI `--allow-test-anchoring`), logged on every open; without it `openAnchorBarrier` refuses `TRUST_ROOT_INVALID {reason: TEST_PROFILE_NOT_ALLOWED}`. (ii) Labels, modes, barrier (`L1_FINAL` in `CONSENSUS_VERIFIED`, §8.2) and the §14 codec apply unchanged, measured against the test chain's L1; where no independently administered validating Shadownet L1 node exists, the TEST profile runs `TRUSTED_NODE` and says so, through the gateway setting **`anchoring.testBarrierMode`** (the mode a TEST profile's barrier is measured in: `"CONSENSUS_VERIFIED"`, the default, or `"TRUSTED_NODE"`; CLI `--test-barrier-mode trusted-node`): the `TRUSTED_NODE` value is admitted only for a TEST-class profile under the opt-in of (i), is logged on every open beside it, and on a PRODUCTION-class profile `openAnchorBarrier` refuses `TRUST_ROOT_INVALID {reason: TRUSTED_NODE_BARRIER_NOT_ALLOWED}`; under it the barrier marks `ELIGIBLE` at `L1_FINAL` in `TRUSTED_NODE` (`l1BlockTime: null`), the barrier record's `mode` (§16.4) says so, every surface of (iii) adds "trusted-node barrier", such anchors never bracket (§4.3), and nothing dispatched under them is claimable beyond (iv) [A-195.1]. (iii) `status()`, reports as printed, evidence bundles and `verify` listings carry the class ("test network; no production finality claim"); `verify` brackets with TEST anchors under the label "bracketed (test chain)", never as production bracketing (§4.3). (iv) A TEST profile may claim: *"recorded on Etherlink Shadownet and publicly reconstructed (format 2; parity with Continuity Sessions 12–13)"*; it may never claim "live public anchoring", "production anchoring", "federated anchoring/execution" or any §7.1 label. (v) The 4aq guardrails (chain 127823 only, key in place, journal-before-submit, spending guideline) are operator rules of the TEST profile; Core Appendix G G.6 points here for them. 4av's post-rc.2 "IronTrellis-defined finality" changes nothing here: `L1_FINAL` stays the rule for every `CONSENSUS_VERIFIED` barrier.

**10.3 Path B (4au) mapped.** [A-183.3] *"Record on chain, judge off chain"* is the **§11 namespace instance plus the §12 persistence closure at `availability: BODIES`** (body descriptors with chunks; the descriptor index's `previousHash`/`recordHash` chain is the per-event on-chain hash chain of 4au) under the TEST class, with §6 statements per head for order, time and anchor; judging is off-chain replay under §9's two outputs. A hash-only variant (descriptors without chunks) is not a §12 literal and is not adopted (**E-38**, §21). The optional on-chain judging demonstration of 4au is the §13 tier-3 technique as a withheld-label lane, unchanged.

**10.4 Code, stage and vectors.** [A-183] Code: `TRUST_ROOT_INVALID {TEST_PROFILE_NOT_ALLOWED}` (gateway; outside Core). Stage: profile/gateway. Additive: yes (new class; production behaviour unchanged). New external vectors: `test-profile-refused-without-opt-in`, `test-profile-accepted-with-opt-in` (both report bytes, checker-reproduced); `shadownet-chain-refused` unchanged. A manifest `class` field replacing the §10.1 table is **Core Appendix E E-39** (post-rc.2, not adopted; deferred so that no manifest byte changes before IronTrellisLiveChainAnchor; §21).

*End of part 1. Part 2 continues at §11.*

`SPEC-IRONTRELLIS-ANCHORING-PROFILES-r1.md` — part 2 of 2 (§11–§21). Part 1 carries the preamble and §1–§10; its conventions (P.4) and precedence (P.2) apply here unchanged.

---

## 11. `irontrellis-anchor-namespace/1`: one immutable instance, discovery, migration

R8-02. Profile/external contract. [A-158]

**11.1 Ruling.** [A-158.0 as amended by A-182.1] Astra's baseline is adopted: authenticated install-selected registration, no permissionless first-writer capture, no administrative overwrite, no zero-hash/null collision. **Profile/external contract, additive (Core §7.4 [A-94.0] stands; no Core field, event or record), rc.2** for the semantics and the namespace object bytes below: rc.2 because the TEST profile needs a destination (§10); IronTrellisLiveChainAnchor the production one (§7.2). Contract **bytecode** is not frozen by the architect (§6.4, A-144.4); it is Astra/builder work vectored against the A-144 vector.

**11.2 Namespace object (bytes frozen) and its derivation.** [A-158.1] [A-167.2]
```
namespaceId = hashCanonical({ version: "irontrellis-anchor-namespace/1",
  domain: <genesis domain as written>, historyId: ContentHash, genesisEventHash: ContentHash,
  profile: { id: Identifier, manifestHash: ContentHash },
  chain: { id: ProtocolString },
  publisher: EthereumAddress (lowercase) })
```
Canonical text per Core §3.1, digest per Core §3.2; no optional field, so no `null`. It is a bootstrap commitment and never a Core event, challenge or record. `destination` is deliberately absent: the instance is the destination. For the profile-manifest payload `P` of §19.2, every field is copied from `P` or is `P`'s hash (`domain: P.domain`, `historyId: P.historyId`, `genesisEventHash: P.genesisEventHash`, `profile: {id: P.id, manifestHash: hashCanonical(P)}`, `chain: {id: P.chain.id}`, `publisher: P.publisher`); `namespaceId` is a pure function of `P`, so there is no fixed point, and the bytes above are unchanged by that derivation.

**11.3 Bootstrap and discovery.** [A-158.2 as amended by A-167.0] The destination is one immutable instance per namespace, deployed by the installer (constructor or deterministic factory) with `namespaceId`, `publisher` and `chainId` as immutables; its address is `chain.destination` of every statement it holds. There is no registry, no registration function, no owner/admin/upgrade/selfdestruct path and no mutable verifier pointer. **Discovery is by trust root, not by chain:** the trust root of §19.3 (A-158.2's "profile manifest" is read as the trust root; "the trust root's hash" is `manifestHash`), a `verifyAnchor` input (§6.3), names `destination`, `publisher` and `namespaceId`; a statement whose `profile.manifestHash` differs from the trust root's `manifestHash`, or whose `chain.destination` differs from the trust root's, is not an anchor of this history whatever any contract says (the exact binding is §19.4). A look-alike instance deployed by anyone else therefore captures nothing. Owner authentication of the manifest itself is **E-35** (§21); at rc.2 the trust root is installer-authenticated like every other profile artefact (the installer responsibility statement of §7.1).

**11.4 Acceptance rule (contract obligations).** [A-158.3] The call carries the **exact canonical statement bytes**; the retained digest is `sha256` over those bytes (equal to `hashCanonical(statement)` iff the bytes are canonical, which the outbox guarantees before signing and the verifier re-checks; a non-canonical re-encoding is a different digest and a conflict, never a collision). The contract enforces: `msg.sender = publisher`; the `"version":"irontrellis-anchor-statement/1"` literal; sequence 0 iff `predecessor` and `previousHead` are `null`; later sequences increment by exactly one, `predecessor` = retained digest, `previousHead` = retained short head; `head.position` nondecreasing, equal position ⇒ identical head and roots; an exact duplicate is idempotent (returns the retained index, no state change); any other statement at the retained sequence or predecessor reverts with no state change. Any further field is parsed, never re-encoded; the decoder's agreement with `canonical()` is vectored. Envelope checks are not prefix proofs (§6.3 unchanged).

**11.5 Nullable fields.** [A-158.4] No sentinel. In the bytes, `null` is the literal. In typed storage a nullable ContentHash is `(present: bool, value: bytes32)`; sequence 0 retains `present = false`; a zero `bytes32` with `present = true` is a value. ContentHash ↔ `bytes32` is the 32 raw bytes; the text form is lowercase hex (Core §3.3).

**11.6 Migration.** [A-158.5] No overwrite, ever. A change of profile, destination or publisher is a **new instance** under a new manifest whose `supersedes: {namespaceId, destination, lastStatementDigest, lastHead: {hash, position}}` (a payload field, §19.2) names the predecessor; the new instance restarts at `sequence 0` (§6.2: `predecessor: null`). Continuity across instances is a verifier check (manifest chain plus prefix replay from the last verified head), never a chain fact. The old instance is left as it is; a compromised or lost publisher key is handled this way (§18.4, §18.5). Any payload change is a migration (§19.6).

**11.7 Code, stage and vectors.** [A-158] [A-167] None in Core; external contract. Additive: n/a. Vector impact: none in Core; external `anchor-namespace/v1/etherlink-mainnet` (the object and digest for the A-144 vector's history, checker-reproduced; its A-167 additions are §19.7). Contract tests: duplicate idempotent, conflict reverts without state change, foreign sender reverts, sequence gap and U53 overflow revert, `present` flag at sequence 0, immutables equal the trust root.

## 12. Persistence tier: closures, descriptors, `availability` literals

R8-04. Persistence profile. [A-159]

**12.1 Ruling.** [A-159.0] Astra's baseline is adopted, as two separately named closures. **Persistence profile, additive (outside Core).** The public opt-in itself is founder-settled and is not reopened. *Status: open. rc.2 as an opt-in profile once its vectors land; otherwise the label is withheld (A-159.0, a judgement on A-145.2's principle: no label without evidence; unchanged by A-182.1; A-186.5). The semantics ship in rc.2 (§7.2), and path B uses this closure at `availability: BODIES` under the TEST class (§10.3), which claims only what §10.2 (iv) allows.*

**12.2 Replay closure.** [A-159.1] At head `h` it is the canonical bodies `canonical(e_0) … canonical(e_h)` (Core §4.2 bytes), nothing more and nothing less: from genesis `referencedEvents` is empty (A-65.4), every body a transition or Core §13.2 view reads is at a position `≤ h`, the type-40 envelope is an event body, and receipt artifacts are outside the history (`RECEIPT_RECORDED` carries hashes only; Core §8.5). "No omitted preimage" therefore means **no omitted position**. The Core §4.1 line `L_q` is reconstructed from `(previousHash, body, recordHash)` and must re-chain under Core §4.3; a reader never claims byte equality with any original whitespace-tolerant input.

**12.3 Consumer closure (named, never inferred).** [A-159.2] [A-167.5] Beyond replay, only these bytes, each bound by a digest a statement or event already carries: (a) the `/2` head attestation object of each statement's `attestationDigest`; (b) receipt artifacts (`irontrellis-receipt/2` payload plus signature) whose `receiptArtifactCommitment` an accepted `RECEIPT_RECORDED` carries, named per commitment; (c) the profile manifest bytes of `profile.manifestHash`, which are the **payload** bytes only (§19.2); the trust root is never a closure artefact because it is reconstructible from the payload and any one statement (§19.5). **Never in any closure:** chain transaction receipts, PHL registry/evidence (Core §6.5.5 [A-93.5]; §5), writer side logs and the rendered requests behind `connector.detailDigest` (A-42), the spool, and keys.

**12.4 Descriptors (bytes frozen at the canonical-text level; ABI is a contract gate as in §11.4).** [A-159.3] Body: `{version: "irontrellis-body-descriptor/1", namespaceId, position: U53, previousHash: ContentHash | null (null iff position 0), eventHash: ContentHash, recordHash: ContentHash, byteLength: U53, chunks: [{digest: ContentHash, length: U53}]}`. The body digest **is** `eventHash`; no second digest exists. Structurally complete iff `sha256(chunk_1 ‖ … ‖ chunk_n) = eventHash`, `Σ length = byteLength`, `recordHash` = Core §4.3 over `(previousHash, eventHash, position)`, and `previousHash` = the retained `recordHash` at `position − 1`; the index advances by CAS on the structural head. Artifact: `{version: "irontrellis-artifact-descriptor/1", namespaceId, kind: "HEAD_ATTESTATION" | "RECEIPT_ARTIFACT" | "PROFILE_MANIFEST", boundBy: ContentHash, byteLength, chunks}` with `boundBy` = `attestationDigest` | `receiptArtifactCommitment` | `manifestHash`. Chunk size is an implementation parameter. Holes, truncation, reordered chunks and conflicting positions never become a contiguous prefix; duplicates return the original entry. Under the TEST class the descriptor index's `previousHash`/`recordHash` chain is the per-event on-chain hash chain of path B (§10.3).

**12.5 `availability` literals (closes the A-144.4 placeholder, §6.2).** [A-159.4] `ANCHOR_ONLY` | `BODIES` (replay closure complete through `head.position` at the manifest's `bodyStore`, §19.2) | `BODIES_AND_ARTIFACTS` (plus every consumer artefact the manifest names). The literal is a publisher claim; the verifier recomputes and reports `availabilityVerified: true | false` and never trusts it. The structural index is distinct from any replay-accepted head (Astra's text, accepted); a withheld suffix is detectable only against a later known head. A hash-only literal (descriptors without chunks) is **E-38** (§21), not adopted. [E-M2, erratum candidate (decision 4ct)] `bodyStore: null` means the bodies are held in the namespace instance at the trust root's `destination` (path B, §10.3); a ProtocolString names an external store.

**12.6 Code, stage and vectors.** [A-159] None in Core. Additive: n/a. Vector impact: none in Core; external `body-descriptor/v1/*` for positions 0 and 6 of the A-144 vector's history and `artifact-descriptor/v1/head-attestation`, checker-reproduced; negatives: reordered chunks, truncated body, wrong `previousHash`, hole, `BODIES` claimed with a missing position.

## 13. Tier-3 resumable staging; `MIRROR_ACCEPTED` is evidence only

R8-05. An implementation technique for the replay-equivalent tier. [A-160]

**13.1 Ruling.** [A-160.0] **Accepted as an implementation technique**, additive, for a tier whose "replay-equivalent" label is **post-rc.2** (judgement: zero rules are gas-qualified and the port is unimplemented; rc.2 ships tiers 1 and 2 as profiles and tier 3 as a withheld-label lane, like "federated execution" under §7.4). The technique is approved now so that G1–G4 work proceeds. Core §7.4 [A-94.1] and §9 are not obstacles: the mirror is external computation whose completed result is **evidence**; Core's verdict is never conditioned on it, and the mirror never authorizes anything. *Status: label open; post-rc.2 (A-160.0; unchanged by A-182.1; A-186.5). The optional on-chain judging demonstration of path B is this lane, unchanged (§10.3).*

**13.2 Conditions.** [A-160.1] (i) The completed-result relation is **exact equality** with `Replay_E` in both directions, including the first-rejection position, code and metadata; a mirror that proves accepts only labels itself so. (ii) A staging job binds, immutably: the edition `E` (effective-text digest plus the build1 procedure identity of Core §8.1 [A-148.4]), the deployed program identity, the accepted pre-state `(head.hash, position, stateRoot, projectionHead)`, the event `position` and `eventHash`, and the complete cursor set Astra lists (parse/canonical cursor, check index, graph frontier and visited sets, counters, scratch deltas, pending root work). (iii) The only caller inputs are body bytes and a work budget; no intermediate verdict, root or state is ever supplied. (iv) Scratch effects are isolated; promotion is one atomic CAS on the accepted head; a job whose predecessor changed is `STALE`; queries expose the accepted state only. (v) Transport states are a closed external set — `STAGED, INCOMPLETE, STALE, CANCELLED, EXHAUSTED, UNSUPPORTED` — and none is, resembles or maps to a Core §8.1 `DenialCode` or a replay refusal code; `UNSUPPORTED` is a withheld-parity report, never a Core result. (vi) No new Core cap, no new refusal, no block time in any semantic step (the event's U53 `timestamp` is the only time; `LOCAL_ONLY` stands, §8.5), no change to the sorted RFC 6962 root (Core §7.1). (vii) The 512-event/16,384-record figures are harness values; **no operational completeness envelope may be advertised before G4 measures one**. (viii) The pre-dispatch barrier MAY record a mirror acceptance as extra evidence under its own label `MIRROR_ACCEPTED`; it never replaces `L1_FINAL` in `CONSENSUS_VERIFIED` (§8.2) and never shortens the barrier.

**13.3 Code, stage and vectors.** [A-160] None in Core. Additive: yes (technique; no semantic change). Vector impact: none in Core; the tier-3 lane consumes the frozen 86, nine roots, regenerated, `authorization/v2r`, owner-policy and PHL suites as data (G2/G3; Core P.8).

## 14. Connector qualification and `irontrellis-anchor-verify-report/1`, with `finality.l1BlockTime`

R8-06. Connector profile; the codec of the §8 labels. [A-161] [A-181.3]

**14.1 Ruling.** [A-161.0 as amended by A-182.1] **Connector profile, additive, required for IronTrellisLiveChainAnchor** (§7.1 needs one mainnet connector in consensus-verified mode). The labels, modes, barrier and residual of §8 are not weakened; this section closes the codec and schedules the evidence.

**14.2 Report.** [A-161.1] [A-181.3] `irontrellis-anchor-verify-report/1`, canonical per Core §3.1, `reportDigest = hashCanonical(report)`, cited by the barrier record (§16.4):
```
{ version: "irontrellis-anchor-verify-report/1",
  profileId, chainId,
  statement: { digest, historyId, head: { hash, position } },
  tx: { hash, l2Block: U53, l2BlockHash: ProtocolString },
  nodes: { evm: NodeId, l1: NodeId, ownRollup: NodeId | null },
  finality: { label, mode, l1Level: U53, l1BlockHash: ProtocolString, operationHash: ProtocolString,
              l1BlockTime: U53 | null,
              refutationResidual: "OPEN" | "CLOSED", cementedAt: U53 | null },
  sentence: <the §8.4 sentence>,
  observedAt: U53,
  continuity: { previousReportDigest: ContentHash | null, contradiction: boolean } }
NodeId = { chainId, protocol, softwareCommit, operator, headLevel: U53 }
```
`l1BlockHash` and `operationHash` are the Tezos base58check strings as the node returns them (not `0x` hex); `cementedAt` is the **L1 level** at which the cementing operation was observed included, never a clock reading (chain time is evidence only; §4.2). Label and mode literals are closed (§8.1). **`finality.l1BlockTime`** is the header timestamp of the L1 block at `l1Level` (`l1BlockHash`), in ms since the Unix epoch, as returned by the independently administered validating L1 node of §8.3 (ii); `null` unless `mode = CONSENSUS_VERIFIED`. It is chain evidence, never a clock reading and never read in replay; the L2 block time is not used (sequencer-controlled; refutable until `CEMENTED`). It is the `T_i` of the bracketing listing (§4.1; Core §18). No `/1` report has been issued (the connector is unbuilt), so the literal stays `/1`; if the builder finds a pinned `/1` report vector, it is regenerated (external vectors are unfrozen until the live claim; Core P.8).

**Printed headline.** [A-193.2] [A-193.3] The printed form of a report (CLI output, the gateway's `status()` text, the evidence bundle's human-readable index) opens with exactly one headline derived from the report's fields and the §10.1 class table, never carried as a field: `LiveChainFinalized` (§7.1: class `PRODUCTION`, `mode = CONSENSUS_VERIFIED`, `label` at or past `L1_FINAL`, `contradiction = false`), followed by the §8.4 sentence; "trusted-node evidence (not bracketing)" (`TRUSTED_NODE`, any class); "test network; no production finality claim" (TEST class, every mode; with "trusted-node barrier" added under §10.2 (ii)'s mode); "not final" (a label below `L1_FINAL`); "contradicted" (`contradiction: true`). `verify`'s per-anchor line of the §4 listing carries the same headline. The gateway's structured `status()` result MAY carry the word in its own package-convention string fields; that is not a shape of this document. A `headline` field would be a `/2` report revision (Core Appendix E E-43, not adopted).

**14.3 Freshness, bootstrap, upgrades, contradiction.** [A-161.2 as amended by A-167.1] [A-181.3] The barrier reads label, mode and identities only (builder item 8, accepted). Both `headLevel`s and `observedAt` are reported; a profile MAY disclose `maxL1HeadLag` (levels; a payload field, §19.2) beyond which a report is `STALE` and unusable (judgement). Node identities are pinned in the manifest, which pins **administration only** (`nodes`: chain id and operator, §19.2); any change of protocol, kernel, software or **operator** between observations is recorded in reports, never pinned, and a change of the independent node's administration voids `CONSENSUS_VERIFIED` until re-attested (a new payload, hence a migration, §19.6). A later report for the same statement with a different `l1BlockHash` or `operationHash` sets `contradiction: true`, blocks every dispatch relying on it and is an incident; there is no weaker-mode fallback (§7.1). The same rule covers `l1BlockTime`: same `l1BlockHash` ⇒ same time.

**14.4 Evidence and vectors.** [A-161 as amended by A-182.1] None in Core. Additive: n/a. External, builder/Astra-produced and checker-reproduced. Negatives, rc.2: `connector/etherlink/trusted-node-not-final`, `same-administration-nodes`, `shadownet-chain-refused` (read with the class table of §10.1), `substring-not-inclusion`, `cemented-by-elapsed-time-refused`. *Status: the positive `connector/etherlink/l1-final-consensus-verified` and the founder-run node evidence (a separate gate) are open; IronTrellisLiveChainAnchor, post-rc.2 (A-161 with A-150.2, §8.3; A-182.1; A-186.5).* External report vectors gain `l1BlockTime` (§4.4).

## 15. Comparison editions

R8-07. Conformance input; no rule. [A-162]

**15.1 Editions.** [A-162] The comparison edition for R8 is the builder's post-A-157 engine (`727c4e1`, vectors `255f203`, A-144 vector `9c8e027`) and checker g25 after its A-157.3 change. build1 remains the normative procedure identity of Core §8.1 [A-148.4], read with A-133–A-136, A-148, A-149, A-156 and A-157. The credential-case discrepancy is closed by A-157: master accepted uppercase before `727c4e1` (builder item 2), now `EVENT_DATA_INVALID` at C4. Astra joins batch16 and keeps three columns (build1/g25 agreement, effective-text conformance, independent derivation); shared engine agreement is never the oracle. Code and stage: none. Additive: n/a. Vector impact: none.

## 16. Outbox resume after a crash; the barrier chain

Q-ARCH-1 and G69-Q2. Gateway/Core-execution profile rule. [A-163] [A-168]

**16.1 Ruling.** [A-163.0 as amended by A-168.0] **Accepted.** The builder's own crash rule decides it: a step may be resumed only when the absence of its durable start record proves the callback never ran. `attempt.json` is created O_EXCL and fsynced **before** the single `upstream.call`, so within the stated durability scope (one host, local POSIX FS, fsync) its absence is that proof. The documented contract was written when the window was milliseconds; the barrier makes it `L1_FINAL` or an outage. The only start record is `attempt.json`; `barrier.json` records what a dispatch relied on and proves nothing about the call. Therefore the resume condition is **absence of `attempt.json` alone**, whatever barrier records exist. The existing O_EXCL barrier is never overwritten and never reused: a resume that reaches the locked section **appends its own barrier record**, and the dispatch relies on the highest-numbered record. **Gateway/Core-execution profile rule; additive (no replay rule, record kind or format changes; `barrier.json` is new, §16.4); rc.2, default on in the live-anchoring profile.** *Status: the default is a judgement (A-163.0: reconcile-only would make the operator re-declare the same business operation under a new key, leaving two intents for one operation); it stands as A-168 ruled, by founder decision 4bo, and the founder may overrule (A-186.5; Core P.9).*

**16.2 Contract sentence.** [A-163.1 as amended by A-168.1] Old (`execution.ts`, gateway): *"a committed admission is never re-invoked, including after a restart."* New, word for word: *"a committed admission whose dispatch-start record (`attempt.json`) exists is never re-invoked, including after a restart; a committed admission with no `attempt.json` has not been dispatched, whatever barrier records exist, and MAY be dispatched once, by a later `run` of the same job that passes the barrier and A-163.2, appends its own barrier record and then creates `attempt.json` with the same O_EXCL create. Exactly-once is the O_EXCL attempt file, not the process lifetime."*

**16.3 Re-checks a resume MUST pass (each failure is `NOT_DISPATCHED {reason}`, reported, never a refusal event).** [A-163.2] [A-168.3] (1) **Same admission:** the durable admission is read by `operationId`; its `admittedSubmissionIdentity` (`idempotencyKey`, `submissionFingerprint`) is recomputed and equal; the dispatched bytes are the admitted request, never re-rendered; additionally the operation's barrier chain, if any, is contiguous from seq 0 and re-hashes — else `ADMISSION_MISMATCH` (no new reason literal). (2) **History continuity:** the current local head extends the admission's head (the admission replays at its position); a rewritten or rolled-back store is `HISTORY_DIVERGED`. (3) **Intent still open:** no later event for the `intentId` (consumption, outcome, effect, cancellation) exists — `INTENT_NOT_OPEN`. (4) **Authority currency:** the ordinary post-barrier `assertCurrent` (control, session fence and expiry at the current head, epoch, stop latch) — `ACCESS_NOT_CURRENT` / `STOPPED`. (5) **Eligibility:** `ELIGIBLE(p)` (§9.2) re-evaluated on a persisted, non-contradicted report (§14.3), using the report the resumer's wait ended on; an old record's report MAY be re-used only by being re-evaluated now (persisted, non-contradicted, not `STALE`, `ELIGIBLE(p)`) — else `DELAYED` and the wait continues outside the lock. (6) **Horizon:** a profile MAY disclose `resumeHorizon` (host time or head positions; gateway configuration disclosed in `status()`, not a payload field, §19.2) beyond which the admission is `RESUME_HORIZON` and the operator re-declares. (7) **Serialization:** the resume runs on the host that owns the durable store, under the writer lock for the locked section; a concurrent resumer loses on O_EXCL.

**16.4 Barrier chain.** [A-163.3 as amended by A-168.2] A-163.3's `resumed` field is kept; two are added:
```
{ version: "irontrellis-mcp-barrier/1", operationId, admissionHead, statementDigest,
  statementHead: { hash, position }, profileId, chainId, label, mode, reportDigest: ContentHash,
  resumed: boolean, barrierSeq: U53, previousBarrierDigest: ContentHash | null }
```
Paths: seq 0 is `<op>.barrier.json`; seq `n ≥ 1` is `<op>.barrier-<n>.json`. Each is O_EXCL and fsynced; `previousBarrierDigest = hashCanonical(record seq n−1)`, `null` iff seq 0. Rules: (i) a barrier record is created only inside the locked `submit` section, immediately before the attempt create, by the holder of the writer lock, after it has read `attempt.json` absent; (ii) **no barrier record is ever created once `attempt.json` exists**; (iii) `resumed = false` iff the record is written by the `run` that appended the admission, `true` iff by the resume path (a first run that crashed before writing any barrier leaves the resumer to write seq 0 with `resumed: true`); (iv) `reportDigest` is the digest of the report on which the writing run's wait ended, re-read and re-evaluated under the lock (§16.3 (5)); it MAY equal an earlier record's; (v) the **relied-on barrier** is defined iff `attempt.json` exists and is the highest-numbered record; its `resumed` says whether the dispatching run was a resume and its `reportDigest` names the report that dispatch relied on. Earlier records are evidence of runs that reached the lock and did not dispatch.

**16.5 Resume procedure in the locked section (barrier present, attempt absent).** [A-168.3] Re-checks (1)–(4) and (6) of §16.3 unchanged, with (1)'s chain requirement and (5)'s report rule as §16.3 states them; then: append barrier seq `k+1` (`resumed: true`), create `attempt.json` (O_EXCL, fsync), the existing `assertCurrent` with the stop latch, one `upstream.call`. A concurrent resumer loses on O_EXCL (§16.3 (7)). After `attempt.json` exists everything is reconcile-only, as settled.

**16.6 Status and evidence.** [A-163.3 as amended by A-168.4] `status()`: `attempt.json` absent → `DELAYED` while a wait is open, else `NOT_DISPATCHED {reason}`; never `OUTCOME_UNKNOWN`; barrier records without an attempt change nothing. The evidence bundle lists the whole chain and marks the relied-on record. The attempt and report formats are unchanged; `report.json` binds the attempt by `attemptDigest` as before.

**16.7 Code, stage and tests.** [A-163] [A-168] None in replay; `execution.ts` pre-invoke hook and contract sentence (§16.2); gateway `submit` locked section (barrier chain, two fields); `status()`. Additive: yes (A-163 is unbuilt; the master contract is only widened; no replay rule, record kind or Core field). Vector impact: none. Builder fault injection: crash during the wait then resume dispatches exactly once; crash after `<op>.barrier.json`, before `attempt.json`, then resume → seq 1 with `resumed: true`, one attempt, exactly one call, seq 0 bytes unchanged; the same after seq 1 → seq 2; crash after `attempt.json` reconciles only, and a later `run` creates no barrier; a broken chain → `NOT_DISPATCHED {ADMISSION_MISMATCH}`, zero calls; every §16.3 failure yields its reason and zero calls.

## 17. rc.2 ships without fee replacement

Q-ARCH-2. Outbox profile. [A-164]

**17.1 Ruling.** [A-164.0] **Yes.** §6.3 already places fee replacements outside the statement, and the IronTrellisLiveChainAnchor minimum scope (§7.1) asks for a durable outbox with a stable submission identity, not liveness under fee pressure. A stuck transaction leaves the account halted and the barrier `DELAYED` (§9.2's conditional completeness, disclosed as an availability limit, never a refusal) until inclusion or §18 clearing. The profile MUST disclose its fee policy at `prepareTransaction` and the fact that no replacement exists. **Outbox profile; additive; rc.2.** Explicit replacement is **E-36** (§21), not adopted.

**17.2 Code, stage and tests.** [A-164] None; outbox. Additive: yes. Vector impact: none; builder transport test (one request per `submitOnce`) stands.

## 18. Operator-signed outbox clearance; `keyExposure`; `CONFLICT_RESOLVED`

Q-ARCH-3 and G69-Q3. Outbox profile. [A-165] [A-169]

**18.1 Ruling.** [A-165.0] [A-169.0] The clearing act is an **operator-signed outbox record, outbox-local; no Core event** (an outbox incident is never a Core event, Core §7.4 [A-94.0]; §6.1; a new type would be a format change, not additive). **Outbox profile; additive; rc.2.** `keyExposure` is a field of the signed record, always present, nullable, non-null iff the disposition is `NONCE_FOREIGN_CONSUMED`. An unsigned side note or an undocumented extra field is refused. The disposition literal for `OUTBOX_CONFLICT`, unnamed in A-165.3, is `CONFLICT_RESOLVED`; `SUPERSEDED_LOCAL` is the losing job's status, not a disposition.

**18.2 Who.** [A-165.1] [A-167.5] The **operator**: the installer-controlled host administrator who already owns the stop latch and the profile, signing with an operator key named in the profile manifest — `operatorKeys` of the payload (§19.2), so a clearance is verifiable by anyone holding `s.profile.manifestHash`, which every statement carries. The operator key is distinct from the publisher, every owner key, the committee key, vote keys, session and counterparty credentials (§2.3's list extended). Never the agent, never the publisher key (it signs transactions only; Core §6.3 dedicated-key rule), never automatic.

**18.3 Record.** [A-165.2 as amended by A-169.1] `irontrellis-outbox-clearance/1`, closed schema; nullable fields written as explicit `null`:
```
{ version: "irontrellis-outbox-clearance/1",
  namespaceId: ContentHash,                     // = trust root's
  chainId: ProtocolString,                      // = payload chain.id
  publisher: EthereumAddress (lowercase),       // = payload publisher
  nonce: U53,
  attemptId: ContentHash | null,
  haltCode: "SIGNING_UNCERTAIN" | "CONSUMED_BY_OTHER" | "OUTBOX_CONFLICT",
  observed: { accountNonce: U53, txAtNonce: ProtocolString | null, bytesMatchOurs: boolean | null,
              includedStatementDigest: ContentHash | null, l1Level: U53 | null, observedAt: U53 },
  disposition: "RECLAIM_SAME_NONCE_SAME_BYTES" | "NONCE_FOREIGN_CONSUMED" | "CONFLICT_RESOLVED",
  keyExposure: "KNOWN_OWN_USE" | "COMPROMISE_SUSPECTED" | null,
  canonicalStatementDigest: ContentHash | null,
  operatorKeyId: Identifier,                    // ∈ payload operatorKeys
  signature: <Core §7.4 ed25519 signature text form> }
```
`signature` is over the 32 raw bytes of `hashCanonical(record without signature)`; the `version` literal inside those bytes is the domain separation. Path `clearances/<chainId>/<publisher>/<nonce>-<n>.json`, `n` the first free index, O_EXCL, fsynced, surfaced by `status()` and in the evidence bundle.

**18.4 Dispositions (closed) and consistency rules.** [A-165.3 as amended by A-169.0] [A-169.2] Mapping `haltCode → disposition` is 1:1 in the order listed; a record violating a rule below is invalid: never created, refused when read. `observed.txAtNonce` non-null iff `accountNonce > nonce`; `bytesMatchOurs` and `l1Level` non-null iff `txAtNonce` non-null; `includedStatementDigest` non-null iff `txAtNonce` is a call to `destination` whose retained digest is known.
- `SIGNING_UNCERTAIN` → **`RECLAIM_SAME_NONCE_SAME_BYTES`**: a one-time re-claim of the same nonce for the **same `statementDigest` only**, the digest inside the attempt record `attemptId` names (at most one stray signed transaction of identical statement bytes can exist; the contract is idempotent on duplicates, §11.4; if the stray lands first, reconcile reports `CONSUMED_BY_SELF`); an EVM nonce cannot be skipped, so "permanently consumed" is read as "never re-claimed for different bytes". `attemptId` non-null; `bytesMatchOurs ≠ false`; `keyExposure = null`; `canonicalStatementDigest = null`.
- `CONSUMED_BY_OTHER` → **`NONCE_FOREIGN_CONSUMED`**: the attempt terminal `FAILED_NONCE_CONSUMED`, a fresh attempt claims the next nonce, and the operator MUST state `keyExposure: "KNOWN_OWN_USE" | "COMPROMISE_SUSPECTED"`; under `COMPROMISE_SUSPECTED` no further send until a §11.6 migration to a new publisher. `attemptId` non-null; `txAtNonce` non-null and `bytesMatchOurs = false`; `keyExposure` non-null; `canonicalStatementDigest = null`.
- `OUTBOX_CONFLICT` → **`CONFLICT_RESOLVED`**: `canonicalStatementDigest` names the surviving statement; if either digest is included on chain it is the only admissible choice; the other is `SUPERSEDED_LOCAL` and never sent. `attemptId` nullable (the outstanding attempt if one exists); `nonce` = the outstanding reservation's nonce, else `observed.accountNonce`; `canonicalStatementDigest` non-null and equal to `includedStatementDigest` when that is non-null; `keyExposure = null`.

Every disposition is appended, never edits a journal entry.

**18.5 Effects.** [A-169.3] The outbox acts on a clearance only after its own reconcile agrees with `observed` on `accountNonce`, `txAtNonce` and `bytesMatchOurs`; otherwise the record stays as appended evidence and the halt stands (`CLEARANCE_OBSERVATION_MISMATCH`). `COMPROMISE_SUSPECTED` is monotone: any such record for `(chainId, publisher)` makes `claimAttempt` refuse that publisher (`PUBLISHER_EXPOSED`) until a trust root whose payload `supersedes` names this `namespaceId` with a different `publisher` is loaded (§11.6); no later clearance lifts it. `KNOWN_OWN_USE`: the attempt is `FAILED_NONCE_CONSUMED` and a fresh attempt claims the next nonce. A clearance whose `operatorKeyId` is not in the payload's `operatorKeys`, or whose signature does not verify, is refused.

**18.6 Code, stage and tests.** [A-165] [A-169] None in Core; outbox clearance codec and `claimAttempt` guard. Additive: yes (record unbuilt; A-165.2's fields kept, one field and one literal added). Vector impact: none in Core. In Astra's `conformance/anchor-attempt/`: one positive clearance per disposition with digest and signature, checker-reproduced; negatives: `keyExposure` null under `NONCE_FOREIGN_CONSUMED`, non-null under the other two, `bytesMatchOurs = false` under `RECLAIM…`, `canonicalStatementDigest ≠ includedStatementDigest`, unknown field, publisher-signed. Builder tests: each halt code clears only under its disposition; a clearance signed by the publisher, an owner key or the agent is refused; re-claim with different bytes is refused.

## 19. `irontrellis-profile-manifest/1` and the trust root

G69-Q1. External profile contract. [A-167]

**19.1 Ruling.** [A-167.0] The cycle (a manifest that names the namespace whose derivation hashes the manifest) is real and is closed by a named boundary: `profile.manifestHash` commits to a **payload** that contains neither `namespaceId` nor `destination`; both are carried in an unhashed **trust root envelope** and are validated by recomputation and by the deployed instance's immutables. The §11.2 namespace bytes are unchanged.

**19.2 Payload.** [A-167.1] `irontrellis-profile-manifest/1`, closed schema, canonical per Core §3.1; `manifestHash = hashCanonical(payload)`; nullable fields written as explicit `null`, never omitted:
```
{ version: "irontrellis-profile-manifest/1",
  id: Identifier,                               // = statement.profile.id
  domain: <genesis domain as written>,
  historyId: ContentHash,
  genesisEventHash: ContentHash,
  chain: { id: ProtocolString },                // no destination
  publisher: EthereumAddress (lowercase),
  operatorKeys: [ { keyId: Identifier, scheme: "ed25519", credential: <as in K> } ],   // ≥ 1, keyIds distinct; §18.2
  nodes: { evm: PinnedNode, l1: PinnedNode, ownRollup: PinnedNode | null },           // PinnedNode = { chainId: ProtocolString, operator: <as NodeId.operator> }
  bodyStore: ProtocolString | null,             // §12.5
  maxL1HeadLag: U53 | null,                     // §14.3
  supersedes: { namespaceId: ContentHash, destination: ProtocolString, lastStatementDigest: ContentHash, lastHead: { hash: ContentHash, position: U53 } } | null }   // §11.6; null iff first instance
```
An unknown field, a missing field, or `namespaceId`/`destination` inside the payload is invalid. `nodes` pins administration only (§14.3's voiding condition); protocol, kernel and software changes are recorded in reports, never pinned (judgement: pinning them would force a §11.6 migration at every upgrade). `resumeHorizon` (§16.3 (6)) is gateway configuration, disclosed in `status()`, not in the payload. No `class` field: the class is derived from the §10.1 table (**E-39**, §21). [E-M2, erratum candidate (decision 4ct)] `bodyStore: null` means the bodies are held in the namespace instance at the trust root's `destination` (path B, §10.3); a ProtocolString names an external store.

**19.3 Trust root and load validation.** [A-167.3] `irontrellis-profile-trust-root/1`, no nullable field:
```
{ version: "irontrellis-profile-trust-root/1", manifest: <payload object>, manifestHash: ContentHash, namespaceId: ContentHash, destination: ProtocolString }
```
`manifest` is the payload inline; the bytes `manifestHash` commits to are `canonical(trustRoot.manifest)` taken as a standalone value. The trust root is the installer-authenticated artefact of §11.3 (E-35 is the owner-attested form). **Load validation** (outbox, gateway and verifier, at profile configuration; failure refuses the profile with `TRUST_ROOT_INVALID {check}`, never a Core refusal): (T1) `manifest` valid per §19.2; (T2) `manifestHash = hashCanonical(manifest)`; (T3) `namespaceId` = §11.2 over `manifest`; (T4) `destination` well-formed for `chain.id` (eip155: lowercase hex EthereumAddress); (T5, one chain read, recorded in the evidence bundle under the report's mode) the instance at `destination` exposes immutables `namespaceId`, `publisher`, `chainId` equal to T3, `manifest.publisher`, `manifest.chain.id`. The class table of §10.1 (any other `(chain.id, profile.id)` pair is `TRUST_ROOT_INVALID`) and the TEST opt-in of §10.2 (i) (`openAnchorBarrier` refuses `TRUST_ROOT_INVALID {reason: TEST_PROFILE_NOT_ALLOWED}`) use the same code [A-183.1] [A-183.2]. (T6) `(manifest.chain.id, manifest.id)` is a pair of the §10.1 table; the check runs in every loader, the outbox included, so that no statement is ever enqueued under an unclassified pair [A-195.2].

**19.4 Statement binding (`verifyAnchor` precondition).** [A-167.4] For trust root `T` and statement `s`: `s.profile.manifestHash = T.manifestHash`; `s.profile.id = T.manifest.id`; `s.domain`, `s.historyId`, `s.genesisEventHash`, `s.chain.id` equal `T.manifest`'s; `s.chain.destination = T.destination`; the carrying transaction's sender `= T.manifest.publisher`. A statement failing any equality is not an anchor of this history and receives no `irontrellis-anchor-verify-report/1`. `s.evidence.manifestDigest` (§6.2) is not the profile manifest's hash and is unchanged.

**19.5 Where the names live.** [A-167.5] `namespaceId`: trust root, contract immutable, §12.4 descriptors, §18.3 clearance, the external vector; never in the statement or the payload. `destination`: trust root, `s.chain.destination`, the attempt identity, a successor's `supersedes.destination`; never in the payload. The `PROFILE_MANIFEST` artefact of §12.3 (c) and §12.4 is the payload bytes only; the trust root is never a closure artefact because it is reconstructible as `{manifest, manifestHash: s.profile.manifestHash, namespaceId: §11.2(manifest), destination: s.chain.destination}` from the payload and any one statement.

**19.6 Consequence (stated, judgement).** [A-167.6] Any payload change, including an operator-key or node-administration change, is a new `manifestHash`, a new `namespaceId` and a §11.6 migration. **E-37** (§21) relaxes this post-rc.2; until adopted, re-attestation is migration.

**19.7 Code, stage and vectors.** [A-167] None in Core; profile codecs for the two new literals; profile load in outbox, gateway and connector. Additive: n/a (external; the §11.2 bytes and every existing literal unchanged). Vector impact: none in Core. External `anchor-namespace/v1/etherlink-mainnet` gains `manifest.json` (payload bytes), `trust-root.json`, `namespace.json` and the digests, checker-reproduced; negatives: `manifestHash` mismatch, `namespaceId` mismatch, unknown or missing payload field, `namespaceId`/`destination` inside the payload, statement with foreign `manifestHash` or `destination`. The frozen `anchor-statement` vector is untouched; if its `profile.manifestHash` was not produced from bytes the builder holds, the namespace vector carries its own sequence-0 statement in a new `conformance/anchor-*` directory.

## 20. The outbox signer test

KI-38 / DEV-99. Profile MUST; the sentence stays informative in Core §7.4. [A-185.2]

**20.1 Rule (profile MUST).** [A-185.2] *"Before enqueueing a statement, the outbox applies A-111.3's signer test to the `/2` attestation it carries (`DECLARED`: not `AGENT`; `ATTESTED`: `HUMAN` at `head.canonicalTime`) and refuses an unqualified signer with the outbox-local code `ATTESTATION_SIGNER_UNQUALIFIED`; nothing unqualified is published."* The signer test is Core §7.4's (the class by `cls` of Core §6.5.3, applied to the pin signer). Reason: the outbox is the publisher of evidence; a published attestation that no reader may use as a root is misleading evidence (Core §7.4 [A-94.1]). Under the default policy every key is `HUMAN` by declaration, so no rc.2 history without a policy changes behaviour. KI-38 is rewritten (not closed) to "outbox lacks the A-185.2 test"; DEV-99's outbox sentence is corrected.

**20.2 Code, stage and tests.** [A-185.2] Code: `ATTESTATION_SIGNER_UNQUALIFIED` (outbox). Stage: profile/outbox. Additive: yes. Vectors: none; builder test.

## 21. Core Appendix E pointers E-32…E-39

Each item below is carried by Core Appendix E and is *open; post-rc.2; not adopted* (A-186.4; A-186.5; P.5). Nothing here is text of this document beyond the section that raised it; Core Appendix E states each item's status.

| Core item | raised by | this document | what it would add |
|---|---|---|---|
| **E-32** `ownerPolicy.required?: { [eventType]: [keyId] }` | A-145.3 | §7.5 (§2.7) | named keys that must be among the counting set for a type, so that "the committee plus any one human" is expressible; additive, guarded |
| **E-33** a genesis `finality` literal naming a connector finality class | A-150.4 | §8.5 | nothing needs it; connector finality lives in the payload (§19.2) and the report (§14.2); format minor |
| **E-34** extend Core §6.5.2 rule 10 to `STATE_CHECKPOINT` | A-151.2 | §2.7 | a policy-time refusal where `byType.STATE_CHECKPOINT` exceeds the epoch's non-`AGENT` credentials; non-additive, so not before rc.2; until then Core §18 lists such policies |
| **E-35** owner-attested profile binding | A-158.2 | §11.3, §19.3 | an owner-signed object over `{namespaceId, manifestHash}` in the Core §7.4 attestation form, allowing discovery through an untrusted registry; not needed while discovery is by trust root; additive |
| **E-36** explicit replacement of a halted anchor attempt | A-164.0 | §17.1 | operator-authorized, identical statement bytes, same nonce, a new attempt identity carrying `replaces: <attemptId>`, one signer callback per replacement, never automatic, never a repeated business effect; additive, closed profile |
| **E-37** `irontrellis-profile-amendment/1` | A-167.6 | §19.6 | an operator-signed, append-only record re-pinning `nodes` or adding an operator key under the same `namespaceId`, verifiable from the payload's `operatorKeys`; until adopted, re-attestation is migration; additive |
| **E-38** a hash-only persistence `availability` literal (`BODY_INDEX`) | A-183.3 | §10.3, §12.5 | body descriptors without chunks, for gas-constrained test or production chains; not needed while path B uses `BODIES` |
| **E-39** a `class: "PRODUCTION" \| "TEST"` field in `irontrellis-profile-manifest/1` | A-183.1 | §10.1, §10.4, §19.2 | would replace the closed `(chain.id, profile.id)` table; deferred so that no manifest byte changes before IronTrellisLiveChainAnchor |
| **E-43** a derived `headline` field in a `/2` verify report (added by AS-02) | A-193.3 | §7.1, §14.2 | would carry the LiveChainFinalized word as data; not needed while it is a pure function of the `/1` report's fields and the §10.1 table |

---

### Superseded wording (part 2 chains)

As Core Appendix D does for Core passages; part 1's chains are its §2.6, §3.3 and §4 chain notes.

| superseded wording | replaced by |
|---|---|
| A-158.0 "rc.2 … because the rc.2 default tier needs a destination (A-145.1)" | A-182.1: "rc.2 (the TEST profile needs a destination; IronTrellisLiveChainAnchor the production one)" (§11.1) |
| A-158.2 "the profile manifest … names `destination`, `publisher` and `namespaceId`" | A-167.0: read as the trust root; "the trust root's hash" is `manifestHash` (§11.3, §19.3) |
| A-161.0 "rc.2-required" | A-182.1: "required for IronTrellisLiveChainAnchor" (§14.1) |
| A-161.2 "Node identities are pinned in the manifest" | A-167.1: `nodes` pins administration only; protocol, kernel and software are recorded, never pinned (§14.3, §19.2) |
| A-161 vector impact "before the rc.2 live-anchoring default is claimed" | A-182.1: negatives rc.2; the positive and the founder-node evidence IronTrellisLiveChainAnchor (§14.4) |
| A-163.0 "a committed admission with no `barrier.json` and no `attempt.json` has not been dispatched"; A-163.1's sentence | A-168.0, A-168.1: absence of `attempt.json` alone; the sentence replaced word for word (§16.1, §16.2) |
| A-163.3 "`barrier.json` gains `resumed: boolean`"; `status()` "`NOT_DISPATCHED {reason}` when `attempt.json` is absent" | A-168.2 (`barrierSeq`, `previousBarrierDigest` added; the chain), A-168.4 (`DELAYED` while a wait is open) (§16.4, §16.6) |
| A-165.2 record (no `keyExposure`; `disposition` literals unnamed) | A-169.1 (§18.3) |
| A-165.3 `OUTBOX_CONFLICT` with no disposition literal | A-169.0: `CONFLICT_RESOLVED`; `SUPERSEDED_LOCAL` is a status (§18.4) |

*End of part 2 and of `SPEC-IRONTRELLIS-ANCHORING-PROFILES-r1.md`.*
