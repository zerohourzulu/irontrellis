# Owner approval policies: reference

This page lists the format-2 rules for owner approval policies, human attestation and recovery, as this release builds them. The rules come from the format-2 specification and its addenda: A-91, A-92, A-96, A-97, A-99, A-102, A-106 to A-112 and A-116 to A-125. Where the addenda conflict, G6.3 wins over G6.2, G6.2 over G6.1 and G6.1 over G6. `docs/HISTORY-FORMAT.md` §15 gives the overview. A history without an `ownerPolicy` behaves exactly as before: any one owner key in force signs each control event alone.

## 1. The policy

The genesis (`DEPLOYMENT_INITIALIZED.data`) and an `OWNER_KEYS_ROTATED` may carry `ownerPolicy`. It is a closed object:

| field | meaning |
|---|---|
| `threshold` (1..64) | how many owner keys must sign a control (◆) event |
| `byType?` | a different count for named ◆ types |
| `keyClasses?` | marks a key id `AGENT` or `HUMAN`; keys not listed are `HUMAN` |
| `labels?` | a short note per key id; never used to decide anything |
| `acknowledged?` | `"SINGLE_SIGNER"`: a recorded choice of one signer |
| `humanFloor?` | `"DECLARED"` (classes as declared) or `"ATTESTED"` (classes need signed statements) |
| `attesters?` | the keys that may sign human attestations |
| `attestations?` | signed statements that a person holds a given owner key (§5) |
| `recovery?` | `"COMMITTED_NEXT_KEYS"`: committed next keys may sign the rotation that reveals them (§4) |

`M_eff(e)`, the number an event needs, is `byType[type]`, else `threshold`. For an `OWNER_KEYS_ROTATED` it is called `M_rot`.

## 2. When a policy is valid

Each failure is `EVENT_DATA_INVALID`. The rules are checked against the `ownerKeys` of the same event, in this order:

1. `threshold` and every `byType` value are at most the number of distinct owner credentials.
2. Every `byType` key names a ◆ type.
3. `byType.OWNER_KEYS_ROTATED`, when present, is at least `threshold`.
4. Every `keyClasses` and `labels` key is a key id of `ownerKeys`, and no two owner keys share a credential.
5. Some key is not `AGENT`, and the non-`AGENT` credentials reach `M_rot`. Agents alone never change the policy.
6. `acknowledged` needs `threshold` 1 and no `byType`.
7. Human attestation (§5.2).
8. A migrated genesis carries no policy.
9. A `byType` value of a power-reducing type (§3) is at most the number of non-`AGENT` credentials.
10. Only a power-reducing type or `STATE_CHECKPOINT` may have a `byType` value below `threshold`.

## 3. Power-reducing events

Seven types may reduce power: `AUTHORITY_REVOKED`, `CONTROL_EPOCH_ADVANCED`, `AGENT_TERMINATED`, `AGENT_UNAPPOINTED`, `BUDGET_DECLARED`, `BUDGET_UPDATED` and `COUNTERPARTY_RETIRED`. A lowered `byType` count applies only to an event that really reduces power, judged from the event and the state before it, before any signature is counted. Otherwise the event needs `threshold`. An event reduces power when it:

* revokes a `PERMISSION` that is not yet revoked and that no unrevoked prohibition is delegated under;
* fences an active agent to a later epoch at which it has no session;
* terminates an active agent that is on no unrevoked prohibition's anchor path (any unrevoked prohibition, with no activity or window term, so an expired or not-yet-valid one counts too; A-203.1): not its grantor, and not the grantor or grantee of a grant it is delegated under (otherwise fence the agent);
* ends a tenure when no active, unexpired budget can still select the agent through that role;
* declares a budget (a budget only ever denies);
* updates an active budget that does not roll over unused amounts, raises no cap, narrows no subject list and does not move `expiresAt` earlier;
* retires an active counterparty.

## 4. Signing a control event

**Co-signatures.** When `M_eff` is 2 or more, the event carries `data.additionalControlAuthorizations`, 1 to 63 entries `{keyId, signature}`, beside `controlAuthorization`. Every signature is over the same format-2 control challenge. Replay accepts the event only when all of these hold (otherwise `CONTROL_AUTHORIZATION_INVALID`):

* The list is present exactly when `M_eff` is 2 or more.
* Every signature verifies with an admissible key: a key in force or, for a recovery rotation, a revealed committed key.
* No key id or credential appears twice among the signers.
* The signers that count reach `M_eff` (§5.3 under `ATTESTED`; under `DECLARED` an `AGENT` key counts for any type except `OWNER_KEYS_ROTATED`).
* At least one counting signer is human-class. An agent key never authorizes alone.

A key's class follows its credential. If one key id with a credential is `AGENT`, every key id with that credential is `AGENT`.

**Recovery.** Under `recovery: "COMMITTED_NEXT_KEYS"` the admissible signers of an `OWNER_KEYS_ROTATED` include every key it reveals whose digest is in the commitment in force. Such a key counts toward `M_rot` with the current keys. It must still prove possession (§6). Without `recovery`, a committed key that is not in force cannot sign the rotation that reveals it.

**No recovery writer in this release (A-197, known issue 24).** Replay honors a recovery rotation exactly as above. The owner API and CLI offer no way to author one: `rotateOwnerKey` needs a current owner key, and `prepareControlEvent` refuses `nextKeyAuthorizations` and key-changing rotations. A deployment that sets `recovery` therefore has a rule replay would honor and no shipped tool to exercise it. Recovering a lost quorum is possible only through an external producer of the event under §4 and the signature rules of §6, which this release neither ships nor documents. The writer is planned after this release. The owner API warns when a policy carrying `recovery` is written (`OWNER_POLICY_RECOVERY_NO_WRITER`).

## 5. Human attestation

### 5.1 Statements

A statement (`irontrellis-human-attestation/1`) is `{version, audience, subject, profile, attesterKeyId, evidenceDigest, notBefore, expiresAt, historyId?, signature}`, signed by an attester over its body without `signature`. It says that a person holds `subject` from `notBefore` up to, but not including, `expiresAt`.

### 5.2 Validity

Under the same `EVENT_DATA_INVALID` rule, in this order:

1. `attestations` needs `attesters`, and `ATTESTED` needs both.
2. Each attester has a distinct key id and credential and passes the key test. It is not an owner credential, not committed as a next key, and not a session or counterparty credential of the history. `ATTESTED` needs at least two attesters.
3. Each statement: one per subject credential; `audience` is the history's domain; `attesterKeyId` names an attester and the signature verifies; the subject is an owner key of the event or a committed next key; `notBefore < expiresAt`; the statement has not expired at the setting event; the subject is not `AGENT`. At the genesis `historyId` is absent. After it, `historyId` is `recordHash(0)`.
4. A statement carried unchanged from the policy in force is exempt from the expiry and `historyId` tests, on every rotation.
5. Under `ATTESTED`, at least `max(1, M_rot)` owner credentials have a statement valid at the setting event. Every power-reducing `byType` value is at most the number of owner credentials whose statement has started.

### 5.3 Classes and counting

At time `t` a key is `AGENT` when `keyClasses` says so. Under `DECLARED` every other key is `HUMAN`. Under `ATTESTED` a key is `HUMAN` while its statement is valid at `t`, `LAPSED` once it has expired, and `NONE` before it starts or without one. The class is read at the event's timestamp.

Under `ATTESTED` the counting signers are:

* `HUMAN` and `AGENT` keys for an ordinary ◆ event;
* `LAPSED` keys too for a power-reducing event, a `STATE_CHECKPOINT` or a restoration;
* only `HUMAN` keys for an `OWNER_KEYS_ROTATED`, or `HUMAN` and `LAPSED` for a restoration.

`NONE` never counts.

### 5.4 Restoration

A restoration is a policy rotation under `ATTESTED` to `ATTESTED` that keeps every key, the commitment and every policy field but `attestations` and `labels`. It keeps the set of subject credentials, and carries each statement unchanged or renews it. A renewal starts after both the old statement's `notBefore` and the time the epoch opened, starts no later than the event, and expires later than the old one. Lapsed keys can sign it, so owners whose statements all expired can renew them.

### 5.5 Time rules

* **T1.** A session-signed (◇) or ▲ event's timestamp stays below every statement expiry still in the future at the head (`TRANSITION_INVALID`). Only an owner-signed event can cross an expiry.
* **T2.** A ◆ event with at most one human-class counting signer has the head's timestamp or a timestamp no later than the latest statement expiry, capped at 2^53 − 2 (`TRANSITION_INVALID`). It is checked right after control authorization.

The writer checks both before it signs or writes. It refuses with `TRANSITION_REJECTED`: `detail.reason` is `ATTESTATION_EXPIRY` (with `detail.expiresAt`) or `ATTESTATION_HORIZON` (with `detail.horizon`). `TRANSITION_INVALID` stays the replay verdict.

## 6. Rotations under a policy

A rotation that keeps every owner key and changes the policy as written is a **policy rotation**. Out of a committed epoch it carries no `nextKeyAuthorizations` and restates the commitment unchanged. A rotation without `ownerPolicy` opens an epoch with the default policy. The rotation is signed under `M_rot` of the policy in force, not the one it sets.

Under a policy (the rotation carries `ownerPolicy`, or the epoch it leaves has one), these rules apply in addition to `docs/HISTORY-FORMAT.md` §7:

* Each revealed key carries exactly one `nextKeyAuthorizations` entry (`TRANSITION_INVALID`).
* No owner key of the new set is a session or counterparty credential of the history (`EVENT_DATA_INVALID`).
* No digest the rotation adds to the commitment names a session or counterparty credential, or an attester of the old or new policy (`TRANSITION_INVALID`). A digest carried from the commitment in force is not tested again.
* While the epoch in force has a policy, a session or counterparty credential may not be an owner key in force, a committed next key or an attester (`TRANSITION_INVALID` on `RUNTIME_SESSION_ADMITTED` and `COUNTERPARTY_REGISTERED`).

## 7. Readers that do not replay

`verifyRotationEvent` checks a rotation from the event, the epoch records and the head before it (A-120.1). It is used by the witness, the snapshot resume and the export verifier. It applies, in order: control authorization with the epoch's policy and counting; T2, with τ the `canonicalTime` of the head before the event; the key test; policy validity; and the rotation rules of §6 that need no history state. It does not check the rules that read the replayed state (the session and counterparty credential tests), and its result says `stateChecked: false`. Full replay is the authority. A rotation that full replay accepts is always accepted here. When T2 would decide and τ is unknown, the rotation is refused as not judged.

**Witness.** Epoch 0 takes its policy from the registered genesis. Each later epoch takes the policy of its rotation, as written. A head statement's signer must be qualified under the policy in force at its position, at its `canonicalTime`: not `AGENT` under `DECLARED`, and `HUMAN` under `ATTESTED`. If it is not, the answer is 400 `WITNESS_SIGNER_UNQUALIFIED` and nothing is recorded. A witness that lacks an epoch's policy answers 409 `WITNESS_POLICY_UNKNOWN`. τ for T2 is the head the witness holds at `previousHead`. Without it the answer is 409 `KEY_EVENT_HEAD_UNKNOWN`, and the owner sends that head's statement first.

**Resume roots.** A `/2` pin seeds a snapshot resume only when all three hold:

* (a) its signer is not `AGENT` (under `ATTESTED`, is `HUMAN`) at the pinned head's time, under the policy in force there;
* (b) under the policy in force after the file's head, no key with the signer's credential is `AGENT` (under `ATTESTED`, the credential has a statement in that policy);
* (c) that policy's `STATE_CHECKPOINT` count is 1.

Otherwise the store uses an in-file checkpoint or replays in full, and `verify` notes `FULL_REPLAY` with the reason. An in-file `STATE_CHECKPOINT` is a resume root at any position.

**Export views.** The verifier derives epochs with their policies from the genesis and the key events. It checks each key event with `verifyRotationEvent`. τ is the time of the event before the key event, when the view carries that event in `events` or `referencedEvents`. Otherwise T2 is skipped and noted as not judged. Under an `ATTESTED` epoch the exporter includes that event. It checks the authenticating checkpoint at `from + 1` under the policy in force there. An `attestations.from` head attestation must pass (a) to (c), with the view's last epoch in place of the file head.

`verify` lists pins and anchor-log heads whose signer is unqualified at its `canonicalTime` (`HEAD_SIGNER_UNQUALIFIED`, report-level).

## 8. State

The owner-key-epoch record carries `policy` as written when the epoch has one, and leaves it out for the default. The genesis record does not repeat `ownerPolicy`. The time each epoch opened is read from the events and is not stored.
