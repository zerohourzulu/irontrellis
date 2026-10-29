# History signatures and owner epochs reference

> Reference from `HISTORY-FORMAT.md` at `00ca4c0` (SHA-256 `aecc62db80fda785ca06b60107097316cdc453416d0fa61baef42c6e903bc35b`). Established scope: the retained field, byte, code, limit and ordered-check contracts below. Not established: a new engine audit, deployment test or broader edition coverage.

Source section numbers are retained for cross-reference with [HISTORY-FORMAT.md](../HISTORY-FORMAT.md). Operational guidance stays in the narrative page. Format-2 owner-policy rules remain in the unchanged [owner-policy reference](owner-policy.md).

**Edition boundary:** Historical legacy/format-1 signature and challenge reference. Format-2 `/2` bindings and owner-policy rules must be checked separately; replacing a literal is not a port.

<!-- source: HISTORY-FORMAT.md:246-377; exact text except relative Markdown links -->

## 7. Control authorization (format 1)

Every control event (◆ in §6) in a format-1 history carries

```
data.controlAuthorization = { keyId: Identifier, signature: Signature }
```

with exactly those two keys. The signature is by the owner key named `keyId` **in force at the event's position** (§7.1; the genesis `ownerKeys` until the first rotation), over the hash of this **challenge**, canonically encoded and hashed with the history's algorithm (SHA-256):

```
{
  "version": "irontrellis-control-authorization/1",
  "domain": <genesis domain>,
  "eventId": <event.id>,
  "eventType": <event.type>,
  "timestamp": <event.timestamp>,
  "previousHead": null | { "hash": <history hash at position-1>, "position": <position-1> },
  "effectHash": hashCanonical(<data without controlAuthorization and nextKeyAuthorizations>, "sha256")
}
```

`previousHead` is `null` only at position 0 (the genesis is not a control event, so in practice the first control event, at position 1, signs the head after the genesis). Because the head before the event is signed, a control event cannot be moved to another position or replayed into another history; because `effectHash` is signed, its effect cannot be altered. Replay rejects an unsigned, malformed, mis-keyed (a `keyId` not among the owner keys in force at that position) or mis-signed control event with `CONTROL_AUTHORIZATION_INVALID`. The effect hash covers everything in `data` except `controlAuthorization` and `nextKeyAuthorizations` (the only other signatures over this same challenge, §7.2; every other type rejects a `nextKeyAuthorizations` field in its closed schema); for `OWNER_KEYS_ROTATED` that is the new key set, the reason and the new next-key commitment. Runtime-signed events (admissions, receipts, administrative events) are not control events and carry no owner signature.

Worked value (from §12): challenge canonical text

```
{"domain":{"deploymentId":"example","protocol":"irontrellis","version":"1"},"effectHash":"0x7edba99b1130c16d4c94f0819b1c6a6865395aaf8a4eb249d6edcd01c93b339b","eventId":"example:principal","eventType":"PRINCIPAL_CREATED","previousHead":{"hash":"0x8cbbc04d19cd600c9306ee2f7a0beb2d451cf75d3c7f4fb33be5324b5921ff9a","position":0},"timestamp":2,"version":"irontrellis-control-authorization/1"}
```

hashes (SHA-256) to `0x132453473e93ffab61204648d2d2d9bf5829b3b36eaf85c012b08294fb0c422c`.

### 7.1 Owner key epochs and `OWNER_KEYS_ROTATED`

A format-1 history has a sequence of **owner key epochs** `[{fromPosition, keys, nextKeyDigests?}]`: epoch 0 is the genesis `ownerKeys` and `nextKeyDigests` from position 0, and every accepted `OWNER_KEYS_ROTATED` opens one more (`nextKeyDigests` is the epoch's next-key commitment, §7.2). Epochs never change once opened. A rotation at position `r`

1. is a control event like any other: its `controlAuthorization` is checked against the owner keys in force at `r`, i.e. the set **before** it (the new keys cannot authorize their own introduction);
2. must obey the key-set rules against every earlier epoch, checked in this order for each new key (`TRANSITION_INVALID` on the first failure):
   - a key id that appeared in any earlier epoch must name the same key (same `scheme`, same `credential` compared case-insensitively): an id is never re-bound to another key;
   - such an id must be in the current set: a **retired** key id never returns (keys carried over from the current set are allowed);
   - a new key id must not carry a credential any earlier epoch declared: a retired key does not come back under another name, and a current key gets no alias;
3. must obey the pre-rotation rules of §7.2: every `nextKeyAuthorizations` entry must verify; out of a committed epoch the rotation must satisfy the commitment; a rotation that keeps every key must add a commitment;
4. opens the epoch `{fromPosition: r + 1, keys: data.ownerKeys, nextKeyDigests?: data.nextKeyDigests}`. It may not appear inside a migrated legacy prefix (§11).

`ownerKeysAt(p)` — the keys **in force at position p** — is the epoch with the greatest `fromPosition ≤ p`. The same rule decides every owner signature by position:

| signature | position `p` it is judged at |
|---|---|
| `controlAuthorization` of the event at position p | p |
| head attestation of the head at position p (pin §9, anchor log §10, remote witness statements) | p |

So the head that ends with a rotation (position `r`) is attested under the old set, every later head under the new set, and an attestation of an older head keeps verifying after its key was retired (it was valid then). An attestation of a head after the rotation signed by a retired key does not verify.

The local API (`LocalOwner#rotateOwnerKey`, `irontrellis owner rotate-key`) keeps the owner key files next to the history in step: see §13 and docs/API.md. A remote party that holds the prior epochs but not the history (a witness) checks a rotation with `verifyRotationEvent(event, { domain, previousHead, epochs })`: schema at `previousHead.position + 1`, the owner signature over the challenge with that `previousHead`, the key-set rules and the pre-rotation rules against the commitments its `epochs` record (§7.2; a verifier that seeds `epochs` from the genesis knows epoch 0's commitment); the new epoch then starts at `previousHead.position + 2`. The result carries `preRotated`, `commitmentOnly` and the new epoch's `nextKeyDigests`.

### 7.2 Next-key commitments (pre-rotation)

An owner key epoch may be **committed** to the keys that will replace it, by digest, so that the key in force alone cannot rotate (the next key is kept off the host; docs/SECURITY.md §2.1).

**Key digest.** `ownerKeyDigest(key) = hashCanonical({ "version": "irontrellis-owner-key-digest/1", "scheme": key.scheme, "credential": lowercase(key.credential) }, "sha256")`. The key id is not part of it: a committed key may be revealed under any key id the §7.1 rules allow.

**Where a commitment is recorded.** An epoch's commitment is fixed by the event that opens it and never changes afterwards: epoch 0's is the genesis `nextKeyDigests` (§6.1), committed by the history id; a later epoch's is the `nextKeyDigests` of the `OWNER_KEYS_ROTATED` that opens it. No event adds, replaces or removes the commitment of the epoch in force. No digest may name a key the history declared, because a declared credential never returns under a new key id (§7.1), so such a commitment could never be satisfied: in the genesis that is a genesis owner key (`EVENT_DATA_INVALID`), in a rotation a key of any earlier epoch or of the rotation's own new set (`TRANSITION_INVALID`). Neither a rotation nor its commitment may appear inside a migrated legacy prefix (§11).

**Rotating out of a committed epoch.** Let `revealed` be the keys of `data.ownerKeys` whose key id is not in the current set (keys carried over are not revealed). The rotation is refused with `TRANSITION_INVALID` (reason prefix `owner key rotation: `), in this order, unless:

1. every entry of `nextKeyAuthorizations` names a revealed key (`keyId`), in its `scheme`, and its `signature` verifies with that key over **the rotation's own control-authorization challenge** (§7: the same hash its `controlAuthorization` signs; checked whether or not the epoch has a commitment);
2. every revealed key's digest is in the commitment;
3. at least one key is revealed;
4. `nextKeyAuthorizations` is present (proof of possession: a revealed public key alone proves nothing);
5. `data.nextKeyDigests` is present: the chain of commitments continues.

Because the challenge's `effectHash` leaves out both signatures and binds everything else, the proofs cover the event id, position (`previousHead`), the new key set and the new commitment, and no signature signs another. A rotation that satisfied a commitment is **pre-rotated**.

**Rotating out of an uncommitted epoch.** The key in force alone rotates (§7.1), and the rotation may start a commitment with `nextKeyDigests`. A rotation whose `ownerKeys` keep every key in force (the same number of keys, each with a key id and key material of the current set) is a **commitment-only rotation**: it is valid only with `nextKeyDigests` (without it, it would change nothing, and it is refused: `TRANSITION_INVALID`, `owner key rotation: a rotation that keeps every owner key changes nothing unless it adds a next-key commitment`), and it opens an epoch with the same keys and the new commitment. This is how a history without a commitment gets one. Out of a committed epoch a commitment-only rotation reveals no key and is refused by rule 3, so a leaked current key can neither replace nor drop a commitment.

**What the local API writes.** `createLocalOwner`, `irontrellis init`, `irontrellis-hook init` and `migrateHistory` / `irontrellis migrate` put the commitment into the genesis (a next key generated as `<history>.owner-next-key.json`, §13, or one the caller names), unless told not to (`nextKey: false`, `--no-next-key`). A history without a commitment gets one with `LocalOwner#commitNextKey` / `irontrellis owner commit-next-key`, which records a commitment-only rotation (reason `next-key commitment`). `ownerKeyStatus()` and `owner status` count the two kinds of rotation apart (`keyRotations`, `commitmentRotations`).

## 8. Signatures

### 8.1 Suites

A suite verifies "this ContentHash was signed by the holder of this credential". The hash handed to a suite is always the *history's* hash of the signed structure (keccak-256 in legacy, SHA-256 in format 1); what the suite then does is scheme-specific:

| scheme | signature | credential | verification |
|---|---|---|---|
| `eip191-personal-sign-keccak256` | `0x` + 130 lowercase hex = `r ‖ s ‖ v`, with `0 < r < n`, `0 < s ≤ (n-1)/2` (low-s), `v ∈ {0x1b, 0x1c}` | EthereumAddress, compared lowercase | ECDSA/secp256k1 public-key recovery over `keccak256(0x19 ‖ "Ethereum Signed Message:\n32" ‖ raw32(hash))`; the recovered address must equal the credential |
| `ed25519` | `0x` + 128 lowercase hex (64 bytes) | `0x` + 64 hex: the raw 32-byte public key, compared lowercase | Ed25519 (RFC 8032) over the **32 raw bytes** of `hash`, no prefix, no pre-hashing |

Legacy histories admit only 65-byte signatures. Format 1 admits both shapes; which one applies is fixed per signer: owner keys by `ownerKeys[].scheme`, runtime sessions by `RUNTIME_SESSION_ADMITTED.credentialScheme`. Test vectors for keccak, EIP-191 recovery and the challenge hashes are in `conformance/crypto-vectors.json`.

### 8.2 Runtime authorization challenge

A consequential authorization (one that will be recorded as an admission) is signed by the runtime session's key over this structure (spec 02 §5.1), canonically encoded and hashed with the history's algorithm:

```
{
  "version": "continuity-runtime-authorization/0.2",
  "domain": <domain, the five legacy fields or the three format-1 fields, as written>,
  "request": { actorId, action, resource, claimedAt, amount?, counterpartyId?, termsCommitment? },
  "authoritative": true,
  "consequential": true,
  "evaluationTime": U53,
  "policyVersion": <genesis policyVersion>,
  "rootRecognitionPolicy": "declared-principal-root/0.2",
  "eventHistoryHash": <head.hash>,
  "eventHistoryPosition": <head.position>,
  "runtimeSessionId", "credentialKeyId", "controlEpoch", "roleId", "roleTenureId", "intentId", "nonce"
}
```

`TRANSACTION_INTENT_ADMITTED.runtimeAuthorizationHash` is that hash and `runtimeSignature` the session's signature over it; replay recomputes the challenge from the recorded proof and the head at the admission's `expectedHistoryHead`, re-derives the proof from the pre-event state, and requires both to match (spec 02 §7.4).

### 8.3 Authorization proof

The ALLOW proof recorded inside an admission (`authorizationProof`) is exactly spec 02 §6.3: `{ proofVersion: "continuity-authorization-proof/0.2", domain, policyVersion, rootRecognitionPolicy, historyHead, evaluationTime, request, recognizedRoot: {rootAuthorityId, principalId, principalRecognitionEventId, rootGrantEventId}, permissionPath: [PermissionGrant…] (1..32, normalized), intersections: [{requiredAuthorityId, requiredByAuthorityIds, recognizedRoot, path, effectiveConstraints}…] (≤ 256), effectiveConstraints, controllingAuthorityIds (1..256), usageSnapshot: [{authorityId, admittedTransactionCount, admittedCumulativeAmount}…] (≤ 256), authorityEvidence: [{authorityId, grantEventId, grantEventPosition}…] (1..1024), checkedProhibitionIds (≤ 256), consequential: boolean }` plus, iff `consequential`, `runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId, intentId, nonce`.

### 8.4 Administrative authorization

Obligation and attempt-duty events carry `administrativeAuthorization = { challenge, authorityProof, runtimeSignature }`, where `challenge` is

```
{ "version": "continuity-administrative-authorization/0.2", domain, request, authoritative: true, consequential: true, evaluationTime, policyVersion,
  rootRecognitionPolicy, eventHistoryHash, eventHistoryPosition, transitionEventId, transitionEventType, transitionEffectHash, runtimeSessionId,
  credentialKeyId, controlEpoch, roleId, roleTenureId, authorityProofHash }
```

`transitionEffectHash` is the hash of the event's data without `administrativeAuthorization`, `authorityProofHash` the hash of `authorityProof`, and `runtimeSignature` the session's signature over the hash of the challenge (spec 03 §I). The administrative action names replay derives from the event are literals an implementer must reproduce: `OBLIGATE` (create an obligation; resource = the source intent's resource), `ASSIGN_PERFORMANCE` (assign; resource = the obligation id), `record-collection-disposition` (status change), `OBSERVE_OUTCOME`, `CREATE_ATTEMPT_DUTY`, `ASSIGN_ATTEMPT_DUTY`, `CLOSE_ATTEMPT_DUTY` (attempt records; resource = the intent id).

### 8.5 Receipts

A receipt artifact is `{ payload, contentHash, signature }` with `payload.schemaVersion` `continuity-receipt/0.2` (legacy, eip191 only) or `irontrellis-receipt/1` (format 1, either suite), `contentHash = hashCanonical(payload)` with the domain's algorithm, and `signature` by the issuing session's key over `contentHash`. `RECEIPT_RECORDED.receiptArtifactCommitment` is `hashCanonical(["continuity-receipt-artifact-commitment/0.2", contentHash, signature])` with the domain's algorithm, and `authorizationProofHash` is `hashCanonical(payload.authorization.proof)` (spec 03 §G). The payload shape is spec 03 §G.1. Receipt verification and record admission over a **legacy** history keep the reference's bound on the histories they carry (more than 4,096 events across the issuance and observed histories is `INVALID_INPUT`; record admission is `OUTPUT_LIMIT_EXCEEDED` from 2,048 events); format 1 has no such bound, because every receipt axis cites only the genesis, the head and the events relevant to the receipt.


