# Witness protocol and independent verification reference

> Reference from `WITNESS.md` at `00ca4c0` (SHA-256 `98a6297888278a5c2b9d16fce4b04f985d6b34168ad2f3957285b2986ad34ed4`). Established scope: the retained field, byte, code, limit and ordered-check contracts below. Not established: a new engine audit, deployment test or broader edition coverage.

Source section numbers are retained for cross-reference with [WITNESS.md](../WITNESS.md). Operational guidance stays in the narrative page. Format-2 owner-policy rules remain in the unchanged [owner-policy reference](owner-policy.md).

<!-- source: WITNESS.md:411-578; exact text except relative Markdown links -->

## 9. Protocol reference (`irontrellis-witness/1`)

All hashes are SHA-256. Canonical JSON is the IronTrellis canonical encoding (`canonicalEncode`, docs/HISTORY-FORMAT.md §2). History hashes are `0x` + 64 lowercase hex; Merkle hashes and proofs are standard base64 with padding, decoded strictly.

### 9.1 History id and head statements

`historyId` is the history hash at position 0 (`historyIdOfGenesis`: for a format-2 history its record hash at position 0, for a format-1 history `eventHistoryHashes[0]`): it commits to the genesis, hence to the domain, the lineage id and the first owner key set. Legacy (`continuity-event/0.2`) histories cannot be witnessed (`UNSUPPORTED_FORMAT`); migrate them first.

```
statement = {
  version:  "irontrellis-head-statement/1",
  historyId,                                   // 0x…
  domain:   { protocol: "irontrellis", version: "1", deploymentId },
  head:     { hash, position, canonicalTime },
  previous: { hash, position } | null          // the witness latest this statement extends
}
signedStatement = { statement, keyId, scheme, signature }
```

The owner key signs `hashCanonical(statement, "sha256")` exactly as it signs a head attestation (Ed25519 over the 32 raw hash bytes; `signature` is `0x` + hex). Validity: exact field sets; `previous` is null or `previous.position <= head.position`, with equal hashes at equal positions; a head (or previous) at position 0 has `hash === historyId`; `keyId`/`scheme` name an owner key in force at `head.position` (docs/HISTORY-FORMAT.md §7.1).

### 9.2 Acceptance rules

**Register** (`{ genesis }`): the genesis must validate as a format-2 or format-1 genesis (a legacy one is `UNSUPPORTED_FORMAT`); `historyId` is computed from it; registering an existing history is idempotent (200 with the original receipt).

**Head** (a signed statement), in this order:

1. The history is registered; the statement is well formed, names this history and the registered domain, and verifies with a key in force at its head position (an identical resubmission of a held statement is not re-checked, since its key may have been retired since). Under a format-2 owner approval policy the signer must also be qualified at the head's `canonicalTime` under the policy in force at that position: not `AGENT`, and `HUMAN` under `humanFloor: "ATTESTED"` (`docs/reference/owner-policy.md` §7). Otherwise 400 `WITNESS_SIGNER_UNQUALIFIED`, and nothing is recorded. A witness that does not know that epoch's policy answers 409 `WITNESS_POLICY_UNKNOWN`.
2. The head, or `previous`, is a head a supersede overrode (§7.4) → 409 `SUPERSEDED` with the latest head: nothing extends a superseded head (the same head stated again on the new chain is held again).
3. No head held yet: accept only `previous: null`, else 409 `STALE_PREVIOUS` with `latest: null`.
4. `previous` equals the latest head: the same head again → 200 `ALREADY_WITNESSED`; a head further on → 201 `APPENDED`; otherwise 400 `INVALID_STATEMENT`.
5. Otherwise, the witness holds a different hash at `head.position` → it appends an `EQUIVOCATION` entry (the held statement and this one) and answers 409 `EQUIVOCATION` with its receipt and the latest head. The history stays open. The evidence is **capped**: at most one `EQUIVOCATION` entry per (history, position) and at most 64 per history. A further conflicting statement at a position that has one is answered 409 `EQUIVOCATION` with that position's recorded entry (a resubmission of a statement already recorded as evidence gets its own recorded entry back); past 64 for the history, with the most recent recorded entry. Nothing is appended beyond the cap (`irontrellis_witness_equivocations_capped_total` counts those answers), so even a stolen owner key cannot grow the log without bound this way; the replay of `log.jsonl` refuses a log beyond the cap.
6. Otherwise, the witness holds this very head (not the latest) → 200 `ALREADY_WITNESSED` with the actual latest.
7. Otherwise → 409 `STALE_PREVIOUS` with the latest head.

**Key event** (`POST …/key-events`, `{ event, previousHead, eventHead, statement?, chain? }`). `event` is an `OWNER_KEYS_ROTATED` event, verbatim (the only owner key event: epoch 0's next-key commitment is in the registered genesis, a later one rides on a rotation); `eventHead` is the head that ends with it, `previousHead` the one before it; `statement` is the signed statement for `eventHead` (its key in force there, `previous` the witness's latest); `chain` is the supersede statement (§7.4). In this order:

1. The history is registered; the body has exactly those fields; the event has an id and is an `OWNER_KEYS_ROTATED` (400 `KEY_EVENT_INVALID`).
2. The same event id with the same event and heads again → 200 with the recorded receipt; another event with that id, or other heads → 400 `KEY_EVENT_INVALID`.
3. `eventHead.position === previousHead.position + 1`, and not before the current epoch's first position (400 `KEY_EVENT_INVALID`).
4. The event passes `verifyRotationEvent` against the epochs this witness knows (schema, the owner signature by a key in force at `previousHead`, the key-set rules; a rotation out of an epoch with a commitment must reveal a committed key with its proof of possession and satisfy `nextKeyAuthorizations`; a commitment-only rotation out of a committed epoch reveals no committed key and is refused). 400 `KEY_EVENT_INVALID` with the reason. A rotation that satisfies the commitment of the epoch it leaves is **pre-rotated**.
5. The witness holds a HEAD at exactly `eventHead` (and, with `chain`, that head is its latest) → 201: it appends the `ROTATED` entry bound to it.
6. It does not: if `statement` (or `chain`) states `eventHead`, verifies with a key in force there, and extends the witness's latest head (`previous` equals the latest, or is null when it holds none) → 201: it appends `HEAD eventHead` and then the key-event entry, in one write. A statement that does not extend the latest → 409 `STALE_PREVIOUS` with the latest head; neither given → 409 `KEY_EVENT_HEAD_UNKNOWN`. A bad statement is 400 `INVALID_STATEMENT` / `SIGNATURE_INVALID`.
7. **Supersede** (a `chain` that does not extend the latest, §7.4): the chain states `eventHead` and verifies there; `chain.previous` (L) is non-null, not after `previousHead`, and a head the witness holds; the rotation is pre-rotated; no supersede yet out of the current epoch; at least one head held after L. There is no limit on the number of heads superseded. Otherwise 409 `SUPERSEDE_REFUSED` (400 `INVALID_STATEMENT` for a malformed or misplaced chain). Then it appends, in one write, `SUPERSEDED` (the range: `supersededFromIndex` = L's leaf, `supersededToIndex` = its own leaf, `supersededLatest` = the latest head it held, `supersededCount` = the heads it held after L), `HEAD eventHead` (the chain; the latest was reset to L, so it extends it), and `ROTATED`; answers 201 with a `superseded` receipt too. The superseded heads leave the heads the witness holds (`GET …/heads/:position` answers 404 for them) and are answered 409 `SUPERSEDED` from then on.

The new epoch starts at `eventHead.position + 1` with the rotation's keys, its `nextKeyDigests` and, in format 2, its `ownerPolicy` as written. Epoch 0 is the genesis's owner keys, next-key commitment and owner approval policy, learned from the REGISTERED entry. In format 2, rule 4 applies the policy of the epoch the rotation leaves: its quorum and counting, recovery signers, and the time rule T2 (`docs/reference/owner-policy.md` §7). T2 needs the time of the head before the rotation. If the witness does not hold that head and T2 would decide, the answer is 409 `KEY_EVENT_HEAD_UNKNOWN`; send that head's statement first. Rotation replies list each epoch with its `policy` when it has one.

**Admin import** (`POST /v1/admin/key-events` with the admin token, or `irontrellis-witness import-key-events --data <dir> <bundle…>` under the server lock): the body is a key-event bundle (§9.9), whose `historyId` names the history; then exactly the key-event rules above with its `statement` and `chain`. The token gates the channel only.

### 9.3 Log entries and the Merkle tree

Each leaf is one entry; `leafHash = SHA-256(0x00 || utf8(canonicalEncode(entry)))`, and the tree is RFC 6962 / RFC 9162 §2.1 (`nodeHash = SHA-256(0x01 || left || right)`, split at the largest power of two below `n`, the empty tree's root is `SHA-256("")`). Inclusion and consistency proofs and their verification follow RFC 9162 §2.1.3–2.1.4. An inclusion proof does not bind the tree size by itself: the size always comes from a signed checkpoint.

```
{ version: "irontrellis-witness-entry/1", kind: "REGISTERED",   historyId, genesis, receivedAt }
{ version: "irontrellis-witness-entry/1", kind: "HEAD",         historyId, signedStatement, receivedAt }
{ version: "irontrellis-witness-entry/1", kind: "ROTATED",      historyId, rotation, previousHead, rotationHead, receivedAt }
{ version: "irontrellis-witness-entry/1", kind: "EQUIVOCATION", historyId, first, second, receivedAt }
{ version: "irontrellis-witness-entry/1", kind: "SUPERSEDED",   historyId, rotation, previousHead, rotationHead, chain,
  supersededFromIndex, supersededToIndex, supersededLatest: { position, hash, index }, supersededCount, receivedAt }
```

`receivedAt` is the witness clock in ms. `genesis` and `rotation` are the events verbatim; `first` is the signed statement the witness held, `second` the conflicting one. A `ROTATED` entry requires `rotationHead.position === previousHead.position + 1`. A `SUPERSEDED` entry carries the rotation that supersedes and its heads (as `ROTATED`), the chain statement (it states `rotationHead`, its `previous` is non-null and before it), and the superseded **range** (so the entry never grows with the number of heads): `supersededFromIndex` (the leaf index of the HEAD entry of L, `chain.previous`), `supersededToIndex` (the log size when the supersede was decided, which is the SUPERSEDED entry's own leaf index), `supersededLatest` (`{ position, hash, index }`, the witness's latest head then, strictly inside the range and after L) and `supersededCount` (the number of heads the witness held after L, at least 1 and at most the leaves inside the range). Every HEAD entry of the history with a leaf index strictly inside the range is superseded; replay (at start and in `check-log`) derives that set from the range and checks the three named values against its own state. It is always followed by the chain's `HEAD` entry and the `ROTATED` entry. `conformance/transparency/vectors.json` has vectors for every entry kind (TypeScript and Python validate them alike). `log.jsonl` stores `{"index":N,"entry":…}` per line, nothing else.

### 9.4 Checkpoints and keys (C2SP signed notes)

A checkpoint is a C2SP tlog-checkpoint in a signed note, byte-compatible with `golang.org/x/mod/sumdb/note` (Ed25519 only):

```
<origin>\n<tree size, decimal>\n<base64 root>\n
\n
— <key name> <base64(keyHash[4] || ed25519 signature[64])>\n
```

The signature line starts with U+2014 EM DASH and a space; the signature is over the body bytes. `keyHash = SHA-256(name || "\n" || 0x01 || publicKey[32])[0:4]`. A **verifier key** is `<name>+<8 hex keyHash>+<base64(0x01 || publicKey)>`; a signer key `PRIVATE+KEY+<name>+<8 hex>+<base64(0x01 || seed)>`. Opening a note ignores signatures by unknown keys and rejects a note on which a known key's signature is bad.

### 9.5 Receipts

```
receipt = {
  version: "irontrellis-witness-receipt/1",
  witness: { origin, verifierKey },
  entry,                // the leaf entry
  index,                // its leaf index
  checkpoint,           // signed note of a tree whose size is greater than index
  inclusionProof        // base64 audit path, leaf to root
}
```

Verification (`verifyWitnessReceipt(receipt, trustedVerifierKeys)`): open the note with the **trusted** keys (never the key the receipt names), parse the checkpoint, check its origin against `witness.origin`, validate the entry, check `index < size`, recompute the leaf hash and verify the inclusion proof against the checkpoint root. Failure reasons, in this order: `RECEIPT_MALFORMED`, `NOTE_UNVERIFIED`, `CHECKPOINT_MALFORMED`, `ORIGIN_MISMATCH`, `ENTRY_MALFORMED`, `INDEX_OUT_OF_RANGE`, `INCLUSION_INVALID`.

### 9.6 HTTP API

JSON request bodies must be `application/json` (UTF-8), at most 64 KiB (1 MiB for registration). Every JSON reply that references log entries carries one top-level `checkpoint` (signed note text) whose size covers every index referenced, and every receipt in that reply uses the same note with the inclusion proof for its size. Every reply has `cache-control: no-store`.

**Nonces.** The history routes (`POST /v1/histories`, `GET /v1/histories/:id`, `POST …/heads`, `POST …/key-events`) and `POST /v1/admin/key-events` take an optional query parameter `nonce`: canonical unpadded base64url (RFC 4648 §5) of 16..64 bytes, given at most once (400 `INVALID_REQUEST` otherwise, checked after the registration token and before the history lookup). With it, every reply that carries log state for a known history (success, 409 `STALE_PREVIOUS` and `EQUIVOCATION` included) also carries `latestNote`: the witness's signed latest note over that nonce (§9.8). The core client always sends a fresh 32-byte nonce.

| route | request | success | errors |
|---|---|---|---|
| `GET /v1/witness` | | 200 `{ version: "irontrellis-witness/1", origin, verifierKey, software }` | |
| `GET /v1/checkpoint` | | 200 the latest signed note, `text/plain; charset=utf-8` | |
| `POST /v1/histories[?nonce=]` | `{ genesis }`; `Authorization: Bearer <token>` unless `registration: "open"` | 201 new / 200 existing: `{ historyId, receipt, checkpoint, latestNote? }` (the `REGISTERED` entry) | 401 `UNAUTHORIZED` (with `WWW-Authenticate`), 400 `INVALID_REQUEST` / `INVALID_GENESIS` / `UNSUPPORTED_FORMAT`, 503 `HISTORY_LIMIT_REACHED` |
| `GET /v1/histories/:id[?nonce=]` | | 200 `{ historyId, domain, equivocations, supersedes, epochs: [{ fromPosition, keys, nextKeyDigests? }], latest: null \| { head, receipt }, lastEquivocation?, lastSupersede?, checkpoint, latestNote? }` (`lastSupersede`: the receipt of the newest `SUPERSEDED` entry, exactly when `supersedes > 0`) | 404 `NOT_REGISTERED` |
| `POST /v1/histories/:id/heads[?nonce=]` | signed statement | 201 `{ status: "APPENDED", receipt, latest, checkpoint, latestNote? }`; 200 `{ status: "ALREADY_WITNESSED", … }` (`latest` is the actual latest) | 404 `NOT_REGISTERED`; 400 `INVALID_STATEMENT`, `SIGNATURE_INVALID` (hint `ROTATION_REQUIRED` when the key id is unknown to every epoch the witness knows); 409 `STALE_PREVIOUS` with `latest` (or `null`) and `checkpoint`; 409 `EQUIVOCATION` with `receipt` (the `EQUIVOCATION` entry), `latest` and `checkpoint`; 409 `SUPERSEDED` with `latest` and `checkpoint` |
| `POST /v1/histories/:id/key-events[?nonce=]` | `{ event, previousHead, eventHead, statement?, chain? }` (§9.2) | 201 new / 200 same again: `{ receipt, superseded?, epochs, latest, checkpoint, latestNote? }` (`receipt`: the `ROTATED` entry; `superseded`: the `SUPERSEDED` entry of a supersede) | 404 `NOT_REGISTERED`; 400 `INVALID_REQUEST`, `KEY_EVENT_INVALID`, `INVALID_STATEMENT`, `SIGNATURE_INVALID`; 409 `KEY_EVENT_HEAD_UNKNOWN`, `STALE_PREVIOUS` (with `latest`), `SUPERSEDE_REFUSED` (with `latest`) |
| `POST /v1/admin/key-events[?nonce=]` | a key-event bundle (§9.9); `Authorization: Bearer <admin token>` | as `…/key-events` | 401 `UNAUTHORIZED`; 400 `INVALID_REQUEST` (not a bundle); otherwise as `…/key-events` |
| `GET /v1/histories/:id/heads/:position` | | 200 `{ head, receipt, checkpoint }` | 404 `NOT_REGISTERED`, 404 `NOT_FOUND` (no head held there) |
| `GET /v1/proofs/inclusion?index=&size=` | `size` defaults to the latest checkpoint's | 200 `{ index, size, proof: [b64] }` | 400 `INVALID_REQUEST` (`size` past the log, `index >= size`) |
| `GET /v1/proofs/consistency?from=&to=` | `to` defaults to the latest checkpoint's | 200 `{ from, to, proof: [b64] }` | 400 `INVALID_REQUEST` (`to` past the log, `from > to`) |
| `GET /v1/entries?start=&end=` | `end` exclusive, defaults to `start + 1000` | 200 `{ start, entries: [entry] }`, clamped to 1,000 entries and to the log size | 400 `INVALID_REQUEST` (`start` past the log, `end < start`) |
| `GET /healthz` | | 200 `{ status: "ok", entries, checkpointSize, checkpointAgeMs }` | 503 `{ status: "failed", … }` after a storage failure; 429 `RATE_LIMITED` (monitoring bucket) |
| `GET /metrics` | `Authorization: Bearer <metricsToken>` when `metricsToken` is configured | 200 Prometheus text (§4.7) | 401 `UNAUTHORIZED`; 429 `RATE_LIMITED` (monitoring bucket) |

`:id` must be `0x` + 64 lowercase hex and numbers non-negative decimal integers (400 `INVALID_REQUEST` otherwise). Errors are `{ error: { code, message, hint? } }` plus the fields listed. Transport-level answers: unknown route 404 `NOT_FOUND`; wrong method 405 `INVALID_REQUEST` with `Allow`; wrong content type 415 `INVALID_REQUEST`; request timeout 408 `INVALID_REQUEST`; body too large 413 `PAYLOAD_TOO_LARGE`; rate limit 429 `RATE_LIMITED` with `Retry-After` (seconds); shutting down or after a storage failure 503 `INTERNAL`; any unexpected failure 500 `INTERNAL` (never a stack trace). The stable codes are `NOT_FOUND`, `UNAUTHORIZED`, `INVALID_REQUEST`, `INVALID_GENESIS`, `UNSUPPORTED_FORMAT`, `NOT_REGISTERED`, `INVALID_STATEMENT`, `SIGNATURE_INVALID`, `STALE_PREVIOUS`, `EQUIVOCATION`, `KEY_EVENT_INVALID`, `KEY_EVENT_HEAD_UNKNOWN`, `SUPERSEDED`, `SUPERSEDE_REFUSED`, `RATE_LIMITED`, `PAYLOAD_TOO_LARGE`, `HISTORY_LIMIT_REACHED`, `INTERNAL`, `WITNESS_POLICY_UNKNOWN`, `WITNESS_SIGNER_UNQUALIFIED`.

### 9.7 What the client checks

The core client (docs/API.md §7a) believes nothing it has not checked:

* It verifies each receipt's own `checkpoint` with the **configured** verifier key (it ignores the top-level `checkpoint`), and checks it for consistency with the largest checkpoint it has seen from that origin, in memory and in the side file: a larger tree needs a valid `GET /v1/proofs/consistency?from=<remembered>&to=<new>`, a smaller one must be proven a prefix of the remembered one, an equal size must have the same root. Any failure is `WITNESS_SPLIT_VIEW`, sticky.
* It sends a fresh random nonce on every history route and requires the `latestNote` in the answer (§9.8): opened with the configured key, for this origin, history and nonce, naming exactly the answer's `latest` (head, leaf index, the tree size of its receipt's checkpoint; or none), and the answer's equivocation and supersede counts. A registration or key-event answer's note must be for the tree size of its receipt; a new registration's note must name no head, and a "not registered" answer followed by a registration whose note names a head is invalid. Missing or wrong: `WITNESS_INVALID_RESPONSE` (reason `LATEST_NOTE_MISSING`, `LATEST_NOTE_INVALID` with the verification reason, or `LATEST_NOTE_MISMATCH`).
* It checks that each receipt names the entry it expects: for `APPENDED`, the HEAD leaf canonically equal to the submitted statement; for `ALREADY_WITNESSED`, a HEAD leaf stating the same head; for every `latest`, a HEAD leaf of this history stating exactly that head; for registration, the REGISTERED leaf of this genesis and history id; for a key event, the ROTATED leaf of this event and these heads (and for a `superseded` receipt, the SUPERSEDED leaf of this rotation and this chain); for `EQUIVOCATION`, an EQUIVOCATION leaf of this history whose `second` is the submitted statement, plus a verified `latest` (otherwise `WITNESS_INVALID_RESPONSE`, not an alarm). `GET /v1/histories/:id` must carry a verifiable `lastEquivocation` exactly when `equivocations > 0`, and a verifiable `lastSupersede` (a SUPERSEDED leaf of this history) exactly when `supersedes > 0`; both counts must equal the latest note's. The epochs (with their `nextKeyDigests`) must be well formed.
* Status handling: 404 on a history route means "not registered". For a witness the history binds without a receipt it is an unsigned answer a reader cannot use: it counts as unreachable (an owner-keyed process registers instead and uses the signed note of that answer). For a witness the history binds with its signed REGISTERED receipt that is a contradiction: the client first fetches and checks the witness's current checkpoint (a split view is the stronger finding), then treats the answer as a denial (§6.1) and never registers again. Otherwise the client registers the genesis when it holds the owner key; a 4xx refusal of that registration is the sticky `WITNESS_REJECTED` state (reason `REGISTRATION_REFUSED`). 5xx (including 503 `HISTORY_LIMIT_REACHED`: a full witness is a capacity problem its operator can fix, not a refusal of this history), 408 and 429 are transient (`WITNESS_UNAVAILABLE`, retried with backoff; `Retry-After` is not read); any other non-2xx is `WITNESS_REJECTED` with the server's code and hint.
* The admin token is sent only on registration, and only when the witness config carries one.
* A witness URL is `https:`, or plain `http:` only to a loopback host or with `allowInsecureHttp` (§4.3).
* A bound witness is asked at its bound URL only (§5.3), and every bound witness is part of every check.

### 9.8 Latest notes (freshness)

A receipt proves that a head is **in** the witness's log; it cannot prove that it is the **latest** head, so a relay could hand the client a genuine receipt for an older head as `latest`. Every answer that asserts a history's latest head therefore carries `latestNote`: a signed note (the witness's checkpoint key, the note format of §9.4) whose body is exactly ten lines, each ending in `\n`:

```
irontrellis-witness-latest/1
<origin>
<historyId>
<nonce>
<latest position, decimal, or "none">
<latest head hash, 0x…, or "none">
<leaf index of that HEAD entry, decimal, or "none">
<tree size of the reply's checkpoint, decimal>
<equivocation count, decimal>
<supersede count, decimal>
```

The three head lines are all `none` exactly when the witness holds no head for the history (registration only). Decimals have no leading zeros and are at most 2^53 − 1; the leaf index is below the tree size; the nonce is the request's, in canonical unpadded base64url of 16..64 bytes. Domain separation: a checkpoint's first line is the origin, and a witness refuses to be configured with the origin `irontrellis-witness-latest/1`; the second line of a latest note is the origin, not a decimal. So a latest note never parses as a checkpoint and a checkpoint never parses as a latest note.

The client checks (`verifyLatestNote(note, [configuredKey], { origin, historyId, nonce })`, then the fields): the note verifies with the **configured** key; origin, history id and nonce match the request; head, hash and leaf index are those of the answer's `latest` receipt (or `none` ⇔ `latest: null`); the tree size is that of the `latest` receipt's checkpoint (of the reply's checkpoint when there is no head, of the receipt's for registrations and rotations); the equivocation and supersede counts match the answer's (the supersede count: `supersedes` of `GET /v1/histories/:id`). The expectation is required and fails closed: a plain object (a Python `dict`) whose fields are exactly `historyId` (a content hash), `nonce` (a valid nonce) and optionally `origin`, each a string of that shape; anything else (omitted, `null`, a `Map`, an array, a `MappingProxyType`, a missing or mistyped field, an unknown key) is `EXPECTATION_INVALID`, so a caller cannot skip the nonce check by accident. Verification reasons, in order: `EXPECTATION_INVALID`, `NOTE_UNVERIFIED`, `LATEST_MALFORMED`, `ORIGIN_MISMATCH`, `HISTORY_MISMATCH`, `NONCE_MISMATCH`. `formatLatestNote`, `parseLatestNote`, `verifyLatestNote`, `isValidNonce` and `newNonce` are on `@ramex-labs/irontrellis/transparency`; the Python verifier has `format_latest_note`, `parse_latest_note`, `verify_latest_note` and `is_valid_nonce`; `conformance/transparency/vectors.json` has format, parse and verify vectors (`latestNotes`).

What a latest note establishes: that the holder of the witness key said, after the client chose the nonce, that this was the history's latest head in a log of that size. It is the answer the rollback decisions (`verify`, the `requireOnOpen` gate, the check before an owner write, each submission round) are made on. The owner-sealed cache of earlier answers in the side file stays an optimization for `requireOnOpen` readers within `cacheMs` (§3); writers never use it.

### 9.9 Key-event bundles

A key-event bundle is one JSON file, `<history>.key-event-<position>.bundle.json`, written by the owner (0600, atomically) for each rotation, and by `irontrellis owner export-key-events`:

```
{
  version:      "irontrellis-key-event-bundle/1",
  historyId,                     // 0x…
  event,                         // the OWNER_KEYS_ROTATED event, verbatim
  previousHead: { hash, position },
  eventHead:    { hash, position },   // position = previousHead.position + 1
  statement,                     // signed statement of eventHead, previous = previousHead, by the key in force at eventHead
  chain?                         // a pre-rotated rotation only: the supersede statement of eventHead, previous = L (§7.4)
}
```

Exact field sets (`validateKeyEventBundle` on `@ramex-labs/irontrellis/transparency`); the statements state `eventHead` for this history. The `chain`, when present, starts from the last head the owner knew a bound witness that lacks the rotation held (without one, no chain). Nothing in a bundle is secret, and it is self-authenticating: a witness imports it (§9.2, admin import) only when every owner signature in it verifies against what the witness already knows.


<!-- source: WITNESS.md:579-579; exact text except relative Markdown links -->

## 10. Verifying receipts independently

<!-- source: WITNESS.md:583-600; exact text except relative Markdown links -->

**TypeScript** (`verifyWitnessReceipt`, from `@ramex-labs/irontrellis` or `@ramex-labs/irontrellis/transparency`):

```js
import { verifyWitnessReceipt } from "@ramex-labs/irontrellis";
const result = verifyWitnessReceipt(receipt, ["witness.example.com+1a2b3c4d+AX…"]);
// { ok: true, checkpoint: { origin, size, root }, index, verifiedBy } or { ok: false, reason, message }
```

The same subpath has the building blocks: `verifyInclusion`, `verifyConsistency`, `openNote`, `parseCheckpoint`, `parseVerifierKey`, `validateEntry`, `entryLeafHash`, `verifySignedHeadStatement`, `verifyLatestNote`.

**Python** (zero dependencies):

```sh
curl -s https://witness.example.com/v1/histories/0x…/heads/12 > receipt.json
python -m irontrellis verify-receipt receipt.json --verifier-key 'witness.example.com+1a2b3c4d+AX…'
```

It accepts a bare receipt or a witness reply that carries one (`{ receipt }` or `{ latest: { receipt } }`), takes `--verifier-key` more than once, prints a JSON report (`status` `VALID` with the index, the checkpoint and a summary of the entry, or `INVALID` with the reason code) and exits 0 or 1. From Python code: `irontrellis.transparency.verify_witness_receipt(receipt, [vkey])`, with the TypeScript reason codes.

