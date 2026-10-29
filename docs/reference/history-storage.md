# Pins, anchors, bindings and side files reference

> Reference from `HISTORY-FORMAT.md` at `00ca4c0` (SHA-256 `aecc62db80fda785ca06b60107097316cdc453416d0fa61baef42c6e903bc35b`). Established scope: the retained field, byte, code, limit and ordered-check contracts below. Not established: a new engine audit, deployment test or broader edition coverage.

Source section numbers are retained for cross-reference with [HISTORY-FORMAT.md](../HISTORY-FORMAT.md). Operational guidance stays in the narrative page. Format-2 owner-policy rules remain in the unchanged [owner-policy reference](owner-policy.md).

<!-- source: HISTORY-FORMAT.md:378-409; exact text except relative Markdown links -->

## 9. Pinned head file

After every successful append the store writes `<history>.head` atomically (write to `<history>.head.tmp-<pid>-<n>`, rename), one JSON object followed by `\n`:

```
{"version":"irontrellis-pinned-head/1","hash":"0x…","position":1,"canonicalTime":2,"recordHash":"0x…","pinnedAt":1700000000000}
```

| field | meaning |
|---|---|
| `hash`, `position`, `canonicalTime` | the head after the append |
| `recordHash` | the `recordHash` of the last line |
| `pinnedAt` | host clock at pinning |
| `attestation?` | format 1, when an owner signer is available: `{ version: "irontrellis-head-attestation/1", head: {hash, position, canonicalTime}, keyId, scheme, signature }`, the owner key's signature over `hashCanonical({ version: "irontrellis-head-attestation/1", domain, head })` (SHA-256). Written together with the pin for local keys; for an asynchronous signer (KMS) the pin is written first and re-written with the attestation when the signature arrives |
| `rollbackAcceptedAt?` | present when an operator re-pinned the file with `acceptRollback` (a pin the file did not contain, a malformed pin, or a missing pin): the host clock at that moment. Also set when a writer with `acceptRollback` finds the pin deleted while it holds the history open |
| `previousPin?` | with `rollbackAcceptedAt`, the pin that was overridden, as it was read (without its own `previousPin`: one level of provenance); absent when there was no readable pin |

The next ordinary write replaces the pin without these two fields, so they record the most recent acceptance only until then. The `version` field is not part of the in-memory `PinnedHead`; readers strip it after checking it.

On open, the store reads the pin **before** the file (a writer appends its line before it rewrites the pin, so the file is then at least as long as the pin it just read) and derives a status:

| status | condition | on open | `verify()` |
|---|---|---|---|
| `MATCHES` | the file's head is the pinned position, with the pin's record hash and history hash there | accepted | fine |
| `AHEAD` | the file is longer than the pin and has the pin's record hash and history hash at the pinned position (normal between an append and its pin, and after a writer that does not pin, such as the Continuity SDK on a legacy file, appended) | accepted | fine |
| `ROLLBACK` | the file's head is before the pinned position, or the record hash or history hash at that position differs | `ROLLBACK_DETECTED`, reason `BEHIND_PIN` | failure `PIN_ROLLBACK` |
| `MALFORMED` | the pin file exists but is not a valid pin (unparsable, wrong `version`, a field of the wrong type) | `ROLLBACK_DETECTED`, reason `PIN_MALFORMED` | failure `PIN_MALFORMED` |
| `MISSING` | no pin file, and the history is format 1 with events after genesis | `ROLLBACK_DETECTED`, reason `PIN_MISSING` | failure `PIN_MISSING` (a note with `allowUnpinned`) |
| `UNPINNED` | no pin file, and none is required: a legacy history (legacy files predate pinning), an empty file, or a format-1 genesis-only history | accepted | note `PIN_UNPINNED` |

A `ROLLBACK` or `MISSING` status beside a *valid* file is re-read up to three times, 10 ms apart, to tolerate a writer between its append and its pin. With `acceptRollback`, a `ROLLBACK`, `MALFORMED` or `MISSING` file, and one refused for its attestation or its anchor log below, is re-pinned as it is (attested when a signer is configured, with `rollbackAcceptedAt` and `previousPin`) instead of refused. With `allowUnpinned`, a `MISSING` pin, an attestation problem and an anchor-log problem are tolerated for reading, and every write still refuses them. `inspect` defers every pin problem to `verify()` and refuses every write. A writer never re-pins a missing pin silently: if the pin disappears while a writer holds the history open, its next append fails with `ROLLBACK_DETECTED` (reason `PIN_MISSING`) unless it was opened with `acceptRollback`.


<!-- source: HISTORY-FORMAT.md:414-449; exact text except relative Markdown links -->

## 10. Anchors

Beyond the pin, two mechanisms catch a restored or cut-back copy. The **remote witnesses** a history binds (§10.1, docs/WITNESS.md) are the rollback defence: services the file's writers cannot rewrite. **Anchors** (this section) are owner-signed evidence about a head kept elsewhere; the local anchor log is the offline fallback that every `verify()` reads.

An **anchor** is an owner-signed head attestation (the `attestation` structure of §9) handed to an anchor target, whose receipt is recorded back into the history as `ANCHOR_RECORDED`. Replay accepts the event iff `anchoredHead.position < <event position>` and `anchoredHead.hash` equals the history hash at that position; anchors are otherwise informational (they grant nothing). `verify()` reports every anchor as `PREFIX_OK` or `MISMATCH` (`anchors[].anchor` echoes `data.anchor`). An anchor binds, unbinds and re-policies no remote witness, whatever its receipt holds: only the events of §10.1 do.

Anchor kinds and their `data.anchor` literals: `local-head-file` (the local anchor log: appends `{"attestation":…,"receivedAt":<ms>}\n` to `<history>.anchors`, mode 0600; receipt `{ file, receivedAt, entryHash }` where `entryHash = sha256(canonical(entry))`), `rekor-v2` (a Sigstore Rekor v2 `hashedrekord` over the attestation hash; **experimental**, never exercised against a live log), `custom` (a target the caller supplies). A receipt is a plain record of at most 64 KiB canonical text.

**The local anchor log** (`<history>.anchors` by default, any path with `localAnchorLog(path)`) is append-only JSON Lines, mode 0600, one entry per submitted attestation:

```
{"attestation":{"version":"irontrellis-head-attestation/1","head":{"hash":"0x…","position":4,"canonicalTime":1790…},"keyId":"owner:1","scheme":"ed25519","signature":"0x…"},"receivedAt":1790…}
```

The local anchor log refuses an attestation that does not verify against the history's owner keys (`ANCHOR_LOG_REJECTED`). A reader must refuse the whole log (`ANCHOR_LOG_UNREADABLE`) when it cannot be read, when its last line is incomplete, or when any line is not an entry of this shape (`head.position` and `head.canonicalTime` non-negative safe integers, `head.hash` and `keyId` strings, `receivedAt` absent or a safe integer). The `ANCHOR_RECORDED` receipt names the log by its base name (`file`), not its path, so a log can be moved or copied elsewhere and still be matched.

**Anchor log verification** (`verify()`, after the pin). Each anchor target that can list what it holds (`entries()`: the local anchor log can, Rekor cannot) is compared with the history. Logs at the same resolved location are read once. `<history>.anchors` is always consulted when it exists; further logs are given by the caller (`anchorLogs`, CLI `--anchors-file`). Each head a log holds is judged:

| `anchorLogHeads[].status` | condition | failure |
|---|---|---|
| `PREFIX_OK` | signed by an owner key in force at its position (§7.1), position ≤ the file's head, and the file's history hash at that position equals `head.hash` | none |
| `NEWER_THAN_FILE` | position past the file's head (events were removed) | `ANCHOR_LOG_ROLLBACK` |
| `NOT_A_PREFIX` | the file holds another history at that position (rewritten or replaced) | `ANCHOR_LOG_ROLLBACK` |
| `SIGNATURE_INVALID` | not a signature by an owner key in force at its position over `{version, domain, head}` | `ANCHOR_LOG_INVALID` |

A log that exists but cannot be read or parsed is `ANCHOR_LOG_UNREADABLE`. Every local anchor the history records (`anchor: "local-head-file"`) names its log in `receipt.file`. When no readable log with that base name was consulted, verification fails with `ANCHOR_LOG_MISSING`: a history that proves its log existed does not get to call a deleted log "no anchor log". `anchorLogStatus` summarizes the result, in this order of precedence:

* `UNREADABLE`;
* `ROLLBACK`;
* `INVALID`;
* `MISSING`;
* `OK`: at least one head held, all `PREFIX_OK`;
* `NONE`: no anchor log holds anything, a note (`ANCHOR_LOG_NONE`), not a failure;
* `NOT_APPLICABLE`: a legacy history, which cannot be anchored; a log holding heads for it only earns the note `ANCHOR_LOG_IGNORED`.

After an accepted rollback (§9), a log that still holds the removed heads keeps failing verification and adds the note `ANCHOR_LOG_AFTER_ACCEPTED_ROLLBACK` until it is archived deliberately. Anchors recorded in the history are checked too: an `ANCHOR_RECORDED` head that is not a prefix is `ANCHOR_MISMATCH`.

<!-- source: HISTORY-FORMAT.md:451-484; exact text except relative Markdown links -->

### 10.1 Remote witness bindings: `WITNESSES_BOUND` and `WITNESSES_UNBOUND`

A format-1 history names the remote witnesses (docs/WITNESS.md) that must be consulted for it with two owner-signed control events. Both are format 1 only, always admitted by the capacity policy, and refused inside a migrated legacy prefix (§11).

```
WITNESSES_BOUND.data = {
  witnesses: [ { url,                    // the witness URL, normalised
                 verifierKey,            // the witness's signed-note verifier key
                 name?,                  // Identifier
                 allowInsecureHttp?,     // true when present: the owner accepted a plain-http URL to a non-loopback host
                 registration? } ],      // the witness's signed receipt of the REGISTERED leaf of this history
                                         // 1..16 witnesses, distinct verifierKey
  policy: { quorum, requireOnOpen, maxUnwitnessedEvents }
}

WITNESSES_UNBOUND.data = {
  verifierKeys: [ <verifierKey>, … ],    // 1..16, distinct
  policy: { quorum, requireOnOpen, maxUnwitnessedEvents },
  acceptedLoss?: { reason,               // Identifier-shaped text
                   heads: [ { verifierKey, head: { hash, position, canonicalTime } } ] }   // 1..16, distinct verifierKey
}
```

The schemas are closed (`EVENT_DATA_INVALID`; a list over 16 members is `INVALID_INPUT`). `url` is printable ASCII of at most 2,048 characters, `http://` or `https://`, an authority without userinfo, no `?`, `#` or `\`, and no trailing `/`. `verifierKey` must parse as a note verifier key `<name>+<hash>+<key>` (docs/WITNESS.md §9.1). `policy.quorum` is an integer in 1..16, `policy.requireOnOpen` a boolean, `policy.maxUnwitnessedEvents` an integer ≥ 1. `registration` must be a plain record; replay checks it (§10.1 rejections), including that it has no fields beyond a witness receipt's (`version`, `witness` = `{origin, verifierKey}`, `entry`, `index`, `checkpoint`, `inclusionProof`). An unbinding names verifier keys only: the URL is not needed to unbind.

Replay keeps the **bound witnesses** (in binding order, each with the id and position of the event that bound it) and the **bound policy** (the `policy` of the newest binding event; there is none before the first). It refuses, with `TRANSITION_INVALID` (reason prefix `witness binding: ` or `witness unbinding: `):

* `WITNESSES_BOUND` with a `registration` that has a field a witness receipt does not have, that does not verify as a witness receipt (docs/WITNESS.md §9.5) under that witness's own `verifierKey`, or whose entry is not the `REGISTERED` leaf of this history (`historyId` the history hash at position 0, `genesis` this history's genesis event); or that leaves more than 16 witnesses bound. A witness already bound is re-bound in place: its `url`, `name`, `allowInsecureHttp` and `registration` are replaced. That is how a witness moves to a new URL, and how one bound while it was unreachable later gets its registration receipt.
* `WITNESSES_UNBOUND` naming a verifier key that is not bound, or with an accepted-loss head for a witness the event does not unbind, or for a head this history contains (nothing was lost).
* either event with a `policy.quorum` above the number of witnesses bound after it (above 1 when none stays bound).

Clients consult the bound witnesses whatever `<history>.witness.json` says (§13), at the URL, with the verifier key and the `allowInsecureHttp` of the binding only: a bound witness is pinned, and the side file cannot move it. A copy of the history cut back to before its first binding names none. The bound policy is the owner-signed minimum: clients apply the strictest of it and every other policy source (the higher quorum, `requireOnOpen` if any says so, the lower `maxUnwitnessedEvents`), and every rollback check needs `bound − quorum + 1` answers from the bound witnesses themselves (docs/WITNESS.md §5.3). A `registration` is how a client knows that a later "not registered" answer from that witness contradicts the witness's own signature; a binding without one (the witness was unreachable when it was bound) proves nothing about the registration. `acceptedLoss` records the owner's decision (docs/WITNESS.md §6.2) and the heads the removed witnesses hold.

A binding is its own event, never part of the genesis: `registration` is a receipt over the genesis hash itself, and witnesses are added and removed over a history's life.

<!-- source: HISTORY-FORMAT.md:486-489; exact text except relative Markdown links -->

API: `boundWitnessesOf(state)`, `boundPolicyOf(state)`, `boundRegistrationOf(state, verifierKey)`, `witnessBindingEvent(…)`; Python: `bound_witnesses_of(state)`, `bound_policy_of(state)`. Conformance: the `anchors-and-witness-bindings` topic (conformance/README.md). `irontrellis witness add` / `LocalOwner#addWitness` write `WITNESSES_BOUND` (also to move a bound witness to a new URL, or to change the policy minimum); `witness remove` / `removeWitness` write `WITNESSES_UNBOUND` for witnesses the history binds, with the remaining witnesses' minimum (a witness known only from the side file is dropped from it, and no event is written); `createLocalOwner({ witness })` / `irontrellis init --witness` write one `WITNESSES_BOUND` at position 2, in the same write as the genesis and the principal, so no pinned head of the history ever lacks it.

What a witness is sent (head statements), what it keeps (its log) and what it returns (receipts) are specified in docs/WITNESS.md §9. Only format-1 histories can be witnessed; the witness identifies a history by its position-0 hash (`historyId`).


<!-- source: HISTORY-FORMAT.md:533-573; exact text except relative Markdown links -->

## 13. Side files and limits

Every side file shares the history's path as a prefix. `irontrellis-hook` keeps all of them, by default, in `~/.irontrellis/projects/<first 16 hex of sha256(project path)>/` (mode 0700), outside the project; the project holds only the hook's config, which records the history path.

| file | content | mode |
|---|---|---|
| `<history>` | the JSONL history (§3). The store reads it as bytes, splits it on `0x0A` and decodes each line as strict UTF-8 on its own, so a format-1 file is readable up to its 1 GiB limit (a single JavaScript string tops out near 512 MiB); a file over its format's limit is refused on open | 0600 |
| `<history>.head` | the pinned head (§9); written through `<history>.head.tmp-<pid>-<n>` and a rename | 0600 |
| `<history>.writer-lock` | `{"pid":<n>,"hostname":"<host>","createdAt":<ms>}` while a writer holds the lock; created with `O_EXCL`, removed on release (only while it is still the holder's own file). A lock older than 60 s (by mtime and `createdAt`) whose `pid` is not alive on the same host is reclaimed; a lock from another host is never reclaimed. The reference SDK's empty lock file is treated as unreadable and reclaimed after 60 s. A reclaim renames the lock to `<history>.writer-lock.stale-<pid>-<n>` first and deletes it only if it is the very file judged stale (same inode, mtime and content); otherwise it links it back. A writer checks before every append that the lock path is still its own file (`STORE_BUSY` otherwise, nothing written) | 0600 |
| `<history>.owner-key.json` | `{"version":"irontrellis-owner-key/1","keyId","scheme":"ed25519","credential":"0x<pubkey>","privateKey":"0x<32-byte seed>"}`, pretty-printed; created with `O_EXCL`. Creating a format-1 history refuses a key file already at this path (`KEY_EXISTS`) unless told to reuse it; loading refuses a file with any group or other permission bit set (POSIX). It may instead hold a **key reference** (`irontrellis-owner-key-ref/1`, §13.1): no key material, the public key and the signer that holds the key | 0600, required |
| `<history>.owner-key.pending.json` | a rotation's new owner key (same shape: a generated key, or the committed next key rewritten as an owner key file; a committed next-key reference is rewritten as an owner key reference, §13.1) between its creation and the recording of `OWNER_KEYS_ROTATED` (§7.1); created exclusively under the writer lock (a generated key with `O_EXCL`, a promoted next key through a temporary file linked into place). On the next open (and before the next rotation): when the history's current owner key set contains its key, the old key file is archived and this file is renamed to `<history>.owner-key.json`; when the history never declared its key, it is removed | 0600 |
| `<history>.owner-next-key.json` | the committed next owner key (pre-rotation, §7.2): `{"version":"irontrellis-owner-next-key/1","keyId","scheme","credential","privateKey"}`, the owner key file's record under another version, so neither loader accepts the other's file; `keyId` is the id the key proposes for the rotation that reveals it. Or a next-key reference (`irontrellis-owner-next-key-ref/1`, §13.1) naming a key a signer holds; a key committed by public key only has no file at all. Written (temporary file, fsync, link, so the path never holds a partial key) by `createLocalOwner` and moved here from its pending file by `commitNextKey` and by a rotation. It belongs **off the agent host**: move it to offline storage and bring it back (`irontrellis owner rotate-key --next-key <file>`) only for the rotation. A rotation that revealed the key from this path replaces it with the fresh next key (or removes it when the fresh key is not a file); `irontrellis owner status` reports what it holds (`COMMITTED`, `IN_FORCE`, `RETIRED`, `UNCOMMITTED`, `UNREADABLE`) | 0600 |
| `<history>.owner-next-key.pending.json` | a fresh next key between its creation and the recording of the rotation that commits to it (`nextKeyDigests`; a commitment-only rotation included). On the next open (and before the next rotation), after the owner key file is settled: when the owner keys in force committed to its digest, it replaces `<history>.owner-next-key.json` (replacing only a copy of a key the history declared, never the committed key itself, a key the history never declared or an unreadable file; a rotation refuses such a file up front with `KEY_EXISTS`); when no epoch ever committed to it, it is removed; an unreadable one is left for the operator (and blocks the next rotation with `KEY_EXISTS`) | 0600 |
| `<history>.owner-key.<keyId>.retired.json` | the key file of an owner key a rotation retired, copied (temp file, fsync, rename) before the new key replaces `<history>.owner-key.json`; `<keyId>` with every character outside `A-Z a-z 0-9 . _ -` replaced by `_` (`owner:1` → `owner_1`), `-2`, `-3`… on a clash. A retired key reference is archived the same way (the key stays in its signer). It can still sign a copy of the history cut back before the rotation: keep it offline. The remote witness client treats every `<history>.owner-key.*.retired.json` (suffixed or not) as a candidate and uses a file only when its key id, scheme and public key match a key in force at that position, never by name, to sign the statement for the rotation head (and a supersede's chain statement) for a witness that has not recorded the rotation yet (docs/WITNESS.md §7.6) | 0600 |
| `<history>.anchors` | the local anchor log (§10), one `{"attestation":…,"receivedAt":…}` per line | 0600 |
| `<history>.witness.json` | the remote witness side file (§10.1, docs/WITNESS.md): `{ version: "irontrellis-witness-state/1", historyId, policy: { witnesses: [{ url, verifierKey, name?, timeoutMs?, token?, allowInsecureHttp? }], quorum, mode, maxUnwitnessedEvents, requireOnOpen, cacheMs }, witnesses: { [origin]: { url, verifierKey, registered, checkpoint?: { size, rootB64, note }, latest?: { head \| null, fetchedAt, seal? }, held?: <HEAD receipt>, splitView?: { detectedAt, message }, rejected?: { code, message, detectedAt, config } } }, pending: [ { kind: "statement", head, statements? } \| { kind: "rotation", rotation, previousHead, rotationHead } ] }`, written atomically. It is writable by whoever can write the history and may only make checks stricter; `seal` is an owner signature over `hashCanonical({ version: "irontrellis-witness-cache/1", historyId, origin, verifierKey, url, head, fetchedAt })`, written and accepted only for bound witnesses (origin from the binding's REGISTERED receipt) and those of the out-of-band minimum. `held` is the witness-signed HEAD receipt of the newest head this history knew the witness held on its chain: the last good head L a supersede starts from (docs/WITNESS.md §7.4); it is used only after it verifies with the witness's configured key and is a prefix of the file, so a planted one can only make a supersede fail closed. A file that cannot be parsed fails the open (`WITNESS_UNREADABLE`) | 0600 |
| `<history>.rotation.pending.json` | the prepared-rotation record of a two-phase owner key rotation (docs/WITNESS.md §7.1): `{ version: "irontrellis-pending-rotation/1", historyId, event, previousHead: { hash, position, canonicalTime }, head: { hash, position, canonicalTime }, statement, incoming: { keyId, scheme, credential }, nextKeyDigests?, staged: { ownerKey, nextKey }, createdAt, seal: { keyId, scheme, signature } }`. `event` is the owner-signed `OWNER_KEYS_ROTATED` exactly as it will be appended at `head.position`; `statement` the old-key head statement for `head` with `previous = previousHead`; `staged` says which of the new keys were staged as files; `seal` is a signature by the old owner key over `hashCanonical({ version: "irontrellis-pending-rotation-seal/1", record: <every other field> })`. Written atomically before the rotation is delivered to the witnesses and removed once it is recorded locally, discarded or aborted. It is judged against the file only: RECORDED (the event is at `head.position`: cleared), OUTSTANDING (the file's head is `previousHead`, the event passes every replay rule there and produces `head`, the statement and the seal verify: writes refuse with `ROTATION_PENDING` until an owner command learns from the bound witnesses whether one holds `head`, then appends it through the normal validated append, provided the staged key files still hold `incoming` / `nextKeyDigests`, or discards it), or OBSOLETE (anything else: removed). While a record is outstanding, the staged key files it names are kept by the settle of the pending key files above | 0600 |
| `<history>.key-event-<position>.bundle.json` | a key-event bundle (docs/WITNESS.md §9.9) for the `OWNER_KEYS_ROTATED` at `<position>`: `{ version: "irontrellis-key-event-bundle/1", historyId, event, previousHead, eventHead, statement, chain? }`, written (temporary file and rename) on every rotation and by `irontrellis owner export-key-events`, for a witness operator to import offline. Only owner-signed data: nothing secret, and a witness imports it only when every signature in it verifies. Nothing reads it back; safe to delete | 0600 |
| `<history>.witness.json.lock` | held for the few milliseconds of a side-file update (`O_EXCL`; one older than 10 s is removed) | 0600 |
| `<file>` given to `irontrellis session admit --new-key`, and `<history>.sessions/<sha256(host session id)>.json` written by the hook | `{"version":"irontrellis-session-key/1","keyId","scheme","credential","privateKey"}`; the hook adds `agentId`, `sessionId`, `hostSessionId`, `admittedAt`. When the hook's session ends or is released, the file is rewritten as `{version, agentId, sessionId, hostSessionId, releasedAt}` without the key | 0600 (directory 0700) |
| `<history>.handovers/<sha256(host session id)>.json` | the hook's handover record (`irontrellis-hook-handover/1`, `packages/hooks/README.md`) | 0600 (directory 0700) |
| `<history>.connector.json` | the hook's connector session key (`packages/hooks/README.md`): `{"version":"irontrellis-hook-connector-key/1","agentId":"hooks:<host>","sessionId","keyId","scheme","credential","privateKey","admittedAt"}`, written by `irontrellis-hook init` when it admits the connector session, which signs CONNECTOR refusals only | 0600 |

Limits an implementation must enforce: per-string 4,096 bytes, identifiers 256 bytes, records 256 keys, lists 4,096 members (256 for action/resource sets, 32 for required intersections, 32 for permission paths, 1,024 for authority evidence, 128 for review observation ids, 64 for owner keys, next-key digests and next-key authorizations, 16 for the witnesses of a binding event, its verifier keys and its accepted-loss heads), depth 32 (28 under `data`), event `data` 1 MiB canonical, anchor receipt 64 KiB canonical, file 64 MiB (legacy) / 1 GiB (format 1), legacy whole-history 4,096 events / 16 MiB canonical. The legacy capacity profile additionally bounds each event at 8 KiB canonical, 32 array members in total and depth 16 (`CAPACITY_EVENT_LIMIT`). Query and decision outputs are bounded at 16 MiB and 4,096 evidence references (a DENY whose evidence would exceed that becomes `INDETERMINATE / OUTPUT_LIMIT_EXCEEDED`). A legacy DENY cites every authority event of the history (spec 02 §6.2), so it can reach that bound; a format-1 DENY or INDETERMINATE cites only the events relevant to the request (the genesis, the head, the actor's lifecycle, the candidate paths' authorities and intersection partners, the prohibitions considered and, for a bound consequential request, its session, tenure and intent events), and so does a format-1 `INTENT_REQUIRED` denial. The ordering rule (sorted by event id, deduplicated) is the same in both formats.

### 13.1 Key references and the command-signer request

A key file (`<history>.owner-key.json`, its pending file, `<history>.owner-next-key.json`, its pending file, a retired archive, or any file given to `--owner-key-ref`, `--next-key-ref`, `--next-key` or `nextKeyFile`) may hold a reference instead of key material (docs/CUSTODY.md):

```json
{ "version": "irontrellis-owner-key-ref/1", "keyId": "owner:1", "scheme": "ed25519", "publicKey": "0x<64 hex>", "signer": { "kind": "ssh-agent" }, "comment": "optional" }
```

* `version`: `irontrellis-owner-key-ref/1` (an owner key) or `irontrellis-owner-next-key-ref/1` (a next key). The owner-key loader accepts `irontrellis-owner-key/1` and `irontrellis-owner-key-ref/1` only, the next-key loader `irontrellis-owner-next-key/1` and `irontrellis-owner-next-key-ref/1` only, so a next key is never loaded as the owner key.
* `keyId`: 1..128 characters without control characters. `scheme`: `ed25519` only. `publicKey`: the Ed25519 public key, `0x` + 64 lowercase hex as written (readers also accept 64 hex without `0x` and an OpenSSH `ssh-ed25519 AAAA…` line; FIDO `sk-ssh-ed25519@openssh.com` and other key types are refused). `comment`: at most 512 characters, ignored.
* `signer`: `{ "kind": <string>, … }`. Built in: `{ "kind": "ssh-agent", "socket"?: <path>, "timeoutMs"?: 100..600000 }` (the SSH agent protocol, draft-miller-ssh-agent, over the Unix socket `socket`, else `$SSH_AUTH_SOCK`, else on Windows the named pipe `\\.\pipe\openssh-ssh-agent`; the key is the `ssh-ed25519` blob of `publicKey`; `SSH_AGENTC_SIGN_REQUEST` with flags 0 over the 32 hash bytes; the `ssh-ed25519` signature's 64 bytes are the Ed25519 signature), `{ "kind": "command", "argv": [<absolute program path>, …], "timeoutMs"?: 100..600000, "env"?: { <NAME>: <value> }, "passEnv"?: [<NAME>, …], "path"?: <absolute directories joined by : (; on Windows)> }` (the program runs in the file-system root with PATH = `path` or `/usr/bin:/bin`; every file-like argument must be absolute; PATH cannot be passed) and `{ "kind": "vault-transit", "address": <https URL, or http to a loopback host>, "mount"?: <path, default "transit">, "key": <Transit key name>, "keyVersion": <integer ≥ 1, pinned>, "namespace"?: <path>, "tokenFile"?: <absolute path>, "caFile"?: <absolute path>, "timeoutMs"?: 100..600000 }` (HashiCorp Vault Transit: `GET /v1/<mount>/keys/<key>` must show an `ed25519`, non-derived key whose version `keyVersion` holds `publicKey`; `POST /v1/<mount>/sign/<key>` with `input` = base64 of the 32 hash bytes, `key_version` = `keyVersion`, `prehashed` = false; the answer `vault:v<keyVersion>:<base64>` carries the 64-byte Ed25519 signature; a reference never holds the Vault token, and a field named like one is refused). Unknown fields are refused; an unknown `kind` is refused unless a backend for it is registered (docs/CUSTODY.md §13).
* No other field. Pretty-printed JSON, written like a key file (temporary file, fsync, link: exclusive, never a partial file), mode 0600. On POSIX a reference must also be owned by the user that loads it (it decides which program signs as the owner); otherwise, and on any other defect, `KEY_UNAVAILABLE`.

A signature obtained through a reference is the same Ed25519 signature over the same 32-byte hash as with a key file (§8.1), verified against `publicKey` before use; nothing in the history or any wire format shows which signer made it. Verifiers need only the public keys the history already carries.

**The command-signer request.** The `command` signer writes one JSON document to the program's stdin, `{ "version": "irontrellis-sign-request/1", "keyId", "scheme": "ed25519", "publicKey": "0x…", "message": <base64 of the 32 hash bytes>, "purpose": <one of control-authorization, head-attestation, head-statement, next-key-proof, rotation-seal, cache-seal, signer-test, unspecified>, "historyId"?: "0x…" }`, and reads one JSON document from its stdout: `{ "signature": <base64 (or base64url) of the 64-byte signature>, "publicKey"?: "0x…" }` with exit status 0, or `{ "error": { "code": "KEY_UNAVAILABLE" | <other>, "message" } }` with a non-zero status. `purpose` and `historyId` are advisory (not authenticated).


