# History encoding and hash reference

> Reference from `HISTORY-FORMAT.md` at `00ca4c0` (SHA-256 `aecc62db80fda785ca06b60107097316cdc453416d0fa61baef42c6e903bc35b`). Established scope: the retained field, byte, code, limit and ordered-check contracts below. Not established: a new engine audit, deployment test or broader edition coverage.

Source section numbers are retained for cross-reference with [HISTORY-FORMAT.md](../HISTORY-FORMAT.md). Operational guidance stays in the narrative page. Format-2 owner-policy rules remain in the unchanged [owner-policy reference](owner-policy.md).

**Edition boundary:** Historical legacy/format-1 read reference. The source comparison includes former writer behavior; current 1.0.0-rc.2 writers refuse these formats with `FORMAT_READ_ONLY`. Format 2 uses its own Amount encoding and chain-tip head.

<!-- source: HISTORY-FORMAT.md:9-111; exact text except relative Markdown links -->

## 1. The two formats

| | `continuity-event/0.2` (legacy) | `irontrellis-event/1` (format 1) |
|---|---|---|
| Store line version | `continuity-portable-file-store/0.2` | `irontrellis-portable-file-store/1` |
| Event encoding in the line | tagged tuples (§3.1) | plain JSON with bigint markers (§3.2) |
| Hash algorithm | keccak-256 | SHA-256 |
| History prefix wrapper | `continuity-event-history/0.2` | `irontrellis-event-history/1` |
| Domain | `{protocol:"continuity", version:"0.2", deploymentId, chainId, verifyingContract}` | `{protocol:"irontrellis", version:"1", deploymentId}` |
| Control events | unsigned | signed by an owner key (`data.controlAuthorization`, §7) |
| Runtime signature suites | `eip191-personal-sign-keccak256` only | `ed25519` (default) or `eip191-personal-sign-keccak256`, per session |
| `ANCHOR_RECORDED`, `OWNER_KEYS_ROTATED`, `WITNESSES_BOUND`, `WITNESSES_UNBOUND` | rejected (`UNSUPPORTED_EVENT_TYPE`) | allowed |
| Whole-history bound | 4,096 events and 16 MiB of canonical text (the reference's capture bound) | none beyond the file cap |
| File cap | 64 MiB | 1 GiB |
| Capacity policy | `continuity-managed-capacity/1`, 96 events | `irontrellis-capacity/1`, `genesis.capacity.maxEvents` or unlimited |

A file's format is decided by the `version` field of its first line; the genesis event's `versions.eventSchemaVersion` must agree. Both formats share the canonical encoding (§2), the event envelope (§4), the 25 legacy event schemas (§5), the replay transition rules and the decision procedure. Legacy histories written by Continuity 0.2.2 open, replay and append in place; lines appended by IronTrellis are byte-identical to what the reference SDK would have written (verified by `packages/core/test/interop.test.mjs`).

## 2. Canonical encoding

Every hash in either format is computed over the UTF-8 bytes of the *canonical text* of a value (`continuity-canonical/0.2`, spec 01 §A). The rules:

* **Records** are `{` + members + `}`, members `"<key>":<value>` joined by `,`, keys sorted by **UTF-8 byte order** (`compareProtocolStrings`: compare the UTF-8 bytes unsigned; a prefix sorts first). This is code-point order, not UTF-16 order and not locale order: `"B" < "a"`, `"10" < "2"`, `"\u{10000}"` sorts after `"￿"`. Keys must be well-formed Unicode of at most 4,096 UTF-8 bytes; a record has at most 256 keys. Keys starting with `$continuity.` are reserved (§2, bigints).
* **Arrays** are `[` + members joined by `,` + `]`, in order, at most 4,096 members, dense (no holes).
* **Strings** escape only `"` (as `\"`), `\` (as `\\`) and the C0 controls U+0000–U+001F, each as lowercase `\u00xx` (so a newline is `\u000a`, not `JSON.stringify`'s `\n`); this holds in every format; everything else, including U+007F, U+2028/2029 and all non-ASCII, is emitted literally. At most 4,096 UTF-8 bytes; lone surrogates are rejected.
* **Numbers** are integers in `-(2^53-1) … 2^53-1`, printed in plain decimal. `-0`, non-integers, `NaN` and infinities are rejected.
* **Bigints** are spelled as a record with the single key `$continuity.bigint` and the decimal string as value: `{"$continuity.bigint":"2500"}`. Range `-(2^256-1) … 2^256-1`; grammar `^(0|-?[1-9][0-9]*)$`, at most 79 characters. On input, a plain JSON record of exactly that shape *is* a bigint. A marker record does not count as a nesting level.
* `true`, `false`, `null` as in JSON. Nothing else is representable (no `undefined`, functions, dates, class instances).
* **Depth** at most 32 containers, counted from the root. Because a replay body nests an event's `data` four containers deep, at most 28 levels are allowed under `data`. **Total** canonical text at most 16 MiB per capture.

Examples (`hashCanonical` is `hash(utf8(canonical(value)))`, output `0x` + 64 lowercase hex):

```
canonical({ maxAmount: 2500n, list: [1, "x", null, true] })
  = {"list":[1,"x",null,true],"maxAmount":{"$continuity.bigint":"2500"}}
hashCanonical({ a: 1 }, "keccak256") = 0x25e7c2a96531eb50246780c1f25742e489bf55210e26981dc02992bb585feb97
hashCanonical({ a: 1 }, "sha256")    = 0x015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862
```

Keccak-256 is the Ethereum variant (padding `0x01 … 0x80`, not SHA-3's `0x06`). SHA-256 is FIPS 180-4.

## 3. Store lines

A history file is UTF-8 text without a byte order mark, one JSON object per line, every line terminated by `\n` (a file that does not end in `\n` has an incomplete record and is invalid). Lines are split on `\n` only; JSON whitespace around the tokens of a line, including a `\r` before its `\n` (a CRLF conversion), is not part of the record and does not change its hash, so both readers accept it with the same result (docs/PLATFORMS.md §5; the writer never emits it). Each line has exactly the four keys `version`, `previousHash`, `event`, `recordHash`; the writer emits them in that order, and a reader checks the key set, not the order:

```
{"version":"<line version>","previousHash":<null | ContentHash>,"event":<stored event>,"recordHash":"<ContentHash>"}
```

* `previousHash` is `null` on the first line and the previous line's `recordHash` on every other line.
* `recordHash = hashCanonical({ version, previousHash, event })` with the format's algorithm, where `event` is the **decoded** event value (a plain value, not the stored encoding) and the record is canonically encoded (so the key order in the hash input is `event, previousHash, version`).

A reader verifies, line by line: the key set, the version literal, the `previousHash` chain, the encoding (§3.1 round-trip for legacy), the `recordHash`, and then applies the event to the replay state. A file with a chain, encoding or hash defect, or whose events replay to `REJECTED`, is invalid as a whole (`INVALID_HISTORY`). Removing a complete suffix of lines is not detectable from the file alone; that is what the pinned head (§9) and the witnesses (§10) are for.

### 3.1 Legacy stored encoding (tagged tuples)

The `event` value of a `continuity-portable-file-store/0.2` line is the tagged-tuple form of the event, exactly as spec 01 §E.2:

| value | stored as |
|---|---|
| `null` | `["null"]` |
| bigint `b` | `["bigint","<decimal>"]` (non-negative only on read) |
| string, boolean, number | `["string",s]`, `["boolean",b]`, `["number",n]` (numbers: non-negative safe integers on read) |
| array | `["array",[<encoded members>]]` |
| record | `["object",[["<key>",<encoded value>],…]]` in canonical key order |

Reading decodes and re-encodes; the re-encoded text must equal the stored text byte for byte (`noncanonical store encoding` otherwise). Example first line of a legacy file (elided):

```
{"version":"continuity-portable-file-store/0.2","previousHash":null,"event":["object",[["data",["object",[["adapterPolicyHash",["string","0x00c3…"]],…]]],["id",["string","first-look:genesis"]],["timestamp",["number",0]],["type",["string","DEPLOYMENT_INITIALIZED"]]]],"recordHash":"0x4d81d24f…"}
```

### 3.2 Format-1 stored encoding (plain JSON)

The `event` value of an `irontrellis-portable-file-store/1` line is the event as plain JSON with bigints spelled as `{"$continuity.bigint":"…"}` markers (`jsonStringifyWithBigints`). The writer emits every record inside the event with its keys in canonical order (§2: UTF-8 byte order, recursively; arrays keep their order), so the envelope is written `data, id, timestamp, type` and the stored bytes do not depend on the key order the caller used. Key order is not significant to a reader: `recordHash` is computed over the canonical form, so a reader must accept any key order (lines written before the writer sorted keys, with the envelope as `id, type, timestamp, data`, remain valid and keep their record hashes). A reader parses the line with a bigint-marker reviver and rejects a malformed marker.

A complete two-event format-1 history, as the store writes it for the worked example in §12:

```
{"version":"irontrellis-portable-file-store/1","previousHash":null,"event":{"data":{"adapterPolicyHash":"0x00c3498e2744943663475d0187ca979cdd09763b88427781883693c4b8c163a7","canonicalLineageId":"lineage:example","domain":{"deploymentId":"example","protocol":"irontrellis","version":"1"},"finality":"LOCAL_ONLY","globalPolicySourceId":"policy:example","ownerKeys":[{"credential":"0xd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737","keyId":"owner:1","scheme":"ed25519"}],"policyVersion":"irontrellis-local-owner/1","rootRecognitionPolicy":"declared-principal-root/0.2","timeSource":"EVENT_TIMESTAMP","versions":{"administrativeAuthorizationVersion":"continuity-administrative-authorization/0.2","authorizationProofVersion":"continuity-authorization-proof/0.2","controlAuthorizationVersion":"irontrellis-control-authorization/1","eventSchemaVersion":"irontrellis-event/1","historyHashAlgorithm":"sha256","queryEnvelopeVersion":"continuity-query-envelope/0.2","receiptSchemaVersion":"irontrellis-receipt/1","runtimeAuthorizationVersion":"continuity-runtime-authorization/0.2","signatureScheme":"ed25519"}},"id":"example:genesis","timestamp":1,"type":"DEPLOYMENT_INITIALIZED"},"recordHash":"0xc816094995b0b4bdcdf06cb693a92db0bb3d98e8bd268aca6b274b9a26b2e5ff"}
{"version":"irontrellis-portable-file-store/1","previousHash":"0xc816094995b0b4bdcdf06cb693a92db0bb3d98e8bd268aca6b274b9a26b2e5ff","event":{"data":{"controlAuthorization":{"keyId":"owner:1","signature":"0xe3b080a8fff8f2617592b0b2044ad9a8f454f90fbbc6dca609a5b9c1fccce93003a60ea1c6d5c9d9ace060ee0facf2f74e5ca5c86527ecf6f5940a8b57821608"},"principalId":"operations"},"id":"example:principal","timestamp":2,"type":"PRINCIPAL_CREATED"},"recordHash":"0xdbd1bc16813c8718407703a301cb6877104838b597795778578a0f724a06ffd9"}
```

## 4. History hash and head

The **history hash** at position `p` is the hash of the canonical text of the wrapper `[<wrapper string>, [e0, e1, …, ep]]`:

```
legacy:   keccak256( utf8( ["continuity-event-history/0.2",[<e0>,…,<ep>]] ) )
format 1: sha256(    utf8( ["irontrellis-event-history/1",[<e0>,…,<ep>]] ) )
```

Implementations compute every prefix incrementally: absorb the prefix bytes `["<wrapper>",[` once, then for each event absorb `,` (except before the first) followed by the event's canonical text, and finalize a *copy* of the state with the suffix `]]` to obtain the hash at that position. The hash of the empty history is the hash of `["<wrapper>",[]]`:

```
legacy empty history:   0x65dc4448f700facf3bfb5d5a80a22e827e673b409b8293994847b56b5629b3b0
format-1 empty history: 0x957049974c129341bd05d84f258de49180a31be24d4f40768afc1570e6d340b7
```

The **head** of a history is `{ hash, position, canonicalTime }`: the history hash at the last position, the zero-based position of the last event, and the timestamp of the last event. Heads are compared field by field. The head *before* an event (used by control authorizations) is the head at `position - 1`; the head *including* an event (used by runtime challenges and admissions) is the head at its own position.

The legacy prefix hasher enforces the reference's whole-history bounds (4,096 events, 16 MiB of canonical wrapper text) so that a history the reference would reject is rejected here too. Format 1 has no whole-history canonical bound.


