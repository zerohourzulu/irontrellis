# Specification 01 — Canonical encoding, hashing, event schema, replay, and the portable file store

Source of truth: `packages/core-0.2/src/core/canonical.ts`, `event-schema.ts`, `portable-replay.ts`, `host-intrinsics.ts`, `portable-adapter-engine.ts`, `portable-administration-codec.ts`, the replay-facing parts of `portable-authority-engine.ts`, and `packages/core-0.2/src/indexer/portable-file-event-store.ts` of the `continuity` repository (core 0.2, package version 0.2.2). Every statement below was derived from the source code and, where marked **[verified]**, confirmed by running the TypeScript sources under Node 22 (`node` imports the `.ts` files directly; `tests/helpers.mjs` does `await import('../packages/core-0.2/src/core/index.ts')`). Statements marked **[unverified]** are read from the code but were not exercised.

The public surface re-exported by `src/core/index.ts` that this document covers: `canonicalEncode`, `hashCanonical`, `hashEventHistory`, `compareProtocolStrings`, `immutableProtocolValue`, `immutableProtocolInput`, `PORTABLE_REPLAY_VERSION`, `replayPortable`, plus the adapter-policy constants. `hashEventHistoryPrefixes`, `validateCanonicalEventShape`, `CORE_EVENT_TYPES`, `coreEventTypeRank`, `createPortableReplayKernel` are module exports of `canonical.ts` / `event-schema.ts` / `portable-replay.ts` that are *not* re-exported from the package index (**[verified]**: `core.hashEventHistoryPrefixes` is `undefined`).

Terminology used throughout:

* **ProtocolString** — a JavaScript string that is well-formed UTF-16 (no lone surrogates) and whose UTF-8 encoding is at most 4 096 bytes.
* **Identifier** — a ProtocolString of 1..256 UTF-8 bytes with no code unit in U+0000..U+001F and no U+007F. (C1 controls U+0080..U+009F, spaces, and every other scalar value are allowed. **[verified]**: `" "` is a valid id.)
* **U53** — a JavaScript number that is a safe integer (`Number.isSafeInteger`), `>= 0`, and not `-0`. Range `0 .. 2^53-1`.
* **Amount** — a JavaScript `bigint` with `0n <= v <= 2^256-1`.
* **ContentHash** — a string matching `/^0x[0-9a-f]{64}$/` (lowercase only).
* **EthereumAddress** — a string matching `/^0x[0-9a-fA-F]{40}$/` (mixed case accepted, no checksum verification).
* **ChainId** — a string matching `/^[1-9][0-9]*$/` whose integer value is in `1 .. 2^256-1`.
* **Signature65** — a string matching `/^0x[0-9a-f]{130}$/` (65 bytes lowercase hex) where `s` (hex chars 66..130) is `!= 0` and `<= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0`, and the last byte (chars 130..132) is `"1b"` or `"1c"`.
* **plain record** — a non-null, non-array object whose prototype is exactly `Object.prototype` or `null`. Class instances, `Date`, `Map`, `Set`, `RegExp`, boxed primitives, and `Object.create(Array.prototype)` are **not** plain records.

---

## A. Canonical encoding — `continuity-canonical/0.2`

### A.0 What the canonical form is (and is not)

The canonical text is **compact JSON** (no whitespace, no trailing newline) with deterministic key ordering and a special spelling for bigints. It is **not** the tagged-tuple form (`["object",[["key",["string","v"]]]]`); that tagged form is only the *storage* encoding of the portable file store (section E) and is never hashed directly. Everything hashed in this engine (`hashCanonical`, history heads, record hashes of the file store, challenge hashes, adapter identities) is keccak-256 over the UTF-8 bytes of this compact-JSON canonical text.

Grammar (produced by `captureNode`/`materializeCanonicalRope` in `canonical.ts`):

```
value   := "null" | "true" | "false" | number | string | bigint | array | record
number  := decimal spelling of a signed safe integer          e.g. 0  -1  9007199254740991
string  := '"' escaped-units '"'
bigint  := '{"$continuity.bigint":"' decimal '"}'              e.g. {"$continuity.bigint":"-5"}
array   := "[" [ value ("," value)* ] "]"
record  := "{" [ member ("," member)* ] "}"
member  := string ":" value                                    keys sorted by compareProtocolStrings
```

Worked examples (**[verified]** exact output of `canonicalEncode`):

| input (JS) | canonical text |
|---|---|
| `{ b: 1, a: "x", c: [true, false, null] }` | `{"a":"x","b":1,"c":[true,false,null]}` |
| `{}` | `{}` |
| `[]` | `[]` |
| `0` | `0` |
| `-1` | `-1` |
| `Number.MAX_SAFE_INTEGER` | `9007199254740991` |
| `5n` | `{"$continuity.bigint":"5"}` |
| `-5n` | `{"$continuity.bigint":"-5"}` |
| `0n` | `{"$continuity.bigint":"0"}` |
| `{ amount: 5n }` | `{"amount":{"$continuity.bigint":"5"}}` |
| `{ "$continuity.bigint": "5" }` (marker object) | `{"$continuity.bigint":"5"}` — identical to `5n` |
| `'a"b\\c\n\t\u0001\u001f\u007f\u0080é€😀/'` | `"a\"b\\c\u000a\u0009\u0001\u001fé€😀/"` (U+007F, U+0080, non-ASCII and `/` emitted raw; only `"`, `\` and U+0000..U+001F are escaped) |
| `{ a: undefined, b: 1 }` | `{"b":1}` (undefined-valued field omitted) |
| `JSON.parse('{"a":1,"__proto__":{"evil":true}}')` | `{"__proto__":{"evil":true},"a":1}` (own `__proto__` key is an ordinary field) |
| `Object.create(null)` with `own:"mine"` | `{"own":"mine"}` |
| shared reference `[s, s]` with `s = {x:1}` | `[{"x":1},{"x":1}]` |
| `{ 'b':1,'B':2,'a':3,'A':4,'':5,'aa':6,'a-':7,'10':8,'2':9,'é':10,'z':11 }` | `{"":5,"10":8,"2":9,"A":4,"B":2,"a":3,"a-":7,"aa":6,"b":1,"z":11,"é":10}` |
| `''` | `""` |

### A.1 Key ordering — `compareProtocolStrings(left, right)`

Exported. Algorithm:

1. Both arguments are validated with `protocolStringByteLength(value, "$left"/"$right")`: a lone surrogate throws `TypeError("Canonical string at $left is not well-formed Unicode.")`; more than 4 096 UTF-8 bytes throws `TypeError("Canonical string at $left exceeds the 4096-byte ProtocolString bound.")`. (**[verified]** `compareProtocolStrings('\ud800','a')` throws.)
2. Encode both to UTF-8 bytes (`TextEncoder`).
3. Compare byte-wise, unsigned, over the shared length; the first differing byte decides (`-1` if left byte is smaller, `1` otherwise).
4. If one is a prefix of the other, the shorter sorts first; equal byte sequences return `0`.

This is **UTF-8 byte order**, which equals Unicode code-point order. It is *not* UTF-16 code-unit order (`'\u{10000}'` sorts **after** `'￿'`; **[verified]**: `compareProtocolStrings('\u{10000}','￿') === 1`), and not locale order (`"B" < "a"`, `"" < everything`, `"10" < "2"`). The return value is exactly `-1`, `0`, or `1`.

Record keys are sorted with this comparator. Sorting is done with `Array.prototype.sort` on the distinct own keys, so stability is irrelevant (keys are unique).

### A.2 Strings

* Must be well-formed UTF-16 (`isWellFormedUnicode`: every high surrogate U+D800..U+DBFF must be immediately followed by a low surrogate U+DC00..U+DFFF; an unpaired low surrogate is malformed).
* UTF-8 length must be `<= 4 096` bytes (`MAX_PROTOCOL_STRING_UTF8_BYTES`). Byte counting: unit `<= 0x7f` → 1, `<= 0x7ff` → 2, surrogate pair → 4, otherwise 3. The limit is checked incrementally; the error is `Canonical string at <location> exceeds the 4096-byte ProtocolString bound.`
* Escaping (`escapedString`): `"` → `\"`; `\` → `\\`; code unit `<= 0x1f` → `\u00` + two lowercase hex digits (e.g. `\u000a`, `\u001f`); everything else, including U+007F, U+2028, U+2029, `/`, and all non-ASCII, is emitted literally (surrogate pairs are copied as the pair).
* Record keys obey the same rules and the same 4 096-byte bound (error location `<location>.{key}`).
* Both limits apply to every string occurrence, in every mode.

### A.3 Numbers

Accepted: JavaScript numbers for which `Number.isSafeInteger(v) && !Object.is(v, -0)`, i.e. integers in `-(2^53-1) .. 2^53-1`, excluding negative zero. Printed with `Number.prototype.toString(10)` (plain decimal, never exponent form since |v| < 1e21).

Rejected in strict mode (`canonicalEncode`, `hashCanonical`, `captureBoundedCanonicalValue`, `captureBoundedCanonicalEventData`):

* `NaN`, `±Infinity` → `TypeError("Canonical number at <loc> must be finite.")`
* non-integers, `-0`, `|v| > 2^53-1` (e.g. `1e21`, `MAX_SAFE_INTEGER+1`) → `TypeError("Canonical number at <loc> must be a signed safe integer other than negative zero.")`

(**[verified]** `canonicalEncode(0) === "0"`, `canonicalEncode(-0)` throws.)

In **structural phase-one** mode (used by `immutableProtocolValue`, `immutableProtocolInput`, and the replay/authority captures) an invalid number is *not* an error: it is kept as an opaque "noncanonical scalar" that has **no canonical text**, is charged 32 bytes against the byte budget, and is left for later typed validation to reject (e.g. `NaN` inside event data replays to `EVENT_DATA_INVALID`; **[verified]**). `immutableProtocolValue({a: NaN})` returns `{a: NaN}`.

### A.4 BigInts

* Range: `-(2^256-1) <= v <= 2^256-1` (`MAX_PROTOCOL_BIGINT = (1n<<256n)-1n`). Out of range in strict mode → `TypeError("Canonical BigInt at <loc> exceeds the 256-bit protocol bound.")` (a "named limit" error with limit metadata 256). In phase-one mode, out-of-range bigints become a 32-byte noncanonical scalar.
* Spelling: `{"$continuity.bigint":"<BigInt.prototype.toString(10)>"}` — a record with the single key `$continuity.bigint` whose value is the decimal string, `-` prefixed for negatives, `"0"` for zero. There is no `+`, no leading zeros, no `n` suffix.
* **Marker decoding (input side):** a plain record whose *only* own key is `$continuity.bigint` is decoded as a bigint. The value must be a string, `<= 4 096` UTF-8 bytes, of length `<= 79` characters, matching `/^(?:0|-?[1-9][0-9]*)$/`, and within the 256-bit bound; otherwise `TypeError("Canonical BigInt marker at <loc>.$continuity.bigint has an invalid decimal value.")` (for `"05"`, `"-0"`, `"+5"`, 80+ digits) or the 256-bit bound error. The captured immutable value of such a record **is a `bigint`** (`typeof immutableProtocolValue({a:{"$continuity.bigint":"7"}}).a === "bigint"`, **[verified]**), so downstream schema checks (`typeof v === "bigint"`) accept marker input exactly as they accept native bigints, and both produce identical canonical text and hashes (**[verified]**: replaying a grant whose `maxAmount` is written as a marker object yields the same head hash as the native bigint).
* **Reserved prefix:** any record key starting with `$continuity.` other than the exact single-key marker shape is rejected: `TypeError("Canonical record at <loc> uses the reserved $continuity. key prefix outside the exact BigInt marker shape.")`. This covers `{ "$continuity.bigint": "5", x: 1 }`, `{ "$continuity.other": ... }`, and a marker combined with any other key even if that other key's value is `undefined` (the reserved-key check runs on the raw own-key list, before undefined elision). Since the marker record is a scalar, it has intrinsic depth 0 (it does not count as a nesting level).
* In **designated scalar slots** (event envelope `id`/`type`/`timestamp`, and authority-operation scalar slots) a marker object is rejected as an "unsupported host kind" even though its decoded value is a bigint (**[verified]**: an event whose `timestamp` is `{ "$continuity.bigint": "5" }` → `INVALID_INPUT`).

### A.5 Booleans and null

`true` → `true`, `false` → `false`, `null` → `null`. Boxed `Boolean`/`String`/`Number` objects are not plain records → `TypeError("Canonical value at <loc> is not a plain record.")`.

### A.6 Records (objects)

Processing order in `captureRecord`:

1. Prototype must be `Object.prototype` or `null` → else `Canonical value at <loc> is not a plain record.` (Date, Map, Set, RegExp, class instances, arrays reached as records.)
2. `Reflect.ownKeys` snapshot. If the raw key count (including symbol keys and undefined-valued keys) exceeds 256 (`MAX_CANONICAL_RECORD_FIELDS`) → named-limit `Canonical record at <loc> exceeds the 256-field bound.` (**[verified]**: 256 keys + one `undefined`-valued key is rejected.)
3. Every key must be a string (symbol key → `Canonical record at <loc> has a non-string key.`) and a ProtocolString (`<loc>.{key}` location).
4. Reserved-prefix check (A.4).
5. Keys are sorted with `compareProtocolStrings`.
6. For each key in sorted order: the own property descriptor is read once (`Reflect.getOwnPropertyDescriptor`); if it is an accessor, the getter is invoked **once** with the record as receiver (a throwing getter → `Canonical accessor at <loc> failed during its single capture.`; a descriptor that disappears → `... changed during descriptor capture.`). Data properties that are non-enumerable are still included (enumerability is ignored; only own-ness matters).
7. A field whose captured value is `undefined` is **omitted** from the canonical text and from the immutable value, but the key is retained in the private "captured record keys" metadata (this is what lets closed-schema validation later reject an *undeclared* key even when its value is `undefined`).
8. Output: `{` + members joined by `,` + `}`, each member `<escaped key>:<value>`.

Duplicate keys cannot occur in a JS object; a record that *appears* to have duplicate keys after unicode differences is impossible (keys are compared as exact strings).

### A.7 Arrays (lists)

Processing order in `captureArray` (only for `Array.isArray(value) === true`):

1. The `length` own descriptor must be a data descriptor with a nonnegative safe integer value (accessor-backed `length` → error; in practice `length` cannot be redefined as an accessor).
2. `length > 4 096` (`MAX_CANONICAL_LIST_MEMBERS`, or a smaller role-specific bound: 256 for authority identifier sets, 32 for required-intersection lists, 1 024 for raw permission/prohibition lists) → named-limit `Canonical array at <loc> exceeds the N-member bound.`
3. `Reflect.ownKeys`: every key must be a string; `length` exactly once; every other key must be a canonical array index (`"0"` or `/^[1-9][0-9]*$/`, `<= 0xfffffffe`, round-tripping through `String(Number(key))`); anything else → `Canonical array at <loc> has an unsupported expando field <key>.`
4. The number of index keys must equal `length` and be exactly `0..length-1` → otherwise `Canonical array at <loc> is sparse or exceeds the N-member bound.` / `... is sparse.` (holes are rejected, **[verified]**).
5. Each member is read via its descriptor (single accessor read allowed) and must not be `undefined` → `Canonical array entry at <loc>[i] is undefined.`
6. Output `[` + members joined by `,` + `]`. Empty array → `[]`.

Arrays are never sorted; order is significant.

### A.8 Nesting depth

`MAX_CANONICAL_DEPTH = 32`. Depth counts **containers** (records and arrays; a bigint-marker record does not count). The root container is depth 1; a scalar at the root is depth 0. A value at container depth 33 → named-limit `Canonical value at <loc> exceeds nesting depth 32.`

**[verified]**: 32 nested arrays (`[[[...1...]]]`) encode; 33 fail. Same for objects.

Because the replay body wraps events in `{"events":[ <event> ]}`, a replay event record is depth 3 and its `data` record is depth 4, so **inside `data` at most 28 further container levels are allowed** (**[verified]**: 28 nested `{a:...}` levels under a data field replay past capture; 29 → `INVALID_INPUT`). `hashEventHistory` has the same shape (`["continuity-event-history/0.2",[event]]`), so the same 28-level bound applies. The standalone `validateCanonicalEventShape` captures `data` at depth 2 (`ancestorContainerDepth: 1`), so it allows 30 levels under data (**[verified]**: 30 ok, 31 → `"$.data: failed canonical base capture"`). `hashCanonical(event)` on a bare event (event depth 1, data depth 2) likewise allows 30 under data (**[verified]**: 30 ok, 31 throws).

Shared (aliased) sub-objects are memoised: the same object reached twice is encoded identically and its intrinsic depth is added to the depth of every occurrence; cycles (`Canonical value at <loc> contains an active cycle.`) are rejected.

### A.9 Total size

`MAX_CANONICAL_UTF8_BYTES = 16 777 216` (16 MiB) of canonical UTF-8 text per capture; `captureBoundedCanonicalValue(value, { maxCanonicalBytes })` accepts a smaller nonnegative safe integer (clamped to 16 MiB; invalid → `TypeError("maxCanonicalBytes must be a nonnegative safe integer.")`). The budget is charged incrementally, per occurrence (aliases are charged every time they appear, although memoised). Exceeding it throws `TypeError("Canonical value at <label> exceeds the <limit>-byte canonical capture bound.")` with label `$` (or the event-data label `$.events[i].data` for the per-event 1 MiB budget, see D.3). Non-canonical scalars in phase-one mode are charged 32 bytes each.

### A.10 Rejected values (summary)

| value | strict-mode error |
|---|---|
| `undefined` at root or as array entry | `Canonical value at $ is undefined.` / `Canonical array entry at $[i] is undefined.` |
| function, symbol | `Canonical value at <loc> has unsupported type function/symbol.` |
| `Date`, `Map`, `Set`, `RegExp`, boxed primitives, class instances, objects with any other prototype | `Canonical value at <loc> is not a plain record.` |
| symbol-keyed record | `Canonical record at <loc> has a non-string key.` |
| lone surrogate in string or key | `Canonical string at <loc> is not well-formed Unicode.` |
| `NaN`/`Infinity` | `... must be finite.` |
| non-integer, `-0`, unsafe integer | `... must be a signed safe integer other than negative zero.` |
| bigint outside ±(2^256−1) | `... exceeds the 256-bit protocol bound.` |
| sparse array / expando / accessor `length` | see A.7 |
| cycle | `... contains an active cycle.` |
| reserved `$continuity.` key | see A.4 |

Note the two documented **raw-helper weaknesses** (asserted by `tests/canonical.test.mjs`): `canonicalEncode` *does* invoke getters (once per encode) and *does* consult a Proxy's traps, so non-deterministic objects can encode differently on each call. Replay's event-data capture (`REPLAY_EVENT_DATA` role) is also getter-tolerant (**[verified]**: an event whose `data` is a getter replays `ACCEPTED`); only the adapter-evidence fields `acknowledgment`, `noEffect`, `adapterProfile` are captured in a "data-only" mode that rejects accessors (`Adapter data accessor at <loc> is unsupported.`) and Node proxies (`Adapter data proxy at <loc> is unsupported.`), with a separate 4 096-byte budget per such field.

### A.11 Public helpers built on capture

* `canonicalEncode(value): string` — strict capture with the 16 MiB budget, returns the canonical text.
* `immutableProtocolValue(value)` — phase-one capture; returns a deep-frozen, null-prototype snapshot with keys defined in sorted order, undefined fields **removed**, bigint markers decoded to bigints, malformed scalars preserved. (Enumeration order caveat: JS puts integer-like keys first in numeric order — `Object.keys(immutableProtocolValue({b:1,'10':2,'2':3,a:4,'':5}))` is `["2","10","","a","b"]` **[verified]**.)
* `immutableProtocolInput(value)` — same capture, but the returned copy **re-adds every originally present key**, including those whose value was `undefined` (so `Object.hasOwn(copy,'a') === true` with `copy.a === undefined`, **[verified]**). Used by the file store so that replay can still reject undeclared-but-undefined fields.
* `isDenseArray(value, maximumLength = 4096)` — pure predicate (no capture): `Array.isArray`, data-descriptor `length` in `0..max`, own keys are exactly `length` plus canonical indices `< length`.

---

## B. Hashing

### B.1 `hashCanonical(value): ContentHash`

`keccak256Bytes(utf8(canonicalEncode(value)))`. Keccak-256 as used by Ethereum: rate 136 bytes, padding byte `0x01` at the position after the last absorbed byte and `0x80` at byte 135 (**not** SHA3's `0x06`). Output `"0x"` + 64 lowercase hex characters. Example (**[verified]**): `hashCanonical({a:1}) === "0x25e7c2a96531eb50246780c1f25742e489bf55210e26981dc02992bb585feb97"`; `hashCanonical("")` (canonical text `""`, two bytes) `=== "0x2392a80f8a87b8cfde0aa5c84e199f163aae4c2a4c512d37598362ace687ad0c"`.

### B.2 `hashEventHistory(events): ContentHash`

`events` must satisfy `Array.isArray` (else `TypeError("Event history must be a runtime array.")`). Result = `hashCanonical(["continuity-event-history/0.2", events])`, i.e. keccak over `["continuity-event-history/0.2",[<e0>,<e1>,...]]`. The empty history hashes the text `["continuity-event-history/0.2",[]]` → `0x65dc4448f700facf3bfb5d5a80a22e827e673b409b8293994847b56b5629b3b0` (**[verified]**). The complete wrapper goes through one strict capture, so all A-limits apply to the whole history at once (4 096 events max, 16 MiB total, depth as in A.8).

### B.3 `hashEventHistoryPrefixes(events): readonly ContentHash[]` (canonical.ts export, not on index)

Exact bytes:

```
EVENT_HISTORY_CANONICAL_PREFIX    = utf8('["continuity-event-history/0.2",[')   (33 bytes)
EVENT_HISTORY_CANONICAL_SEPARATOR = utf8(',')                                    (1 byte)
EVENT_HISTORY_CANONICAL_SUFFIX    = utf8(']]')                                   (2 bytes)
```

Algorithm: strictly capture the wrapper `["continuity-event-history/0.2", events]` once; create a Keccak state and absorb PREFIX; for each captured event at position `p`: if `p > 0` absorb SEPARATOR; absorb `utf8(canonicalEncode(event))`; clone the state, absorb SUFFIX into the clone, finalize the clone → `hashes[p]`. Returns a frozen array; empty input → `[]` (**[verified]**). By construction `hashes[p] === hashEventHistory(events.slice(0, p+1))` (**[verified]** for two events: `0xa24b7265…`, `0xbf33b651…`).

Replay uses the identical incremental construction (D.5), so a replay head hash at position `p` equals `hashEventHistory(acceptedEvents.slice(0, p+1))` (**[verified]**: `replay(events.slice(0,2)).head.hash === hashEventHistory(events.slice(0,2))`).

### B.4 `PortableHistoryHead`

```
{ hash: ContentHash, position: U53, canonicalTime: U53 }
```

* `hash` — the prefix hash of the accepted history up to and including the event at `position` (B.3).
* `position` — zero-based index of the last accepted event (`eventCount - 1`).
* `canonicalTime` — **the timestamp of the last accepted event** (`finalEvent.timestamp`), not a maximum. Because accepted timestamps are non-decreasing (D.6) this coincides with the maximum. Head for the fixture prefix of length 1: `{ hash: "0xe035299cb5520cc603d60273ae4c51ea1eaddad3cc9a47102edab60447d38397", position: 0, canonicalTime: 0 }` **[verified]**.

The "next head" passed into a transition (D.7) is the head *including* the event being applied: `{ hash: prefixHash(p), position: p, canonicalTime: event.timestamp }`.

---

## C. Event schema — `continuity-event/0.2`

Source: `event-schema.ts`. Two entry points share the same per-type rules:

* `validateCanonicalEventShape(input)` — standalone: captures the event itself (strict capture of `data` with a 1 048 576-byte budget) and returns `{ ok: true, typeRank, event }` or `{ ok: false, code, reason }` with `code ∈ {EVENT_ENVELOPE_INVALID, EVENT_TYPE_UNSUPPORTED, EVENT_DATA_INVALID}`.
* `refineCapturedCoreEvent(baseEvent)` — used by replay on an already captured base event; returns the same result shape. Replay maps its failures to replay codes (D.6).

`reason` strings are of the form `<path>: <message>` where `<path>` starts at `$` (standalone) and uses `.field` and `[index]` segments. Replay does **not** expose reasons; only `validateCanonicalEventShape` does. Reasons are documented here because the *first failing check* determines them and, more importantly, determines the LIMIT-vs-SEMANTIC classification that replay turns into `INVALID_INPUT` vs `EVENT_DATA_INVALID`.

### C.1 Event types and ranks

`CORE_EVENT_TYPES` (rank = index):

```
 0 DEPLOYMENT_INITIALIZED        13 TRANSACTION_INTENT_ADMITTED
 1 PRINCIPAL_CREATED             14 TRANSACTION_INTENT_CONSUMED
 2 AGENT_CREATED                 15 TRANSACTION_OUTCOME_RECORDED
 3 ROLE_CREATED                  16 RECEIPT_RECORDED
 4 SUCCESSION_RULE_DECLARED      17 OBLIGATION_CREATED
 5 AGENT_APPOINTED               18 OBLIGATION_PERFORMANCE_ASSIGNED
 6 AGENT_UNAPPOINTED             19 OBLIGATION_STATUS_RECORDED
 7 ROLE_TRANSFERRED              20 AGENT_TERMINATED
 8 RUNTIME_SESSION_ADMITTED      21 OUTCOME_OBSERVATION_RECORDED
 9 CONTROL_EPOCH_ADVANCED        22 ATTEMPT_DUTY_CREATED
10 AUTHORITY_GRANTED             23 ATTEMPT_DUTY_ASSIGNED
11 AUTHORITY_REVOKED             24 ATTEMPT_DUTY_REVIEW_CLOSED
12 TRANSACTION_INTENT_DECLARED
```

`isCoreEventType(v)` is an exact string membership test; `coreEventTypeRank` returns the index or `undefined`.

### C.2 Envelope

An event is a plain record with **exactly** the four own keys `id`, `type`, `timestamp`, `data` (any order; no extra keys, no symbol keys, even an extra key whose value is `undefined` is rejected):

| field | rule | failure |
|---|---|---|
| `id` | Identifier (1..256 bytes, no C0/DEL) | `$.id: must be an Identifier` |
| `type` | ProtocolString (any string ≤ 4 096 bytes, well-formed; may be empty) | `$.type: must be a bounded ProtocolString` |
| `timestamp` | U53 | `$.timestamp: must be a U53` |
| `data` | plain record whose canonical text ≤ 1 048 576 bytes | `$.data: must be a plain protocol record` / `$.data: exceeds the 1048576-byte event-data byte limit` |

Standalone envelope failure reasons (all `EVENT_ENVELOPE_INVALID`): `$: event must be a plain protocol record` (null, non-object, wrong prototype), `$: failed event prototype capture`, `$: failed event own-key capture`, `$: event has a non-string field`, `$: event has an undeclared field`, `$.<key>: is required`, `$.<key>: failed descriptor capture`, `$.<key>: changed during envelope capture`, `$.<key>: accessor failed during its single capture`. Standalone `data` capture failures: shape error → `EVENT_ENVELOPE_INVALID "$.data: must be a plain protocol record"`; byte-limit → `EVENT_DATA_INVALID "$.data: exceeds the 1048576-byte event-data byte limit"`; any other capture error (over-long string, out-of-range bigint, depth, NaN, …) → `EVENT_DATA_INVALID "$.data: failed canonical base capture"`. Envelope scalars are checked in the order id, type, timestamp, data; the data capture happens **before** the type-membership check, so an unknown type with bad data reports the data problem first; an unknown type with good data → `EVENT_TYPE_UNSUPPORTED "$.type: unsupported 0.2 EventType <JSON.stringify(type)>"`.

### C.3 Validation phases for `data`

For a known type, two passes run over the captured data using the *captured record-key snapshot* (so undefined-valued keys are visible):

1. **Named-limit preflight** (`preflightEventNamedLimits`) — walks a per-type tree of "named limit slots" (listed in C.5) and records only *hard-limit* failures (`failLimit`): an Identifier slot holding a string whose UTF-8 length exceeds 256 bytes (or whose UTF-16 length exceeds 256), a BigInt slot holding a bigint outside ±(2^256−1), or a list slot longer than its maximum. It ignores semantic defects (wrong types, missing fields, malformed strings) and keeps walking. Any LIMIT here makes the whole result a **LIMIT failure**.
2. **Closed-schema pass** (`validateEventData`) — the exact per-type rules below, short-circuiting at the first failure. A failure is SEMANTIC unless it came from `failLimit` (identifier/protocol-string length overflow, amount magnitude overflow, list-size overflow), in which case it is LIMIT.

The result is `{ ok:false, code:"EVENT_DATA_INVALID", reason }`, branded as a LIMIT failure when `failureKind === "LIMIT"`. Replay converts LIMIT-branded failures to `INVALID_INPUT` and SEMANTIC ones to `EVENT_DATA_INVALID` (**[verified]**: `principalId` of 257 chars → `INVALID_INPUT`; an extra field plus a 257-char `principalId` → `INVALID_INPUT` because the preflight runs first; `maxAmount = 2^256` → `INVALID_INPUT`). A limit failure in a slot **not** in the named-limit tree (e.g. `ObligationRecord.description` > 4 096 bytes, which is a ProtocolString) is still LIMIT-branded when reached, but an earlier semantic failure in the closed-schema pass wins over it.

`ShapeValidator.record(value, path, required, optional)` — the closed-record primitive used everywhere:

1. `value` must be a plain record → `<path>: must be a plain protocol record`.
2. The captured key snapshot must exist → `<path>: is not part of the captured record-key snapshot` (cannot happen for captured input).
3. Every captured key must be in `required ∪ optional` → `<path>.<key>: is not a declared field` (this fires for undeclared keys whose value is `undefined`; **[verified]**).
4. Every required key must be own and `!== undefined` → `<path>.<key>: is required`.

Optional keys may be absent or present-with-`undefined` (treated as absent). Unless stated, sub-records have **no** optional keys.

### C.4 Scalar and list primitives (with their reasons)

| primitive | rule | failure reason (`<p>` = path) |
|---|---|---|
| `identifier` | string; `length <= 256` and UTF-8 ≤ 256 (else **LIMIT**); well-formed; non-empty; no `/[\u0000-\u001f\u007f]/` | `<p>: must be an Identifier` |
| `protocolString` | string; UTF-8 ≤ 4 096 (else **LIMIT**); well-formed | `<p>: must be a bounded ProtocolString` |
| `u53` | see U53 | `<p>: must be a U53` |
| `amount` | bigint; magnitude ≤ 2^256−1 (else **LIMIT** `<p>: exceeds the 256-bit BigInt magnitude bound`); `>= 0n` | `<p>: must be an Amount` |
| `contentHash` | `/^0x[0-9a-f]{64}$/` | `<p>: must be a lowercase ContentHash` |
| `ethereumAddress` | `/^0x[0-9a-fA-F]{40}$/` | `<p>: must be an EthereumAddress` |
| `chainId` | `/^[1-9][0-9]*$/` then `1 <= n <= 2^256-1` | `<p>: must be a canonical ChainId string` / `<p>: is outside the ChainId bound` |
| `signature65` | `/^0x[0-9a-f]{130}$/` ; `s != 0 && s <= MAX_LOW_S && v ∈ {"1b","1c"}` | `<p>: must be a lowercase 65-byte signature` / `<p>: must use a low-s value and recovery byte 27 or 28` |
| `literal(allowed)` | string member of `allowed` | `<p>: must be one of A, B, C` |
| `identifierList({nonempty, maximum})` | `Array.isArray`; `length <= maximum` (default 4 096; else **LIMIT** `<p>: exceeds the N-member set bound`); if nonempty required and empty → `<p>: has invalid list cardinality`; each member `identifier` at `<p>[i]`; no duplicates → `<p>[i]: duplicates an Identifier` | `<p>: must be a dense Identifier list` |
| `enumList(allowed, nonempty)` | array (and nonempty if required) else `<p>: must be a dense nonempty enum list`; each `literal`; no duplicates → `<p>[i]: duplicates a member` | |
| `reviewObservationIds` | `identifierList` with maximum 128, then strictly increasing under `compareProtocolStrings` | `<p>: must be strictly sorted` |

`isPlainRecord` is used directly (without a reason) in a few places; those produce the generic fallback reason `$.data: invalid closed event payload` when no other problem was recorded.

### C.5 Shared sub-records

Field lists are given as `required [optional]`. Checks run left to right and stop at the first failure.

**authorizationDomain** `{protocol, version, deploymentId, chainId, verifyingContract}`: `protocol === "continuity"` and `version === "0.2"` (no reason recorded → generic fallback), `deploymentId` identifier, `chainId`, `verifyingContract` address. Named-limit tree: `deploymentId`.

**versionSet** (used by `DEPLOYMENT_INITIALIZED` closed schema) `{eventSchemaVersion, receiptSchemaVersion, queryEnvelopeVersion, authorizationProofVersion, runtimeAuthorizationVersion, administrativeAuthorizationVersion, signatureScheme}` — each must **equal** exactly, checked in this order: `continuity-event/0.2`, `continuity-receipt/0.2`, `continuity-query-envelope/0.2`, `continuity-authorization-proof/0.2`, `continuity-runtime-authorization/0.2`, `continuity-administrative-authorization/0.2`, `eip191-personal-sign-keccak256`; failure `<p>.<key>: must equal <expected>`.

**declaredVersionSet** (genesis probe only): same seven keys, each merely an Identifier.

**historyHead** `{hash, position, canonicalTime}`: contentHash, u53, u53.

**actionRequest** `{actorId, action, resource, claimedAt} [amount, counterpartyId, termsCommitment]`: identifiers, u53 `claimedAt`, optional amount / identifier / contentHash.

**evidenceReference** — tagged by `kind` (must be a plain record with string `kind`, else `<p>: must be a tagged EvidenceReference record`; unknown kind → `<p>.kind: is not an EvidenceReference kind`):

* `EVENT` `{kind, eventId, eventType, position, historyHash}`: identifier; `eventType` must be a core event type (`<p>.eventType: is not an EventType`); u53; contentHash.
* `AUTHORITY` `{kind, authorityId, grantEventId}`: identifiers.
* `RUNTIME_CREDENTIAL` `{kind, keyId, sessionId, admissionEventId}`: identifiers.
* `RECEIPT_COMMITMENT` `{kind, receiptContentHash, eventId, position}`: contentHash, identifier, u53.
* `EXTERNAL` `{kind, evidenceType, reference, attesterId}`: identifiers.

**authorityConstraints(requiredIntersectionMaximum = 32)** `{actions, resources, quantitative, maxDelegationDepth, requiredIntersectionIds} [notBefore, expiresAt, maxAmount, maxCumulativeAmount, maxTransactions]`:

1. LIMIT pre-checks: `actions.length > 256` → `<p>.actions: exceeds the 256-member action set bound`; `resources.length > 256` → `... resource set bound`; `requiredIntersectionIds.length > max` → `<p>.requiredIntersectionIds: exceeds the <max>-member required-intersection bound`.
2. `actions` identifierList nonempty ≤ 256; `resources` identifierList nonempty ≤ 256; `quantitative` boolean (`<p>.quantitative: must be boolean`); `maxDelegationDepth` u53; `requiredIntersectionIds` identifierList (may be empty) ≤ max; optional `notBefore`, `expiresAt`, `maxTransactions` u53; optional `maxAmount`, `maxCumulativeAmount` amount.
3. If `quantitative === false` and either amount ceiling is present → `<p>: nonquantitative constraints cannot carry amount ceilings`.

**permissionGrant** `{kind, authorityId, grantorId, granteeId, rootAuthorityId, independent, constraints} [parentAuthorityId]`: `kind === "PERMISSION"` (no reason), identifiers, `independent` boolean (`<p>.independent: must be boolean`), constraints.

**prohibitionGrant**: plain record with `kind === "PROHIBITION"` (`<p>.kind: must be PROHIBITION`); `scope === "ROOT"` → `{kind, scope, authorityId, grantorId, rootAuthorityId, constraints} [subjectActorId, parentAuthorityId]`; `scope === "GLOBAL"` → `{kind, scope, authorityId, grantorId, constraints} [subjectActorId]`; otherwise `<p>.scope: must be ROOT or GLOBAL`.

**authorityGrant**: plain record (`<p>: must be an authority grant record`), dispatched on `kind` (`<p>.kind: must be PERMISSION or PROHIBITION`).

**recognizedRoot** `{rootAuthorityId, principalId, principalRecognitionEventId, rootGrantEventId}` identifiers.
**authorityUsage** `{authorityId, admittedTransactionCount (u53), admittedCumulativeAmount (amount)}`.
**authorityEvidence** `{authorityId, grantEventId, grantEventPosition (u53)}`.
**permissionGrantList(nonempty)**: array (`<p>: must be a bounded permission path`); `length > 32` → LIMIT `<p>: exceeds the 32-member authority-path bound`; each permissionGrant; distinct `authorityId` (`<p>[i]: duplicates a path authority`).
**intersectionProof** `{requiredAuthorityId, requiredByAuthorityIds (identifierList nonempty ≤256), recognizedRoot, path (permissionGrantList nonempty), effectiveConstraints (authorityConstraints with intersection max 256)}`.

**authorizationProof** `{proofVersion, domain, policyVersion, rootRecognitionPolicy, historyHead, evaluationTime, request, recognizedRoot, permissionPath, intersections, effectiveConstraints, controllingAuthorityIds, usageSnapshot, authorityEvidence, checkedProhibitionIds, consequential} [runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId, intentId, nonce]`:

1. LIMIT pre-checks: `intersections.length > 256` (`proof-intersection bound`), `usageSnapshot.length > 256` (`authority-usage bound`), `authorityEvidence.length > 1024` (`authority-evidence bound`).
2. `proofVersion === "continuity-authorization-proof/0.2"`, domain, `policyVersion` identifier, `rootRecognitionPolicy === "declared-principal-root/0.2"`, historyHead, `evaluationTime` u53, actionRequest, recognizedRoot, `permissionPath` permissionGrantList nonempty, `intersections` array, `effectiveConstraints` (intersection max 256), `controllingAuthorityIds` identifierList nonempty ≤ 256, `usageSnapshot` array, `authorityEvidence` non-empty array, `checkedProhibitionIds` identifierList ≤ 256 (may be empty), `consequential` boolean. If any of these fails without a recorded reason → `<p>: contains an invalid AuthorizationProof field`.
3. Each `intersections[i]` intersectionProof with distinct `requiredAuthorityId` (`duplicates a required authority`); each `usageSnapshot[i]` authorityUsage distinct `authorityId` (`duplicates an authority`); each `authorityEvidence[i]` authorityEvidence distinct `authorityId`.
4. The seven consequential fields must all be present (own and not undefined) iff `consequential === true` (`<p>.<field>: is required for a consequential proof` / `must be absent from a nonconsequential proof`); when consequential: identifiers except `controlEpoch` u53.

**adapterProfile** `{profileId, profileVersion, descriptorHash}` and `validateKnownPortableAdapterProfile` (canonical equality with one of the five known profiles, see F.4). Failure yields no reason (generic fallback).

**adapterEvidence(noEffect=false)** `{schemaVersion, kind, adapterProfile, domain, intentId, admissionHead, idempotencyKey, submissionFingerprint, result}`: adapterProfile, authorizationDomain, historyHead `admissionHead`; `result` plain record; for noEffect: `result` exactly `{kind, reference}` then `validatePortableAdapterNoEffectShape(record)`; otherwise `result.kind` dispatch: `SIMULATED_SUBMISSION` → `{kind, submissionReference}`; `LOCAL_PACKET_CREATED` → `{kind, manifestDigest{algorithm, value}}`; `REMOTE_SERVICE_REPORTED` → `{kind, reportDigest{algorithm, value}}`; `LOCAL_DOCUMENT_RELEASED` → `{kind, publicationManifestDigest{algorithm, value}}`; `LOCAL_ENDPOINT_STATE_CHANGED` → `{kind, transitionDigest{algorithm, value}}`; other → false; then `validatePortableAdapterAcknowledgmentShape(record)` (F.5 explains the reconstruction it performs). Any false without reason → generic fallback.

**transactionIntent** `{intentId, nonce, actorId, action, resource, roleId, roleTenureId, adapterProfile} [amount, counterpartyId, termsCommitment]` — adapterProfile is checked **first**, then identifiers, optional amount / identifier / contentHash.

**obligationTransitionPolicy** `{fromStatus, toStatus, acceptedAttesterIds, action, requiredAuthorityIds}`: statuses ∈ `OPEN, OUTCOME_UNKNOWN, DISPUTED, DISCHARGED, IMPOSSIBLE_OR_ESCALATED`; both identifier lists nonempty ≤ 256; `action` identifier.

**obligationRecord** `{obligationId, sourceIntentId, causalReceiptContentHash, durableRoleId, creationRoleTenureId, description, trigger, deadline, status, beneficiaryId, termsCommitment, performanceAssigneeId, successionRuleId, transitionPolicies} [counterpartyId]`: identifiers; `causalReceiptContentHash`, `termsCommitment` contentHash; `description` protocolString; `deadline` u53; `status ∈ {OPEN, OUTCOME_UNKNOWN}`; `transitionPolicies` non-empty array (else `<p>: contains an invalid ObligationRecord field`); each policy; `(fromStatus,toStatus)` pairs distinct (`<p>.transitionPolicies[i]: duplicates a status-transition pair`).

**administrativeChallenge** `{version, domain, request, authoritative, consequential, evaluationTime, policyVersion, rootRecognitionPolicy, eventHistoryHash, eventHistoryPosition, transitionEventId, transitionEventType, transitionEffectHash, runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId, authorityProofHash}`: `version === "continuity-administrative-authorization/0.2"`, domain, actionRequest, `authoritative === true` (`must be true`), `consequential === true`, u53, identifier, `rootRecognitionPolicy === "declared-principal-root/0.2"`, contentHash, u53, identifier, `transitionEventType ∈` the seven administrative types (`OBLIGATION_CREATED, OBLIGATION_PERFORMANCE_ASSIGNED, OBLIGATION_STATUS_RECORDED, OUTCOME_OBSERVATION_RECORDED, ATTEMPT_DUTY_CREATED, ATTEMPT_DUTY_ASSIGNED, ATTEMPT_DUTY_REVIEW_CLOSED`), contentHash, identifiers, u53 `controlEpoch`, identifiers, contentHash.

**administrativeAuthorization** `{challenge, authorityProof, runtimeSignature}`: challenge, authorizationProof, signature65.

**attemptDutyRecord** `{dutyId, sourceIntentId, sourceAdmissionEventId, durableRoleId, creationRoleTenureId, description, deadline, performanceAssigneeId, status}`: identifiers, protocolString, u53, identifier, `status === "OPEN"` (literal).

### C.6 Per-type `data` shapes

Path prefix is `$.data`. "→ replay" notes give the additional transition preconditions of section D.

**DEPLOYMENT_INITIALIZED** `{domain, adapterPolicyHash, canonicalLineageId, versions, policyVersion, rootRecognitionPolicy, globalPolicySourceId, timeSource, finality}` — checked in order: domain; `adapterPolicyHash` must be one of the six adapter-policy hashes (F.3) (no reason → generic); `canonicalLineageId` identifier; `versions` versionSet (exact); `policyVersion` identifier; `rootRecognitionPolicy === "declared-principal-root/0.2"`; `timeSource === "EVENT_TIMESTAMP"`; `finality === "LOCAL_ONLY"`; `globalPolicySourceId` identifier. Named-limit tree: `domain.deploymentId, canonicalLineageId, versions.*(7), policyVersion, globalPolicySourceId`.

**PRINCIPAL_CREATED** `{principalId}` identifier.

**AGENT_CREATED** `{agentId, principalId, controllerId, initialControlEpoch}` identifiers, u53. → replay: `initialControlEpoch` must be `1`.

**ROLE_CREATED** `{roleId, principalId, exclusive}`; `exclusive === true` (`$.data.exclusive: must be true`).

**SUCCESSION_RULE_DECLARED** `{ruleId, principalId, predecessorAgentId, successorAgentId, roleId, trigger, permittedEventTypes}`; `trigger === "AGENT_TERMINATED"` (no reason); `permittedEventTypes` non-empty enumList over `AGENT_TERMINATED, ROLE_TRANSFERRED, OBLIGATION_PERFORMANCE_ASSIGNED` (no duplicates; any order).

**AGENT_APPOINTED** `{agentId, roleId, roleTenureId, tenureNumber (u53), principalId} [successionRuleId]`.

**AGENT_UNAPPOINTED** `{agentId, roleId, roleTenureId, principalId}`.

**ROLE_TRANSFERRED** `{roleId, fromAgentId, fromRoleTenureId, toAgentId, toRoleTenureId, toTenureNumber (u53), principalId, transferKind ∈ {SUCCESSION, REASSIGNMENT}} [successionRuleId]`.

**RUNTIME_SESSION_ADMITTED** `{sessionId, agentId, controllerId, controlEpoch (u53), credentialKeyId, credentialAddress (ethereumAddress)} [expiresAt (u53)]`.

**CONTROL_EPOCH_ADVANCED** `{agentId, controllerId, fromEpoch (u53), toEpoch (u53)}`.

**AUTHORITY_GRANTED** `{grant}` authorityGrant.

**AUTHORITY_REVOKED** `{authorityId, revokerId}`.

**TRANSACTION_INTENT_DECLARED** — the data *is* a transactionIntent.

**TRANSACTION_INTENT_ADMITTED** `{intentId, evaluationTime (u53), expectedHistoryHead (historyHead), authorizationProof (authorizationProof), runtimeAuthorizationHash (contentHash), runtimeSignature (signature65)}`.

**TRANSACTION_INTENT_CONSUMED** `{intentId, adapterId, idempotencyKey, submissionFingerprint, status, evidenceReference, acknowledgment, transactionReference}` — order: identifier, identifier, contentHash, contentHash, `status === "SUBMITTED"` (no reason), `transactionReference` identifier, `acknowledgment` adapterEvidence, `evidenceReference`.

**TRANSACTION_OUTCOME_RECORDED** `{intentId, status, attesterId, evidenceReference} [noEffect]` — if `status !== "FAILED"` the record is re-validated **without** `noEffect` as an allowed key (so a present-but-undefined `noEffect` fails with `$.data.noEffect: is not a declared field`); `status ∈ {CONFIRMED, FAILED, DISPUTED, OUTCOME_UNKNOWN}`; if `FAILED`, `noEffect` must be adapterEvidence(noEffect=true) (missing → `$.data.noEffect: must be a plain protocol record`), else `noEffect` key must be absent; `attesterId`; `evidenceReference`.

**RECEIPT_RECORDED** `{receiptContentHash, receiptArtifactCommitment, intentId, issuerAgentId, runtimeSessionId, controlEpoch (u53), roleId, roleTenureId, authorizationProofHash}` (hashes are contentHash, ids identifiers).

**OBLIGATION_CREATED** `{record (obligationRecord), actorId, administrativeAuthorization}`.

**OBLIGATION_PERFORMANCE_ASSIGNED** `{obligationId, fromAgentId, toAgentId, successionRuleId, actorId, administrativeAuthorization}`.

**OBLIGATION_STATUS_RECORDED** `{obligationId, fromStatus, toStatus, actorId, action, administrativeAuthorization, attesterId, evidenceReference}` (statuses from the five-member enum).

**AGENT_TERMINATED** `{agentId, principalId, successionRuleId, roleId, roleTenureId}`.

**OUTCOME_OBSERVATION_RECORDED** `{intentId, sourceAdmissionEventId, acknowledgment, actorId, administrativeAuthorization}`; `acknowledgment` must be a plain record with `schemaVersion === "continuity-remote-service-report-ack/1"` and pass adapterEvidence.

**ATTEMPT_DUTY_CREATED** `{record (attemptDutyRecord), actorId, administrativeAuthorization}`.

**ATTEMPT_DUTY_ASSIGNED** `{dutyId, fromAgentId, toAgentId, actorId, administrativeAuthorization}`.

**ATTEMPT_DUTY_REVIEW_CLOSED** `{dutyId, actorId, observationEventIds (reviewObservationIds), summaryDigest (contentHash), administrativeAuthorization}`.

### C.7 Named-limit trees (preflight slots)

Only these slots are scanned by the LIMIT preflight (`CORE_EVENT_NAMED_LIMITS`). IDENTIFIER = 256-byte identifier; BIGINT = 256-bit magnitude; LIST(max, name) = length bound.

* `LIMIT_DOMAIN = {deploymentId: ID}`
* `LIMIT_ADAPTER_PROFILE = {profileId, profileVersion}`
* `LIMIT_ADAPTER_EVIDENCE = {schemaVersion, kind, adapterProfile: LIMIT_ADAPTER_PROFILE, domain: LIMIT_DOMAIN, intentId, result: {kind, reportDigest.algorithm, publicationManifestDigest.algorithm, manifestDigest.algorithm, transitionDigest.algorithm}}`
* `LIMIT_VERSION_SET` = the 7 version identifiers
* `LIMIT_ACTION_REQUEST = {actorId, action, resource, amount: BIGINT, counterpartyId}`
* `LIMIT_EVIDENCE_REFERENCE` tagged on `kind`: EVENT `{eventId}`, AUTHORITY `{authorityId, grantEventId}`, RUNTIME_CREDENTIAL `{keyId, sessionId, admissionEventId}`, RECEIPT_COMMITMENT `{eventId}`, EXTERNAL `{evidenceType, reference, attesterId}`
* `limitAuthorityConstraints(n) = {actions: LIST(256,"action set") of ID, resources: LIST(256,"resource set"), requiredIntersectionIds: LIST(n,"required-intersection set"), maxAmount: BIGINT, maxCumulativeAmount: BIGINT}`; grants use n=32, effective constraints n=256
* `LIMIT_PERMISSION_GRANT = {authorityId, grantorId, granteeId, rootAuthorityId, parentAuthorityId, constraints(32)}`
* `LIMIT_AUTHORITY_GRANT` tagged on `kind` with common `{authorityId, grantorId, constraints(32)}`: PERMISSION `{granteeId, rootAuthorityId, parentAuthorityId}`; PROHIBITION tagged on `scope` with common `{subjectActorId}`: ROOT `{rootAuthorityId, parentAuthorityId}`, GLOBAL `{}`
* `LIMIT_RECOGNIZED_ROOT` (4 ids), `LIMIT_AUTHORITY_USAGE = {authorityId, admittedCumulativeAmount: BIGINT}`, `LIMIT_AUTHORITY_EVIDENCE = {authorityId, grantEventId}`, `LIMIT_PERMISSION_PATH = LIST(32,"authority path") of LIMIT_PERMISSION_GRANT`
* `LIMIT_INTERSECTION_PROOF = {requiredAuthorityId, requiredByAuthorityIds: LIST(256,"required-by authority set"), recognizedRoot, path, effectiveConstraints(256)}`
* `LIMIT_AUTHORIZATION_PROOF = {domain, policyVersion, request, recognizedRoot, permissionPath, intersections: LIST(256,"proof-intersection set"), effectiveConstraints(256), controllingAuthorityIds: LIST(256,"controlling-authority set"), usageSnapshot: LIST(256,"authority-usage set"), authorityEvidence: LIST(1024,"authority-evidence set"), checkedProhibitionIds: LIST(256,"checked-prohibition set"), runtimeSessionId, credentialKeyId, roleId, roleTenureId, intentId, nonce}`
* `LIMIT_TRANSACTION_INTENT = {adapterProfile, intentId, nonce, actorId, action, resource, roleId, roleTenureId, amount: BIGINT, counterpartyId}`
* `LIMIT_OBLIGATION_TRANSITION_POLICY = {acceptedAttesterIds: LIST(256,"accepted-attester set"), action, requiredAuthorityIds: LIST(256,"required-authority set")}`
* `LIMIT_OBLIGATION_RECORD = {obligationId, sourceIntentId, durableRoleId, creationRoleTenureId, trigger, beneficiaryId, counterpartyId, performanceAssigneeId, successionRuleId, transitionPolicies: LIST(∞) of policy}`
* `LIMIT_ADMINISTRATIVE_CHALLENGE = {domain, request, policyVersion, transitionEventId, runtimeSessionId, credentialKeyId, roleId, roleTenureId}`; `LIMIT_ADMINISTRATIVE_AUTHORIZATION = {challenge, authorityProof}`
* `LIMIT_ATTEMPT_DUTY_RECORD = {dutyId, sourceIntentId, sourceAdmissionEventId, durableRoleId, creationRoleTenureId, performanceAssigneeId}`

Per type: DEPLOYMENT_INITIALIZED `{domain, canonicalLineageId, versions, policyVersion, globalPolicySourceId}`; PRINCIPAL_CREATED `{principalId}`; AGENT_CREATED `{agentId, principalId, controllerId}`; ROLE_CREATED `{roleId, principalId}`; SUCCESSION_RULE_DECLARED `{ruleId, principalId, predecessorAgentId, successorAgentId, roleId}`; AGENT_APPOINTED `{agentId, roleId, roleTenureId, principalId, successionRuleId}`; AGENT_UNAPPOINTED `{agentId, roleId, roleTenureId, principalId}`; ROLE_TRANSFERRED `{roleId, fromAgentId, fromRoleTenureId, toAgentId, toRoleTenureId, principalId, successionRuleId}`; RUNTIME_SESSION_ADMITTED `{sessionId, agentId, controllerId, credentialKeyId}`; CONTROL_EPOCH_ADVANCED `{agentId, controllerId}`; AUTHORITY_GRANTED `{grant}`; AUTHORITY_REVOKED `{authorityId, revokerId}`; TRANSACTION_INTENT_DECLARED = LIMIT_TRANSACTION_INTENT; TRANSACTION_INTENT_ADMITTED `{intentId, authorizationProof}`; TRANSACTION_INTENT_CONSUMED `{intentId, adapterId, transactionReference, acknowledgment, evidenceReference}`; TRANSACTION_OUTCOME_RECORDED `{intentId, noEffect, attesterId, evidenceReference}`; RECEIPT_RECORDED `{intentId, issuerAgentId, runtimeSessionId, roleId, roleTenureId}`; OBLIGATION_CREATED `{record, actorId, administrativeAuthorization}`; OBLIGATION_PERFORMANCE_ASSIGNED `{obligationId, fromAgentId, toAgentId, successionRuleId, actorId, administrativeAuthorization}`; OBLIGATION_STATUS_RECORDED `{obligationId, actorId, action, administrativeAuthorization, attesterId, evidenceReference}`; AGENT_TERMINATED `{agentId, principalId, successionRuleId, roleId, roleTenureId}`; OUTCOME_OBSERVATION_RECORDED `{intentId, sourceAdmissionEventId, acknowledgment, actorId, administrativeAuthorization}`; ATTEMPT_DUTY_CREATED `{record, actorId, administrativeAuthorization}`; ATTEMPT_DUTY_ASSIGNED `{dutyId, fromAgentId, toAgentId, actorId, administrativeAuthorization}`; ATTEMPT_DUTY_REVIEW_CLOSED `{dutyId, actorId, observationEventIds: LIST(128,"attempt-review-observations"), administrativeAuthorization}`.

Walk rules: a RECORD node is only descended when the value is a plain record and the field is own and not undefined; a LIST node only when `Array.isArray`; a TAGGED_RECORD applies `common` first, then the variant whose tag string matches (unknown tag → no variant). Nothing else is inspected.

### C.8 Genesis version probe (`validateCapturedGenesisVersionProbe`)

Applies only to a captured base event whose `type === "DEPLOYMENT_INITIALIZED"`. It runs the DEPLOYMENT_INITIALIZED named-limit preflight, then requires the closed record `{domain, adapterPolicyHash, canonicalLineageId, versions, policyVersion, rootRecognitionPolicy, globalPolicySourceId, timeSource, finality}` with: domain valid; `adapterPolicyHash` a **ContentHash** (not yet a known policy); `canonicalLineageId` identifier; `versions` a **declaredVersionSet** (seven Identifiers, any values); `policyVersion` identifier; `rootRecognitionPolicy === "declared-principal-root/0.2"` (`must equal declared-principal-root/0.2`); `globalPolicySourceId` identifier; `timeSource === "EVENT_TIMESTAMP"`; `finality === "LOCAL_ONLY"`. Failure code is always `EVENT_DATA_INVALID`, LIMIT-branded when appropriate. On success it returns the seven declared version strings, which replay then compares (D.6).

---

## D. Replay — `continuity-replay/0.2`

Source: `portable-replay.ts` (`replayPortable`, `createPortableReplayKernel`, `reduceCapturedEvent`, `applyTransition`) with the capture machinery of `canonical.ts` (`captureBoundedCanonicalReplayBodyIncrementally`) and the signed-transition validators of `portable-authority-engine.ts`.

### D.1 Result shape

```
PortableReplayResult =
  | { operationVersion: "continuity-replay/0.2", status: "ACCEPTED", head: PortableHistoryHead, eventCount: number }
  | { operationVersion: "continuity-replay/0.2", status: "REJECTED", code: PortableReplayCode, eventPosition?: number, eventId?: string }

PortableReplayCode = "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "UNSUPPORTED_EVENT_SCHEMA" | "UNSUPPORTED_EVENT_TYPE"
                   | "GENESIS_REQUIRED" | "GENESIS_DUPLICATE" | "EVENT_ID_DUPLICATE" | "EVENT_TIME_REGRESSION"
                   | "EVENT_DATA_INVALID" | "TRANSITION_INVALID"
```

Results are frozen. On `REJECTED`, `eventPosition`/`eventId` are defined **only when known** (they are own properties only if present). On `ACCEPTED`, `eventPosition` and `eventId` exist as own, non-enumerable properties with value `undefined` (**[verified]**: `Object.getOwnPropertyNames` lists all six). `eventCount === head.position + 1`. `ACCEPTED` means every event was captured, schema-validated and applied, and the history is non-empty; every other status means the *first* failure encountered in position order (with the precedence in D.6).

### D.2 Outer input (`captureReplayOuter`)

`replayPortable(input)`:

1. `input` must be a plain record (prototype `Object.prototype` or `null`; arrays and `null` rejected) → else `INVALID_INPUT` (no position).
2. `Reflect.ownKeys(input)` must be exactly two string keys, `operationVersion` and `events` (any order; a symbol key or a third key → `INVALID_INPUT`; **[verified]** an extra key rejects).
3. `operationVersion` is read via its descriptor (getters allowed, invoked once; throwing getter → `INVALID_INPUT`). It must be a string of `length <= 4096`, well-formed, UTF-8 ≤ 4 096 → else `INVALID_INPUT`. If it is not exactly `"continuity-replay/0.2"` → `UNSUPPORTED_VERSION`. This check happens **before** `events` is read (**[verified]**: `{operationVersion:'nope', events:5}` → `UNSUPPORTED_VERSION`).
4. `events` is read via its descriptor (throwing getter → `INVALID_INPUT`). A missing key is impossible after step 2; `events: undefined` proceeds to capture and fails there.

### D.3 Body capture

The engine constructs the frozen null-prototype body `{ operationVersion: "continuity-replay/0.2", events }` and captures it in **structural phase-one** mode with a 16 MiB budget (`captureBoundedCanonicalReplayBodyIncrementally`), with the caller's `input` object marked "active" so that any event data referencing the outer input object is treated as a cycle. Consequences:

* `events` must be `Array.isArray` → else TypeError → `INVALID_INPUT` (no position).
* `events.length <= 4 096`, dense, no expandos, no `undefined` entries (A.7); the 4 097th event → `INVALID_INPUT` without position (**[verified]**).
* Total canonical bytes of `{"events":[...],"operationVersion":"continuity-replay/0.2"}` ≤ 16 777 216; before visiting each event the engine also requires that the remaining budget can still hold `],"operationVersion":"continuity-replay/0.2"}` (44 bytes) — otherwise `INVALID_INPUT`.
* Each event is captured by `captureReplayEvent` in the `REPLAY_EVENT` role, which (before any schema logic) enforces the **base envelope**: a plain record (prototype check) with **exactly** the own keys `{id, type, timestamp, data}` (`Canonical replay event at $.events[i] has an invalid envelope.`); `id` captured as an identifier-role designated scalar (string, non-empty, ≤ 256 UTF-8 bytes, ≤ 256 UTF-16 units, no C0/DEL; marker objects/records rejected); `type` a ProtocolString (≤ 4 096 bytes; may be empty); `timestamp` a U53 (checked as `typeof number && isSafeInteger && >= 0 && !is(-0)`); `data` a plain record (prototype `Object.prototype`/`null`, not array). The `data` subtree is captured with a **fresh local budget of 1 048 576 bytes** (label `$.events[i].data`) in addition to the global budget. The captured event is re-materialised as a frozen null-prototype record with keys `data, id, timestamp, type` (this order) and canonical text `{"data":…,"id":…,"timestamp":…,"type":…}`.
* Every capture failure inside the events list is annotated with the position of the event being captured, and with its `id` when the id had already been captured successfully. `replayPortable` reports it as `INVALID_INPUT` with `eventPosition` (and `eventId` when known). **[verified]** examples: extra envelope key → `{code: INVALID_INPUT, eventPosition: 1}` (no id); `data` missing / array / class instance / `timestamp: -1` / `timestamp: 1.5` / `timestamp: "1"` / 4 097-byte `type` / data larger than 1 MiB / >4 096-byte string in data / depth overflow in data / bigint marker as timestamp → `INVALID_INPUT` with `eventPosition` **and** `eventId`; `id: ''`, `id: 5`, `id` with control char, `id` 257 bytes, lone-surrogate id, event `null`/array/Date/class instance → `INVALID_INPUT` with `eventPosition` only.
* Strings > 4 096 bytes anywhere in the body throw at capture (→ `INVALID_INPUT`). Malformed-Unicode strings ≤ 4 096 units, non-integer/NaN/-0 numbers and >256-bit bigints **inside `data`** do not throw at capture; they become 32-byte noncanonical scalars and are rejected later by the schema (`EVENT_DATA_INVALID`; **[verified]** for NaN, -0, lone surrogate; a >256-bit bigint in a named BigInt slot becomes `INVALID_INPUT` via the LIMIT preflight, and in an identifier slot `EVENT_DATA_INVALID`).
* Aliasing: the same event object appearing twice is captured once and re-validated at the second occurrence (which then fails as `GENESIS_DUPLICATE`/`EVENT_ID_DUPLICATE` in the reducer). A `data` object shared between two events is fine structurally.

The reducer (D.6) is invoked synchronously **after each event is captured** ("visitor"). The first reducer failure **stops** the operation immediately with that failure (`STOPPED`), so an event at a later position is never inspected once an earlier one fails (**[verified]**: position 2 `TRANSITION_INVALID` is reported even though position 3 is `null`). A capture failure at position *p* can only be reported if all events before *p* reduced successfully.

The package-internal `createPortableReplayKernel()` (used when an event list is embedded in a larger authority/receipt operation) has the same reducer but **never stops capture**: it remembers the first failure and returns it from `finish()`; `visit()` after `finish()` throws.

### D.4 Replay state (draft)

```
acceptedEvents        : AcceptedCanonicalEventShape[]           // frozen captured events, in order
eventHistoryHashes    : ContentHash[]                             // prefix hash per position
historyHashState      : Keccak state (PREFIX absorbed, then event texts joined by ",")
eventPositionsById    : Map<eventId, position>
genesis               : PortableGenesisRecord | undefined         // = data of event 0
lastTimestamp         : number | undefined

principals            : Map<id, { id, creationEventId, creationEventPosition }>
agents                : Map<id, { id, principalId, controllerId, currentControlEpoch, terminated }>
reservedAgentIds      : Map<successorAgentId, Set<ruleId>>        // ids reserved by succession rules
roles                 : Map<id, { id, principalId, currentTenureId?, latestTenureNumber }>
successionRules       : Map<ruleId, { data: SuccessionRuleDeclaredData }>
tenures               : Map<tenureId, { id, roleId, agentId, principalId, tenureNumber, successionRuleId?, closed, successionLock? }>
currentTenureIdsByAgent : Map<agentId, Set<tenureId>>
runtimeSessions       : Map<sessionId, { id, agentId, controllerId, controlEpoch, credentialKeyId, credentialAddressKey (lowercased), admissionEventId, admissionEventPosition, expiresAt? }>
runtimeSessionIdsByAgent : Map<agentId, sessionId[]>
credentialKeyIds      : Set<credentialKeyId>                       // global uniqueness
credentialAddressKeysByAgent : Map<agentId, Set<lowercase address>>
intentDeclarations    : Map<intentId, { data: PortableTransactionIntent }>
intentAdmissions      : Map<intentId, { intentId, actorId, nonce, admissionEventId, admissionEventPosition, admissionHead, runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId, adapterIdentity }>
intentConsumptions    : Map<intentId, { intentId, eventId, eventPosition, head, adapterId, idempotencyKey, submissionFingerprint, transactionReference, acknowledgment, evidenceReference }>
intentOutcomeStates   : Map<intentId, { latest: OutcomeRecord, terminal?: OutcomeRecord }>
                        // OutcomeRecord = { intentId, eventId, eventPosition, head, status, attesterId, evidenceReference, noEffect? }
outcomeObservations   : Map<intentId, Observation[]>               // { intentId, sourceAdmissionEventId, acknowledgment, actorId, eventId, eventPosition, observedAt }
attemptDuties         : Map<dutyId, { record, creationEventId, creationEventPosition, creationActorId, currentAssigneeId, assignments[] }>
attemptDutyReviews    : Map<dutyId, Review[]>                      // { dutyId, actorId, observationEventIds, summaryDigest, eventId, eventPosition, reviewedAt }
attemptDutyIdsBySourceIntent : Map<intentId, dutyId>
receiptCommitments    : Map<receiptContentHash, ReceiptRecordedData & { eventId, eventPosition, head }>
obligations           : Map<obligationId, { record, status, performanceAssigneeId, creationEventId, creationEventPosition, creationHead }>
obligationIdsBySourceIntent : Map<intentId, obligationId>
nonceReservationsByActor : Map<actorId, Map<nonce, { intentId, admissionEventId, admissionEventPosition, admissionHead }>>
authorities           : Map<authorityId, { grant, grantEventId, grantEventPosition, revocationEventId?, revocationEventPosition?, revokerId? }>
recognizedRoots       : Map<rootAuthorityId, { rootAuthorityId, principalId, principalRecognitionEventId, rootGrantEventId }>
authorityUsage        : Map<authorityId, { authorityId, admittedTransactionCount, admittedCumulativeAmount (bigint) }>
```

Optional fields (`currentTenureId`, `successionRuleId`, `successionLock`, `expiresAt`, `terminal`, `noEffect`, `revocationEventId`…) are **absent** (not present-with-undefined) when unset; the engine reads them with an own-property check (`ownOptional`). The frozen `PortableReplayState` returned by the kernel exposes the same maps (each getter returns a fresh detached copy) plus `events`, `eventHistoryHashes`, `head`, `genesis`; `reservedAgentIds` is exposed as `Map<id, string[]>`. `replayPortable` itself exposes only `head` and `eventCount`.

"Active agent" = present in `agents` and `terminated === false`. "Authority endpoint exists" = id present in `principals` **or** `agents`.

### D.5 History commitment

Before applying event `e` at position `p`: clone the running Keccak state (which already contains PREFIX and the texts of events `0..p-1` joined by `,`); if `p > 0` absorb `,`; absorb `utf8(canonicalEncode(e))` (canonical text of the captured event, i.e. `{"data":…,"id":…,"timestamp":…,"type":…}`); clone again, absorb `]]`, finalize → `nextHead = { hash, position: p, canonicalTime: e.timestamp }`. Only if the transition succeeds does the running state advance and are `acceptedEvents`, `eventHistoryHashes[p]`, `eventPositionsById[e.id]`, `lastTimestamp` updated. `nextHead` is passed to the transitions that record it (admission, consumption, outcome, receipt, obligation creation).

### D.6 Per-event reducer (`reduceCapturedEvent`) — order of checks

For the captured event at position `p` (all failures carry `eventPosition = p` and `eventId = event.id`, except step 1):

1. Base envelope re-validation (`validateIncrementallyCapturedReplayBaseEvent`): identifier `id`, ProtocolString `type`, U53 `timestamp`, plain-record `data` with captured bytes ≤ 1 048 576. Failure → `INVALID_INPUT` with `eventPosition` only. (Unreachable in practice because capture already enforces the same rules.)
2. If `p === 0`:
   a. `type !== "DEPLOYMENT_INITIALIZED"` → `GENESIS_REQUIRED`.
   b. Genesis probe (C.8) fails → `INVALID_INPUT` if LIMIT-branded, else `EVENT_DATA_INVALID`.
   c. `versions.eventSchemaVersion !== "continuity-event/0.2"` → `UNSUPPORTED_EVENT_SCHEMA`.
   d. Any of `receiptSchemaVersion`, `queryEnvelopeVersion`, `authorizationProofVersion`, `runtimeAuthorizationVersion`, `administrativeAuthorizationVersion`, `signatureScheme` differing from the expected values (F.1) → `UNSUPPORTED_VERSION` (with position/id, unlike the outer `UNSUPPORTED_VERSION`).
3. Schema refinement (`refineCapturedCoreEvent`, section C): unknown `type` → `UNSUPPORTED_EVENT_TYPE` (**[verified]** also for `type: ""`); LIMIT-branded data failure → `INVALID_INPUT`; other data failure → `EVENT_DATA_INVALID`.
4. `p > 0 && type === "DEPLOYMENT_INITIALIZED"` → `GENESIS_DUPLICATE` (a second genesis is fully schema-checked first: a malformed one reports `EVENT_DATA_INVALID`, **[verified]**).
5. `id` already accepted → `EVENT_ID_DUPLICATE` (checked after schema; **[verified]**: duplicate id with invalid data → `EVENT_DATA_INVALID`; duplicate id with regressed timestamp → `EVENT_ID_DUPLICATE`).
6. `lastTimestamp !== undefined && timestamp < lastTimestamp` → `EVENT_TIME_REGRESSION`. Timestamps are **non-decreasing**; equal timestamps are allowed (**[verified]**).
7. Compute `nextHead` (D.5); `applyTransition` returns `false` → `TRANSITION_INVALID`.
8. Commit.

After all events: an empty accepted list → `GENESIS_REQUIRED` with no position (`replay([])`, **[verified]**). Otherwise `ACCEPTED` with `head = { hash: eventHistoryHashes[last], position: last, canonicalTime: events[last].timestamp }`.

### D.7 Transitions (`applyTransition`) — preconditions in check order and effects

All condition lists are evaluated in the order written; the first false condition yields `TRANSITION_INVALID`. `pos` denotes `acceptedEvents.length` (the position of the event being applied). Identifier equality is exact string equality.

**DEPLOYMENT_INITIALIZED**
* `pos === 0 && genesis === undefined`; `resolvePortableAdapterPolicy(data.adapterPolicyHash) !== undefined`.
* Effect: `genesis = data`.

**PRINCIPAL_CREATED** `{principalId}`
* `principalId` not in `principals`, not in `agents`, not in `reservedAgentIds`.
* Effect: `principals[principalId] = { id, creationEventId: event.id, creationEventPosition: pos }`.

**AGENT_CREATED** `{agentId, principalId, controllerId, initialControlEpoch}`
* `agentId` not in `agents`; `agentId` not in `principals`; `principalId` in `principals`; `initialControlEpoch === 1`.
* `controllerId` is **not** checked against anything.
* Effect: `agents[agentId] = { id, principalId, controllerId, currentControlEpoch: 1, terminated: false }`.

**ROLE_CREATED** `{roleId, principalId, exclusive}`
* `roleId` not in `roles`; `principalId` in `principals`.
* Effect: `roles[roleId] = { id, principalId, latestTenureNumber: 0 }` (no `currentTenureId`).

**SUCCESSION_RULE_DECLARED** `{ruleId, principalId, predecessorAgentId, successorAgentId, roleId, trigger, permittedEventTypes}`
* `ruleId` not in `successionRules`; `principalId` in `principals`; role exists and `role.principalId === principalId`; `predecessorAgentId` in `agents` (terminated agents allowed); `successorAgentId` **not** in `principals` (it need not exist as an agent yet).
* Effect: `successionRules[ruleId] = { data }`; `reservedAgentIds[successorAgentId] ∪= {ruleId}` (this blocks a later PRINCIPAL_CREATED with that id).

**AGENT_APPOINTED** `{agentId, roleId, roleTenureId, tenureNumber, principalId, successionRuleId?}`
* agent active; role exists; role has **no** `currentTenureId`; `role.principalId === principalId`; `roleTenureId` not in `tenures`; `tenureNumber === role.latestTenureNumber + 1`.
* If `successionRuleId` present: rule exists and `rule.predecessorAgentId === agentId && rule.roleId === roleId && rule.principalId === principalId`.
* Effect (`openTenure`): `tenures[roleTenureId] = { id, roleId, agentId, principalId, tenureNumber, successionRuleId (only if given), closed: false }`; `roles[roleId] = { ...role, currentTenureId: roleTenureId, latestTenureNumber: tenureNumber }`; `currentTenureIdsByAgent[agentId] ∪= {roleTenureId}`.

**AGENT_UNAPPOINTED** `{agentId, roleId, roleTenureId, principalId}`
* role exists; tenure exists; `role.currentTenureId === roleTenureId`; `!tenure.closed`; `tenure.agentId === agentId`; `tenure.roleId === roleId`; `role.principalId === principalId`; `tenure.principalId === principalId`; tenure has **no** `successionLock`.
* Effect (`closeTenure`): tenure `closed: true`; role rebuilt as `{ id, principalId, latestTenureNumber }` (drops `currentTenureId`); remove from `currentTenureIdsByAgent` (deleting the set when empty).

**ROLE_TRANSFERRED** `{roleId, fromAgentId, fromRoleTenureId, toAgentId, toRoleTenureId, toTenureNumber, principalId, transferKind, successionRuleId?}`
* role exists; tenure `fromRoleTenureId` exists; `role.currentTenureId === fromRoleTenureId`; `!tenure.closed`; `tenure.agentId === fromAgentId`; `tenure.roleId === roleId`; `role.principalId === principalId`; `toAgentId` active; `toRoleTenureId` not in `tenures`; `toTenureNumber === role.latestTenureNumber + 1`.
* `REASSIGNMENT`: `successionRuleId` must be absent **and** the from-tenure must have no `successionLock`.
* `SUCCESSION`: `successionRuleId` present **and** from-tenure has a `successionLock`; lock fields must equal `{ agentId: fromAgentId, principalId, successionRuleId, roleId, roleTenureId: fromRoleTenureId }`; rule exists with `predecessorAgentId === fromAgentId`, `successorAgentId === toAgentId`, `roleId`, `principalId`, and `permittedEventTypes` includes `"ROLE_TRANSFERRED"`.
* Effect: close the from-tenure; open `{ roleId, agentId: toAgentId, roleTenureId: toRoleTenureId, tenureNumber: toTenureNumber, principalId }` **without** a `successionRuleId` on the new tenure. (Note the from-agent is *not* required to be active — it is normally terminated.)

**RUNTIME_SESSION_ADMITTED** `{sessionId, agentId, controllerId, controlEpoch, credentialKeyId, credentialAddress, expiresAt?}`
* `addressKey = credentialAddress.toLowerCase()`.
* agent active; `controllerId === agent.controllerId`; `controlEpoch === agent.currentControlEpoch`; `sessionId` not in `runtimeSessions`; `credentialKeyId` not in the **global** `credentialKeyIds` set; `addressKey` not already used by **this agent**.
* For every prior session of this agent: reject if `session.controlEpoch === agent.currentControlEpoch && (session.expiresAt === undefined || event.timestamp < session.expiresAt)` — i.e. at most one unexpired session per agent per epoch; a session expires at `expiresAt` inclusive (`timestamp >= expiresAt` is expired).
* Effect: `runtimeSessions[sessionId] = { id, agentId, controllerId, controlEpoch, credentialKeyId, credentialAddressKey: addressKey, admissionEventId: event.id, admissionEventPosition: pos, expiresAt? }`; add key id, address key, session id to the indices.

**CONTROL_EPOCH_ADVANCED** `{agentId, controllerId, fromEpoch, toEpoch}`
* agent active; `controllerId === agent.controllerId`; `fromEpoch === agent.currentControlEpoch`; `toEpoch === fromEpoch + 1`; `fromEpoch + 1` safe integer.
* Effect: `agent.currentControlEpoch = toEpoch`. Existing sessions are untouched (they become "fenced" because their epoch is stale).

**TRANSACTION_INTENT_DECLARED** (data = intent)
* `intentId` not in `intentDeclarations`; `actorId` in `agents` (terminated allowed); `roleId` in `roles`; `roleTenureId` in `tenures` (closed allowed); genesis defined; `validatePortableAdapterProfileForPolicy(genesis.adapterPolicyHash, adapterProfile)` — the profile must be canonically identical to a profile that is a member of the genesis-selected policy edition (F.3/F.4).
* Effect: `intentDeclarations[intentId] = { data }`.

**AGENT_TERMINATED** `{agentId, principalId, successionRuleId, roleId, roleTenureId}`
* agent active; role, tenure, rule exist; `currentTenureIdsByAgent[agentId]` exists with **exactly one** member which is `roleTenureId`; `role.currentTenureId === roleTenureId`; `!tenure.closed`; `tenure.agentId === agentId`; `tenure.roleId === roleId`; `agent.principalId === principalId`; `role.principalId === principalId`; `rule.principalId === principalId`; `rule.predecessorAgentId === agentId`; `rule.roleId === roleId`; `rule.permittedEventTypes` includes `"AGENT_TERMINATED"`; if the tenure carries a `successionRuleId` it must equal `data.successionRuleId`.
* Effect: `agent.terminated = true`; `tenure.successionLock = { agentId, principalId, successionRuleId, roleId, roleTenureId }` (the tenure stays open and current until a SUCCESSION transfer).

**AUTHORITY_GRANTED** `{grant}`
* genesis defined; `grant.authorityId` not in `authorities`; interval valid (`notBefore < expiresAt` when both present).
* `PERMISSION`: grantor and grantee are authority endpoints (principal or agent, terminated allowed); every `requiredIntersectionIds[i]` is an existing **permission** authority (revoked ones still count); if no `parentAuthorityId`: grantor must be a **principal**; else parent must be an existing permission, `permissionChildRemainsWithinPathLimit(parent)` (the chain parent → parent.parent → … must terminate at a rootless permission within depth: child depth starts at 2 and each hop increments; a chain reaching depth > 32, or a dangling/non-permission parent, fails), `grant.grantorId === parent.granteeId`, `grant.rootAuthorityId === parent.rootAuthorityId`, and `constraintsAreAttenuated(parent.constraints, grant.constraints)` (D.8).
* `PROHIBITION`: `prohibitionConstraintsAreValid` (interval valid, `requiredIntersectionIds` empty, `maxDelegationDepth === 0`, no `maxCumulativeAmount`, no `maxTransactions`); if `subjectActorId` present it must be in `agents`; `GLOBAL`: `grantorId === genesis.globalPolicySourceId`; `ROOT`: grantor is an endpoint; `recognizedRoots[rootAuthorityId]` exists; if `grantorId === root.principalId`: no `parentAuthorityId`, root permission exists and its constraints attenuate the prohibition's; else `parentAuthorityId` required, parent permission exists with same `rootAuthorityId`, `parent.granteeId === grantorId`, attenuation holds.
* Effect: `authorities[authorityId] = { grant, grantEventId: event.id, grantEventPosition: pos }`. For PERMISSION additionally: if no parent and `authorityId === rootAuthorityId` and grantor is a principal → `recognizedRoots[rootAuthorityId] = { rootAuthorityId, principalId, principalRecognitionEventId: principal.creationEventId, rootGrantEventId: event.id }`; if constraints have `maxTransactions` or `maxCumulativeAmount` → `authorityUsage[authorityId] = { authorityId, admittedTransactionCount: 0, admittedCumulativeAmount: 0n }`.

**AUTHORITY_REVOKED** `{authorityId, revokerId}`
* record exists and has no `revocationEventId`.
* `GLOBAL` prohibition: `revokerId === genesis.globalPolicySourceId`. Any other grant: `recognizedRoots[grant.rootAuthorityId]` must exist and `revokerId === root.principalId`, or (`parentAuthorityId` present and `revokerId === grant.grantorId`).
* Effect: record gains `{ revocationEventId: event.id, revocationEventPosition: pos, revokerId }`.

**TRANSACTION_INTENT_ADMITTED** — see D.9. Additional replay-side checks after the validator returns VALID: `intentId` not already in `intentAdmissions`; `nonceReservationsByActor[actorId][nonce]` absent; every usage update's authority already has a usage record; the proof's `runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId` all present; declaration exists; genesis defined.
* Effect: `adapterIdentity = derivePortableAdapterIdentityForAcceptedAdmission(event, nextHead, declaration.adapterProfile, genesis.adapterPolicyHash)` (D.11); `intentAdmissions[intentId] = { intentId, actorId, nonce, admissionEventId: event.id, admissionEventPosition: pos, admissionHead: nextHead, runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId, adapterIdentity }`; nonce reservation `{ intentId, admissionEventId, admissionEventPosition, admissionHead }`; `authorityUsage[id] = update` for each usage update.

**TRANSACTION_INTENT_CONSUMED**
* admission exists; `intentId` not in `intentConsumptions`; no terminal outcome for the intent; `admissionBoundControlTupleIsCurrent(admission, event.timestamp)` (D.10); `adapterId === admission.adapterIdentity.adapterProfile.profileId`; `idempotencyKey === identity.idempotencyKey`; `submissionFingerprint === identity.submissionFingerprint`; `validatePortableAdapterAcknowledgment(acknowledgment, identity)` (F.5); `transactionReference === portableAdapterAcknowledgmentTransactionReference(acknowledgment, identity)` (the digest/reference inside `result`); `evidenceReference` equals (field-wise on `kind, evidenceType, reference, attesterId`) `portableAdapterAcknowledgmentEvidence(identity, acknowledgment)` = `{ kind: "EXTERNAL", evidenceType: acknowledgment.schemaVersion, reference: hashCanonical(acknowledgment), attesterId: profileId }`.
* Effect: `intentConsumptions[intentId] = { intentId, eventId, eventPosition: pos, head: nextHead, adapterId, idempotencyKey, submissionFingerprint, transactionReference, acknowledgment, evidenceReference }`.

**TRANSACTION_OUTCOME_RECORDED**
* admission exists (consumption is **not** required); if a terminal outcome exists, `status` must be `"DISPUTED"`.
* `FAILED`: `noEffect` present; `attesterId === "adapter:simulated"`; `validatePortableAdapterNoEffect(noEffect, identity)`; `evidenceReference` field-equals `portableAdapterNoEffectEvidence(identity, noEffect)` = `{ kind: "EXTERNAL", evidenceType: "continuity-adapter-no-effect/0.2", reference: hashCanonical(noEffect), attesterId: "adapter:simulated" }`.
* Other statuses: `noEffect` absent and `earlierEvidenceReferenceIsValid(evidenceReference)` (D.12).
* Effect: `record = { intentId, eventId, eventPosition: pos, head: nextHead, status, attesterId, evidenceReference, noEffect? }`; `terminal = existing.terminal ?? (status ∈ {CONFIRMED, FAILED} ? record : undefined)`; `intentOutcomeStates[intentId] = { latest: record, terminal? }`. A terminal outcome is never replaced; later `DISPUTED` records only update `latest`.

**RECEIPT_RECORDED**
* `receiptContentHash` not in `receiptCommitments`; `intentId` in `intentDeclarations`; `issuerAgentId` in `agents`; `runtimeSessionId` in `runtimeSessions`; `roleId` in `roles`; `roleTenureId` in `tenures`. No congruence between them is checked, and no signature is verified.
* Effect: `receiptCommitments[receiptContentHash] = { ...data, eventId, eventPosition: pos, head: nextHead }`.

**OBLIGATION_CREATED** `{record, actorId, administrativeAuthorization}`
* Lookups: intent = `intentDeclarations[record.sourceIntentId]`, admission, consumption (same key), receipt = `receiptCommitments[record.causalReceiptContentHash]`, role = `roles[record.durableRoleId]`, tenure = `tenures[record.creationRoleTenureId]`, rule = `successionRules[record.successionRuleId]`.
* `record.obligationId` not in `obligations` and not in `attemptDuties`; no obligation already for `sourceIntentId`; intent, admission, consumption, receipt, role, tenure, rule all exist; `intent.intentId === admission.intentId === consumption.intentId === receipt.intentId`; `admission.admissionEventPosition < consumption.eventPosition < receipt.eventPosition < pos`; `record.trigger === consumption.eventId`; `record.durableRoleId === intent.roleId === receipt.roleId`; `record.creationRoleTenureId === intent.roleTenureId === receipt.roleTenureId`; `role.currentTenureId === tenure.id`; `!tenure.closed`; `tenure.roleId === record.durableRoleId`; `record.performanceAssigneeId === intent.actorId`; `tenure.agentId === record.performanceAssigneeId`; `data.actorId === record.performanceAssigneeId`; `intent.termsCommitment === record.termsCommitment` (both must be present since `record.termsCommitment` is required); `counterpartyId` presence **and** value identical between intent and record; `rule.roleId === record.durableRoleId`; `rule.predecessorAgentId === record.performanceAssigneeId`; `rule.principalId === role.principalId`; `rule.trigger === "AGENT_TERMINATED"`; `rule.permittedEventTypes` ⊇ `{AGENT_TERMINATED, ROLE_TRANSFERRED, OBLIGATION_PERFORMANCE_ASSIGNED}`; `obligationPoliciesAreValid(record.transitionPolicies)` (D.13).
* A `TRANSACTION_INTENT_DECLARED` event for this intent must exist at a position `< admission.admissionEventPosition` (always true when the admission exists, since admission requires a prior declaration).
* Let `proof = acceptedEvents[admission.admissionEventPosition].data.authorizationProof`; require `receipt.authorizationProofHash === hashCanonical(proof)`, `receipt.issuerAgentId === proof.request.actorId`, `receipt.runtimeSessionId === proof.runtimeSessionId`, `receipt.controlEpoch === proof.controlEpoch`, `receipt.roleId === proof.roleId`, `receipt.roleTenureId === proof.roleTenureId`.
* Administrative transition (D.9) with requirements `{ request: { actorId: data.actorId, action: "OBLIGATE", resource: intent.resource, claimedAt: event.timestamp, termsCommitment: record.termsCommitment, counterpartyId? (from record) }, requiredPrincipalId: role.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: tenure.id }`.
* Effect: `obligations[obligationId] = { record, status: record.status, performanceAssigneeId: record.performanceAssigneeId, creationEventId, creationEventPosition: pos, creationHead: nextHead }`; `obligationIdsBySourceIntent[sourceIntentId] = obligationId`.

**OBLIGATION_PERFORMANCE_ASSIGNED** `{obligationId, fromAgentId, toAgentId, successionRuleId, actorId, administrativeAuthorization}`
* obligation exists and is unresolved (`status ∉ {DISCHARGED, IMPOSSIBLE_OR_ESCALATED}`); `fromAgentId === obligation.performanceAssigneeId`; `successionRuleId === obligation.record.successionRuleId`; role = `roles[record.durableRoleId]` exists; rule exists; role has a current tenure which exists and is open; `tenure.agentId === toAgentId`; `tenure.roleId === record.durableRoleId`; `rule.roleId === record.durableRoleId`; `rule.principalId === role.principalId`; `rule.predecessorAgentId === fromAgentId`; `rule.successorAgentId === toAgentId`; `rule.trigger === "AGENT_TERMINATED"`; `rule.permittedEventTypes` includes `"OBLIGATION_PERFORMANCE_ASSIGNED"`.
* Scan all accepted events: the **last** `AGENT_TERMINATED` matching `{agentId: fromAgentId, principalId: rule.principalId, successionRuleId, roleId: durableRoleId, roleTenureId: record.creationRoleTenureId}` and the **last** `ROLE_TRANSFERRED` with `transferKind === "SUCCESSION"`, same `successionRuleId`, `principalId`, `roleId`, `fromAgentId`, `fromRoleTenureId === creationRoleTenureId`, `toAgentId`, `toRoleTenureId === tenure.id`; both must exist and `terminationPosition < transferPosition`.
* Administrative transition with `{ request: { actorId, action: "ASSIGN_PERFORMANCE", resource: obligationId, claimedAt: timestamp }, requiredPrincipalId: rule.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: tenure.id }`.
* Effect: `obligation.performanceAssigneeId = toAgentId`.

**OBLIGATION_STATUS_RECORDED** `{obligationId, fromStatus, toStatus, actorId, action, administrativeAuthorization, attesterId, evidenceReference}`
* obligation exists, unresolved, `fromStatus === obligation.status`; a policy with matching `(fromStatus, toStatus, action)` exists (first match in list order); `attesterId ∈ policy.acceptedAttesterIds`; `obligationEvidenceAttributesAttester` (D.12); role = `roles[record.durableRoleId]` exists with a `currentTenureId`.
* Administrative transition with `{ request: { actorId, action: data.action, resource: obligationId, claimedAt: timestamp }, requiredPrincipalId: role.principalId, requiredAuthorityIds: policy.requiredAuthorityIds, roleId: role.id, roleTenureId: role.currentTenureId }`.
* Effect: `obligation.status = toStatus`.

**OUTCOME_OBSERVATION_RECORDED / ATTEMPT_DUTY_CREATED / ATTEMPT_DUTY_ASSIGNED / ATTEMPT_DUTY_REVIEW_CLOSED** (E5/E6 extensions)
* `attemptSource(intentId)`: genesis policy hash must be E5 or E6; intent declaration and admission exist; `admission.adapterIdentity.adapterProfile.profileId === "adapter:remote-service-report"`; role = `roles[intent.roleId]` has a current tenure that exists, is open, and whose agent is active → `{intent, admission, role, tenure}`; otherwise undefined (→ fail).
* `authorizeAttemptRecord(actorId, source, action)`: `actorId === source.tenure.agentId` and administrative transition with `{ request: { actorId, action, resource: intent.intentId, claimedAt: timestamp, termsCommitment? (from intent) }, requiredPrincipalId: role.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: tenure.id }`.
* OUTCOME_OBSERVATION_RECORDED: source defined; `admission.admissionEventId === sourceAdmissionEventId`; `validatePortableAdapterAcknowledgment(acknowledgment, identity)`; `acknowledgment.result.kind === "REMOTE_SERVICE_REPORTED"`; authorize with action `"OBSERVE_OUTCOME"`. Effect: append `{ intentId, sourceAdmissionEventId, acknowledgment, actorId, eventId, eventPosition, observedAt: timestamp }` to `outcomeObservations[intentId]`. (Any number of observations; does not consume the intent.)
* ATTEMPT_DUTY_CREATED: source for `record.sourceIntentId`; `record.sourceAdmissionEventId === admission.admissionEventId`; `record.durableRoleId === role.id`; `record.creationRoleTenureId === tenure.id`; `record.performanceAssigneeId === tenure.agentId`; `record.status === "OPEN"`; `dutyId` not in `attemptDuties` nor `obligations`; no duty yet for the source intent; authorize `"CREATE_ATTEMPT_DUTY"`. Effect: `attemptDuties[dutyId] = { record, creationEventId, creationEventPosition, creationActorId: actorId, currentAssigneeId: record.performanceAssigneeId, assignments: [] }`; index by source intent.
* ATTEMPT_DUTY_ASSIGNED: duty exists; source defined; `fromAgentId === duty.currentAssigneeId`; `toAgentId !== fromAgentId`; `toAgentId === source.tenure.agentId`; authorize `"ASSIGN_ATTEMPT_DUTY"`. Effect: push `{ fromAgentId, toAgentId, actorId, eventId, eventPosition, assignedAt }`, `currentAssigneeId = toAgentId`.
* ATTEMPT_DUTY_REVIEW_CLOSED: genesis policy **E6 only**; duty exists; `duty.currentAssigneeId === actorId`; source defined; `observations.length === observationEventIds.length`; if non-empty, `observationEventIds` strictly sorted (`compareProtocolStrings`); authorize `"CLOSE_ATTEMPT_DUTY"`; every recorded observation's `eventId` appears in `observationEventIds`. Effect: push `{ dutyId, actorId, observationEventIds, summaryDigest, eventId, eventPosition, reviewedAt }` to `attemptDutyReviews[dutyId]`. (The duty is not closed/removed; reviews can repeat.)

### D.8 Constraint attenuation (`constraintsAreAttenuated(parent, child)`)

All must hold: child interval valid; `child.actions ⊆ parent.actions`; `child.resources ⊆ parent.resources`; `parent.requiredIntersectionIds ⊆ child.requiredIntersectionIds` (inherited intersections must be kept); `parent.maxDelegationDepth !== 0`; `child.maxDelegationDepth <= parent.maxDelegationDepth - 1`; not (`parent.quantitative && !child.quantitative`); if `parent.notBefore` present → child has `notBefore >= parent.notBefore`; if `parent.expiresAt` present → child has `expiresAt <= parent.expiresAt`; if `parent.maxAmount` present → child has `maxAmount <= parent.maxAmount`; if `parent.maxCumulativeAmount` present → child has `maxCumulativeAmount <= parent's`; if `parent.maxTransactions` present → child has `maxTransactions <= parent's`. Subset tests use `Array.prototype.includes` (exact strings, order irrelevant).

### D.9 Signed transitions

**Runtime authorization challenge** (`createPortableRuntimeAuthorizationChallenge`, portable-authority-engine.ts):

```
{ version: "continuity-runtime-authorization/0.2",
  domain: { protocol, version, deploymentId, chainId, verifyingContract },   // copied field-wise
  request: { actorId, action, resource, claimedAt, amount?, counterpartyId?, termsCommitment? },  // optional keys only when present
  authoritative: true, consequential: true,
  evaluationTime, policyVersion, rootRecognitionPolicy: "declared-principal-root/0.2",
  eventHistoryHash: historyHead.hash, eventHistoryPosition: historyHead.position,
  runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId, intentId, nonce }
```
`credentialKeyId`, `intentId`, `nonce` are mandatory (else TypeError). Its hash is `hashCanonical(challenge)` (keys sorted per A.1 when encoded).

**Signature scheme** `eip191-personal-sign-keccak256` (`portableEip191Digest`, `recoverPortableContentHashSigner`): digest = `keccak256( "\x19Ethereum Signed Message:\n32" ‖ bytes32(messageHash) )` (prefix bytes `19 45 74 68 65 72 65 75 6d 20 53 69 67 6e 65 64 20 4d 65 73 73 61 67 65 3a 0a 33 32`, 28 bytes, then the 32 raw bytes of the 0x-hex hash). Signature = `0x ‖ r(32) ‖ s(32) ‖ v(1)` lowercase hex with `v ∈ {0x1b, 0x1c}` (recovery id 0/1) and low-s. Recovery is a self-contained secp256k1 implementation: `R = (r, y)` with `y = sqrt(r³+7)` chosen so that `y` odd ⇔ `v == 0x1c`; if `r³+7` is a non-residue → undefined; `Q = r⁻¹·(s·R − e·G)` with `e = digest mod n`; the address is `"0x" + last 20 bytes of keccak256(x‖y)` in **lowercase**. Any exception → undefined. The recovered address is compared to `session.credentialAddressKey` (the lowercased `credentialAddress` of the admitted session); `r` is not range-checked beyond the curve test **[unverified]**.

**TRANSACTION_INTENT_ADMITTED** (`validatePortableIntentAdmissionTransition(state, event)`; `state.head` is the head *before* this event):

1. `event.timestamp === data.evaluationTime === proof.evaluationTime`; `data.intentId === proof.intentId`; `data.expectedHistoryHead` and `proof.historyHead` both equal `state.head` (hash, position, canonicalTime); `proof.consequential === true`; `proof.rootRecognitionPolicy === "declared-principal-root/0.2"`.
2. `data.runtimeSignature` is a Signature65.
3. Build the challenge from `proof.domain`, `proof.request`, `proof.evaluationTime`, `proof.policyVersion`, `state.head`, and binding `{ runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId, intentId, nonce }` from the proof; `data.runtimeAuthorizationHash === hashCanonical(challenge)`.
4. `agents[proof.request.actorId]` exists (terminated allowed here); session `runtimeSessions[proof.runtimeSessionId]` exists with `session.agentId === actor.id` and `session.credentialKeyId === proof.credentialKeyId`; signature recovers to `session.credentialAddressKey`.
5. `authorizePortableState(state, { expectedHistoryHead: state.head, domain: proof.domain, policyVersion: proof.policyVersion, rootRecognitionPolicy: proof.rootRecognitionPolicy, request: proof.request, evaluationTime: proof.evaluationTime, consequential: true, binding })` must return `decision === "ALLOW"` and `canonicalEncode(authorization.proof) === canonicalEncode(proof)` — the supplied proof must be byte-for-byte the proof the engine itself derives. The staging performed inside (`stagePortableStateAuthorization`) checks, in order: head equality; `evaluationTime` U53 and `>= state.head.canonicalTime`; domain equals `genesis.domain` (verifyingContract compared case-insensitively); `policyVersion === genesis.policyVersion` and `rootRecognitionPolicy === genesis.rootRecognitionPolicy`; request well-formed; authority corpus valid; actor active; session found and owned by the actor; not expired (`evaluationTime < session.expiresAt`); `credentialKeyId` and signature present and matching; the signature over the challenge verifies; `session.controlEpoch >= agent.currentControlEpoch` (else SESSION_FENCED); `binding.controlEpoch === session.controlEpoch === agent.currentControlEpoch`; role/tenure: `role.currentTenureId === binding.roleTenureId`, tenure open, `tenure.roleId === binding.roleId`, `tenure.agentId === agent.id`; intent declared; the intent projection `{ adapterProfile, intentId, nonce, actorId, action, resource, roleId, roleTenureId, amount?, counterpartyId?, termsCommitment? }` built from request+binding equals the declaration field-wise (optional fields must agree in presence and value); intent not already admitted; then the authority algebra (`evaluateAuthorityAlgebra`, `proofForCandidate`, `finalizeSuccessfulAuthorityCandidate` — the delegation/prohibition/intersection engine, specified separately) produces the canonical winning proof; finally `occupiedCandidateNonceDenial`: the nonce must not already be reserved for the actor.
6. Declaration exists; `sameIntent(declaration, projection)`; intent not admitted.
7. Usage: for each `proof.controllingAuthorityIds[i]` the authority must exist and be a PERMISSION; if it has neither `maxTransactions` nor `maxCumulativeAmount` skip; else a usage record must exist; if `maxCumulativeAmount` is present the request must carry `amount`; `count' = count + (maxTransactions ? 1 : 0)`, `cum' = cum + (maxCumulativeAmount ? amount : 0n)`; require `count'` safe, `count' <= maxTransactions` (when present), `cum' <= maxCumulativeAmount` (when present), `cum' <= 2^256-1`. Collect `{ authorityId, admittedTransactionCount: count', admittedCumulativeAmount: cum' }`.
8. Return `{ status: "VALID", intentId, actorId: proof.request.actorId, nonce, usage }`.

**Administrative transitions** (`validatePortableAdministrativeTransition(state, event, requirements)`), for the seven administrative types:

1. Type gating: `OUTCOME_OBSERVATION_RECORDED`, `ATTEMPT_DUTY_CREATED`, `ATTEMPT_DUTY_ASSIGNED` require genesis policy E5 or E6; `ATTEMPT_DUTY_REVIEW_CLOSED` requires E6.
2. Let `wrapper = data.administrativeAuthorization`, `challenge = wrapper.challenge`, `proof = wrapper.authorityProof`. Require: `canonicalEncode(challenge.domain) === canonicalEncode(genesis.domain)`; same for `proof.domain`; `canonicalEncode(challenge.request) === canonicalEncode(requirements.request)` (so optional keys must match exactly; e.g. for OBLIGATE the request includes `termsCommitment` and `counterpartyId` iff the record has one); `challenge.request.actorId === data.actorId`; `challenge.policyVersion === genesis.policyVersion`; `challenge.rootRecognitionPolicy === genesis.rootRecognitionPolicy`; `challenge.eventHistoryHash === state.head.hash`; `challenge.eventHistoryPosition === state.head.position` (head **before** this event); `challenge.evaluationTime === event.timestamp`; `challenge.transitionEventId === event.id`; `challenge.transitionEventType === event.type`; `challenge.transitionEffectHash === hashCanonical(portableAdministrativeTransitionEffect(event))`; `challenge.authorityProofHash === hashCanonical(proof)`; `challenge.roleId === requirements.roleId`; `challenge.roleTenureId === requirements.roleTenureId`.
3. Control tuple: actor = `agents[requirements.request.actorId]` active; session `runtimeSessions[challenge.runtimeSessionId]` with `agentId === actor.id`; not expired at `event.timestamp` (`timestamp >= expiresAt` fails); `session.credentialKeyId === challenge.credentialKeyId`; `session.controlEpoch === challenge.controlEpoch === actor.currentControlEpoch`; `roles[requirements.roleId].currentTenureId === requirements.roleTenureId`; tenure exists, open, `roleId` matches, `agentId === actor.id`.
4. `recoverPortableContentHashSigner(hashCanonical(challenge), wrapper.runtimeSignature) === session.credentialAddressKey`.
5. `expected = createPortableAdministrativePolicyProof(state, requirements, event.timestamp)` must be defined and `canonicalEncode(expected) === canonicalEncode(proof)`. The expected proof is a **non-consequential** authorization of `requirements.request` against the current head/genesis domain/policy, which must be `ALLOW` with a recognised root whose `principalId === requirements.requiredPrincipalId`, every `requiredAuthorityIds` member among the controlling grants of the selected candidate graph, no quantitative/capped grant anywhere on the winning paths (`quantitative`, `maxAmount`, `maxCumulativeAmount`, `maxTransactions` all absent/false), an empty `usageSnapshot`, and no `amount` in the request.

**Transition effect projections** (`portableAdministrativeTransitionEffect`, portable-administration-codec.ts) — the hashed object contains `transitionEventType: event.type` plus: OUTCOME_OBSERVATION_RECORDED `{intentId, sourceAdmissionEventId, acknowledgment, actorId}`; ATTEMPT_DUTY_CREATED `{record, actorId}`; ATTEMPT_DUTY_REVIEW_CLOSED `{dutyId, actorId, observationEventIds, summaryDigest}`; ATTEMPT_DUTY_ASSIGNED `{dutyId, fromAgentId, toAgentId, actorId}`; OBLIGATION_CREATED `{record, actorId}`; OBLIGATION_PERFORMANCE_ASSIGNED `{obligationId, fromAgentId, toAgentId, successionRuleId, actorId}`; OBLIGATION_STATUS_RECORDED `{obligationId, fromStatus, toStatus, actorId, action, attesterId, evidenceReference}`. (The `administrativeAuthorization` wrapper itself is never part of the effect.)

**RUNTIME_SESSION_ADMITTED** carries no signature; it merely *registers* `credentialAddress` (stored lowercased) and `credentialKeyId`. **RECEIPT_RECORDED** carries hashes only; replay verifies nothing cryptographic about it (receipt artifact verification lives in `portable-receipts.ts`, out of scope).

### D.10 Admission control currency (`admissionControlRecordsMatch(admission, useTime, agent, session, role, tenure)`)

All of: agent exists and not terminated; session exists; `session.agentId === admission.actorId`; `session.credentialKeyId === admission.credentialKeyId`; `session.expiresAt` absent or `useTime < expiresAt`; `session.controlEpoch === admission.controlEpoch`; `agent.currentControlEpoch === admission.controlEpoch`; role and tenure exist; `role.currentTenureId === admission.roleTenureId`; `!tenure.closed`; `tenure.roleId === admission.roleId`; `tenure.agentId === admission.actorId`. Exported as `portableAdmissionControlIsCurrent(state, intentId, useTime)`.

### D.11 Adapter identity for an accepted admission (`derivePortableAdapterIdentityForAcceptedAdmission`)

Requires `event.type === "TRANSACTION_INTENT_ADMITTED"`, `admissionHead.canonicalTime === event.timestamp`, and the declared profile valid for the genesis policy. With `domain = event.data.authorizationProof.domain`, `intentId = event.data.intentId`:

* `idempotencyKey = hashCanonical(["continuity-adapter-idempotency/0.2", domain.protocol, domain.version, domain.deploymentId, domain.chainId, domain.verifyingContract.toLowerCase(), intentId])`
* `submissionFingerprint = hashCanonical({ version: "continuity-adapter-submission/0.2", intentId, admissionEvent: <the whole captured admission event>, durableEventHistoryHash: admissionHead.hash })`
* `adapterNoEffectReference = hashCanonical(["continuity-adapter-no-effect/0.2", "adapter:simulated", idempotencyKey, submissionFingerprint])`
* identity `= { idempotencyKey, submissionFingerprint, durableEventHistoryHash: admissionHead.hash, adapterNoEffectReference, adapterProfile: <policy's canonical profile object for profileId>, domain, intentId, admissionHead }` where `admissionHead` is the head **including** the admission event.

### D.12 Evidence references against earlier state

`earlierEvidenceReferenceIsValid(evidence)`: `EVENT` → an accepted event with that id exists at `evidence.position`, `evidence.eventType === event.type`, `evidence.historyHash === eventHistoryHashes[position]`; `AUTHORITY` → authority exists and `grantEventId` matches; `RUNTIME_CREDENTIAL` → session exists with matching `credentialKeyId` (`keyId`) and `admissionEventId`; `RECEIPT_COMMITMENT` → receipt commitment for `receiptContentHash` exists with matching `eventId` and `position`; `EXTERNAL` → always valid.

`obligationEvidenceAttributesAttester(evidence, attesterId)`: `EXTERNAL` → `evidence.attesterId === attesterId`; otherwise must be `EVENT` and valid as above, and the referenced event's `data.attesterId === attesterId`, or its `data.evidenceReference` is `EXTERNAL` with `attesterId === attesterId`.

### D.13 Obligation policy validity (`obligationPoliciesAreValid`)

Non-empty list; for each policy: `fromStatus ∉ {DISCHARGED, IMPOSSIBLE_OR_ESCALATED}`; `acceptedAttesterIds` and `requiredAuthorityIds` are non-empty and strictly increasing under `compareProtocolStrings`; every `requiredAuthorityIds[i]` exists in `authorities` (permission or prohibition, revoked or not); the list is strictly ordered by `(rank(fromStatus), rank(toStatus))` with ranks `OPEN=0, OUTCOME_UNKNOWN=1, DISPUTED=2, DISCHARGED=3, IMPOSSIBLE_OR_ESCALATED=4` (a later policy must have a greater `from` rank, or equal `from` and greater `to`).

---

## E. Portable file store — `continuity-portable-file-store/0.2`

Source: `packages/core-0.2/src/indexer/portable-file-event-store.ts` (exported from the package as `./store`). Node-only, synchronous `fs` API.

### E.1 File format

A UTF-8 text file (decoded with `TextDecoder("utf-8", { fatal: true })` — invalid UTF-8 throws the decoder's `TypeError`) consisting of zero or more **lines**, each terminated by `\n`. Each line is a JSON object (serialised by `JSON.stringify`, so no whitespace) with exactly the keys, in this written order:

```
{"version":"continuity-portable-file-store/0.2","previousHash":<null | ContentHash>,"event":<tagged>,"recordHash":<ContentHash>}
```

* `version` — always `"continuity-portable-file-store/0.2"` (`FORMAT`).
* `previousHash` — `null` for the first record, otherwise the `recordHash` of the previous line.
* `event` — the accepted event in the **tagged-tuple storage encoding** (E.2).
* `recordHash` — `hashCanonical({ version: FORMAT, previousHash, event })` where `event` is the **decoded** event value (a plain JS value, not the tagged form) and the object is canonically encoded per section A (keys sorted: `{"event":…,"previousHash":…,"version":…}`; `previousHash: null` encodes as `null`). **[verified]** against the fixture: line 1 has `previousHash: null`, event = the genesis event, `recordHash = 0x4d81d24f7dff9f4aee041d08c5d7fdb3d07f03e30a0c0607a172f14a13b454ce`; recomputing `hashCanonical({version, previousHash, event})` for each line reproduces every `recordHash`.

Example first two lines of `tests/fixtures/handover-history.jsonl` (elided):

```
{"version":"continuity-portable-file-store/0.2","previousHash":null,"event":["object",[["data",["object",[["adapterPolicyHash",["string","0x00c3498e…"]],…]]],["id",["string","first-look:genesis"]],["timestamp",["number",0]],["type",["string","DEPLOYMENT_INITIALIZED"]]]],"recordHash":"0x4d81d24f…"}
{"version":"continuity-portable-file-store/0.2","previousHash":"0x4d81d24f…","event":["object",[["data",["object",[["principalId",["string","principal:first-look"]]]]],["id",["string","first-look:principal"]],["timestamp",["number",1]],["type",["string","PRINCIPAL_CREATED"]]]],"recordHash":"0x88206b5f…"}
```

### E.2 Tagged storage encoding (`encode` / `decode`)

`encode(v)` (writer side; every node is a tagged array):

| JS value | encoded |
|---|---|
| `null` | `["null"]` |
| bigint `b` | `["bigint", b.toString()]` (decimal, `-` allowed on write) |
| array | `["array", [encode(x) …]]` |
| other object | `["object", [[key, encode(value)] …]]` in **`Object.entries` order** |
| string / boolean / number | `["string", s]` / `["boolean", b]` / `["number", n]` |
| anything else (undefined, function, symbol) | throws `Error("Unsupported stored value.")` |

`decode(v, depth=0)` (reader side, strict):

* `depth > 128` or `v` not an array → `Error("Invalid stored encoding.")`.
* `["null"]` (length exactly 1) → `null`. Every other node must have length exactly 2.
* `["bigint", s]` → `BigInt(s)` only if `s` is a string matching `/^(0|[1-9][0-9]*)$/` with `length <= 78` (**non-negative only**; 78 digits allows up to 2^256−1).
* `["string", s]` with string `s`; `["boolean", b]` with boolean `b`.
* `["number", n]` only if `Number.isSafeInteger(n) && n >= 0` (**non-negative only**; `-0` passes and later makes `hashCanonical` throw).
* `["array", list]` → decoded elements; `["object", entries]` → a **null-prototype** object; each entry must be a 2-element array with a string key not already present (`Error("Invalid stored object.")`); values are defined as enumerable, non-writable data properties.
* Anything else → `Error("Invalid stored encoding.")`.

Because the writer always encodes a value that came out of `immutableProtocolValue` (null-prototype object with keys inserted in `compareProtocolStrings` order), the stored object key order is canonical sort order **except** that JavaScript enumerates integer-like keys (`"0"`, `"42"`, …) first in ascending numeric order regardless of insertion order. (No valid 0.2 event contains integer-like keys, so in practice the stored order is exactly canonical byte order, as in the fixture: `data, id, timestamp, type`.)

### E.3 Construction and path rules

`new PortableFileEventStore(path)`:

1. `absolute = resolve(path)`; if it does not exist but is a dangling symlink → `Error("Dangling store symlinks are unsupported.")`.
2. `this.path = existsSync(absolute) ? realpathSync(absolute) : resolve(realpathSync(dirname(absolute)), basename(absolute))` — the **parent directory must exist** (otherwise `realpathSync` throws `ENOENT`, **[verified]**); a symlink to the file resolves to the real path (**[verified]**).
3. `#checkPath()`: re-checks dangling symlink; if the file exists it must be a regular file with `nlink === 1` whose realpath equals `this.path` → else `Error("Portable store requires a regular, non-aliased file.")` (**[verified]**: a hard link makes `readAll` throw).

`#checkPath()` runs at construction, at the start of every `readAll()`, and at the start of `withExclusiveWriter()`.

### E.4 `readAll(): readonly PortableCanonicalEvent[]`

1. `#checkPath()`; missing file → frozen `[]`.
2. Open read-only; `size > 64 MiB` (`MAX_FILE_BYTES = 67 108 864`) → `Error("Portable store file limit exceeded.")`; read the whole file with a `readSync` loop (a zero-byte read before completion → `Error("Portable store truncated during read.")`); decode as strict UTF-8.
3. Empty content → frozen `[]`. Content not ending in `\n` → `Error("Portable store has an incomplete record.")`.
4. Split `contents.slice(0,-1)` on `\n`; for each line, in order, with `previousHash` starting at `null`:
   * `JSON.parse(line)` (an empty line throws the raw `SyntaxError`; a `\r` before `\n` is tolerated because `JSON.parse` ignores trailing whitespace, **[verified]**).
   * The record must be a non-null object whose sorted key list joined by `,` is exactly `event,previousHash,recordHash,version`, with `version === FORMAT` and `previousHash === previousHash` (strict `===`, so `null` vs `null` on the first line) → else `Error("Portable store format or hash chain mismatch.")` (this is also the error for a non-object line such as `5` or `[]`).
   * `event = decode(record.event)`; then `JSON.stringify(encode(event)) === JSON.stringify(record.event)` → else `Error("Noncanonical store encoding.")`. Note this round-trip preserves the stored key order, so a stored object with keys in non-canonical order is **not** detected here (**[verified]**: swapping the `data`/`id` entries still reads back); what it does catch is an object whose integer-like keys are not first in numeric order. `["number", -0]` is *not* caught here (both stringify as `0`) but then fails inside `hashCanonical` with `TypeError("Canonical number at $.event.<path> must be a signed safe integer other than negative zero.")` (**[verified]**).
   * `hash = hashCanonical({ version: FORMAT, previousHash, event })`; `record.recordHash !== hash` → `Error("Portable store integrity check failed.")` (**[verified]** by editing a stored timestamp). Any canonical-capture failure inside `hashCanonical` (e.g. `-0`, an over-long string) propagates as its own `TypeError`.
   * push `event`; `previousHash = hash`.
5. `replayPortable({ operationVersion, events })` must be `ACCEPTED` → else `Error("Portable store history rejected: <code>.")`.
6. Return `immutableProtocolValue(events)` (deep-frozen snapshot).

Removal of a complete valid **suffix** of records is undetectable (the remaining prefix still replays; **[verified]**).

### E.5 Appending

`#append(event, events)` (private; `events` is the current list as read):

1. `captured = immutableProtocolInput(event)` — retains present-but-undefined keys so replay's closed-schema check can reject undeclared ones (**[verified]**: `{...data, zzz: undefined}` → `Portable store history rejected: EVENT_DATA_INVALID.`).
2. `head = replay([...events, captured])` — throws `Error("Portable store history rejected: <code>.")` unless `ACCEPTED`.
3. `stable = immutableProtocolValue(captured)` — drops undefined-valued **declared optional** fields before storage (**[verified]**: an `AGENT_APPOINTED` with `successionRuleId: undefined` is stored without that key).
4. Recompute the chain: `previousHash = null; for item of events: previousHash = chainHash(previousHash, item)`.
5. Line = `JSON.stringify({ version: FORMAT, previousHash, event: encode(stable), recordHash: chainHash(previousHash, stable) }) + "\n"`.
6. Open in append mode (`"a"`, creates the file); if `currentSize + lineBytes > 64 MiB` → `Error("Portable store file limit exceeded.")`; `writeSync` loop (`count <= 0` → `Error("Portable store made no write progress.")`); `fsyncSync(fd)`; open the parent directory read-only and `fsyncSync` it; close both.
7. Return `head` (the head **after** the append).

`append(event): void` — `withExclusiveWriter(w => #append(event, w.readAll()))`; return value discarded.

`appendAll(events): void` — `stable = immutableProtocolInput(events)` (whole batch captured up front); under the writer: read; if the batch is non-empty, `replay([...existing, ...stable])` must be ACCEPTED (validates the *whole* batch before writing anything; **[verified]**: `[e, e]` → `EVENT_ID_DUPLICATE` and nothing written); then `#append` each event in turn, extending the in-memory list (each `#append` replays again). An I/O failure mid-batch can leave a valid prefix written.

`appendAtExpectedHead(event, expected): PortableHistoryHead` — compare-and-set: under the writer: `stableExpected = immutableProtocolValue(expected)` (any capture error propagates); `events = readAll()`; `observed = events.length ? replay(events).head : undefined`; if `observed === undefined` (empty store — **always a conflict**, **[verified]**) or `stableExpected.hash !== observed.hash || .position !== .position || .canonicalTime !== .canonicalTime` → throw `PortableStoreConflictError(observed)`; else `#append(event, events)` and return the new head. Extra keys in `expected` are ignored; missing keys simply mismatch.

### E.6 Locking — `withExclusiveWriter(callback)`

1. `#checkPath()`.
2. Lock file `${this.path}.writer-lock` opened with flags `"wx"` (exclusive create). `EEXIST` → `PortableStoreBusyError`; other errors propagate. There is **no stale-lock recovery**: a crashed writer leaves the lock and every later writer gets `PortableStoreBusyError`.
3. A frozen `PortableStoreWriter` `{ readAll, appendAtExpectedHead }` is passed to `callback`. Both methods first run `check()`: if a writer operation is already in progress → `Error("Portable writer operation is not reentrant.")` (only `appendAtExpectedHead` sets the in-progress flag; `readAll` does not, so calling `w.readAll()` inside `appendAtExpectedHead`'s replay is impossible anyway); if the writer has expired → `Error("Portable store writer capability expired.")` (**[verified]**: using the writer object after the callback returns throws).
4. `finally`: `active = false`; close the lock fd; **unlink the lock file** (**[verified]**: lock absent after return). The callback's return value is returned; exceptions propagate after cleanup.
5. Nested `store.append(...)` inside the callback on the *same* store throws `PortableStoreBusyError` (**[verified]**).

### E.7 Error classes

| class / error | when |
|---|---|
| `PortableStoreConflictError` (`name: "PortableStoreConflictError"`, message `"Portable store head changed before conditional append."`, own `observedHead` property = `immutableProtocolValue(observedHead)` only when a head was observed) | `appendAtExpectedHead` on an empty store or when the observed head differs |
| `PortableStoreBusyError` (`name: "PortableStoreBusyError"`, message `"Portable store already has an active cooperative writer."`) | lock file already exists |
| `Error("Dangling store symlinks are unsupported.")` | constructor / checkPath |
| `Error("Portable store requires a regular, non-aliased file.")` | not a regular file, `nlink !== 1`, or realpath differs |
| `Error("Portable store file limit exceeded.")` | file > 64 MiB on read, or append would exceed 64 MiB |
| `Error("Portable store truncated during read.")` | short read |
| `TypeError` from `TextDecoder` | invalid UTF-8 |
| `Error("Portable store has an incomplete record.")` | non-empty content without trailing `\n` |
| `SyntaxError` from `JSON.parse` | unparsable line (including an empty line from `\n\n`) |
| `Error("Portable store format or hash chain mismatch.")` | wrong key set / version / previousHash, or non-object line |
| `Error("Invalid stored encoding.")`, `Error("Invalid stored object.")` | decode failures (E.2) |
| `Error("Noncanonical store encoding.")` | encode(decode(x)) ≠ x |
| `Error("Portable store integrity check failed.")` | recordHash mismatch |
| `Error("Portable store history rejected: <PortableReplayCode>.")` | replay not ACCEPTED (on read or before any write) |
| `Error("Unsupported stored value.")` | encode of undefined/function/symbol (unreachable after replay acceptance) |
| `Error("Portable writer operation is not reentrant.")`, `Error("Portable store writer capability expired.")` | writer misuse |
| `Error("Portable store made no write progress.")` | `writeSync` returned 0 |

---

## F. Exported constant strings

### F.1 Operation / schema versions

| name (file) | value |
|---|---|
| `PORTABLE_REPLAY_VERSION` (portable-replay.ts, index) / `REPLAY_OPERATION_VERSION` (canonical.ts) | `continuity-replay/0.2` |
| canonical form name (doc string) | `continuity-canonical/0.2` |
| event-history wrapper tag | `continuity-event-history/0.2` |
| `EVENT_SCHEMA_VERSION` | `continuity-event/0.2` |
| `RECEIPT_SCHEMA_VERSION` | `continuity-receipt/0.2` |
| `QUERY_ENVELOPE_VERSION` / `PORTABLE_QUERY_VERSION` | `continuity-query-envelope/0.2` |
| `AUTHORIZATION_PROOF_VERSION` / `PORTABLE_AUTHORIZATION_PROOF_VERSION` | `continuity-authorization-proof/0.2` |
| `RUNTIME_AUTHORIZATION_VERSION` / `PORTABLE_RUNTIME_AUTHORIZATION_VERSION` | `continuity-runtime-authorization/0.2` |
| `ADMINISTRATIVE_AUTHORIZATION_VERSION` | `continuity-administrative-authorization/0.2` |
| `SIGNATURE_SCHEME` (versions.signatureScheme) | `eip191-personal-sign-keccak256` |
| `PORTABLE_ROOT_RECOGNITION_POLICY` (rootRecognitionPolicy) | `declared-principal-root/0.2` |
| `PORTABLE_AUTHORITY_EVALUATION_VERSION` | `continuity-authority-evaluation/0.2` |
| `PORTABLE_AUTHORIZATION_VERSION` | `continuity-authorization/0.2` |
| `PORTABLE_INTENT_ADMISSION_VERSION` | `continuity-intent-admission/0.2` |
| receipt capture versions (canonical.ts) | `continuity-receipt-verification/0.2`, `continuity-receipt-record-admission/0.2` |
| store `FORMAT` | `continuity-portable-file-store/0.2` |
| genesis literals | `timeSource: "EVENT_TIMESTAMP"`, `finality: "LOCAL_ONLY"`, domain `protocol: "continuity"`, `version: "0.2"` |
| bigint marker key / reserved prefix | `$continuity.bigint` / `$continuity.` |

### F.2 Adapter identifiers and versions (portable-adapter-engine.ts)

| name | value |
|---|---|
| `PORTABLE_ADAPTER_IDEMPOTENCY_VERSION` | `continuity-adapter-idempotency/0.2` |
| `PORTABLE_ADAPTER_SUBMISSION_VERSION` | `continuity-adapter-submission/0.2` |
| `PORTABLE_ADAPTER_NO_EFFECT_VERSION` | `continuity-adapter-no-effect/0.2` |
| `PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION` | `continuity-adapter-acknowledgment/0.2` |
| `SIMULATED_ADAPTER_ID` | `adapter:simulated` |
| `LOCAL_EVIDENCE_PACKET_ADAPTER_ID` | `adapter:local-evidence-packet` |
| `LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID` | `adapter:local-synthetic-endpoint-state` |
| `LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION` | `continuity-local-endpoint-state-ack/1` |
| `LOCAL_DOCUMENT_RELEASE_ADAPTER_ID` | `adapter:local-document-release` |
| `LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION` | `continuity-local-document-release-ack/1` |
| `REMOTE_SERVICE_REPORT_ADAPTER_ID` | `adapter:remote-service-report` |
| `REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION` | `continuity-remote-service-report-ack/1` |
| `PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION` | `continuity-attempt-observation-duty/1` |
| `PORTABLE_ATTEMPT_DUTY_REVIEW_EXTENSION` | `continuity-attempt-duty-review/1` |
| `MAX_PORTABLE_ADAPTER_EVIDENCE_BYTES` | `4096` |
| adapter policy schema tag | `continuity-adapter-policy/0.2` |
| replay rule ids (inside descriptors) | `continuity-adapter-replay/local-packet/1`, `…/simulated/1`, `…/local-endpoint-state/1`, `…/local-document-release/1`, `…/remote-service-report/1` |

### F.3 Adapter policy hashes (**[verified]** values; each is `hashCanonical` of the object shown)

Descriptors (all `profileVersion: "1"`):

```
LP  = { profileId: "adapter:local-evidence-packet",          profileVersion: "1", acknowledgmentSchemaVersion: "continuity-adapter-acknowledgment/0.2",     replayRuleId: "continuity-adapter-replay/local-packet/1" }
SIM = { profileId: "adapter:simulated",                       profileVersion: "1", acknowledgmentSchemaVersion: "continuity-adapter-acknowledgment/0.2",     replayRuleId: "continuity-adapter-replay/simulated/1" }
ES  = { profileId: "adapter:local-synthetic-endpoint-state",  profileVersion: "1", acknowledgmentSchemaVersion: "continuity-local-endpoint-state-ack/1",    replayRuleId: "continuity-adapter-replay/local-endpoint-state/1" }
DR  = { profileId: "adapter:local-document-release",          profileVersion: "1", acknowledgmentSchemaVersion: "continuity-local-document-release-ack/1", replayRuleId: "continuity-adapter-replay/local-document-release/1" }
RS  = { profileId: "adapter:remote-service-report",           profileVersion: "1", acknowledgmentSchemaVersion: "continuity-remote-service-report-ack/1",  replayRuleId: "continuity-adapter-replay/remote-service-report/1" }
```

| constant | edition | hashed object | value |
|---|---|---|---|
| `PORTABLE_ADAPTER_POLICY_HASH` | E1 | `{ schemaVersion: "continuity-adapter-policy/0.2", profiles: [LP, SIM] }` | `0x00c3498e2744943663475d0187ca979cdd09763b88427781883693c4b8c163a7` |
| `PORTABLE_ADAPTER_POLICY_E2_HASH` | E2 | `profiles: [LP, ES, SIM]` | `0x22eb40a92e50c998e007f67f0af0bc584e25f4b21c9bd802cbebe5981828810e` |
| `PORTABLE_ADAPTER_POLICY_E3_HASH` | E3 | `profiles: [DR, LP, ES, SIM]` | `0xda1ac0f7af67e35a2acd3e213089bafd65204e4bb50e6a0823f8e7e941168666` |
| `PORTABLE_ADAPTER_POLICY_E4_HASH` | E4 | `profiles: [DR, LP, ES, RS, SIM]` | `0xe332eb30cd57a0106582649f124d33d17272096cd42b96d9155b53594a3894a5` |
| `PORTABLE_ADAPTER_POLICY_E5_HASH` | E5 | E4 profiles + `semanticExtension: "continuity-attempt-observation-duty/1"` | `0x32c2a5608c7110f1a291517e136cedf62d59a2cb81be1141dd2705bce307ab29` |
| `PORTABLE_ADAPTER_POLICY_E6_HASH` | E6 | E4 profiles + `semanticExtensions: ["continuity-attempt-observation-duty/1","continuity-attempt-duty-review/1"]` | `0xa90baac702f22f5a5f71141318a7651c1d963bbbee28138bbea835d942d0114c` |

`resolvePortableAdapterPolicy(hash)` returns the edition for exactly these six strings and `undefined` otherwise (no default). Policy membership: E1 = {LP, SIM}; E2 = {LP, ES, SIM}; E3 = {DR, LP, ES, SIM}; E4/E5/E6 = {DR, LP, ES, RS, SIM}. E5/E6 enable the attempt-duty events; E6 additionally enables `ATTEMPT_DUTY_REVIEW_CLOSED`.

### F.4 Adapter profiles (`{ profileId, profileVersion: "1", descriptorHash }`, `descriptorHash = hashCanonical(descriptor)`; **[verified]**)

| profileId | descriptorHash |
|---|---|
| `adapter:local-evidence-packet` | `0xd4b988c1f23603cf35d9abd0db5a7eb56ef7a5fba1a8f3e904490c1ce4458d64` |
| `adapter:simulated` | `0xa9f3354121fdbc4d983093e34684d5ddc841874f8fccadbafe30df65f2e16ac2` |
| `adapter:local-synthetic-endpoint-state` | `0x486bad2029389663117b06785e641f3a6ec2a90ca89b60e95267965ddc5977ed` |
| `adapter:local-document-release` | `0x9749dc03bd4db3c4a1f8eba707fa5ab49ea02f0a948b22697a3b7152a01393bc` |
| `adapter:remote-service-report` | `0xa86975f20bd2cac74ab19ccfed948a18c8c85c05407ca925dc685ac4b5d460c0` |

A profile value is accepted (`validateKnownPortableAdapterProfile` / `…ForPolicy`) iff, after the adapter-engine snapshot+capture (E.8 below), it is a record with exactly those three keys and `canonicalEncode(value) === canonicalEncode(knownProfile)`.

### F.5 Adapter acknowledgment / no-effect canonical shapes (used by replay in D.7)

All adapter-evidence values pass through `capture()`: a descriptor-only snapshot (no getters/setters, all fields enumerable, keys ≤ 256 per record, depth ≤ 16, ≤ 4 096 "units" (nodes + UTF-8 bytes of strings), no arrays anywhere, no proxies, plain records only, `undefined` values forbidden) followed by a strict canonical capture bounded to **4 096 bytes** and a check that no captured record key is missing from the value. Any violation → the validator returns `false`.

`identitySnapshot(identity)` requires the closed record `{ idempotencyKey, submissionFingerprint, durableEventHistoryHash, adapterNoEffectReference, adapterProfile, domain, intentId, admissionHead }` (plus optional `operationVersion === "continuity-adapter-submission/0.2"`), known profile, valid domain (`chainId` also `length <= 78` here), identifier `intentId`, `admissionHead` = closed `{hash, position, canonicalTime}` with ContentHash/U53/U53, ContentHash `submissionFingerprint`, `durableEventHistoryHash === admissionHead.hash`, `idempotencyKey === derive(domain, intentId)`, `adapterNoEffectReference === derive(idempotencyKey, submissionFingerprint)`.

Evidence identity fields copied into every acknowledgment/no-effect: `{ adapterProfile, domain, intentId, admissionHead, idempotencyKey, submissionFingerprint }`.

* Simulated ACK: `{ schemaVersion: "continuity-adapter-acknowledgment/0.2", kind: "ACKNOWLEDGMENT", …identity, result: { kind: "SIMULATED_SUBMISSION", submissionReference: submissionFingerprint } }` — the reference is forced to equal the fingerprint.
* Local packet ACK: same schemaVersion, `result: { kind: "LOCAL_PACKET_CREATED", manifestDigest: { algorithm: "sha256", value: <0x…64 hex from the supplied value> } }`.
* Endpoint-state ACK: `schemaVersion: "continuity-local-endpoint-state-ack/1"`, `result: { kind: "LOCAL_ENDPOINT_STATE_CHANGED", transitionDigest: { algorithm: "keccak256", value } }`.
* Document-release ACK: `schemaVersion: "continuity-local-document-release-ack/1"`, `result: { kind: "LOCAL_DOCUMENT_RELEASED", publicationManifestDigest: { algorithm: "sha256", value } }`.
* Remote-service-report ACK: `schemaVersion: "continuity-remote-service-report-ack/1"`, `result: { kind: "REMOTE_SERVICE_REPORTED", reportDigest: { algorithm: "sha256", value } }`.
* No-effect (simulated only): `{ schemaVersion: "continuity-adapter-no-effect/0.2", kind: "NO_EFFECT", …identity, result: { kind: "SIMULATED_NO_EFFECT", reference: adapterNoEffectReference } }`.

`validatePortableAdapterAcknowledgment(value, identity)` reconstructs the expected ACK for the identity's profile (taking the digest `value` from the supplied ACK where applicable, which must match `/^0x[0-9a-f]{64}$/`) and requires `canonicalEncode(value) === canonicalEncode(expected)`. Hence every field of a stored ACK, including `admissionHead`, `domain`, and `adapterProfile`, must equal the admitted identity exactly. The `*Shape` variants used by the event schema derive the identity from the ACK's own fields (so they check internal consistency only, not membership in any history). `transactionReference` for a consumption is the digest `value` (or `submissionReference`) inside `result`.

---

## G. Traps for a re-implementer

1. **Canonical ≠ tagged.** Hashes are over compact sorted JSON (section A). The `["object",[…]]` form exists only inside JSONL lines and is never hashed; its `recordHash` is computed over the *decoded* event.
2. **Key order is UTF-8 byte order**, not UTF-16, not locale, not "JSON.stringify insertion order": `"" < "10" < "2" < "A" < "a" < "é"`, and astral characters sort after U+FFFF. Sorting must happen on the *keys*, and the comparator throws on malformed keys (validate first).
3. **Only `"`, `\` and U+0000–U+001F are escaped**, with lowercase `\u00xx`. U+007F, U+2028/2029, `/`, and all non-ASCII are emitted raw. `JSON.stringify` would produce the same bytes for well-formed input except that it escapes lone surrogates as `\udXXX` — those are rejected here instead.
4. **Numbers are integers only**, `-0` is rejected, and there is no float path. Non-integers are not "rounded" or "stringified". In replay they are silently carried as 32-byte opaque scalars and rejected later by the schema (`EVENT_DATA_INVALID`), not by capture.
5. **BigInt marker objects are bigints.** `{ "$continuity.bigint": "5" }` in input is *decoded* into `5n` (same hash, same schema acceptance as a native bigint), but the marker must be the *only* key, the string must match `^(0|-?[1-9][0-9]*)$` with ≤ 79 chars, and `"$continuity."`-prefixed keys are otherwise forbidden. Markers are rejected in the envelope scalar slots (`id`, `type`, `timestamp`).
6. **`undefined` fields vanish from text but not from the key snapshot.** Canonical output omits them, `immutableProtocolValue` drops them, `immutableProtocolInput` keeps them, and closed-schema validation sees them (an undeclared key with value `undefined` is still "not a declared field"; a declared optional key with value `undefined` is fine). The 256-field limit counts them. An `undefined` **array element** is an error, not an omission.
7. **Empty arrays and records are valid** (`[]`, `{}`), including `requiredIntersectionIds: []` and `checkedProhibitionIds: []`; but `actions`, `resources`, `permittedEventTypes`, `permissionPath`, `controllingAuthorityIds`, `authorityEvidence`, `transitionPolicies`, `acceptedAttesterIds`, `requiredAuthorityIds` must be non-empty.
8. **Depth is counted from the outermost container of the *operation*, not of the event.** In replay (and `hashEventHistory`) event `data` sits at depth 4, so only 28 nested containers fit under it; the standalone shape validator and `hashCanonical(event)` on a bare event allow 30. Bigint-marker records add no depth.
9. **Timestamps are non-decreasing**, not strictly increasing; equal timestamps are accepted. `canonicalTime` is the last event's timestamp. `expiresAt` is exclusive: a session is usable only while `time < expiresAt`.
10. **Check precedence per event**: capture (`INVALID_INPUT`) → genesis-position checks (`GENESIS_REQUIRED`, probe `EVENT_DATA_INVALID`/`INVALID_INPUT`, `UNSUPPORTED_EVENT_SCHEMA`, `UNSUPPORTED_VERSION`) → type (`UNSUPPORTED_EVENT_TYPE`) → named-limit preflight (`INVALID_INPUT`) → closed schema (`EVENT_DATA_INVALID`) → `GENESIS_DUPLICATE` → `EVENT_ID_DUPLICATE` → `EVENT_TIME_REGRESSION` → `TRANSITION_INVALID`. Schema failures therefore beat duplicate-id and time-regression failures for the same event, and a LIMIT overflow anywhere in the named-limit tree beats a semantic failure in an earlier field. Across events the first failing position wins and later events are not examined.
11. **Two different `UNSUPPORTED_VERSION`s**: the outer `operationVersion` mismatch (no position) and a genesis `versions` mismatch other than `eventSchemaVersion` (with position 0 and the genesis id). A wrong `eventSchemaVersion` is `UNSUPPORTED_EVENT_SCHEMA`. A wrong `adapterPolicyHash` (well-formed but unknown) is `EVENT_DATA_INVALID`, not an unsupported-version code.
12. **`eventId` is optional in rejections**: absent when the failure happened before the id was captured (bad `id`, non-record event, extra envelope key) and for the empty-history `GENESIS_REQUIRED`.
13. **The replay event canonical text is `{"data":…,"id":…,"timestamp":…,"type":…}`** — the sorted order of the four envelope keys — and the prefix hash absorbs exactly `["continuity-event-history/0.2",[` + texts joined by `,` + `]]`. Do not hash `{operationVersion, events}`.
14. **`data` byte budget is 1 048 576 bytes of canonical text, inclusive**, measured on the data record alone; overflow is `INVALID_INPUT` (not `EVENT_DATA_INVALID`) in replay. Strings anywhere are capped at 4 096 UTF-8 bytes (identifiers at 256), and both caps are *byte* caps with a UTF-16-length fast-fail.
15. **Identifier rejects DEL and C0 only**; spaces, C1 controls, and any other scalar are fine. `type` is a ProtocolString, so `""` is a legal envelope type that then fails as `UNSUPPORTED_EVENT_TYPE`.
16. **Ethereum addresses are case-insensitive** (no EIP-55 check) and are stored lowercased; the recovered signer is lowercase hex. Content hashes and signatures must be lowercase; a signature must be low-s with `v` = `1b`/`1c` and `s ≠ 0`.
17. **`credentialKeyId` is globally unique** across all sessions of all agents; `credentialAddress` is unique **per agent**; only one unexpired session per agent per epoch; sessions from earlier epochs remain in state but are "fenced".
18. **`AGENT_TERMINATED` does not close the tenure**; it locks it. The tenure stays `currentTenureId` of the role until a `ROLE_TRANSFERRED` with `transferKind: "SUCCESSION"`. `AGENT_UNAPPOINTED` and `REASSIGNMENT` are impossible on a locked tenure. The successor's new tenure has no `successionRuleId`.
19. **`SUCCESSION_RULE_DECLARED` reserves the successor id**: a later `PRINCIPAL_CREATED` with that id fails, but an `AGENT_CREATED` with it succeeds. The predecessor must already be an agent; the successor need not exist yet.
20. **Authority existence tests count revoked authorities** (`requiredIntersectionIds`, policy `requiredAuthorityIds`, `AUTHORITY` evidence). Revocation is a flag on the record, not a deletion. A recognised root is created only by a parentless PERMISSION whose `authorityId === rootAuthorityId` and whose grantor is a principal.
21. **Usage records exist only for permissions with `maxTransactions` or `maxCumulativeAmount`**; a `maxCumulativeAmount` authority requires the request to carry `amount`. Counters are cumulative across admissions and never decremented.
22. **Admission binds the head *before* the event** (`expectedHistoryHead`, `proof.historyHead`, challenge `eventHistoryHash/Position`) but stores the head *including* the event (`admissionHead`, used in the adapter identity and every ACK). Administrative challenges likewise bind the prior head. The submission fingerprint hashes the **entire admission event**.
23. **Optional-field congruence uses presence and value**: `counterpartyId` must be present in the obligation record iff present in the intent; the challenge `request` is compared by canonical text, so an absent vs. present key is a mismatch even if the value would be `undefined`.
24. **Proof equality is textual.** Both the admission proof and the administrative proof must canonically equal the engine-derived proof; any extra, reordered-but-equal (fine), missing, or differently-typed field fails as `TRANSITION_INVALID`.
25. **Outcome semantics**: a `FAILED`/`CONFIRMED` outcome becomes terminal; afterwards only `DISPUTED` records are accepted (they update `latest`, never `terminal`). Consumption is blocked once a terminal outcome exists but an outcome does *not* require a prior consumption. `FAILED` requires the simulated no-effect proof and `attesterId: "adapter:simulated"`.
26. **`RECEIPT_RECORDED` is existence-only**: the cited ids must exist, nothing else is cross-checked, no signature is verified, and `receiptContentHash` is the map key (a second receipt with the same hash fails).
27. **`OBLIGATION_CREATED` re-reads the admission event** to compare the receipt's `authorizationProofHash` with `hashCanonical(admissionEvent.data.authorizationProof)` and the receipt's issuer/session/epoch/role/tenure with the proof's.
28. **File store**: `appendAtExpectedHead` on an empty store *always* conflicts (`observedHead` absent); the record's `previousHash` is compared with `===` so the first line must literally have `null`; a stored negative number, negative bigint, or float is unreadable (`Invalid stored encoding.`) even though the writer could in principle emit it; the round-trip "Noncanonical store encoding" check does **not** detect reordered object entries; CRLF line endings are tolerated on read; the lock file has no stale recovery; a removed valid suffix is undetectable; the parent directory must exist before construction; hard links (`nlink !== 1`) are refused.
29. **Object enumeration order** leaks into the tagged storage form: integer-like keys come first in numeric order. Not reachable with valid 0.2 events, but a generic reimplementation of `encode` must reproduce it to match `recordHash`-independent byte equality of lines (the hash itself is order-independent).
30. **`canonicalEncode` is not safe on hostile objects** (getters run, proxies consulted); replay's event-data capture tolerates getters but the adapter-evidence subtrees (`acknowledgment`, `noEffect`, `adapterProfile`) reject accessors and Node proxies and are additionally capped at 4 096 bytes each.
31. **`events` must be a real Array** (`Array.isArray`), dense, with only index keys and `length`; array-likes, typed arrays, and arrays with extra properties are `INVALID_INPUT`. The same event object appearing twice is captured once and then rejected by the reducer as a duplicate id.
32. **Keccak padding is `0x01…0x80`** (Ethereum keccak-256), not NIST SHA3-256 (`0x06`).

---

## Appendix: fixture reference values (**[verified]**)

Fixture: `tests/fixtures/handover-history.json` (26 events; same events as the `.jsonl`). Types in order: DEPLOYMENT_INITIALIZED, PRINCIPAL_CREATED, AGENT_CREATED ×2, ROLE_CREATED, SUCCESSION_RULE_DECLARED, AGENT_APPOINTED, RUNTIME_SESSION_ADMITTED, AUTHORITY_GRANTED ×5, TRANSACTION_INTENT_DECLARED, TRANSACTION_INTENT_ADMITTED, TRANSACTION_INTENT_CONSUMED, RECEIPT_RECORDED, TRANSACTION_OUTCOME_RECORDED, OBLIGATION_CREATED, CONTROL_EPOCH_ADVANCED, AGENT_TERMINATED, ROLE_TRANSFERRED, RUNTIME_SESSION_ADMITTED, OBLIGATION_PERFORMANCE_ASSIGNED, AUTHORITY_REVOKED, TRANSACTION_INTENT_DECLARED.

* Genesis canonical text: `{"data":{"adapterPolicyHash":"0x00c3498e2744943663475d0187ca979cdd09763b88427781883693c4b8c163a7","canonicalLineageId":"lineage:first-look","domain":{"chainId":"31337","deploymentId":"core-0.2-reference:first-look","protocol":"continuity","verifyingContract":"0x0000000000000000000000000000000000003002","version":"0.2"},"finality":"LOCAL_ONLY","globalPolicySourceId":"policy-source:first-look","policyVersion":"local-evidence-intake-policy:first-look/0.2","rootRecognitionPolicy":"declared-principal-root/0.2","timeSource":"EVENT_TIMESTAMP","versions":{"administrativeAuthorizationVersion":"continuity-administrative-authorization/0.2","authorizationProofVersion":"continuity-authorization-proof/0.2","eventSchemaVersion":"continuity-event/0.2","queryEnvelopeVersion":"continuity-query-envelope/0.2","receiptSchemaVersion":"continuity-receipt/0.2","runtimeAuthorizationVersion":"continuity-runtime-authorization/0.2","signatureScheme":"eip191-personal-sign-keccak256"}},"id":"first-look:genesis","timestamp":0,"type":"DEPLOYMENT_INITIALIZED"}`
* `hashEventHistory([genesis])` = replay head after 1 event = `0xe035299cb5520cc603d60273ae4c51ea1eaddad3cc9a47102edab60447d38397` (position 0, canonicalTime 0).
* Event 1 canonical text: `{"data":{"principalId":"principal:first-look"},"id":"first-look:principal","timestamp":1,"type":"PRINCIPAL_CREATED"}`; `hashCanonical(event1) = 0xf3455a16a2af7a75bfae76f1311c15b879009fe8c94ae0ad48ddf9fa0db1dbb0`; head after 2 events `0xa6f8cae49ad736cfcb45734fcf37da48d9fd364d5a93c7cc875560f4112f70b9` (position 1, canonicalTime 1).
* Full replay: `ACCEPTED`, head `{ hash: 0x4958d40342fc047d3fff0d3ab0f36e572ea28d9a1bb6dcbfbc1961c52231b779, position: 25, canonicalTime: 25 }`, `eventCount: 26`.
* Store line 1 `recordHash` = `hashCanonical({version:"continuity-portable-file-store/0.2", previousHash:null, event:genesis})` = `0x4d81d24f7dff9f4aee041d08c5d7fdb3d07f03e30a0c0607a172f14a13b454ce`; line 2 `previousHash` = that value, `recordHash = 0x88206b5f1c0d57961a812eea68d29e19daded7c8790fb082846e8172a8ccdd09`.
* Admission event 14: `data` keys `authorizationProof, evaluationTime, expectedHistoryHead, intentId, runtimeAuthorizationHash, runtimeSignature`; the proof's 23 keys are `authorityEvidence, checkedProhibitionIds, consequential, controlEpoch, controllingAuthorityIds, credentialKeyId, domain, effectiveConstraints, evaluationTime, historyHead, intentId, intersections, nonce, permissionPath, policyVersion, proofVersion, recognizedRoot, request, roleId, roleTenureId, rootRecognitionPolicy, runtimeSessionId, usageSnapshot`. Consumption event 15's ACK `admissionHead` is `{ canonicalTime: 14, hash: 0xf156c2c9…, position: 14 }` — the head *including* the admission event.
