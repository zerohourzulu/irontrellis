# History format

An IronTrellis (formerly Continuity) history is a file of events: who granted what to whom, which actions were admitted or refused, and which duties survive when an agent is replaced. A reader takes none of it on trust. Signatures bind particular requests and effects to particular heads, and hashes detect changed content, so a reader checks both on every line and replays every event under its format's rules. Anyone holding the file and the owner's keys reaches the same answers.

Say an auditor receives a history and the owner's published keys, and asks whether an agent was allowed to make a payment on Tuesday. Her verifier reads line 0 to learn the format, checks every line, and replays every event. The recorded admission must re-derive exactly, or the history is refused at that position. What the file alone can't tell her is whether it's the newest copy: someone may have removed a complete suffix. For that she compares its head with the pin, the anchors and the remote witnesses (§9, §10).

**Scope.** IronTrellis Core 1.0.0-rc.2 writes format 2. Non-format-2 histories and fenced migration sources are read-only: writers refuse them with `FORMAT_READ_ONLY`. This page explains the current format, then the older encoding and signature rules needed to inspect historical files.

The `docs/reference/` pages keep the exact legacy and format-1 byte tables. The format-2 bytes as released (session-challenge profile `g3`) are pinned by the `conformance/v2-g3` and `conformance/v2-regenerated` vectors, with `conformance/v2-owner-policy` and `conformance/v2-human-attestation` for owner policies and PHL, Proof of Human Lineage. `conformance/v2` keeps the frozen record of the r2.3 rules, which verifies only under the `frozen-r2.3` profile. This page does not restate the format-2 bytes field by field.

**Not covered.** Signatures do not establish external truth, and hashes alone do not detect removal of a valid suffix. This page explains the format; it is not an audit of the engine or a conformance run. The [owner-policy reference](reference/owner-policy.md) gives the current policy rules, and [legacy-semantics](legacy-semantics/README.md) describes the historical transition rules. [CONFORMANCE](CONFORMANCE.md) and the [conformance README](../conformance/README.md) describe the test suites.

## 1. Current format and compatibility

### Releasing format 2

Publishing 1.0.0-rc.2 releases format 2. Histories written by 1.0.0-rc.2 keep their verdicts: later versions read them exactly as 1.0.0-rc.2 does, or refuse them. Rule fixes after 1.0.0-rc.2 come as a new format.

Format 2 as released means session-challenge profile `g3`. The `frozen-r2.3` profile only verifies the frozen conformance vectors ([CONFORMANCE](CONFORMANCE.md#format-2-as-released-means-profile-g3)).

### What format 2 is

Format 2 uses `irontrellis-event/2` and `irontrellis-portable-file-store/2`. Its history head is the chain tip. Amounts are decimal strings under the format-2 scalar rules; older bigint-marker encodings must not be copied into format-2 data. The first store-line version and genesis event-schema version select the interpretation. Version literals inside signed structures are exact protocol identifiers, not labels to rename casually.

Format 2 has 42 event types, with projection type codes 0–40 and 42 (code 41 is unassigned; `RECONCILIATION_OBSERVED` is 42). Format 1 has the first 29. Legacy has the first 25, and a legacy history may also carry the three duty-policy types, 29–31, which the engine reads as the frozen Continuity reference does.

In format 2 a `PublicKey32` is `0x` and 64 lowercase hex digits. An uppercase digit is `EVENT_DATA_INVALID` at that event, and `admitRuntime` refuses such a session key before signing (`INVALID_INPUT`, reason `PUBLIC_KEY_CASE`). Legacy and format-1 histories, and a migrated prefix, keep their older any-case rule.

Format 2 adds the features below, and a projection and export view. They are distinct from the older event-count budget and whole-history hash.

| Addition | What to know |
|---|---|
| State records and their Merkle root | The state root commits the prescribed record set; the root at a position includes that position's own event record. A checkpoint carries the root just before it, and adds only its own event record. |
| Checkpoints and snapshot resume | Resume recomputes the root; a saved root field is not trusted. A snapshot whose records do not reproduce its root is not used: the store replays the full history, `verify()` reports a `SNAPSHOT_STALE` note, and the snapshot is rebuilt. No error is thrown, and no answer comes from the stale snapshot. |
| `usage` counters and nonce records | The format-2 `usage` counters are distinct from the older capped authority-usage accounting. Nonce records arise at declaration, rather than at admission. |
| Native budgets | Budgets are evaluated after the authority result, with their documented group, role, period and charging rules. An authority path alone is not the complete format-2 admission decision. |
| Signed intent declarations, refusal and effect records, counterparty receipts | Each carries its own bindings. Recording them does not prove the outside effect happened, or that all provider events were captured. Not every refusal is recorded: in 1.0.0-rc.2 the coding-agent hook's protective rules refuse a call before the history is opened, so those refusals leave no record. |
| Attestation v2 | Includes the domain. Pins, anchors, witness statements and snapshot and export checks must use the corresponding versioned rules, never an older challenge with a renamed literal. |

Owner approval policies and the PHL attestation policy ship in 1.0.0-rc.2: thresholds, per-type thresholds, `PR_eff`, credential separation, committed-key recovery (replay only; 1.0.0-rc.2 has no writer for a recovery rotation), `ATTESTED`, lapse, restoration and T1/T2. See [§15](#15-format-2-owner-approval-policies). Reconciliation observations have their own current schema in [§14](#14-format-2-reconciliation-observations).

Migration targets format 2, with a plan, a fence and resumable phases; see [§11](#11-migration-and-read-only-sources) and [MIGRATION](MIGRATION.md). Upgrading a reader does not convert a historical file in place or authorize an old-format writer.

### Read-only compatibility catalog

This table identifies the historical formats for reading and verification. Their source export described older writing workflows; those commands and byte examples are **historical**, not current 1.0.0-rc.2 write recipes.

| Property | Legacy | Format 1 |
|---|---|---|
| Event schema | `continuity-event/0.2` | `irontrellis-event/1` |
| Store line | `continuity-portable-file-store/0.2` | `irontrellis-portable-file-store/1` |
| Stored event | tagged tuples | plain JSON with bigint markers |
| History hash | Keccak-256 | SHA-256 |
| Control events | unsigned | owner-signed |
| Runtime suites | EIP-191 | Ed25519 or EIP-191, per session |
| Historical file cap | 64 MiB | 1 GiB |
| Whole-history capture bound | 4,096 events / 16 MiB canonical text | no equivalent whole-history canonical bound |

The [encoding](reference/history-encoding.md) and [event](reference/history-events.md) references keep this older catalog, its domain shapes and exact literals. Don't treat their field tables, scalar grammars, event count or writer behavior as a complete format-2 specification.

## 2. Canonical encoding

The historical profiles summarized here hash UTF-8 canonical text, not a caller's JSON formatting. Format 2 has its own scalar and capture rules, including Amount strings and the rejection of reserved `$continuity.` data keys; read its exact grammar from the current specification, don't infer it from these marker rules.

| Value | Historical rule |
|---|---|
| Record keys | Sorted by unsigned UTF-8 byte order |
| Arrays | Keep their order |
| Strings | Must be well-formed Unicode |
| Numbers | Safe integers only; negative zero, fractions, infinities and unsupported host values are refused |
| Bigints | The single-key `$continuity.bigint` marker, not interchangeable with JSON numbers or arbitrary decimal strings |

Capture has separate limits for strings, record keys, array members, depth and total text, and the event envelope adds its own data limit. A value that parses as JSON is therefore not necessarily an admissible protocol value. When translating a history, don't normalize missing fields into `null`, reorder lists, or coerce scalar types.

The [encoding reference](reference/history-encoding.md#2-canonical-encoding) keeps the exact escaping and bigint grammar, limits and hash examples. Keccak-256 here is the Ethereum variant, not SHA-3; SHA-256 is the format-1 history algorithm. Implementers must resolve any ambiguity against the normative specification and vectors, not by choosing a host serializer by name.

## 3. Historical store lines

For the legacy and format-1 read path, a store is UTF-8 JSON Lines without a byte-order mark. Every record ends in a newline; an incomplete final record is invalid. A line has exactly `version`, `previousHash`, `event` and `recordHash`. The first `previousHash` is `null`; each later one names the preceding record hash.

`recordHash` hashes the canonical record containing the line version, the previous hash and the **decoded event**, not the raw line's spacing or the legacy tagged representation. Readers check the field set, version, chain, stored encoding and record hash, then apply the event to replay state. A defect in any of those checks, or a rejected replay, invalidates the history as a whole.

Legacy tagged tuples must decode and re-encode identically. Format-1 writers sort record keys recursively, but readers accept other key orders because hashing canonicalizes them. Arrays keep their order. CRLF conversion does not change a record's hash: lines split at the newline, and the carriage return is JSON whitespace. See the [complete stored encodings and two-event file](reference/history-encoding.md#3-store-lines).

Removing a complete suffix can leave a valid hash chain. That is why reading the pin and consulting external evidence are separate from replay.

## 4. Historical history hash and head

For legacy and format 1, the record hash links store lines. The **history hash** instead covers the canonical wrapper and every decoded event through a position; its wrapper and hash algorithm depend on the format. An incremental implementation absorbs each canonical event and finalizes a copy of its hasher to obtain each prefix hash. The exact wrappers and empty-history values are in the [hash reference](reference/history-encoding.md#4-history-hash-and-head).

The historical head is `{hash, position, canonicalTime}`: the prefix hash, the zero-based position of the last event, and that event's timestamp. Format 2 uses its record-chain tip instead of this whole-history wrapper hash. Compare heads field by field.

A challenge may bind the head **before** an event or the head **including** it; the two are not substitutes. Control authorization signs the previous head. Runtime authorization and admission use the head required by their own recorded challenge and proof.

A hash establishes correspondence to bytes under the chosen algorithm. It does not establish that the named history is the newest copy, or that an external outcome occurred.

## 5. Historical event envelope and rejection order

An event has exactly `id`, `type`, `timestamp` and `data`. IDs are bounded, well-formed identifiers and must be unique across the history. Position zero must be genesis, and genesis cannot recur. Timestamps are non-negative safe integers and cannot regress; their units belong to the application, and the local API uses milliseconds. `data` is a captured plain record with a closed schema for its type.

For the legacy and format-1 path, replay checks, in this order:

1. envelope and capture;
2. genesis position and version;
3. event type;
4. closed schema;
5. duplicate genesis;
6. duplicate ID;
7. time regression;
8. format-1 control authorization;
9. transition preconditions.

A rejected event leaves state unchanged and reports its position. Schema errors and named-limit capture errors have different codes, so the order matters when an input has several defects.

The [envelope and event reference](reference/history-events.md) keeps every field, scalar definition and rejection code. Its 29-type count is the format-1 catalog (legacy has the first 25, plus types 29–31); format 2 has 42.

## 6. Reading genesis, grants and evidence

Genesis declares the domain, lineage, adapter policy, version literals, policy version, root recognition, global policy source, time source and finality. Format 1 also declares owner keys, and may declare capacity, next-key commitments and migration provenance. These declarations become part of the history's identity; they are not configuration a reader can replace later.

A permission names its grantor, grantee, root and optional parent. A root permission names itself as root and has no parent. A delegation inherits its parent's root and must attenuate its constraints. ROOT and GLOBAL prohibitions have distinct shapes and scopes. Constraints describe actions, resources, time, quantitative ceilings, delegation depth and required intersections. Proofs carry normalized grants; history events keep their written lists.

Evidence references identify events, authority grants, runtime credentials, receipt commitments or external evidence, with the kind-specific fields needed to locate and interpret the claim. Obligation records also carry their causal receipt, durable role and creation tenure, assignee, terms commitment and transition policies.

The [event reference](reference/history-events.md) contains the closed schemas and full genesis versions. The cited legacy specifications define transition preconditions such as tenure currency, succession locks and usage changes; a field table alone does not implement replay.

## 7. Control authorization and owner epochs

Current format-2 counting and authorization follow [§15](#15-format-2-owner-approval-policies) and the owner-policy reference. This section explains the older signature and epoch model needed to read historical data. Never reconstruct the current `/2` challenge by editing an old literal.

In format 1, marked control events carry `{keyId, signature}` in `controlAuthorization`. The named owner key must be in force at that event's position. Its challenge binds the domain, event ID, type, timestamp, previous head and an effect hash. The effect excludes the signatures over that same challenge, not arbitrary application fields. Runtime-signed admissions, receipts and administrative events are not owner control events.

This binds approval to both the proposed effect and its place in the history: moving the event, changing its effect, or signing with a key not in force fails authorization. The exact exclusion list, canonical challenge and worked hash are in the [signature reference](reference/history-signatures.md#7-control-authorization-format-1). Format-2 co-signatures follow the owner-policy reference, not this single-signature shape.

### 7.1 Rotation boundaries

Owner epochs are immutable once opened, and genesis supplies epoch zero. For a rotation at position `r`:

| Position | Keys |
|---|---|
| up to `r` | The old set. It authorizes the rotation at `r`, and still attests the head ending at `r`. |
| `r + 1` onward | The new set, which opens the new epoch. |

An older valid attestation stays valid after the key retires, because the position it attests has not changed.

A key ID cannot be rebound to another credential, a retired ID cannot return, and a credential already declared cannot be introduced under another ID. Carrying current keys forward is different from reintroducing retired ones. Remote rotation verification uses the prior epochs and the supplied heads; the format-2 policy reference states which checks need full replay state.

### 7.2 Committed next keys

A next-key commitment belongs to the event that opens an epoch, and it cannot be replaced in place. Its digest binds the scheme and the normalized credential, not the future key ID. Rotating out of a committed epoch must reveal committed keys, verify the required proofs of possession over the rotation challenge, and continue the commitment chain. Keep the next key beyond the current signer's reach.

Under the documented format-1 rules, an uncommitted epoch can acquire a commitment through a rotation that keeps its keys and adds the commitment. A committed epoch cannot use that operation to erase or replace its commitment. Format-2 policy rotations and recovery add rules of their own: use the [owner-policy reference](reference/owner-policy.md), not a single-key recovery shortcut.

The [epoch and pre-rotation reference](reference/history-signatures.md#71-owner-key-epochs-and-owner_keys_rotated) keeps the ordered tests, errors and local API behavior. [CUSTODY](CUSTODY.md) explains where current, next and retired keys belong.

## 8. Historical runtime signatures and receipts

The byte reference for this section is legacy and format 1; current format-2 declarations, challenges, receipts and admission bindings need their current versioned definitions. The signature suite receives the history algorithm's hash of a signed structure. Ed25519 signs the raw 32 hash bytes; EIP-191 uses its specified Ethereum prefix and recovery rules. The scheme of the particular owner key or admitted session selects the verifier; byte length alone is not the authorization decision.

A consequential runtime challenge binds the request, evaluation time, policy, history head, session and control epoch, role tenure, intent and nonce. Admission records the runtime hash and signature. Replay recomputes the challenge and re-derives the authorization proof from the appropriate pre-event state, and requires the recorded values to match.

Administrative events bind the transition ID and type, effect hash and authority-proof hash as well as the session context. The action and resource used for the policy query are derived from the transition, and implementers must reproduce those literals. A receipt artifact binds its payload hash and the issuing session's signature; its recorded commitment binds the hash and signature together. Receipt limits also differ between legacy and format 1.

See [signature suites, complete challenges, proof fields and receipt commitments](reference/history-signatures.md#8-signatures). An external signer produces the same protocol signature as a local key; its custody mechanism is not encoded in the history.

## 9. Pinned heads

After a successful append, the store atomically rewrites `<history>.head`. The pin holds the history head, the last record hash and the pinning time, with an owner attestation when available. An asynchronous signer may add the attestation after the first pin write. The store reads the pin before the history, so an append in progress can leave the file ahead of the pin without falsely indicating a rollback.

| Pin result | Meaning |
|---|---|
| `MATCHES` | file and pin agree |
| `AHEAD` | file extends the pinned prefix |
| `ROLLBACK` | file is shorter or differs at the pinned position |
| `MALFORMED` | the pin cannot be interpreted as a valid pin |
| `MISSING` | a required pin is absent |
| `UNPINNED` | no pin is required for this documented format/state |

The [pin reference](reference/history-storage.md#9-pinned-head-file) gives the exact required-pin cases, retries, open and verify codes, and attestation checks. An attestation must be by a key in force at its position, and must cover a prefix. A valid earlier attestation can be carried forward when later writers cannot sign; verification reports that distinction.

Events written with a runtime session's key instead of the owner key, such as the refusals the coding-agent hook and the gateway record, leave the pin attested at an earlier head. They stay unattested, and unwitnessed (§10.1), until the next owner write; sooner, `irontrellis repin` attests the head and `irontrellis witness sync` submits it to the witnesses.

`acceptRollback` deliberately repins and records acceptance provenance; it is not a silent repair. `allowUnpinned` permits specified read cases while writes stay refused. Inspection defers findings to verification and does not write. A missing pin during an open writer's lifetime is not silently recreated by its next append.

An attacker who restores both an old history and its genuine old attested pin defeats evidence kept only beside that file. Exposing the newer head needs a witness or an anchor kept beyond that attacker's reach.

## 10. Anchors and witness bindings

An anchor gives an owner-signed head attestation to a target and records the receipt as `ANCHOR_RECORDED`. Replay checks that the anchored head precedes the event and matches the history prefix. An anchor is informational: it grants no authority, and cannot bind, remove or change a remote witness.

The local anchor log is an append-only sequence of attestations. Verification checks signatures, prefix membership, missing recorded logs and unreadable logs. A newer or non-prefix head is rollback evidence; an invalid signature is a different finding. Accepting a local rollback does not erase a log's contrary evidence. Rekor v2 remains experimental in 1.0.0-rc.2 and has not been exercised against a live log.

Chain anchoring is a separate path that does not write `ANCHOR_RECORDED`: the anchor outbox sends anchor statements to a chain, and the gateway's pre-dispatch barrier checks anchor reports before an admitted call is dispatched. 1.0.0-rc.2 doesn't verify chain anchors itself: its anchor check produces no report, and the barrier takes the mode a supplied report declares on its producer's word. The separate tools used for the demonstration anchoring records report `TRUSTED_NODE` only, never consensus-verified ([known issues 54 and 71](records/KNOWN-ISSUES-r2.5.md)). The [anchoring profiles](spec/SPEC-IRONTRELLIS-ANCHORING-PROFILES-r2.md) define the modes.

### 10.1 Binding remote witnesses

`WITNESSES_BOUND` and `WITNESSES_UNBOUND` record owner-signed witness identities and a policy minimum. Bound URLs, verifier keys and insecure-HTTP choices come from the binding, not from a writable side file. The latest binding event supplies the bound policy; clients combine it with other policy sources only as documented, never weakening that minimum.

A verified registration receipt records that a witness accepted this genesis. A later denial of that registration is different from an unreachable service. A binding created without a receipt cannot make the same assertion. An accepted-loss unbinding records the owner's decision and the heads being abandoned; it does not restore lost events.

The [binding reference](reference/history-storage.md#101-remote-witness-bindings-witnesses_bound-and-witnesses_unbound) keeps the field sets, policy constraints and replay errors. [WITNESS](WITNESS.md) explains freshness, quorum intersections, outages and rotation delivery. Its protocol reference also records the format-2 policy extensions; don't use older format-1-only descriptions as a complete format-2 support matrix.

## 11. Migration and read-only sources

Migration turns a legacy or format-1 history into format 2, using a plan, a fence marker and resumable phases. The source bytes stay unchanged. Each phase is read from the files themselves:

```mermaid
flowchart LR
    P["PLANNED<br/>the plan exists"] --> W["WRITTEN<br/>the format-2 target is complete"]
    W --> N["PINNED<br/>the owner attests the target's head"]
    N --> F["FENCED<br/>a .migrated marker beside the source names the target"]
```

Once fenced, the source is read-only, with `FORMAT_READ_ONLY` and reason `MIGRATED`. Re-running completes the recorded migration rather than starting an unrelated successor, and `--status` reports the actual phase.

Some format-1 sources are refused at plan time with `MIGRATION_UNSUPPORTED`. Each stays readable and verifiable.

| Source | `detail.reason` |
|---|---|
| A format-1 history that was itself migrated from legacy | `SOURCE_ALREADY_MIGRATED` |
| A format-1 history that rotated its owner keys | `SOURCE_KEY_ROTATED` |
| A format-1 history that bound or unbound witnesses | `SOURCE_WITNESS_BOUND` |

Amount conversion follows the specified field-path list and its inverse. It is not a global rewrite of every decimal-looking string or nested signed value. Use [MIGRATION](MIGRATION.md) for the current operational path; a changed package version alone is not a migration.

The old export also describes a **legacy-to-format-1** migration. That historical construction carried the original genesis and endpoint in `migratedFrom`, kept a legacy shadow for signed runtime data, and required the shadow hash to match at the declared endpoint. Its exact fields and checks are kept in the [historical migration reference](reference/history-migration-examples.md#11-migration-and-the-legacy-shadow), only to interpret those existing histories. It is not the current target or writer API: `migrateHistory` and `irontrellis migrate` write format 2 only.

## 12. Historical worked history

The [worked example](reference/history-migration-examples.md#12-worked-example), with the [two stored lines](reference/history-encoding.md#32-format-1-stored-encoding-plain-json), follows a genesis and a principal creation through canonical bytes, effect hash, control challenge, signature, record hashes and history heads. Its fixed test seed is example material, not a deployment key. The values and Python output are kept from an earlier edition of this page; this page does not claim to have rerun the example.

It is a read-only format-1 example, not a current initialization recipe. Use it to tell apart three things often confused during implementation: the stored line bytes, a line's record hash, and the history-prefix hash used in a challenge.

## 13. Side files and limits

Side files share the history path as a prefix. They don't all have the same trust role: some hold secrets, some are signed evidence, and some are attacker-writable caches that must be validated before use. They include:

| Role | Side files, named after `<history>` |
|---|---|
| Secrets | current and staged owner keys (`.owner-key.json`, `.owner-key.pending.json`), committed next keys (`.owner-next-key.json`), retired keys (`.owner-key.<keyId>.retired.json`), the hook's session keys (`.sessions/`) |
| Signed evidence | the pin (`.head`), the anchor log (`.anchors`), the prepared rotation (`.rotation.pending.json`), key-event bundles (`.key-event-<position>.bundle.json`) |
| Writable cache, validated before use | the witness state (`.witness.json`) |
| Locks and records | the writer lock (`.writer-lock`), the witness state's lock (`.witness.json.lock`), the hook's handovers (`.handovers/`) |

The [side-file reference](reference/history-storage.md#13-side-files-and-limits) keeps the exported names, schemas, file modes, atomic-write procedures and crash-settlement rules, plus the catalog's capture, evidence and file bounds. It does not supply a complete current snapshot or state-record specification. Interpret pending files against the actual history; deleting them as general cleanup can interrupt recovery. A writer also checks that it still owns its lock before appending.

### 13.1 Key references

A current, next or retired key file may hold a signer reference instead of private material. The loader distinguishes owner and next-key versions. References are closed records, protected like key files, and signer results are verified against the pinned public key before use. The command signer's `purpose` and `historyId` are advisory, not authenticated policy inputs. The exact reference and command-request fields are in the [reference](reference/history-storage.md#131-key-references-and-the-command-signer-request); operational choices are in [CUSTODY](CUSTODY.md).

## 14. Format-2 reconciliation observations

`RECONCILIATION_OBSERVED` records an admitted session's signed claim about a provider event. The history stores the event's digest, not its full contents. The claim names the supplied call fields, explicitly identifies unsupplied fields, and says whether it matches an earlier admission or refusal for the same actor. It binds the pre-event head and the session context; it has no owner control signature.

Replay distinguishes schema, session fencing, signature and context, transition, duplicate and capacity failures, in a defined order. Repeating the same stream, event and digest is a duplicate; a new digest for the same stream and event records the earliest conflicting observation. State records track both observations and a per-reconciler stream cursor.

The [format-2 extension reference](reference/history-reconciliation.md#14-format-2-reconciliation_observed-type-42) keeps the exact type code, fields, challenge, ordering, record counts and projection flags. A matched claim does not prove that the provider sent every event, or that an external effect happened. Conflicting digests show a changed account, not which account is true.

## 15. Format-2 owner approval policies

An `ownerPolicy` decides how many owner signatures a control event needs, and which keys count.

| Rule | What it means |
|---|---|
| Thresholds | M-of-N control signatures, with per-type thresholds, and rules for events that actually reduce power (`PR_eff`). |
| Co-signatures | Every co-signature covers the same challenge, so the signers approve the same effect at the same position. |
| Rotation | Authorized under the outgoing policy. The new policy belongs to the next epoch; omitting it opens the documented default policy. |
| Agent keys | Cannot authorize alone, or count toward a rotation. |
| Credential separation | Owner, committed-next, attester, session and counterparty credentials are kept apart. |
| Committed-next recovery | Has explicit policy conditions. Replay accepts a recovery rotation, but 1.0.0-rc.2 has no writer that produces one. |
| PHL, `humanFloor: "ATTESTED"` | Current attester statements decide whether a key is HUMAN; expiry produces LAPSED. Lapsed credentials keep specified power-reducing, checkpoint and restoration uses, not general power expansion. |
| T1 and T2 | Restrict time movement in the contexts the policy rules define. |

Readers without full replay state have a narrower task. Witness, resume and export checks apply the available epoch, counting and time rules; `stateChecked: false` identifies omitted full-state checks. A qualified witness signer and a single-key snapshot seed are subject to their own conditions, not merely a valid cryptographic signature.

**A limit today.** The coding-agent hook signs the events of each new session with the single owner key file beside the history and can't collect co-signatures, so it can't yet be used with a multi-signature owner policy or an owner key kept offline ([CUSTODY](CUSTODY.md) §9; [known issue 22](records/KNOWN-ISSUES-r2.5.md) lists the other single-key writer paths).

Use the [owner-policy reference](reference/owner-policy.md) for the exact predicates, ordering and codes. These checks do not establish real-world human identity, or custody beyond the recorded attestation assumptions.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
