# irontrellis (Python)

IronTrellis (formerly Continuity) is a signed, replayable record of authority, duties and succession for AI agents. This package is its **Python verifier and evaluator** for legacy and format-1 histories: it reads a captured history, verifies it, and answers the same `authorize` and `survives` questions as the TypeScript engine, with the same answers. It shares no code with the writer, so it is an independent second check. Agents change. The structure holds.

> **Legacy and format-1 histories only.** IronTrellis 1.0.0-rc.2 writes format 2, and this package doesn't read it: it refuses a format-2 history with `UNSUPPORTED_VERSION`. The package stays at version 1.0.0rc1 until it is ported to format 2. To verify a format-2 history, use the Node CLI's `irontrellis verify`.

## 60-second quickstart

It needs Python 3.11 or later, and has no dependencies.

```sh
pip install --pre irontrellis     # a release candidate: pip skips pre-releases without --pre
# or, from a checkout of the repository: pip install ./python
python -m irontrellis verify history.jsonl
python -m irontrellis authorize history.jsonl --actor alex --action read --resource incident:42
python -m irontrellis survives history.jsonl --agent bea
python -m irontrellis verify-receipt receipt.json --verifier-key 'witness.example+1a2b3c4d+AQ…'
```

| Command | What it answers | Exit code |
|---|---|---|
| `verify <history>` | Replays the history and reports its head, agents, authorities, anchors and witness bindings | 0 accepted; 1 rejected or unreadable |
| `authorize <history> --actor --action --resource` | ALLOW, DENY or INDETERMINATE for one request, at the head (`--at` for another time; `--amount` and `--counterparty` where the request needs them; `--full` for the whole result) | 0 ALLOW; 2 DENY or INDETERMINATE; 1 rejected or unreadable |
| `survives <history> --agent` | What the agent's departure leaves behind (`--at` for a later time) | 0; 2 for a time before the head (`CAUSAL_TIME_INVALID`); 1 rejected or unreadable |
| `verify-receipt <receipt.json> --verifier-key <vkey>` | Whether a remote witness receipt is valid, against the witness verifier keys you trust (repeat `--verifier-key` for each) | 0 valid; 1 invalid or unreadable |

The package also installs the same commands as `irontrellis-py`.

```python
from irontrellis import replay_history, authorize_state, derive_survives, BigInt

stored, result = replay_history("history.jsonl")    # either store format; records checked and replayed line by line
# result: ACCEPTED with a state, or REJECTED with a code and position (a record defect raises StoreError)
state = result.state
decision = authorize_state(state, {
    "expectedHistoryHead": state.head,
    "domain": state.genesis["domain"],
    "policyVersion": state.genesis["policyVersion"],
    "rootRecognitionPolicy": state.genesis["rootRecognitionPolicy"],
    "request": {"actorId": "alex", "action": "pay", "resource": "ledger", "claimedAt": state.head["canonicalTime"], "amount": BigInt(50)},
    "evaluationTime": state.head["canonicalTime"],
    "consequential": False,
})
print(decision["decision"], decision.get("code"))   # ALLOW / DENY / INDETERMINATE and the code
print(derive_survives(state, "bea", state.head["canonicalTime"])["lifecycleStatus"])
```

Every decision reads a captured history; it does not execute anything.

## What it verifies

* **Legacy and format-1 histories.** `continuity-event/0.2` (legacy tagged-tuple store lines, keccak-256 record hashes) and `irontrellis-event/1` (plain JSON lines, sha256). The store reader checks every line's `previousHash` chain and `recordHash`.
* **Replay, exactly as the reference.** The canonical encoding is byte-identical to the TypeScript `canonicalEncode`; the 29 event schemas, the genesis probe, the named-limit preflight (`INVALID_INPUT` vs `EVENT_DATA_INVALID`) and every transition precondition are ported from the engine, so the same history is accepted or rejected at the same position with the same code. The fuzzer found three exceptions (known issues 72, 74 and 75 in docs/records/KNOWN-ISSUES-r2.5.md): two malformed inputs that both engines reject at the same position, with different codes, and one text that the TypeScript parser accepts and this package rejects, which only a JavaScript string can carry, never a stored file.
* **Signatures.** Runtime signatures on admissions, receipts and administrative events are verified with pure-Python secp256k1 recovery (EIP-191 personal-sign) or Ed25519; proofs inside admissions are re-derived and compared canonically. Format-1 **control events** must carry an owner signature over the pre-event head by an owner key in force at their position (`CONTROL_AUTHORIZATION_INVALID` otherwise): an unsigned, moved, edited or mis-keyed control event is refused.
* **Owner key rotation** (`OWNER_KEYS_ROTATED`): owner key epochs (`state.owner_key_epochs`), the key-set rules (a retired key id never returns, an id is never re-bound, no second name for a key; `TRANSITION_INVALID`), `owner_keys_at(state, position)`, `verify_head_attestation_at(attestation, state)` (a head attestation judged by the keys in force at the attested position) and `verify_rotation_event(event, domain, previous_head, epochs)`.
* **Pre-rotation**: epochs carry `nextKeyDigests` (a commitment to the digests of the next owner keys, `owner_key_digest(key)`), fixed by the event that opens the epoch: the genesis (`nextKeyDigests` in `DEPLOYMENT_INITIALIZED`) or a rotation. A rotation out of a committed epoch must reveal committed keys, prove possession of one (`nextKeyAuthorizations`, signatures over the rotation's own control-authorization challenge) and commit again; a rotation that keeps every key must add a commitment (the commitment-only rotation, `keeps_every_owner_key`); `TRANSITION_INVALID` otherwise. `verify_rotation_event` returns `preRotated`, `commitmentOnly` and the new epoch's `nextKeyDigests`; `owner_key_event_transition` is the rule set replay shares.
* **Witness bindings.** `WITNESSES_BOUND` / `WITNESSES_UNBOUND` with their closed schemas and replay rules (a registration receipt must be the witness's signed `REGISTERED` leaf of this history; quorum, accepted-loss and migrated-prefix rules), `bound_witnesses_of(state)` and `bound_policy_of(state)`.
* **Remote witness receipts** (`irontrellis.transparency`): RFC 6962 / RFC 9162 Merkle leaf and node hashing, roots, and the iterative inclusion and consistency proof verifiers (`verify_inclusion`, `verify_consistency`: False for any bad input, never an exception); C2SP signed notes as in `golang.org/x/mod/sumdb/note` (`open_note`: strict padded base64, `— ` U+2014 signature lines, at most 100 signatures, unknown signers ignored, a known key with a bad signature rejects the note, Go's key-name rules; `parse_verifier_key`), tlog checkpoints (`parse_checkpoint`), owner-signed head statements (`verify_signed_head_statement` against the owner keys in force at the head position), witness log entries (`validate_entry`, including the `historyId` of a `REGISTERED` genesis and a `ROTATED` entry's `previousHead` one position before its `rotationHead`; `entry_leaf_hash`) and `verify_witness_receipt(receipt, trusted_verifier_keys)`, with the TypeScript core's reason codes in its order: `RECEIPT_MALFORMED`, `NOTE_UNVERIFIED`, `CHECKPOINT_MALFORMED`, `ORIGIN_MISMATCH`, `ENTRY_MALFORMED`, `INDEX_OUT_OF_RANGE`, `INCLUSION_INVALID`. `python -m irontrellis verify-receipt <receipt.json> --verifier-key <vkey>` does the same from the command line (exit 0 valid, 1 invalid).
* **Migrated histories.** A format-1 history with `migratedFrom` rebuilds the legacy shadow heads for the re-recorded prefix so the original runtime signatures still verify, and checks the prefix reproduces the source head. A history that ends inside its declared prefix (head position below `migratedFrom.position`) is refused with `TRANSITION_INVALID` (`migrated prefix incomplete`), exactly as the Node engine does.
* **Anchors.** `ANCHOR_RECORDED` must cite a prefix hash of this very history.
* **The full decision procedure** of Continuity's authorization specification (docs/legacy-semantics/02-authorization.md in the repository): domain/policy checks, the validated authority corpus (delegation paths, attenuation, intersection cycles, recognized roots), candidate evaluation with the exact failure precedence, prohibitions (ROOT and GLOBAL), time windows, per-request amounts and usage-based cumulative/count caps, consequential bindings, and the ALLOW **proof** with `controllingAuthorityIds`, `usageSnapshot`, `authorityEvidence` and `checkedProhibitionIds`. DENY/INDETERMINATE results carry the sorted failure list with event evidence references, as the engine emits them.
* **SURVIVES**: what an agent's departure leaves behind — lifecycle, tenures, unresolved intents, adapter outcomes, obligations and current performance assignments, invalidated authority dependencies, and, in a history made for the attempt recorder (adapter edition E5 or E6), outcome observations and attempt duties.

## What it does not do

**It doesn't read format 2.** The port to format 2 is pending; it will be written from the format-2 specification and its conformance suites. Until then:

| You give it | It answers |
|---|---|
| A format-2 history file (`.jsonl`), to `python -m irontrellis verify` | `ERROR` with the code `UNSUPPORTED_VERSION`, exit 1: the store reader refuses format-2 lines |
| Format-2 events (a `.json` array) | `REJECTED` at position 0 with `UNSUPPORTED_VERSION`, exit 1 |
| A receipt for a format-2 history, to `verify-receipt` | `INVALID` (`ENTRY_MALFORMED`), exit 1: it reads receipts of format-1 histories only |

**It does not detect truncation.**

| What | Checked by `python -m irontrellis verify` |
|---|---|
| The record chain, every signature, and that a migrated prefix is complete | Yes |
| The pinned head (`<history>.head`) | No |
| The anchor log (`<history>.anchors`) | No |
| The remote witness settings (`<history>.witness.json`), and the witnesses themselves | No: it never contacts a witness |

When the history binds remote witnesses (owner-signed `WITNESSES_BOUND` events, which it replays and checks), its report lists them in `witnessBindings`, the owner-signed policy minimum of the newest binding in `witnessPolicyMinimum` (`{quorum, requireOnOpen, maxUnwitnessedEvents}`, or `null`), and carries the note `REMOTE_WITNESS_NOT_CONSULTED` (the same code as the Node verifier's check without the network). `verify-receipt` checks one receipt you hand it, not that the history matches the witness's latest head.

So a history with a whole suffix removed is still a valid chain, and it passes: `ACCEPTED`, exit 0, and `authorize` answers from the shortened history (a revocation that was cut off no longer counts). Use `irontrellis verify` (the Node CLI) when you need rollback and truncation detection, and this verifier as a second, independent check next to it.

The other limits:

* It **never writes a history**. Appending events, signing control events, pinning heads, anchoring and migration are the TypeScript engine's job (`@ramex-labs/irontrellis`, the `irontrellis` CLI).
* It has no check of a published history id and owner keys (the Node CLI's `verify --expect-history-id` and `--expect-owner-key`): it confirms a file against itself only.
* It does not produce query **envelopes**: `survives_portable` reproduces the portable SURVIVES query's capture, discovery, replay and causal-time checks and its answer rows, but not the evidence lists, disclosure negotiation or the output budget of `continuity-query-envelope/0.2`. WHY and RESPONSIBLE are not implemented.
* It does not admit intents, issue receipts or evaluate receipt policy, and it has no store locking.
* Ed25519 verification is pure Python (≈2 ms per signature). Install the optional extra `pip install --pre "irontrellis[fast]"` to verify with OpenSSL through `cryptography`; the result is the same.

## Conformance

The package passes the repository's conformance suites through `conformance/adapters/python.py`: every legacy and every format-1 vector (`node conformance/run.mjs --suite all --adapter conformance/adapters/python.py`). `tests/test_transparency.py` runs every section of `conformance/transparency/vectors.json` (Merkle, notes, keys, checkpoints, statements, entries, receipts; RFC 6962, `sumdb/note` and C2SP published vectors included) in-process. A differential pytest runs the Python and TypeScript engines over every fixture history and thousands of generated requests and compares the full results. It needs `node` and a built TypeScript core (`packages/core/dist`); without them, pytest skips it.

```sh
cd python && pip install -e ".[test]" && pytest
```

## Performance

Measured on 24 September 2026, with Python 3.11 on one core of a small shared machine (docs/history/BENCHMARKS-2026-09-24.md, §8, in the repository). These are dated measurements, not a guarantee.

| History | Replay |
|---|---|
| The legacy handover fixture, 26 events (keccak-256, secp256k1 recovery and proof re-derivation in pure Python) | about 150 ms |
| 2,001 format-1 events, 2,000 of them owner-signed control events, with `cryptography` | about 1 s |
| The same history, pure-Python Ed25519 | about 5 s |

A warm `authorize_state` on the replayed state takes well under a millisecond; the first call on a state builds the corpus index (a few milliseconds per thousand authorities). `python/bench/replay_bench.py` reproduces the numbers.

## Reference

* `irontrellis.canonical` — `canonical_encode`, `capture_value`, `BigInt` (a JavaScript `bigint`; a plain `int` is always a JavaScript number), `to_plain`/`from_plain` for the `{"$continuity.bigint": …}` wire marker.
* `irontrellis.hashing` — `hash_canonical`, `HistoryHasher`, `hash_event_history_prefixes`.
* `irontrellis.crypto` — `keccak256`, `recover_address`, `eip191_digest`, `ed25519.verify`, `suite_for(scheme)`.
* `irontrellis.store` — `replay_history(path)` / `replay_history_bytes(data)` → `(StoredHistory, ReplayResult)`: each line's record checks, then its event, before the next line, with the replay rules of the file's line format, exactly as the TypeScript store reads a file (the first defect in file order is the one reported; `python -m irontrellis verify` uses it). `read_history(path)` / `read_history_text(text)` → `StoredHistory(format, events, record_hashes)` check the record chain, and refuse a file whose genesis declares another event format than its lines (for example an owner-unsigned legacy history in format-1 lines) with `HistoryRejected` (a `StoreError` carrying the `code`, `position` and `reason` the TypeScript store and `replay_history` report, `EVENT_DATA_INVALID` at 0), so `replay(stored.events)` and `replay(load_events(path))` always replay a store under the rules its lines declare. They do not replay: use `replay_history` for the first defect in file order. `load_events` reads `.json` arrays too (`StoreError` when the file is not a JSON event array).
* `irontrellis.replay` — `replay(events)`, `replay_portable(operation_version, events)`, incremental `apply_event(state, raw)`.
* `irontrellis.owner_keys` — `owner_keys_at`, `verify_head_attestation`, `verify_head_attestation_at`, `verify_rotation_event`, `owner_key_digest`, `owner_key_event_transition`, `owner_key_rotation_failure`.
* `irontrellis.transparency` — `leaf_hash`, `node_hash`, `root_of`, `inclusion_proof`, `consistency_proof`, `verify_inclusion`, `verify_consistency`, `decode_base64` (strict), `note_key_hash`, `verifier_key`, `parse_verifier_key`, `parse_signer_key`, `sign_note`, `open_note` → `OpenedNote(body, verified_by)` or `NoteError(code)`, `format_checkpoint`, `parse_checkpoint` → `Checkpoint(origin, size, root, extensions)`, `validate_head_statement`, `head_statement_hash`, `verify_signed_head_statement(signed, owner_keys)` (a `position -> keys` callable, a replay state or key epochs), `validate_entry`, `encode_entry`, `entry_leaf_hash`, `verify_witness_receipt`, `bound_witnesses_of(state)` (the remote witnesses a history binds, as the Node core's `boundWitnessesOf`).
* `irontrellis.authority` — `authorize_state(state, body)`, `authorize_portable(input)` (the legacy `continuity-authorization/0.2` envelope), the challenge, proof and transition validators.
* `irontrellis.survives` — `derive_survives(state, agent, at)`, `survives_portable(...)`.

Concepts: see `docs/PRINCIPLES.md` and `docs/GLOSSARY.md` in the repository. License: Apache-2.0.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
