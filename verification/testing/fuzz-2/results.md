# FUZZ-FORMAT2-02 (D+ (d)): results of the 23-hour format-2 differential run

*Builder (Mac), 2026-10-26. The run was on our Linux test VM, branch fuzz-format2-01 at 5835c26, with the independent format-2 checker g25/12 (g25-worker-02.py). It started 2026-10-25T04:23:08Z and ran 1,380 minutes. Results: fuzz-format2-02-results.tgz (sha256 d2c79fa2…), unpacked in x/. The serious cases are in cases/, and are replayed on master 7213a52 with replay-case.mjs.*

## The campaigns

| target, seed | iterations | exec/s | failures (unique) |
|---|---:|---:|---:|
| replay 311 / 312 / 313 | 1.20 M / 1.19 M / 1.18 M | 14.4 | 99 / 98 / 104 |
| events 341 | 428.6 M | 5,176 | 23 |
| store 321 / 322 | 2.00 M / 2.02 M | 24 | 2 / 1 |
| transparency 331 | 438.9 M | 5,300 | 0 |
| canonical 351 | 5.8 M (run 7 only) | 1,937 | 0 |

No regressions, and no `findings` entries.

**Canonical 351:** six of its seven runs died at the 2 GiB heap cap, each after about 3½ hours. The cause is V8 "Mark-Compact … allocation failure"; the restart wrapper resumed each one. This is heap growth in the canonical target, a fuzzer issue rather than an engine finding.

## The failures, by tier

| tier | count | what |
|---|---:|---|
| TS_F2_DISAGREE (replay) | 290 | TypeScript and g25 disagree. Almost all are both-refuse cases with different first codes or positions. 24 are verdict differences (below) |
| F2_CHECKER_CRASH | 9 | g25 raises AttributeError on non-string values (`'int'/'bool'/'NoneType' object has no attribute 'encode'`). A g25 bug |
| SIGNED_CONTENT_ALTERED | 2 | an accepted event carries a signature over other content. Needs triage (below) |
| TS_PY_DISAGREE (events) | 23 | TypeScript and the Python package's validateEvent on formats 0.2 and 1. The duty-policy types in 0.2 (Python UNSUPPORTED_EVENT_TYPE), INVALID_INPUT against EVENT_DATA_INVALID for over-length Identifiers, and format-2 fields in format 1. Known differences between the packages; to check against KNOWN-ISSUES |
| TS_PY_DISAGREE (store) | 3 | the store reader: format-2-only fields in format 1 (TS EVENT_DATA_INVALID, Python UNSUPPORTED_VERSION) |

## The verdict differences (F2_VERDICT)

**TypeScript accepts, g25 refuses: 4 cases (counts 7, 5, 7, 1). One root cause, a finding.** All four are migrated histories, three from a 0.2 source and one from a format-1 source. In each, `migratedFrom.versions` differs from the source genesis's own `migratedFrom.genesis.versions` in one or two literals:
- a space inserted: `irontrellis-con trol-authorization/1`;
- a leading space;
- `runtimeAuthorizationVersion` and `administrativeAuthorizationVersion` swapped;
- a 64-byte hex blob in place of a version string.

The fuzzer then re-signed the history:
- TypeScript checks `migratedFrom.versions` only as a closed set of Identifiers (events.ts, about line 1028) and uses the source genesis's versions. It accepts.
- g25 builds the shadow challenges from `migratedFrom.versions`, so its signature or hash checks fail, and it refuses.

r5.2 §16.2 step 4 says `versions` is "the source `versions` block as written". No check or code is stated for a mismatch. All four still replay ACCEPTED on master 7213a52.

**TypeScript refuses, g25 accepts: about 20 patterns.** These are g25's gaps. g25 lacks:
- the Identifier type on untyped fields (known divergence 01);
- the nesting-depth and ProtocolString limits;
- the witness-binding receipt checks;
- the malformed control signature check;
- A-17.2's migrated-domain rule.

None is an engine finding.

## Still to triage

- **The 2 SIGNED_CONTENT_ALTERED cases: both are false positives of the fuzzer's invariant** (triaged 2026-10-26). fuzz/lib/invariants.mjs `signaturesOf` collects every signature-shaped string anywhere in an event's data (`/^0x[0-9a-f]{128,130}$/`). In both cases the fuzzer copied a seed signature into a field that carries no signature:
  - the format-1 genesis's `canonicalLineageId`, an Identifier;
  - an ANCHOR_RECORDED `receipt.witness.actorId.signature`, inside `receipt`, which the core schema accepts as any plain record (events.ts ANCHOR_RECORDED) and never verifies.
  Neither is a signature the engine relies on. Fix in the fuzzer (rc.3): match signatures only at the slots the schema defines as signatures.
- **The events/store TS_PY_DISAGREE items:** check them against KNOWN-ISSUES.
