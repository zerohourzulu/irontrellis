# conformance/v2-g3 — the architect's format-2 suite, regenerated under A-54 / A-59

Regenerated from the architect generator per A-54 (founder-approved 2026-10-11) and A-59; differs from conformance/v2 only in the session challenges of §8.6/§10.1/§10.2/§11.2.

`conformance/v2` stays frozen, byte-identical, as the r2.3 record (it verifies under the challenge profile `frozen-r2.3`). This directory holds the same vectors (same ids, kinds, topics, purposes and expected codes) over the same 40-event history, re-signed with the challenges of profile `g3`: the intent-declaration (§8.6), refusal (§10.1, A-59), effect (§10.2) and counterparty-wrapper (§11.2) challenges also bind the event's `eventId`, `eventType` (the challenge's own literal) and `timestamp`; the `/2` literals are kept; the §8.2 runtime challenge and the control and lifecycle challenges are unchanged. A history is verified under one profile (A-59.3). Location: provisional decision of the lead (DEVIATIONS).

## Running

```
node conformance/run.mjs --suite v2-g3 --adapter conformance/adapters/node.mjs     # profile g3 (passed to the adapter as IRONTRELLIS_CHALLENGE_PROFILE)
node conformance/run.mjs --suite v2    --adapter conformance/adapters/node.mjs     # the frozen r2.3 record, profile frozen-r2.3
```

Loader, request shapes and comparison: as `conformance/v2/README.md`.

## Regenerating

```
IRONTRELLIS_RC1_DIST=<1.0.0-rc.1 baseline tree>/packages/core/dist node conformance/v2-g3/generate/generate.mjs [--check]
```

The 1.0.0-rc.1 dist is built from the baseline commit `e50cc8c` (`packages/core`, `tsc -p tsconfig.json`); with it the frozen generator reproduces `conformance/v2` byte for byte, and this generator reproduces this directory byte for byte (`--check`).

## What changed against `conformance/v2/generate/` (G2-APPLY-NOTES §4, changes 1–9)

1. `lib.mjs declarationChallenge(domain, data, head, session, envelope)`: `eventId`, `eventType: "TRANSACTION_INTENT_DECLARED"`, `timestamp`.
2. `lib.mjs refusalChallenge(domain, d, envelope)`: `eventId`, `eventType: "REQUEST_REFUSED"`, `timestamp` (A-59.1).
3. `lib.mjs effectChallenge(domain, d, head, envelope)`: `eventId`, `eventType: "EFFECT_RECORDED"`, `timestamp`.
4. `lib.mjs counterpartyRecordChallenge(domain, d, head, envelope)`: `eventId`, `eventType: "COUNTERPARTY_RECEIPT_RECORDED"`, `timestamp`. A missing envelope throws.
5. `runtimeChallenge` (§8.2), `controlChallenge`: unchanged.
6. The refusal, connector-refusal, effect and wrapper constructors draw the event id before hashing (same counter values as before); the declaration passes its transcribed event.
7. Every negative vector that re-signs a session-signed event passes that event (its id and timestamp) as the envelope.
8. The self-check recomputes each challenge with the event as the envelope.
9. Outputs regenerated: `vectors.json`, `histories/`, `MANIFEST.json` (`suite: "v2-g3"`, `challengeProfile: "g3"`), `SELF-CHECK.json`.

Also: the header comment, and `inputs-ref` is read from `conformance/inputs-ref` (the build tree's layout; the architect's tree had it one level higher). No other line differs (`diff -r conformance/v2/generate conformance/v2-g3/generate`).

## Effect on the outputs

Events 0–10 and the format-1 twin are byte-identical to `conformance/v2`; from position 11 (the first declaration) every signature, event hash, record hash, projection head and state root after it changes. Expected codes are unchanged; the vectors that stop before position 11 or carry the frozen format-1/legacy events are byte-identical, the others differ in the events or attestation they carry, and the five that pin a head, state root or projection head after position 10 pin new values.

Pinned roots (`rootAt(p)`, record count): genesis-only (0) `0xa74d0c60…351d` (3, unchanged); cp-1 prefix (24) `0x0b9593f9…3fae` (53); cp-2 prefix (33) `0xe6ca555b…36b1` (66); cp-3 prefix (36) `0xa8d48373…dbc6` (72); full history (39) `0xb08326ad…b3d6` (75), head `0x7cbde34e…7108`, projection head `0x5bf92cd7…5600`. Checkpoint `data.stateRoot` (`rootAt(p−1)`): cp:1 `0x3fd08f20…1ef1` (52), cp:2 `0xd6030a7e…35c8` (65), cp:3 `0xac8327a6…3583` (71), cp:4 `0x894a9856…0dbd` (74). The full values are in `MANIFEST.json`, the vectors and `RESULTS/PINNED-ROOTS.json`.
