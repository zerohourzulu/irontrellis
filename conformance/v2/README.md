# conformance/v2 — format-2 vectors for IronTrellis Core (r2.1 suite; unchanged in r2.2)

86 vectors over one 40-event format-2 history (`histories/budget-v2.json`), with its format-1 twin (`histories/budget-v2-twin-format1.json`) and the two frozen-suite reference histories under `../../inputs-ref/`. Generated 2026-10-10 (r2.1) by the architect's generator in `generate/`; byte-deterministic. r2 regenerated the suite for the r2 rules (completed state records, bounded rollover with `carryBase`, role budgets, refusal/effect bindings, envelope bindings, attestation `domain`, export view); r2.1 fixed the three prefix vectors to pin `rootAt(p)` (the root after the checkpoint's own event record), changed the `intent` record to an `outcomes` list and the `agent` record to carry termination fields, and added the duplicate-nonce vector; the r1 and r2 suites are superseded. These vectors are **frozen by this package** (SPEC §19): the builder regenerates a *separate* suite (`conformance/v2-regenerated`, BUILD-INSTRUCTIONS §5) and never edits this one.

## Running

The suite uses the rc.1-final runner unchanged in protocol (`conformance/legacy/ADAPTER.md`) with the format-2 additions of SPEC §17. The builder adds `--suite v2` to `conformance/run.mjs` (G1):

```
node conformance/run.mjs --suite v2 --adapter conformance/adapters/node.mjs
node conformance/run.mjs --suite v2 --level verifier -- python3 conformance/adapters/python.py   # Python stays format 1: expected to refuse with UNSUPPORTED_VERSION (BUILD §8)
```

Loader rules (mirror of the v1 loader): `vectors.json` is an array; a vector with `history: {ref, eventCount, head}` resolves `ref` to `histories/<ref>.json` and takes the first `eventCount` events (the only ref is `budget-v2`); a vector with `events` carries its own events. The three read-compatibility vectors (`format-1-read`, `legacy-read`) carry inline the events of the frozen suites' `replay/v1/accepts-signed-handover` and `replay/legacy/accepts-handover` vectors, copied byte-for-byte into `../../inputs-ref/` for reference; the `legacy-read` vector keeps the legacy `input` extras (`eventCount`, `eventsSha256`), which the runner passes through unchanged.

Requests per kind (identical to v1 except the new op):

| kind | request | compared fields of the response |
|---|---|---|
| `replay` | `{op:"replay", operationVersion, events}` | `status`, `head` (`hash`, `position`, `canonicalTime`), `code`, **`stateRoot`**, **`projectionHead`** |
| `export` (new) | `{op:"export", events, fromPosition, toPosition, include}` | `version`, `domain`, `genesisEventHash`, `from`, `to` (each with `position`, `head`, `stateRoot`, `projectionHead`, `recordCount`), `eventCount`, `checkpointIds` |
| `authorization` | `{op:"authorize", events, ...input}` (`input` has `domain`, `request`, `evaluationTime`, `policyVersion`, `rootRecognitionPolicy`, `authoritative`, `consequential`, `expectedHistoryHead`, `operationVersion`) | `decision`, `code`, `scopeAssurance`, `controllingAuthorityIds`, `failureCodes`, **`budgetId`** |
| `headroom` (new) | `{op:"headroom", events, budgetId, at}` | the SPEC §9.7 record, or `null` for an unknown budget (compared as a whole) |
| `attestation` | `{op:"verify-attestation", events, attestation}` | `signatureValid`, `prefix`, **`stateRootValid`**, **`projectionValid`**, `valid` |

Comparison is the legacy runner's (declared expected-field projection on objects, exact arrays and scalars with JSON types). Amounts are decimal strings everywhere in format-2 `input`/`expect`; `head`, `stateRoot`, `projectionHead` are `0x`-hex. Non-format-2 histories answer `stateRoot: null`, `projectionHead: null`, `stateRootValid: true`, `projectionValid: true`.

Levels: `verifier` runs `replay`, `attestation` and `export` (and `survives`, none here); `evaluator` adds `authorization` and `headroom`. (`duty-view`, SPEC §17, has no vector in this suite; the builder's regenerated suite uses it.)

## Topics and counts

| topic | kinds | what the vectors establish |
|---|---|---|
| format-2-chain (6) | replay | full history accepted with its pinned head, state root and projection head; three prefixes ending at `cp:1`, `cp:2`, `cp:3` (their `stateRoot` is `rootAt(p)`, after the checkpoint's own `event` record; the checkpoint's `data.stateRoot` is `rootAt(p−1)`); genesis-only (three records: genesis, ownerKeyEpoch 0, event 0); a control event moved to another position fails its signature (`CONTROL_AUTHORIZATION_INVALID`) |
| format-2-encoding (5) | replay | `{"$continuity.bigint"}` amount, negative amount, leading-zero amount → `EVENT_DATA_INVALID`; format-1 literals in a format-2 genesis → `UNSUPPORTED_VERSION`; `domain.version` `"1"` in format 2 → `EVENT_DATA_INVALID` |
| budgets (11 + 16) | replay, authorization | schema (no cap, zero-length window, update leaving no cap, rollover without `carryCap`, unknown subject key), unsigned/tampered declaration, duplicate id, update of unknown id, admission the budgets refuse, admission whose metric differs from the declaration (`TRANSITION_INVALID`); decisions: rollover after a cap lowering (frozen `carryBase`: allow 10 / deny 11), role budget allow/deny (`roleIds`), subjects update covering a new resource, per-operation at/over cap, authority denial precedes budgets, period undefined before origin, expired budget ignored, closed budget ignored, zero amount, other metric not matched, INDETERMINATE untouched, exact fill of period 0 and one over |
| signed-intents (4) | replay | missing `declarationAuthorization` → `EVENT_DATA_INVALID`; wrong key or altered amount → `DECLARATION_AUTHORIZATION_INVALID`; a second declaration with the same `(actorId, nonce)` → `TRANSITION_INVALID` |
| refusals (9) | replay | not reproduced (code differs / would be allowed), tampered code, stale head, CONNECTOR without `connector`, stranger signature, actor mismatch, `evaluationTime ≠ timestamp`, CONNECTOR refusal signed by a session other than the connector's |
| checkpoints (4) | replay | wrong state root, wrong record count, wrong projection head, citing another head |
| effects (3) | replay | unknown intent, tampered amount, `measurer.id` not the signing session's agent |
| counterparty-receipts (8) | replay | unregistered counterparty, bad envelope signature, chain break, altered envelope, stale wrapper, envelope for another history (`historyId`), envelope for another intent (`intentDigest`), re-registering an ACTIVE counterparty |
| headroom (9) | headroom | period 1 after the cap lowering (rollover 5 frozen, remaining 10), period 0 view, period 2 rollover from the base (10 → remaining 70), period 1,000,000 idle stretch in constant work (remaining 110), period 1 before the lowering (remaining 50), closed budget, before origin, unknown budget (`null`), view before an update at an earlier head |
| attestation (7) | attestation | valid final head, wrong state root, wrong projection head, stranger key, earlier head, not a prefix, wrong domain label |
| export (1) | export | the view from the `cp:1` position to the `cp:3` position with the roots at both ends pinned |
| format-1-read (2) | replay | the frozen v1 signed-handover history still replays byte-identically; a format-2 event kind inside a format-1 history → `UNSUPPORTED_EVENT_TYPE` |
| legacy-read (1) | replay | the frozen legacy handover history still replays |

Total 86: replay 53, authorization 16, headroom 9, attestation 7, export 1. `MANIFEST.json` lists every vector id with its kind, topic and purpose, and the history's event count, head, state root (`0x6a26…3d85`), record count (75) and projection head. Pinned roots: genesis-only `0xa74d…351d` (3 records); cp-1 prefix (position 24) `0x3b4d…7071` (53); cp-2 prefix (33) `0x6614…7c0d` (66); cp-3 prefix (36) `0x804c…17b0` (72); full history (39) `0x6a26…3d85` (75); the export vector pins positions 24 and 36 again; the four checkpoints carry `rootAt(p−1)`: `0xcd3d…889f` (52), `0x0d2c…98ed` (65), `0x2648…7ebc` (71), `0xfcbb…c1e7` (74).

## The history

`budget-v2` (domain `irontrellis-conformance-v2`, format 2), 40 events: genesis (owner `owner:1`, next-key digest of `owner:2`), principal `operations`, agent `spender`, role `cashier`, tenure `cashier:1`, session `session:spender` (key `key:spender`, expires 5000), the connector's agent `gateway` and session `session:gateway` (key `key:gateway`), grant `metered` (spend on `petty-cash`, `petty-cash-2/3/4`, max 100 per operation), budgets `b-amount` (`FIXED_WINDOW` 1000 ms from 0, `amountCap` 100, rollover up to 50) and `c-count` (`countCap` 2 → updated to 3 → closed), later `d-perop` (`perOperationCap` 40 on `petty-cash-2`, subjects later extended to `petty-cash-3`), `e-future` (origin 2000, `petty-cash-3`), `f-expired` (`expiresAt` 1050, `petty-cash-4`), `g-role` (`roleIds: [cashier]`, `perOperationCap` 30 on `petty-cash-4`); admissions of 60, 30 (period 0), 5 (period 0, after the count update) and 55 (period 1, t = 1100, rollover 5); five refusals (BUDGET amount, BUDGET count, CORE, BUDGET per-operation, CONNECTOR signed by the gateway session); four checkpoints; one effect; counterparty `acme` registered with two chained receipts; at the end `b-amount`'s cap lowered 100 → 60 (rollover 5 frozen in `carryBase`) and `d-perop`'s subjects updated, then `cp:4`. Positions 0–39: genesis, principal, agent, role, appointment, session, gateway agent, gateway session, grant (0–8); `b-amount`, `c-count` (9–10); declare/admit 60 (11–12); declare/admit 30 (13–14); refusals amount, count, core (15–17); `d-perop`, `e-future`, `f-expired`, `g-role` (18–21); refusals per-operation, connector (22–23); `cp:1` (24); effect (25); counterparty registered (26); two receipts (27–28); `c-count` updated (29); declare/admit 5 (30–31); `c-count` closed (32); `cp:2` (33); declare/admit 55 at t = 1100 (34–35); `cp:3` (36); `b-amount` lowered, `d-perop` subjects (37–38); `cp:4` (39).

## How it was generated, and what is SPEC ORACLE

`generate/generate.mjs` (with `generate/lib.mjs`) is the architect's generator. It is **not** a format-2 engine and must not be mistaken for one:

1. The unchanged-semantics prefix is built as a **format-1 twin** with the frozen rc.1-final engine (`IRONTRELLIS_RC1_DIST` → `packages/core/dist` of a built rc.1-final tree), so every admission's `authorizationProof` is the engine's own. The twin is saved as `histories/budget-v2-twin-format1.json`.
2. The twin is **transcribed** to format 2 (SPEC §16.3): Amount strings, format-2 literals and domain, control events re-signed over the §6.1 challenge with the format-2 chain head, admissions re-signed over the §8.2 challenge, consumptions dropped, `declarationAuthorization` added. New format-2 events are then inserted natively.
3. Expectations: authority decisions come from the rc.1 engine on the twin (`core.authorizePortable`); everything new comes from the functions marked **SPEC ORACLE** in `lib.mjs` — `evaluateBudgets`, `remainingAmountOf`, `carryIn` (closed-form rollover with `carryBase`), `periodIndex`, `budgetMatches` (incl. `roleIds` via `rolesOf`), `chargeBudgets`, `headroom`, `stateRoot`/`stateLeaf`/`merkleRoot`, `projectionFields`/`projectionRow`/`projectionHeads` — and from the state tracker `tracker()` in `generate.mjs` (the §7.2 record table in code, including the `event` and `nonce` records and `carryBase`). These are the only places where decision logic lives outside the SPEC. If the SPEC and an oracle function disagree, that is a spec contradiction under the builder's stop rule: stop and report; do not "fix" either side.

Mechanical (not oracle) parts of `lib.mjs`: canonical encoding (rc.1's `canonicalEncode`), SHA-256, `eventHash`, `recordHash`, store lines, the challenge constructors (`controlChallenge`, `runtimeChallenge`, `declarationChallenge`, `refusalChallenge`, `effectChallenge`, `counterpartyRecordChallenge`, `attestationBody`), Ed25519 signing and verification via rc.1's signer and Node's `crypto`.

`generate.mjs --check` regenerates everything in memory and exits 1 if any output file differs; its scratch files go to the OS temp directory (`irontrellis-v2-generate-<pid>`), never into the package.

Self-check (`SELF-CHECK.json`, `ok: true`): every control signature verifies against `owner:1` over the §6.1 challenge with the chain head; every declaration, admission, refusal, effect and receipt wrapper verifies against the named session's key (`key:spender`, or `key:gateway` for the connector refusal) over its challenge, and every refusal's `evaluationTime` equals its timestamp; every counterparty envelope verifies against `acme:1`; every checkpoint's `head`, `stateRoot`, `recordCount` and `projectionHead` match a recomputation from scratch; the store lines re-chain; the projection chain re-derives; the §7.2 `event` records re-derive the chain; timestamps never regress; every type is one of the 41. The sha256 of `histories/budget-v2.jsonl` is recorded there.

What this suite cannot cover (and the builder's regenerated suite must, cross-checked at G2.5): obligations, duties and the duty-policy machinery, issuer receipts, consumptions, outcomes and observations, successions, anchors, owner-key rotation and witness binding in format 2 (and their state records), `migrate` with its fence, EIP-191 sessions, `BUDGET_SET_TOO_LARGE`, the 257th budget, `EFFECT_LIMIT`, `CAPACITY_EXCEEDED`, `AMOUNT_OVERFLOW`, a `roleIds` budget across a real handover, counterparty re-registration after retirement, export views with records.

## Regenerating (architect only)

```
IRONTRELLIS_RC1_DIST=/path/to/irontrellis-1.0.0-rc.1/packages/core/dist node conformance/v2/generate/generate.mjs --check
```

requires Node ≥ 20 and a built rc.1-final tree (`pnpm install --frozen-lockfile --ignore-scripts && pnpm -r run build`). Regeneration without `--check` rewrites the files; since the suite is frozen, a rewrite that changes any byte is a format change and needs a new suite directory, not an edit here.

## Test keys

See `TEST-KEYS.md`. All keys are published test material; never use them outside conformance.
