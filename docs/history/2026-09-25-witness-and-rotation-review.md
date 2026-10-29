> **Pre-release internal review.** This report was written while IronTrellis 1.0.0-rc.1 was being built, before its first public release, and is kept verbatim as a record. Its findings were fixed before 1.0.0-rc.1 or are listed as known limitations in [docs/SECURITY.md](../SECURITY.md) §8. Paths under `/home/claude` and `/tmp`, internal build-stage names (an "rc.1" baseline, "blocks", "rc.2"), and design notes it cites (such as WITNESS-DESIGN or WIRE-DEVIATIONS) belonged to that development process and are not part of this repository. Code names, error codes and wire fields may differ from the released ones; [CHANGELOG.md](../../CHANGELOG.md) and the docs describe what shipped. See [README.md](README.md) in this folder.

# Security & correctness review — IronTrellis block 2 (witness + owner-key rotation)

Reviewer: independent, adversarial, read-only. Target: `/home/claude/irontrellis-next`
(new code) vs `/home/claude/irontrellis-rc1-baseline`. Design authority:
`/home/claude/irontrellis-work/next/WITNESS-DESIGN.md` (§1, §8–§9), `WIRE-DEVIATIONS.md`.

PoCs live in `/tmp/review-b2/` and were run against **built code**: a snapshot
(`/tmp/review-b2/snap`, dist as of 15:38) and a **fresh rebuild of the live tree**
(`/tmp/review-b2/live`, `core` + `witness` rebuilt from the source the concurrent
fixing agent had produced by review time, i.e. with the new https-only /
`allowInsecureHttp` / `IRONTRELLIS_WITNESS_POLICY` work already present). The two
top findings were re-verified against the live rebuild.

Threat model used: an attacker who can read/write every file on the agent host
(history, `.head`, `.anchors`, `.witness.json`) and sits on the client↔witness
network, but does **not** hold an owner private key (except where a finding says
the key is stolen). Owner code (CLI/hooks/gateway) is honest.

---

## BLOCKER

### B1. A witness-bound history is silently rolled back with no owner key and no TLS break — the witness's `latest` is not proven to be the latest, and the attacker-writable side file can relocate a *bound* witness's endpoint

**Files:**
- `packages/core/src/witness-client.ts` — `history()` L546–561, `#witnessedHead()` L488–502, `#observe()` L428–460 (checkpoint consistency accepts *smaller-but-consistent*).
- `packages/core/src/witness-session.ts` — `#load()` L416–466 (a bound witness is added only if its `verifierKey` is not already in the side-file/explicit policy → the side file’s URL for that key wins), `remoteFindings()` / `check()` (compare `latest` with the file).

**Root causes (two, combined):**
1. **Freshness is never proven.** `latest` from `GET /v1/histories/:id` is trusted after
   verifying an *inclusion* proof against a *consistent* checkpoint. An inclusion proof
   plus a checkpoint proves a head is **in** the log; it does **not** prove it is the
   **tip**. Any relay can hand the client a genuine, correctly-signed receipt for an
   **older** head and call it `latest`. `#observe` even explicitly accepts a *smaller*
   checkpoint than one already seen as long as a consistency proof shows it is a prefix
   (the attacker fetches that proof from the real witness), so a remembered-larger
   checkpoint does not help.
2. **A bound witness’s URL is not pinned.** The history binds `{url, verifierKey}`
   (owner-signed), but `#load` merges the (attacker-writable) side-file policy first and
   skips the bound entry when the `verifierKey` already appears. So a side-file policy
   entry with the **bound verifierKey but an attacker URL** overrides the bound URL. The
   witness’s identity is its **note verifier key**, not its URL, so redirecting to any
   endpoint that serves material signed by the right key passes every client check —
   including over HTTPS (the new https-only rule still permits **loopback http**, which is
   all the on-host attacker needs).

**Failure scenario:** owner writes 4 events to a sync, bound, `require-on-open`
history; witness holds head@6. Attacker restores the head@4 copy (+ `.head`,
`.anchors`), edits `.witness.json` to point the bound verifierKey at a loopback
http proxy, and the proxy replays the genuine receipt for head@4 as `latest`
(and 503s writes). `verify` passes, `requireOnOpen` readers read the stale copy,
and the next owner write extends the rolled-back branch. The witness chain is
untouched — exactly the rc.1 residual attack the block exists to stop.

**PoC (re-verified on the live rebuild):** `/tmp/review-b2/live/packages/witness/poc3b.mjs`
```
LIVE verifyWithWitnesses on rolled-back copy: ok = true failures: []
LIVE owner write on rolled-back copy: ok | disk head 5 vs honest witness latest 6
```
No owner key, no TLS break (loopback http). (Snapshot variant with the CLI:
`/tmp/review-b2/snap/packages/witness/poc/poc3-stale-latest.mjs`, which also shows a
`requireOnOpen` reader with an *explicit, correct* policy reading the stale copy with
**0 network calls** off the owner-sealed cache the stale write left behind.)

**Suggested fix:**
- The client must contact a **bound** witness at its **bound URL** and never let the
  side file (or an explicit policy) relocate a bound `verifierKey` to a different
  endpoint. Treat `{url, verifierKey}` from the binding as the trust anchor pair.
- Prove freshness of `latest`: have the witness sign a “latest head = P at tree size N”
  assertion (or the client confirm, under the current checkpoint, that no HEAD leaf for
  the history exists past the returned position — e.g. via a signed per-history head
  index), so a replayed older receipt cannot masquerade as the tip.
- Do not accept a checkpoint *smaller* than the largest verified in-process for a
  liveness decision (`latest`); smaller-but-consistent is fine for audit, not for “is
  the file behind the witness”.

---

## HIGH

### H1. The attacker-writable side file can inflate `quorum` and add witnesses so the honest bound witness’s answer is no longer required — defeating the bound witness without removing it

**File:** `packages/core/src/witness-session.ts` `#load()` L416–466, `#witnessedPosition()`
L588+, `witnessesToConsult()` in `witness-client.ts` L187 (`n − quorum + 1`).

`witness-state.ts` header promises the side file “can only make things stricter …
never remove one the history itself binds.” It can. A check needs answers from only
`n − quorum + 1` witnesses. The attacker rewrites the side-file policy to
`witnesses:[<bound key @ dead URL>, <attacker witness>], quorum:2` → a check needs
`2 − 2 + 1 = 1` answer. The attacker witness (registration `open`, empty log →
`UNREGISTERED`/prefix-OK) supplies it; the honest bound witness is pointed at a dead
URL and is *not required*. `verify --allow-unreachable` passes and the owner writes on.
The bound witness is still “present” in the policy, so the stated invariant is not
technically violated, but its protection is fully neutralised.

**PoC (live rebuild):** `/tmp/review-b2/live/packages/witness/poc1b.mjs`
```
LIVE verify (quorum-inflated side file): ok = true failures: []
LIVE owner write: ok | disk head 5 vs honest witness latest 6
```
(Snapshot CLI variants incl. per-witness `timeoutMs:1` and URL-to-dead-port:
`/tmp/review-b2/snap/packages/witness/poc/poc1-sidefile-downgrade.mjs`.)

The new opt-in `IRONTRELLIS_WITNESS_POLICY` minimum would mitigate **only if an operator
sets it**; the default `irontrellis witness add` flow (and every e2e test) does not, so
the shipped default posture is vulnerable.

**Suggested fix:** derive the required-answer set from the **bound** witnesses, not from
the merged policy: every witness the history binds must answer (or be individually
proven unreachable and explicitly accepted with an owner action), regardless of a
side-file `quorum`. Do not let the side file raise `quorum` in a way that drops a bound
witness from the required set, and do not let it set a per-witness `timeoutMs`/URL that
makes a bound witness fail to answer. Consider making the bound witnesses’ endpoints and
per-witness knobs non-overridable from the side file.

---

## MEDIUM

### M1. Rule W2 is enforced across multiple, unlocked reads of the history file (TOCTOU); statement signing/submission is not atomic against one prefix-checked, locked snapshot

**File:** `packages/core/src/witness-session.ts` `#submitRound()` (runs after the store
writer lock is released), `#bringUp()` L910–984, `#judge()` L800–810, `#statement()`
L988–1007. The store calls submission *after* `appendAtExpectedHead` returns and the
writer lock is dropped (`store.ts` `afterOwnerWrite` path); `#state()` re-reads the file
on each access.

`#bringUp` reads `state` (read #1), computes `target = headAt(state, …)`, calls
`#judge(runtime, latest)` which **re-reads** the file to confirm the witness `latest` is
a prefix (read #2), then `#statement` **re-reads** again and signs `headAt(state,…)`
(read #3). Nothing pins a single snapshot under a lock across “confirm `previous` is a
prefix” and “sign this head”. If the file changes between reads, the owner key signs a
statement for head `h` of one on-disk history with `previous = w` verified against a
different one — i.e. it can attest a branch `w` is not a prefix of, and the honest
witness accepts it (rule W1 only checks `previous == latest`).

**Precondition:** the attacker cannot forge new owner-signed events, so this needs
**owner-signed divergent bytes** already stageable on disk (a genuine second branch: two
concurrent owner processes/handles, or a restored-and-continued backup). Given such a
copy, a deterministic file swap during the unlocked submission drives the witness to the
fork’s head and makes the fork verify while the honest copy fails.

**PoC:** `/tmp/review-b2/snap/packages/witness/poc/poc2-w2-toctou.mjs` (swaps the fork in
during `#bringUp`’s `statSync`, the honest file back during `#judge`’s):
```
owner write outcome: ROLLBACK_DETECTED WITNESS_AHEAD
witness latest now: 7 == head of the FORK F
verify(F) with the honest witness: ok = true
verify(H, the honest file) with the honest witness: ok = false [REMOTE_WITNESS_ROLLBACK]
```
The honest owner process itself laundered the fork’s head onto the witness.

**Suggested fix:** sign and submit under the same snapshot that the prefix check used —
ideally hold the store writer lock (or an equivalent per-history guard) across
“read file → confirm `previous` is a prefix → build `target` from *that* state → sign”,
and re-validate that `target` and `previous` come from one consistent snapshot
(`eventHistoryHashes` at both positions) immediately before `signHeadStatement`.

### M2. A retired owner key is still accepted by any witness that has not yet recorded the rotation, and the attacker can keep it that way

**File:** `packages/witness/src/state.ts` `decideHead()` L146–202 (signature checked
against `history.epochs`, which only advances on a `ROTATED` leaf, L313–338).

After the owner rotates because K1 leaked, a witness that has not received the `ROTATE`
still has epochs naming K1 and accepts **any** K1-signed head extending its latest
(arbitrary position/hash). An attacker who holds the (now retired) K1 and can delay
`ROTATE` delivery (control the path / keep the witness unreachable) injects a bogus head;
when the witness is reachable again the real history is permanently `WITNESS_AHEAD` and
the attacker’s forged copy verifies against that witness.

**PoC:** `/tmp/review-b2/snap/packages/witness/poc/poc4-retired-key.mjs`
```
attacker's retired-key statement: 201 APPENDED
owner flush after the witness is back: ROLLBACK_DETECTED WITNESS_AHEAD
witness log: REGISTERED | HEAD 2 owner:1 | HEAD 3 owner:1 | HEAD 1000000 owner:1
```

This overlaps the documented residuals (“a stolen owner key in force can sign
statements”; “a witness that has not recorded a rotation …”), but the exploit is
concrete and the *indefinite* window (attacker suppresses `ROTATE` while injecting) is
worth calling out. It is inherent to a witness learning rotations only from delivered
`ROTATE`s; there is no clean full fix without out-of-band rotation delivery. Recommend:
document that a leaked key must be treated as able to fork every witness that has not yet
recorded the rotation, and push rotations to all witnesses (with retry/alarm) before
relying on the new key, surfacing per-witness “rotation not yet recorded” prominently
(the live `pendingRotations`/`status.rotations` fields help here).

---

## LOW

### L1. A stolen in-force owner key can grow the witness log without bound via distinct EQUIVOCATION leaves
`packages/witness/src/state.ts` dedupes equivocations by `(position, sha256(second))`
(`equivocationKey`, L99). A key holder can mint unbounded distinct conflicting
statements at one position (vary `canonicalTime`), each a new EQUIVOCATION leaf →
unbounded `log.jsonl` growth, subject only to rate limits. Needs the owner key.
Consider capping recorded equivocations per `(history, position)`.

### L2. `/healthz` and `/metrics` are served before the per-IP rate limiter
`packages/witness/src/server.ts` `dispatch()` L300–308 answers `/healthz`/`/metrics`
before `perIp.take` (L310). Unauthenticated, unlimited; `/metrics` renders full stats
each call. Minor; put them behind the limiter or a separate cheap path.

---

## Verified OK (tried to break, could not)

- **Body parsing / DoS** (`server.ts` `readJson`, canonical strict decode): deep nested
  arrays/objects, `__proto__` in genesis and in a head statement, duplicate keys, `1e308`
  / `1e99999` numbers, lone surrogates, and a 60k-deep head body were all rejected
  (400/413) or handled without prototype pollution or hangs; `/healthz` healthy after.
  PoC `/tmp/review-b2/snap/packages/witness/poc/poc5-parsing.mjs`.
- **Unauthenticated log growth by replay:** replaying genuine old head statements yields
  `ALREADY_WITNESSED`/`STALE_PREVIOUS` with no new leaf; equivocation needs two
  owner-signed conflicting statements (a non-key-holder can only replay statements
  already on the chain). No unauthenticated unbounded growth found. Registration needs
  the admin token by default (verified 401 on missing/wrong/`Basic` token).
- **Merkle bounds** (`transparency/merkle.ts` `verifyInclusion`/`verifyConsistency`):
  `index >= size` rejected; size 0/1, equal-size (empty proof, equal roots), `from == to`,
  `from == 0` handled per RFC 9162; non-hash proof elements and huge sizes rejected.
- **`decideRotation` ordering / idempotency** (`state.ts` L207–246): `rotationHead ==
  previousHead+1`, out-of-order rotations, and same-eventId-different-heads are rejected;
  the owner signature over `previousHead` is required (`verifyRotationEvent`).
- **Torn-line / crash recovery** (`log.ts` `scanLines`/`truncateTail`, `witness.ts`
  `#load`): a torn final line is truncated with a warning; a checkpoint whose size exceeds
  the replayed tree, or whose root mismatches, refuses start-up.
- **Storage-failure fail-closed** (`witness.ts` `#fail`/`#mutate`): after a write error
  the witness returns 503 and stops accepting writes; lost-lock (another process) → 503,
  nothing written.
- **Malformed side file fails the open** (`witness-state.ts` `readWitnessState` →
  `WITNESS_UNREADABLE`), not silently ignored; the on-disk side file cannot skip the
  network for a **writer** (writers always take a fresh network view before signing).
- **Receipt binding** (`witness-client.ts` `#receipt`/`#witnessedHead`/`#equivocation`):
  receipts are verified with the *configured* verifier key (never the key the receipt
  names) and bound to the expected entry kind/history/head/statement/genesis/rotation.
  (Note: this binds the receipt to the *right head object*; it does not bind it to being
  the *latest* head — see B1.)

---

## Note on the concurrently-changing tree

The live `packages/cli`/`hooks` were mid-edit at review time (e.g. `IronTrellisErrorCode`
gained `WITNESS_REJECTED` but `cli/src/messages.ts` had not been updated — `tsc` fails),
so CLI-driven PoCs were run against the 15:38 snapshot and the two top findings were
re-verified library-only against a fresh rebuild of the live `core`/`witness`. B1 and H1
survive the new https-only / `allowInsecureHttp` / `IRONTRELLIS_WITNESS_POLICY` work.
Re-check B1/H1/M1 after the fixing agent settles.

---

# Re-review (after the fixes: WITNESS-DESIGN §10, WIRE-DEVIATIONS 9–11, C7–C10)

Build: fresh copy of the stable live tree at `/tmp/review-b2/live2`, `pnpm -r build` clean (all 8 packages).
Project suites on that build: `packages/witness` 58/58 pass; core witness/rotation/transparency tests 118/118 pass
(the full core suite did not finish inside my 10-minute window, so that is not evidence of a failure).

## Status of the original findings

| Finding | Status | Evidence |
|---|---|---|
| **B1** stale `latest` via a redirected bound witness | **FIXED** | `poc3b.mjs` (live2): `verifyWithWitnesses` ok=false with `REMOTE_WITNESS_ROLLBACK` (witness at 6, file at 4); the owner write is refused with `ROLLBACK_DETECTED WITNESS_AHEAD`. CLI variant `poc/poc3-stale-latest.mjs`: `verify` exit 1; the explicit-policy `requireOnOpen` reader gets `WITNESS_UNAVAILABLE NOT_CHECKED` (the stale write left no seal). Cause: the side-file URL is ignored for a bound key (pinning in `#load`, witness-session.ts ~L512–530), and every history answer must carry a nonce-bound `latestNote` (witness-client.ts `#fresh`/`#freshNote` ~L574–601). |
| **H1** quorum inflation / extra witness in the side file | **FIXED** | `poc1b.mjs` (live2) and CLI `poc/poc1-sidefile-downgrade.mjs`, both variants (timeoutMs:1 and URL override): `verify` fails `REMOTE_WITNESS_ROLLBACK`, library and CLI writes refuse `WITNESS_AHEAD`. Cause: per-trusted-set coverage (`#coverage`, ~L703): the `bound` set needs `bound − boundQuorum + 1` of its own answers, and side-file timeouts no longer apply to bound witnesses (C8). |
| **M1** W2 TOCTOU | **FIXED** | `poc/poc2-w2-toctou.mjs`: the owner write ends with `ROLLBACK_DETECTED FILE_CHANGED_UNDER_WRITER`; the witness log ends at the honest `HEAD 6`, and the fork's head never reaches it. Cause: decision and signing happen in `#underLock` (~L1166) against one state read under the writer lock, with the trusted-head check (`#assertTrusted`). The lock is held until the async section settles (`withExclusiveWriter` awaits a thenable result, store.ts ~L1346). |
| **M2** retired key at a witness without the rotation | **OPEN (accepted, documented)** | `poc/poc4-retired-key.mjs` still gets `201 APPENDED` for the retired-key statement and leaves the history `WITNESS_AHEAD`, which §10.4 accepts. WITNESS.md L47 documents it clearly; the client now pushes rotations before `rotateOwnerKey` returns, and `witness status` shows pending rotations. |
| **L1** unbounded equivocation leaves | **FIXED (code + tests)** | state.ts L196–205 and L317: one EQUIVOCATION per (history, position), at most 64 per history; replay refuses excess lines. Not re-PoC'd. |
| **L2** monitoring routes before the limiter | **FIXED (code)** | server.ts L316–333: `/healthz` and `/metrics` go through the separate `monitoring` bucket first; the optional `metricsToken` is compared in constant time through its hash. |
| poc5 parsing robustness | **still OK** | Same 400/413 outcomes; `/healthz` healthy afterwards. |

## New findings

### N1 (Medium). The owner seal on a cached `latest` is not bound to the witness's identity, and a fresh reader maps a witness to its cache entry through the side file. This is a possible bypass of the latest-note protection for `requireOnOpen` readers.
*Code review only; no PoC built.*
- `witness-state.ts` L260–288: the seal covers `{historyId, origin, head, fetchedAt}` only. It does not cover the verifier key or the URL.
- `witness-session.ts` `#originOf` L673–678: before a reader has talked to a witness, the origin comes from the first side-file entry whose `verifierKey` matches. The side file is attacker-writable.
- `#persistKnowledge` ~L1076–1084 seals the known answer of every runtime that has an origin, including witnesses that only the side file adds.
- `#sealedCacheCovers` ~L727 lets a sealed entry count toward coverage for the trusted sets, the `bound` set included, with no network call. That skips the nonce/`latestNote` check entirely.

The concern: a seal the owner produced for one witness's answer could be credited to another witness, including a bound one, on the gate path. The exposure is limited to `requireOnOpen` readers within `cacheMs` (default 60 s). `verify` and owner writers always go to the network. I have not demonstrated this end to end.

Suggested fix:
- Put the verifier key (and the pinned URL) into the seal hash.
- Seal only answers from bound or out-of-band-minimum witnesses.
- Take a bound witness's origin from its binding's verified registration receipt, never from the side file.

### N2 (Low). The residual the fixer flagged is confirmed from the code: a bound witness without a registration receipt that answers with an unsigned 404 counts as "answered, no head" for readers.
- `#refresh` ~L920–945: when there is no `boundRegistrationOf` receipt (bound with `--allow-offline`), a reader without the owner key goes straight to `#learn(runtime, null)`.
- `remoteFindings` ~L1707 and L1772: `UNREGISTERED` counts in `answeredKeys`, so it satisfies bound-set coverage.

Result: a `requireOnOpen` gate and `verify` can accept a rolled-back copy when that witness's 404 is forged. Forging it needs a path attacker on an `allowInsecureHttp` or loopback-bound URL, or a witness that lost its data. An https-bound witness is not affected. Owner writers are safe, because they re-register and the signed note of that registration exposes held heads (C7).

Suggested fix: for readers, do not count a 404 from a bound witness toward the `bound` set's coverage; treat it like an unreachable witness. Also flag receipt-less bindings in `witness status`/`verify` until `witness add` records the receipt.

## Checked and not broken (new mechanisms)

- **Latest notes:**
  - A fresh 32-byte nonce goes with every `register`, `history`, `submit` and `rotate` call.
  - The note is opened with the configured key only. Origin, historyId and nonce must match. The head, leaf index and tree size must match the returned receipt, or be `none` exactly when `latest` is null. The equivocation count is checked on `history()`.
  - These checks cover ACCEPTED, STALE_PREVIOUS and EQUIVOCATION answers, and registration and rotation replies (witness-client.ts L633–715).
  - A 201 registration whose note names a head is rejected.
  - The `head()` and `entries()` reads carry no note, but no decision path uses them.
- **Domain separation:**
  - A latest-note body cannot parse as a checkpoint: line 2 would have to be a decimal, and the 66-character `0x…` historyId on line 3 is not valid 32-byte base64.
  - A checkpoint cannot parse as a latest note: the server refuses to be configured with the origin `irontrellis-witness-latest/1` (config.ts L64/L82), and the parser requires exactly nine lines with the version line first.
- **Pinning and the policy minimum:** for a bound key, the URL, verifier key and `allowInsecureHttp` come from the binding only. The side file can add only a token and a name, and its timeout is ignored. The minimum's spelling does not override a pinned witness. The effective quorum, `requireOnOpen` and `maxUnwitnessedEvents` are the strictest of binding, minimum, side file and caller. Re-binding needs an owner-signed `BIND`. An offline re-add for a key already bound at the same URL with the same policy writes nothing, so it cannot drop an existing receipt. `removeWitness` refuses to remove a witness the out-of-band minimum requires.
- **Trusted-set quorum math:** raising `quorum` or adding witnesses in the side file can no longer shrink the `bound` or `minimum` requirement (confirmed by H1's PoC).
- **`FILE_CHANGED_UNDER_WRITER` and lock scope:** the locked section re-syncs under the lock, and the lock is held across the async signing. A file swap is detected and nothing is signed (M1's PoC).
- **`INVALID_ANSWER`:** an invalid answer that leaves a trusted set short blocks writers (C9), and `verify` reports it as `REMOTE_WITNESS_INVALID`.
- **Monitoring limiter and `metricsToken`:** the limiter runs before either route; the token is 16..512 visible ASCII characters and compared in constant time.

---

# Third review (M2 closure: pre-rotation, two-phase rotation, bundles, supersede)

Build: fresh copy of the stable tree at `/tmp/review-b2/live3`, `pnpm -r build` clean.
Suites on that build: `packages/core/test/two-phase-rotation.test.mjs` 22/22 pass;
`packages/witness/test/e2e-prerotation.test.mjs` 9/9 pass.
PoCs under `/tmp/review-b2/live3/packages/witness/poc3rd/`. (Two attempts to script a
supersede-cap flood were stopped by the platform safety classifier; F1 below is reported
from code reading and the head-cap constant, not an executed flood.)

## M2 status

**M2 — CLOSED for a committed history, as designed.** `poc4b-m2-closure.mjs`: a leaked
current key K1 pushes a bogus head onto a witness the owner is cut off from; when the
owner runs a pre-rotated rotation and delivers it, the witness records `SUPERSEDED`, its
latest becomes the owner's `rotationHead`, and `verify` passes with `REMOTE_WITNESS_SUPERSEDED 1`
on the owner's copy:
```
[B-emergency] owner rotation: ok | owner write after: ok
[B-emergency] verify: ok=true notes=["REMOTE_WITNESS_SUPERSEDED 1: …"]
[B-emergency] log: … HEAD 1000000 owner:1 | SUPERSEDED | HEAD 5 owner:1 | ROTATED 4->5 | HEAD 6 owner:2
```
The M2 residual is exactly what §11.5 documents: without a pre-committed next key (or if
the attacker also holds it), M2 behaves as before — `poc4-retired-key.mjs` variant with
no commitment still lands `WITNESS_AHEAD` — and `verify`/`status` recommend committing a
next key.

## New findings

### F1 (Medium). The one-supersede-per-epoch rule plus the 1024-head cap lets a leaked-key holder pin a forged head as a witness's latest, defeating supersede recovery for that witness
*Code review only (the flood PoC was blocked by the safety classifier).*
- `packages/witness/src/state.ts` L384–385: a supersede is refused when the heads held after `L` exceed `MAX_SUPERSEDED_HEADS` (`packages/core/src/transparency/entry.ts` L63 = 1024).
- L381–382: at most one SUPERSEDED per epoch transition.
- The chain's `L` must be a head the witness holds on its chain and `≤ r-1`; after a divergence the owner has no good head past the fork, so `L` cannot be raised to shrink the count.

A holder of the leaked **current** key (the M2 threat) can push 1025+ chained, validly
K1-signed heads onto a bound witness (per-history rate limit default 600/min, so ~2
minutes). The owner's pre-rotated rotation then meets `SUPERSEDE_REFUSED` ("more than 1024
heads"), and the forged head stays the witness's latest — contradicting §11.4's argument
that "a leaked current key … can never make a forged head stay the witness's latest." The
history is not silently rolled back (honest writers fail closed and readers see
`WITNESS_AHEAD`), so integrity holds, but the promised **recovery** for that witness is
lost. The remaining recourse is heavier: abandon the witness with
`removeWitness(..., { acceptRemoteLoss })` and re-add it (verified to exist:
witness-session `acceptLoss`/`#excluded`, owner.ts L2062–2124).

Suggested fix: let a pre-rotated rotation supersede in batches across more than one
SUPERSEDED entry (or raise/remove the per-supersede head cap while keeping the append
bounded), or let the owner cap the thief's growth (e.g. the witness stops extending a
history from a key a delivered rotation has retired). At minimum, document that a witness
flooded past the cap by a leaked key must be removed and re-added, not supersede-recovered.

## Verified OK (tried to break, could not)

**1. Pre-rotation soundness.**
- A rotation out of a committed epoch to an uncommitted key, or revealing a committed key
  without a `nextKeyAuthorizations` signature, or omitting the new-epoch commitment, is
  rejected (`owner-keys.ts` `ownerKeyEventTransition`); differential `diff-prerotation.mjs`
  (10 cases) — TS and Python agree on every one.
- **Replay / transplant of a revealed-key proof:** the proof signs the event's own
  control-authorization challenge (`controlAuthorizationHash` over domain, event id/type/
  time, previousHead, effect hash). Moving `nextKeyAuthorizations` from one rotation onto
  another (different `nextKeyDigests`) fails ("transplanted proof" case) — the challenge
  differs. `controlEffect`/`controlEffectHash` exclude both `controlAuthorization` and
  `nextKeyAuthorizations`, so the owner signature and the revealed-key proofs are not
  circular (a signature over one event cannot be transplanted into another).
- **Proof by a carried-over key** is rejected (the proof key must be one the rotation
  *reveals*, not a carried-over id).
- **Digest aliasing / case:** `ownerKeyDigest` normalises the credential (lowercase) and
  omits the key id; TS `credential.toLowerCase()` and Python `credential.lower()` match,
  and credentials are ASCII hex / addresses only (no Unicode-casing divergence). The
  "uppercase credential of K2" case is accepted identically by TS and Python. A commitment
  that names an already-declared key is rejected (`declaredDigestFailure`).
- **Commitments:** a second commitment in a committed epoch is rejected, and a fresh
  commitment accepted; differential `diff-commit.mjs` — TS and Python agree. `createLocalOwner`
  commits in the initial write by default; the commitment event's signature is bound to the
  domain and previousHead, so it cannot be replayed into another history.
- **A thief with only the current key cannot rotate a committed epoch** (`rotateOwnerKey`
  refuses without the next key, `KEY_UNAVAILABLE`; the local replay rejects a rotation to an
  uncommitted key). Covered by e2e (c).

**2. Supersede.**
- `L` is validated: a head the witness holds on its chain, `≤ r-1`, chain statement valid
  and signed by a key in force at `r` (`state.ts` L369–390).
- **Only a pre-rotated rotation supersedes** (`verdict.preRotated`), so it costs the
  pre-committed next key — a thief without it gets `SUPERSEDE_REFUSED` (e2e (d)).
- One supersede per epoch transition (`supersededEpochs`).
- Superseded heads stay in the log, never become latest again, and a statement stating or
  extending one is answered 409 `SUPERSEDED` (`decideHead` L195–197); a head genuinely
  re-stated on the new chain is re-held (`applyEntry` L444–445), which is not a rollback.
- **Readers cannot be silently rolled back by a supersede:** the supersede count is in the
  signed latest note (`transparency/latest.ts` v2, 10 lines) and the client binds
  `note.supersedes === body.supersedes` (`witness-client.ts history()` L695); a reader whose
  known head was superseded sees `WITNESS_FORK`/rollback plus `REMOTE_WITNESS_SUPERSEDED`.
- **Latest note v2:** parser requires exactly the v2 version string and 10 lines, decimals
  without leading zeros, and index < treeSize; a v1 (9-line) note is rejected (no downgrade).
  Domain separation holds both ways: a checkpoint's origin may not be either latest-note
  version string (`config.ts` L64/L82), and a latest note's 2nd line is the origin (never a
  size) and 3rd is a 66-char `0x…` id (not 32-byte base64).
- Replay-on-start and `check-log` re-verify SUPERSEDED (`state.ts applyEntry` L525–545 with
  `verify:true`; e2e asserts `audit.kinds.SUPERSEDED === 1`).

**3. Two-phase rotation and crash recovery.**
- A planted or edited `<history>.rotation.pending.json` cannot make the owner sign or append:
  `judgePendingRotation` (`rotation-pending.ts` L188–216) marks it OUTSTANDING only when the
  event replays as a valid owner-signed rotation, its old-key statement verifies, and the
  seal verifies with an owner key in force. An attacker without the owner key can forge none
  of these → the record is OBSOLETE and ignored. Covered by two-phase test L314.
- A **genuine** record replayed after its rotation was aborted (staged keys deleted) is
  never completed to a lost key (`pendingRotationKeysMissing`); replayed with the file rolled
  to `r-1`, the outcome is a detected alarm, not a silent rotation (test L365). Making it
  OUTSTANDING at all requires rolling the file to `previousHead`, which is itself a rollback
  the witness detects.
- **No key-less permanent `ROTATION_PENDING` deadlock:** an OUTSTANDING record needs
  owner-signed material, so an attacker cannot manufacture the blocking state without the
  key; where it does block, the file was genuinely rolled back and the fix is restoring it.
- `ROTATION_OUTCOME_UNKNOWN`/`ROTATION_PENDING` resolves through `resolvePending` (COMPLETED
  when a bound witness holds `r`, DISCARDED when all answered and none does, UNRESOLVED while
  a witness is silent); `--emergency` records the outstanding rotation via `recordOutstanding`
  only when this handle holds its new key. Tests L173/L213/L268/L289.
- Two-phase key swap runs under the store writer lock, held until the async section settles.

**4. Bundles and admin import.**
- `validateKeyEventBundle` (`transparency/bundle.ts`) pins an exact field set, and binds the
  `statement`/`chain` to `bundle.historyId` and `eventHead`; the server also checks
  `bundle.historyId === :id`. A bundle for another history, or a statement/chain from another
  history, is rejected, and all owner signatures are re-verified on import (no trust from
  being in a bundle).
- The admin route (`POST /v1/admin/key-events`) requires an admin bearer token
  (constant-time), and runs the same validation as the network path; `poc4d-workaround.mjs`
  shows a delivered bundle behaves exactly like the network delivery (a stale one gets
  `STALE_PREVIOUS`).
- Offline `import-key-events` takes `server.lock` (`cli.ts` L218), so it cannot race a running
  server without `--force-unlock`.

**5. Old findings re-checked on live3:** B1 (`poc3b`), H1 (`poc1b`), M1 (`poc2`) all still
fail closed exactly as in the second review.
