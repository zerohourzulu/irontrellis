# Transparency vectors (witness wire formats)

IronTrellis (formerly Continuity) can bind a history to a remote witness: a small service, run somewhere else, that remembers the latest owner-signed head of each history it serves, so that a copy rolled back to an older head can be caught. The witness and its clients must agree on every byte they exchange. `vectors.json` fixes those formats, as specified in the [witness protocol reference](../../docs/reference/witness-protocol.md#9-protocol-reference-irontrellis-witness1) (§9, reached from [docs/WITNESS.md](../../docs/WITNESS.md) §9): RFC 6962 Merkle inclusion and consistency proofs, C2SP signed notes and verifier and signer keys, tlog checkpoints, owner-signed head statements, witness log entries, witness receipts, and the witness-signed latest notes over a client nonce.

Like `../crypto-vectors.json`, these are pure-function vectors. They are not run through `run.mjs` and its adapter line protocol; each implementation loads the file in its own tests.

## What a runner checks

| Section | What a runner does | Expected |
| --- | --- | --- |
| `merkle.published` / `merkle.generated` | hash each leaf, append, compute the root at every size | `leafHashes`, `roots[size]` |
| `merkle.inclusion` | `verifyInclusion(leafHash, index, size, proof, root)` | `valid` |
| `merkle.consistency` | `verifyConsistency(from, to, fromRoot, toRoot, proof)` | `valid` |
| `notes` | open `note` with `verifierKeys` | `expect`: `{ok, body, verifiedBy}` or `{ok:false, error}` |
| `keys.verifierKeys` / `keys.signerKeys` | parse the key string | `valid` (+ name, key hash, public key / derived verifier key) |
| `keys.signing` | sign `body` with `signerKey` | `note`, byte for byte (Ed25519 is deterministic) |
| `checkpoints` | strict checkpoint parse | `valid` (+ origin, size, base64 root, extensions) |
| `statements` | verify `signed` with the keys of the last `ownerKeyEpochs` entry whose `fromPosition <= statement.head.position` | `expect`; `statementHash` when the statement is well-formed |
| `entries` | structural validation; canonical text; leaf hash. All five kinds: `REGISTERED` (with and without a genesis next-key commitment), `HEAD`, `ROTATED`, `EQUIVOCATION` and `SUPERSEDED` (a pre-rotated rotation, its chain statement and the superseded range `supersededFromIndex` / `supersededToIndex` / `supersededLatest` / `supersededCount`, including a 100,000-leaf flood), with invalid `SUPERSEDED` variants (a count of 0 or beyond the range, a latest outside the range or at or before the last good head, a chain without `previous`, a list of heads instead of a range, …) | `valid`, `canonical`, `leafHash` |
| `receipts` | verify `receipt` with `trustedVerifierKeys` | `expect`: `{ok, index, checkpoint}` or `{ok:false, reason}` |
| `latestNotes.format` | format the latest-note body (`irontrellis-witness-latest/1`, ten lines, the last the supersede count) from `fields` ([witness protocol reference §9.8](../../docs/reference/witness-protocol.md#98-latest-notes-freshness)) | `body`, or `valid: false` with `error` |
| `latestNotes.parse` | strict parse of `body` | `fields`, or `valid: false` with `error` |
| `latestNotes.verify` | open `note` with `trustedVerifierKeys`, parse, check against `expect` (`origin?`, `historyId?`, `nonce?`) | `result`: `{ok, latest}` or `{ok:false, reason}` |

The `conventions` block in the file states the encodings and error codes.

## Where the vectors come from

Each vector carries a `source`:

| `source` | Meaning |
| --- | --- |
| `transparency-dev/merkle`, `golang.org/x/mod/sumdb/note`, `c2sp.org/signed-note`, `c2sp.org/tlog-checkpoint` | Copied verbatim from that published source; `sources` names the files |
| `generated` | Made by the TypeScript core |

## Regenerating

```sh
pnpm --filter @ramex-labs/irontrellis build
node conformance/transparency/generate.mjs           # rewrite vectors.json
node conformance/transparency/generate.mjs --check   # exit 1 if a fresh generation differs (pnpm conformance:transparency)
```

`generate.mjs` builds its statements, entries and receipts from `scenario.mjs`, with fixed seeds and a fixed clock, and refuses to write a Merkle or entry vector its own verifier disagrees with. A difference on `--check` means the core changed and needs a decision, not a silent refresh.

## Runners

| Language | Runner | Where it runs |
| --- | --- | --- |
| TypeScript | `packages/core/test/transparency-conformance.test.mjs` | `pnpm test` in `packages/core` |
| Python | `python/tests/test_transparency.py`, against `python/src/irontrellis/transparency.py` | `pytest` in `python/`, `pnpm test:python`, and CI's Python jobs, including the one without Node |

The Python runner runs every section above with the same checks as the TypeScript runner, including byte-for-byte deterministic note signing, plus tamper, reason-order and Merkle property tests. Ed25519 uses the package's pure-Python verifier, or OpenSSL through `cryptography` when the optional `fast` extra is installed; the results are the same. It adds no new runtime dependency.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
