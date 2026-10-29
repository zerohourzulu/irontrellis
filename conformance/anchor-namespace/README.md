# Anchor namespace and profile vectors

IronTrellis (formerly Continuity) can anchor a history on a public chain under an *anchoring profile*: which chain, which publisher address, which operator keys and which nodes. The profile's *payload*, the profile manifest, is hashed, and a *namespace id* is derived from it. A *trust root* bundles the payload, its hash, the namespace id and the destination contract address (anchoring specification §11 and §19).

These fixtures fix those bytes, and check that an anchor statement binds to them, with the production helpers of the MCP gateway: `encodeProfilePayload`, `deriveNamespace`, `encodeTrustRoot` and `checkStatementBinding`. Everything in them is synthetic, and nothing is installed.

## Run it

From the repository, with Core's `dist` and the existing package dependencies in place:

```
node conformance/anchor-namespace/generate.mjs
node conformance/anchor-namespace/generate.mjs --check
```

Node runs the helpers' TypeScript source directly, through its built-in type stripping. Nothing rebuilds Core, contacts a node, signs or deploys a contract. `--check` writes nothing: it compares the exact list of generated files and every byte, including the hashes of the production source files the fixtures were made from, so a reviewed change to those sources needs a deliberate regeneration. Local serialization and SHA-256 calculations, done independently, must agree with the production codec and with Core's canonical and hash functions.

## The fixtures

| File | What it is |
| --- | --- |
| `fixtures/manifest.json` | The profile payload. Its digest is `manifestHash` |
| `fixtures/namespace.json` | The namespace, assembled independently from the payload and its hash, then matched to `deriveNamespace` |
| `fixtures/trust-root.json` | The trust root: the payload inline, the derived namespace id and an illustrative destination. Its whole-envelope digest is diagnostic only |
| `fixtures/statement.json` | A separate sequence-0 statement. It keeps the anchor-statement vector's domain, history, head, roots and attestation fields as they were, and replaces its profile id and hash and its destination |
| `fixtures/manifest-maxLag-zero.json` | The same payload with `maxL1HeadLag: 0`. Numeric zero is a value distinct from an explicit `null`, so its namespace id differs |
| `fixtures/cases.json` | The positive binding and the negative cases below |
| `fixtures/digests.json`, `fixtures/provenance.json` | The digests, and where the fixtures came from: the anchor-statement file's SHA-256 and the hashes of the production sources |

The original `conformance/anchor-statement` files are neither rewritten nor given this new digest; only their SHA-256 is recorded.

## What the positive case shows

The trust root passes load checks T1 to T4 of anchoring specification §19.3: the payload is valid, `manifestHash` is the payload's hash, the namespace id is derived from the payload, and the destination is well formed for the chain. T5, a read of the deployed instance, is not performed. The statement then matches the trust root on all eight equalities of §19.4: the manifest hash, the profile id, the domain, the history id, the genesis event hash, the chain id, the destination, and the publisher as the transaction's sender.

That is all it proves. Every result stays `UNVERIFIED`, with dispatch disabled. It supplies no installer authentication, no read of a deployed instance, no separation of roles, no accepted migration, no signature and no consensus evidence. The history and attestation bindings it inherits are provenance, not a new replay or signature check.

## The negative cases

`cases.json` records 17 refusals and mismatches: the ones the specification requires, and more.

| Kind | Cases | Expected |
| --- | --- | --- |
| Trust root | The manifest hash or the namespace id substituted; an extra or a missing payload field, including a missing explicit `supersedes: null`; the namespace id or the destination inside the payload; a destination in upper case; a duplicate operator key id | `TRUST_ROOT_INVALID`, naming the failing check |
| Statement binding | Each of the eight equalities broken on its own | `bindingsMatch: false`, with only that equality false |

A structurally well-formed statement with a foreign binding returns `bindingsMatch: false`; it is not a Core refusal.

## The labels are placeholders

The `synthetic-*` profile and operator identifiers and the repeated-byte addresses are placeholders. The operator credential is the standard public encoding of the Ed25519 base point, not a generated key. A mainnet chain id in a fixture is not mainnet enrollment.

## What remains open

This closes a gate for the production codec's vectors only. The deployed contract's immutables, agreement with a raw-byte contract decoder, the live-evidence vectors of the connector profile (anchoring specification §14) and actual qualification remain separate gates.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
