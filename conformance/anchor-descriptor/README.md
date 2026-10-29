# Anchor descriptor vectors

IronTrellis (formerly Continuity) can commit a history to a public chain at one head with an anchor statement, but a reader who wants to replay that history also needs its event bodies. The anchoring specification's persistence profile (§12) defines how they are published; no code in this release publishes them. Each body goes out with a *body descriptor*: its namespace, position, previous record hash, event hash, record hash, byte length, and the digest and length of each chunk. Each other artifact a reader needs, such as a head attestation or a profile manifest, gets an *artifact descriptor*.

This folder checks those descriptor rules against real history bytes. It is conformance support only: it adds no production export and no persistent store, and nothing here is published anywhere.

## What is here

| Path | What it holds |
| --- | --- |
| `support/descriptors.mjs`, `support/canonical.mjs` | Conformance-only copies of the reviewed descriptor and canonical helpers. `support/PROVENANCE.json` records the exact hash of each copied source |
| `support/profiles.mjs` | A small adapter to the production profile codec of the MCP gateway |
| `fixtures/` | All seven event bodies of the history and their descriptors, two artifact descriptors, the cases, the digests and their provenance |
| `generate.mjs` | Writes the fixtures, or with `--check`, reproduces and compares them |

## Run it

The namespace and profile fixture must exist first, and Core's `dist` and the existing package dependencies must be in place:

```
node conformance/anchor-namespace/generate.mjs --check
node conformance/anchor-descriptor/generate.mjs
node conformance/anchor-descriptor/generate.mjs --check
```

`--check` writes nothing. It checks the exact list of fixture files and every byte of each.

## What the generator checks

It reads the anchor-statement vector, unchanged, and the seven-event `rotation-v2` history that vector was made from, exactly as kept. All seven canonical event bodies and their descriptors are included, so positions 0 and 6 both have a complete structural prefix.

Event digests and record links must agree three ways: the descriptor helper, Core's own hash functions, and a 93-byte record preimage assembled independently (Core specification §4.3). The record hash at position 6 equals the vector's head; the one at position 0 equals its history id. This is a test of hashes and structure, not a fresh replay or signature check. Canonical body bytes don't preserve the whitespace of the original input.

The two artifact fixtures are the kept `/2` head attestation and the profile manifest **payload** of the namespace fixture. A trust-root envelope is refused as a profile artifact. An artifact descriptor that passes here establishes only canonical bytes, kind and commitment: not the artifact's full schema, its signature, its inclusion in an accepted history or its persistence. Receipt commitments are covered by the separate reviewed descriptor package these helpers were copied from, which is not in this repository; this folder invents and signs no receipt.

Twelve negative cases, none of which passes:

| Case | What it changes | Expected |
| --- | --- | --- |
| `reordered-chunks`, `truncated-body` | The chunks of the position-6 body | `DESCRIPTOR_INVALID`, `CHUNK_LENGTH` |
| `wrong-previousHash`, `wrong-recordHash` | One hash of the position-6 descriptor | `DESCRIPTOR_INVALID`, `RECORD_HASH` |
| `omitted-null-previousHash` | The position-0 descriptor without its `previousHash` field, which must be an explicit `null` | `DESCRIPTOR_INVALID`, `body:CLOSED_FIELDS` |
| `null-at-nonzero-position` | `previousHash: null` at position 6 | `DESCRIPTOR_INVALID`, `POSITION_NULL_LINK` |
| `foreign-namespace` | A descriptor from another namespace | `DESCRIPTOR_INVALID`, `NAMESPACE_MISMATCH` |
| `conflicting-position` | A different body at a position already kept | `DESCRIPTOR_INVALID`, `POSITION_CONFLICT` |
| `hole-before-position-6` | Position 6 appended right after position 0 | `DESCRIPTOR_INVALID`, `PREFIX_HOLE` |
| `valid-hash-but-foreign-retained-predecessor` | A rehashed position-1 descriptor: it passes on its own, but doesn't join the position-0 entry that is kept | `DESCRIPTOR_INVALID`, `PREVIOUS_HASH_MISMATCH` |
| `bodies-claim-with-missing-positions` | A publisher's `BODIES` claim while positions are missing | No structural coverage; `availabilityVerified: false` |
| `profile-envelope-is-not-payload` | The trust-root envelope offered in place of the manifest payload | `DESCRIPTOR_INVALID` |

A failed append leaves the tested in-memory state unchanged. An exact old body, chunked differently, returns its original kept entry and doesn't rewind the head. These are synchronous in-memory checks, not a proof of durable or on-chain compare-and-swap.

## What it doesn't do

The profile, address and operator labels are synthetic and installed nowhere. The public signatures it keeps are fixture data. No key is created or accessed, and no signature, transaction, node request or contract execution takes place. Structural coverage is distinct from replay acceptance, and it always reports `availabilityVerified: false`. No frozen conformance directory is edited.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
