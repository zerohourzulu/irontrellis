# @irontrellis/reference-0.2

A frozen copy of **Continuity Core 0.2.2** and the **Core 0.3 preview.8.2** SDK,
taken from the Continuity repository at commit `18a8448502e783070669f505c4964a9911cbf0cc`
("Handle an exited adapter leader during process-group cleanup").

It exists for one reason: the IronTrellis differential tests
(`packages/core/test/**`) run every legacy-format decision through this
engine and through the new engine and require the answers to be identical.
This package is the oracle. It is `private: true` and is never published.

## What is in here

| path | origin in the Continuity repository |
| --- | --- |
| `core-0.2/src/` | `packages/core-0.2/src/` — canonical JSON, replay, authority, queries, admission, receipts, administration, the JSONL store, the SDK coordinators |
| `core-0.3/src/` | `packages/core-0.3/src/` — the local owner / runtime / execution / attempts API (imports `../../core-0.2/src/...`, so the relative layout is preserved) |
| `tests/helpers.mjs`, `tests/generators.mjs` | `tests/` — fixture loaders and the seeded corpus generator |
| `tests/fixtures/**` | `tests/fixtures/**` — the handover, mandate and original-core case histories |
| `integrations/core-0.2-reference/cases/demo-08f957452f74/` | `history.jsonl` and `export/history.json` of the recorded demo case (only the two files the store/replay/queries tests read) |
| `LICENSE`, `NOTICE` | the Continuity licence (Apache-2.0) and notice |

The legacy conformance vectors, manifest, adapter contract and Python runner
live at the repository root under `conformance/legacy/` (byte-identical
vectors); the legacy node adapter there imports this package.

## Rules

* **Do not edit these sources.** The only change from the original tree is
  the one relative import in `tests/helpers.mjs` (`../packages/core-0.2/...`
  became `../core-0.2/...` because the sources sit one level higher here).
* Bug fixes belong in `packages/core`, never here. If the reference is wrong,
  the differential test documents the deliberate divergence (see
  `docs/ARCHITECTURE.md` §8: RESPONSIBLE on unsorted grants, and the capacity
  policy).
* Tests reach it through `packages/core/test/reference.mjs`; nothing else
  should import from this directory.

## Dependencies

`viem` (pinned to the version the Continuity repository used) is a
devDependency only because the differential tests sign legacy runtime
admissions and receipts with viem's EIP-191 accounts, exactly as the Core 0.3
tests did. The reference sources themselves depend on nothing but `node:*`.

The sources are TypeScript and run under Node's type stripping
(Node >= 22.18, no build step).
