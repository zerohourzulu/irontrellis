# @ramex-labs/irontrellis-reference-0.3

**Frozen material.** A byte-identical copy of the **Continuity v0.3.0-preview.10.2** source and tests (the duty-policy, history, history-store and capacity machinery), kept as the reference oracle for the IronTrellis Core format-2 port. It is `private: true` and is never published.

## Rules

* **Never edit these files.** Bug fixes belong in `packages/core`; a disagreement with the oracle is documented in the differential tests, not fixed here.
* `FREEZE-LIST.txt` is the architect's `conformance/reference-0.3-FREEZE-LIST.txt` (350 files, `sha256  path`). Every file sits at its listed path under this directory, with one exception: the frozen root `package.json` (the Continuity evaluation manifest) is kept byte-identical as `continuity-package.json`, because `package.json` here is the workspace manifest. No test reads it.
* `verify-freeze.mjs` checks every listed file's sha256, the freeze list's own sha256, and that nothing else was added. It is the package's `test` script, so `pnpm -r test` fails on any change.

## Running

```sh
pnpm --filter @ramex-labs/irontrellis-reference-0.3 run verify-freeze
pnpm --filter @ramex-labs/irontrellis-reference-0.3 run test:oracle        # core-0.2 tests and the fast core-0.3 files
pnpm --filter @ramex-labs/irontrellis-reference-0.3 run test:oracle:slow   # history-store (~190 s), duty-disposition (~10 min, silent)
```

or one file at a time from this directory:

```sh
node --experimental-strip-types --test-concurrency=1 --test tests/core-0.3/history.test.mjs
```

Node ≥ 22.18 runs the TypeScript sources through type stripping; there is no build step. The engine imports only `node:*`; the test helpers load `viem` (devDependency, pinned at 2.55.19 as in `packages/reference-0.2`), resolved from this package's `node_modules`.

One case is expected to fail: `packages/core-0.2/test/common-engine.test.mjs` case 15 needs `integrations/agent-gateway`, which is not frozen. It leaves `integrations/.core02-reader-check-*/` behind; `verify-freeze` warns about it, delete it.
