# Legacy conformance vectors (`continuity-event/0.2`)

The 34 vectors in `vectors.json` (19 authorization, 11 replay, 4 SURVIVES) and
`MANIFEST.json` are preserved **byte for byte** from the Continuity repository
(commit `18a8448`). They are the regression evidence that the legacy format is
still read and decided exactly as before. Do not regenerate them; a mismatch is
a finding, not a reason to edit the expectation.

The histories the vectors refer to (`first-look`, `no-review-power`, `mandate`)
are loaded from `packages/reference-0.2/tests/fixtures/`.

## Files

| file | purpose |
| --- | --- |
| `vectors.json`, `MANIFEST.json` | the corpus and its per-vector purposes and hashes |
| `ADAPTER.md` | the one-JSON-line-per-request adapter contract |
| `run.py` | the bounded Python runner (exit 0 match, 1 semantic mismatch, 2 execution error) |
| `test_runner.py` | unit tests for the runner plus a permissive-adapter negative control |
| `adapters/node.mjs` | the reference adapter, verbatim except that it imports the frozen reference package |

## Run

From the repository root, with Node >= 22.18 and Python >= 3.9:

```sh
python3 -B conformance/legacy/run.py -- node conformance/legacy/adapters/node.mjs
python3 -B -m unittest discover -s conformance/legacy -p test_runner.py -v
```

The first command is what `pnpm test:conformance:legacy` runs. To check the
**new** engine against the same corpus, point the runner at the IronTrellis
node adapter instead:

```sh
python3 -B conformance/legacy/run.py -- node conformance/adapters/node.mjs
```

The format-1 vectors and the IronTrellis runner live one level up, in
`conformance/`.
