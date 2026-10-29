# Conformance

IronTrellis (formerly Continuity) claims that anyone holding a history can replay it and get the answers its writer got. Conformance vectors test that claim for an implementation. Each vector is a named case: an input, such as a history and a question about it, and the exact result the implementation must give.

Passing them is finite evidence. It is not protocol certification, complete implementation equivalence or proof of every input path.

**An example.** You've written your own verifier. Wrap it in an *adapter*, a program that reads one JSON request per line and answers one JSON line each, and run a suite against it:

```sh
node conformance/run.mjs --suite v2-g3 --adapter path/to/my-adapter.mjs
```

The runner prints how many cases matched, mismatched, failed with an error or never ran, and names each field that differs.

## The suites

| Suite | What it holds | Signed under profile |
| --- | --- | --- |
| `legacy` | Frozen Continuity vectors, byte identities preserved | — |
| `v1` | Format-1 vectors; the packaged Python verifier/evaluator's scope | — |
| `v2` | Frozen format-2 vectors, the record of the r2.3 rules (a verify-only profile: format-2 writes under it are refused) | `frozen-r2.3` |
| `v2-g3` | The same specification vectors, regenerated under `g3` | `g3` |
| `v2-regenerated` | Format-2 cases derived from this engine's answers: a provenance distinct from the independent specification vectors | `g3` |
| `v2-owner-policy` | Owner approval policy cases | `g3` |
| `v2-human-attestation` | PHL, Proof of Human Lineage, attestation cases | `g3` |
| `transparency` | Witness wire-format and proof cases, loaded by the unit tests rather than the runner | — |

Each runner suite's `MANIFEST.json` lists its cases, and the runner prints the counts. Never rename or regenerate frozen evidence to match a new implementation.

### Format 2 as released means profile `g3`

A *session-challenge profile* fixes the structure of some challenges a runtime session signs. Under `g3`, the challenges for an intent declaration, a refusal, an effect and a counterparty receipt also bind the event's id, type and timestamp. `g3` is format 2 as released, and the engine's default.

`frozen-r2.3` reproduces the earlier challenges, without that binding. It exists only to verify the frozen `v2` vectors: under it, every format-2 write (a new history, an owner write, a session write) is refused with `CHALLENGE_PROFILE_READ_ONLY` before anything is written.

A history verifies under one profile; the engine never retries the other. The runner passes each suite's profile to the adapter as `IRONTRELLIS_CHALLENGE_PROFILE`, and `--profile` overrides it, for example to show that `v2` does not verify under `g3`.

## Running the suites

From a built checkout with the selected suites installed:

```sh
pnpm build
node conformance/run.mjs --suite all --adapter conformance/adapters/node.mjs
node conformance/run.mjs --suite v2 --adapter conformance/adapters/node.mjs
node conformance/run.mjs --suite v2-g3 --adapter conformance/adapters/node.mjs
node conformance/run.mjs --suite v2-regenerated --adapter conformance/adapters/node.mjs
node conformance/run.mjs --suite v2-owner-policy --adapter conformance/adapters/node.mjs
node conformance/run.mjs --suite v2-human-attestation --adapter conformance/adapters/node.mjs
```

`all` selects **legacy and v1 only**; run each format-2 suite by name. `--filter <text>` narrows the cases for diagnosis, and `--json` prints the full report.

On 24 October 2026, all seven runner suites matched with this repository's Node adapter: no mismatch, no error, no case left unrun.

## Reading a result

| Exit status | Meaning |
| --- | --- |
| 0 | Every selected case matched |
| 1 | A completed response disagreed |
| 2 | Setup or transport failed, or the adapter answered a case with an error (that case gets an ERROR row and the run continues) |

The comparison checks only the object fields a case's expected result names. Arrays must match in order and length; scalars must match exactly, with their JSON types, and an explicit `null` counts; tagged BigInt values compare exactly.

DENY, INDETERMINATE and a rejected replay can be correct results. A transport failure or an unimplemented adapter operation is not a passing refusal, and an empty selection qualifies nothing. When you report a run, keep the suite and profile, the implementation, the matched, mismatched and error counts, and any cases not run.

## Writing a new implementation

Start with exact canonical encoding, hashes and signatures; then closed schemas and the ordered replay checks; then authorization and the queries you support. Use each suite's [manifest and adapter documentation](../conformance/README.md) and [HISTORY-FORMAT](HISTORY-FORMAT.md). Compare failures as well as successes, and record gaps instead of putting compatibility answers into the adapter. Broader generated differential testing complements the vectors.

Other implementations, for comparison:

- The **Python package** is not a format-2 implementation.
- The **separate checker written from the specification alone** is advisory; select it and report its results on their own.
- The **frozen reference engine** is a legacy oracle: agreeing with it says nothing about format-2 features it doesn't implement.

## What conformance shows

**Established:** the finite suite results above and the runner's documented behavior. **Not covered:** any output field a case's expected result leaves out, hostile storage or operating-system behavior, arbitrary external effects, or a formal proof of the whole Core.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
