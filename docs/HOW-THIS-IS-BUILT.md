# How this project is built

IronTrellis (formerly Continuity) is built with substantial AI assistance, written specifications, independent review and executable checks. People make the product decisions and are responsible for each release. A language model's opinion is neither a proof nor a policy authority: a claim counts only when something checkable stands behind it.

## One finding, from start to finish

While the decision rules were being checked with Lean, a proof assistant, the work turned up a signed, 12-event history in which revoking a grant turned a clear DENY into an ALLOW: the engine checked a spending limit too late, after it had already picked a path. The engine was fixed, and the core of the promise was then proved for the model of the decision procedure: revoking a permission never widens the permissions still in force, at the stage before the final checks. The proof does not yet cover those checks, so it does not show that a refusal can never become an approval. [Why we check IronTrellis with Lean](FORMAL-VERIFICATION.md) tells the whole story.

Each layer of evidence below works the same way: it checks a stated scope, and its limits are written down next to it.

## The layers of evidence

| Layer | What it checks | What it doesn't show |
|---|---|---|
| Frozen legacy references and vectors | Continuity's defined behavior, preserved byte for byte | Anything about format 2 |
| Conformance suites, one per format | Exact expected fields and refusals, for named cases | Cases that aren't listed |
| Unit, integration, crash and recovery, and installed-package tests | Particular implementations and boundaries, including the packed packages installed as a user would install them | Paths the tests don't take |
| Fuzzing, with a TypeScript and Python differential | Malformed input on every surface that reads data IronTrellis didn't write itself. For legacy and format-1 input, the Python verifier gets the same inputs as the TypeScript engine, and any disagreement is a finding. | Inputs the fuzzer doesn't generate |
| A separate format-2 checker | An independent implementation, kept outside this repository, for its supported scope. Its evidence is advisory: `conformance/v2-owner-policy/compare-checker.mjs` compares the engine with the checker's pinned outputs. | Agreement on the whole format |
| Lean | Selected mathematical models of the rules, against explicit assumptions and a list of claims | The shipped TypeScript: a theorem about a model isn't automatically a theorem about the code |

## Where things stand

At this commit, on Linux, every package and integration suite passes, every conformance suite matches, and the packed install check (`scripts/verify-install.mjs`) reports 70 passed, 0 failed, 0 skipped. Not every example was rerun for this commit. [Conformance](CONFORMANCE.md) explains which suites are selected, and [Benchmarks](BENCHMARKS.md) gives the dates and formats of measured performance.

## How a change gets in

- A behavior change needs a reviewed decision, a compatibility analysis and appropriate tests, following the [RFC process](RFC.md).
- Regenerating vectors to hide a disagreement isn't validation. Frozen vectors are never edited: a mismatch is a finding.
- A reproducibility claim must name the source, toolchain, fixtures and list of claims it rests on.
- Format 2 is released with the first public publication of 1.0.0-rc.2. From then on, a later version reads a format-2 history exactly as 1.0.0-rc.2 does, or refuses it, and fixes to the rules come as a new format.

## Not in this repository yet

A selection of the Lean proofs is in `verification/SelectLeanProofs/`, with the commands to rebuild them and print the axioms each theorem uses. The full editions, the list of claims and a CI check aren't in this repository yet, so CI doesn't rebuild the proofs.

## Known limits

| Limit | Where to read more |
|---|---|
| A hostile host, with access to the process, files or keys | [Security](SECURITY.md) |
| A compromised signing key | [Security](SECURITY.md), [Custody](CUSTODY.md) |
| Incomplete evidence about external outcomes | [Security](SECURITY.md) |
| Python coverage that depends on the profile: legacy and format 1 only | [Conformance](CONFORMANCE.md) |
| The gap between abstract models and the code's behavior | [Why we check IronTrellis with Lean](FORMAL-VERIFICATION.md) |

Public deployment, an external cryptographic audit and production qualification each need evidence of their own. [Security](SECURITY.md) describes the boundaries, and the [historical reviews](history/README.md) keep their dated findings as they were, without relabeling them as current results.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
