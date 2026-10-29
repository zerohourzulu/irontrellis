# Owner approval policy vectors (engine-derived)

An IronTrellis (formerly Continuity) history is controlled by its owner keys. An *owner approval policy* says how many of those keys must sign each kind of control event: for example, two of three for most events, and a different count for some types. Co-signatures carry the extra approvals. These vectors test owner approval policies and co-signatures in format 2 (Core specification §6.5).

`generate.mjs` builds every history from fixed keys and replays it with this engine (`packages/core/dist`), so the expected results are this engine's own answers. They are not the acceptance test: the specification defines the owner-policy group by the cases that its own generator and an independent checker produce from its text (§6.5.9). Until they publish it, this suite records what the engine does, so that a reviewer can compare.

The specification places the group under `conformance/v2/owner-policy/`. It lives here instead because `conformance/v2` is byte-frozen. The runner loads any `conformance/v2-<name>/` directory.

## Running

```
pnpm --filter @ramex-labs/irontrellis build
node conformance/run.mjs --suite v2-owner-policy --adapter conformance/adapters/node.mjs
node conformance/v2-owner-policy/generate.mjs            # write vectors.json, MANIFEST.json, histories/
node conformance/v2-owner-policy/generate.mjs --check    # exit 1 when a fresh generation differs
node conformance/v2-owner-policy/compare-checker.mjs <checker pin file> …   # replay an independent checker's pins here
```

The generator also asserts each expected outcome, so a change in the engine stops the generation instead of silently moving a vector. `compare-checker.mjs` replays the pin files an independent checker built for itself, and prints a verdict for each pin: `AGREE`, or the kind of difference (`RETIRED`, `SUPERSEDED`, `HELD` or `DIFFER`).

## What is covered

Every vector is a replay vector, named `replay/v2op/<name>`. It pins its code and, when the history is accepted, its head, state root and projection head.

| Topic | What it pins | Core spec |
| --- | --- | --- |
| policy-schema-and-validity | The policy's form and validity: thresholds, per-type counts (`byType`), key classes, labels and the acknowledged single-signer mode, among them `rejects-acknowledged-with-bytype` and `rejects-tampered-policy`; and the two rules on per-type counts: a power-reducing type may not ask more than the non-agent keys can give (`rejects-bytype-power-reducing-above-non-agent`), and only some types may go below the threshold (`rejects-bytype-below-threshold-for-non-reducing-type`, `accepts-bytype-below-threshold-for-checkpoint`, `rejects-bytype-below-threshold-for-anchor`, `accepts-bytype-below-threshold-for-budget-declared`) | §6.5.2, §6.5.3 |
| quorum | Co-signatures, among them a quorum met, surplus signatures, a duplicate key id, a signer outside the epoch, too few signers, an agent co-signer on an ordinary event, and an agent alone (`rejects-agent-alone-m1` and `rejects-agent-alone-m2`) | §6.5.3 |
| power-reduction | The `…-at-pr-threshold` names. Under `{threshold: 2}` with the event's type at 1, the lower count applies only to an event that reduces power by its effect. A rollover budget update, a revocation that a live prohibition depends on, and the termination of a prohibition's grantor or of an agent on its anchor path do not | §6.5.3 |
| policy-rotations | Rotations of the policy: `accepts-policy-rotation-same-keys`, built out of a committed epoch, as the specification restated it; dropping or replacing the commitment; a rotation that changes nothing; `rejects-recovery-without-option`; next-key proofs with and without a policy (`rejects-partial-next-key-proofs-under-policy`, `accepts-partial-next-key-proofs-without-policy`); and the pinned root `accepts-policy-history` | §6.5.4 |
| credentials | Credential separation. Under a policy, no owner key, committed next key or attester shares a credential with any session or counterparty; a carried commitment that names such a credential is not tested again, but revealing it is refused; attesters are never committed, never shared with a session or counterparty, and never admitted as sessions. Without a policy, some of these duplicates are accepted | §6.5.7 |
| migration | A policy in a migrated genesis, and co-signatures inside a migrated prefix: both refused | §6.5.2, §16.2 |
| recovery | Committed next keys signing the rotation that reveals them: the next key alone, an unrevealed or uncommitted key, a missing proof (`builder-rejects-recovery-without-proof`), a mixed quorum, one credential revealed under two key ids (`rejects-duplicate-credential-on-recovery`), and an agent counted | §6.5.3, §6.5.4 |

Names that start with `builder-` are cases this implementation added beyond the specification's list. `accepts-policy-history` is the pinned root: its history, `histories/policy-history.json`, has owner key epochs carrying a `policy` at epoch 0, after a policy rotation and after a key rotation. `MANIFEST.json` lists every pinned position.

## Retired names

| Name | Why it was retired |
| --- | --- |
| `rejects-duplicate-credential` | Under a policy, a credential under two key ids is refused at the genesis (`rejects-duplicate-credential-in-owner-keys`), so the duplicate-credential step of the quorum count, which it targeted, can never fire in an accepted epoch. The generator still consumes that name's event serial, so every other vector and the pinned history keep their bytes |
| `builder-rejects-recovery-held`, `builder-rejects-human-floor-held` | They pinned parts of the group that were on hold. Those parts were released on 12 October 2026: recovery is in this suite, and human attestation is in [`conformance/v2-human-attestation`](../v2-human-attestation/README.md) |

The three credential names that need attesters are here, not in the human-attestation suite.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
