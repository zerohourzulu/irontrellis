# Human attestation vectors (engine-derived)

IronTrellis (formerly Continuity) lets a history's owner require that the keys approving sensitive events belong to people, not agents. An owner policy with `humanFloor: "ATTESTED"` selects the attestation policy for PHL, Proof of Human Lineage. Named attesters then sign statements about the owner keys. A key counts as `HUMAN` only while a statement for it is valid. Otherwise a key classed as an agent is `AGENT`, and any other key is `LAPSED` once its statement has expired, or `NONE` before it starts or without one (Core specification §6.5.5).

These vectors test those rules. `generate.mjs` builds every history from fixed keys and replays it with this engine (`packages/core/dist`), so the expected results are this engine's own answers. They are not the acceptance test: the specification defines the group by the cases that its own generator and an independent checker produce from its text (§6.5.9).

## Running

```
pnpm --filter @ramex-labs/irontrellis build
node conformance/run.mjs --suite v2-human-attestation --adapter conformance/adapters/node.mjs
node conformance/v2-human-attestation/generate.mjs            # write vectors.json, MANIFEST.json, histories/
node conformance/v2-human-attestation/generate.mjs --check    # exit 1 when a fresh generation differs
node conformance/v2-owner-policy/compare-checker.mjs <checker pin file> …   # replay an independent checker's pins here
```

`compare-checker.mjs` takes pin files an independent checker built for itself: each pin carries its full events and the outcome the checker expects. It replays every pin with this engine and prints a verdict for each: `AGREE`, or the kind of difference (`RETIRED`, `SUPERSEDED`, `HELD` or `DIFFER`).

## What is covered

Every vector is a replay vector, named `replay/v2ha/<name>`. Every `ATTESTED` policy names two attesters. An attester signs a statement over `hashCanonical(statement without signature)`.

| Topic | What it pins | Core spec |
| --- | --- | --- |
| policy-validity | The statements and attesters at the event that sets the policy: audience, attester, signature, subject, interval, freshness, two attesters, enough valid statements for the rotation quorum (`M_rot`), and per-type thresholds for power-reducing types that the started statements can meet | §6.5.2, §6.5.5 |
| counting | The class of each signer (`HUMAN`, `AGENT`, `LAPSED`, `NONE`), and who counts on ordinary events and on rotations | §6.5.3, §6.5.5 |
| lapse-and-reduction | A `LAPSED` key counts only on a power-reducing event, a restoration or a checkpoint | §6.5.3 |
| restoration | A policy rotation that only renews or carries statements; renewals start after the epoch opened, and by the event | §6.5.4, §6.5.5 |
| statements | `historyId` after the genesis, the carry waiver, and the pinned root `accepts-attestation-history` | §6.5.2, §6.5.5 |
| recovery | A pre-attested committed next key signs the recovery rotation; an unattested one is `NONE` | §6.5.3, §6.5.4 |
| time | Rule T1: a session-signed event never passes an unexpired statement's expiry. Rule T2: one human-class signer advances time at most to the horizon, never to 2^53 − 1 | §6.5.6 |

`MANIFEST.json` lists every vector with its topic and purpose, and every pinned position of `histories/attestation-history.json`.

Names that start with `builder-` are cases this implementation added beyond the specification's list. Where the specification later restated a case, the vector follows the restatement:

- `accepts-fence-by-lapsed-and-agent` keeps a later statement, so that the horizon is not passed;
- `rejects-restoration-with-stale-statements` is a real restoration that leaves too few statements valid when it takes effect;
- `rejects-restoration-with-stashed-statement` has a second case, `rejects-restoration-with-stashed-statement-below-t-set`.

No part of the group is on hold: the last parts held back were released on 12 October 2026.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
