# Owner-key CLI contracts

Reference from master `00ca4c0` OPERATOR. See [the key runbook](../OPERATOR.md#4-owner-keys-what-is-and-is-not-supported) for custody and recovery decisions, and [API rotation contracts](api-owner.md) for staging, crash recovery and result fields. Policy-enabled format-2 ceremonies additionally follow the existing [owner-policy reference](owner-policy.md); these templates are not a general recovery bypass. No command was run for this docs pass.

**Edition boundary:** Current control writes must target format 2; legacy/format-1 histories are read-only (`FORMAT_READ_ONLY`). Old creation and legacy→format-1 migration templates are historical, not current setup instructions; the current commands are `irontrellis init` and `irontrellis migrate` ([MIGRATION](../MIGRATION.md)).

## Rotation and commitment options

<!-- Source OPERATOR.md:65-96; command-signatures-fields-and-refusals-condensed -->

| Command / input | Contract |
|---|---|
| `irontrellis owner status [--json]` | Current keys, rotation counts, commitment and pending files; `commitment.nextKeyDigests` is the committed digest; `KEY_FILE_PENDING` identifies staged files |
| `irontrellis owner rotate-key [--reason <text>] [--key-id <id>]` | Records `OWNER_KEYS_ROTATED`; new set applies from the following position; a commitment requires its key via `--next-key` / API `nextSigner` |
| `--next-key <file>` | Promotes the committed next key; missing or wrong key is `KEY_UNAVAILABLE` before writing |
| API `newSigner`, `retire: [...]` | Select another signer, or add/drop individual keys subject to current rules; a newly generated replacement cannot overwrite a file whose key remains in force |
| `irontrellis owner commit-next-key` | Commitment-only rotation: current keys remain; existing commitment is `TRANSITION_REJECTED` |
| `irontrellis init --no-next-key` | Creates without the default commitment; `commit-next-key` can add one later |
| `irontrellis init --next-public-key "ssh-ed25519 AAAA…"` | Commits by public key without placing its private half on the host |
| `irontrellis owner commit-next-key --public-key <key>` | Same public-key commitment option for an existing uncommitted epoch |
| API `nextSigner`, `nextPublicKey`, `nextKeyReference` | Alternative custody inputs, with exclusions and possession rules in the API contract |

The file workflow uses `<history>.owner-key.pending.json`, `<history>.owner-next-key.pending.json`, `<history>.owner-key.<keyId>.retired.json`, and `<history>.rotation.pending.json`. An unreadable pending file is not discarded automatically: it blocks rotation with `KEY_EXISTS`. Once a key is promoted, the external copy is a current-key backup, not a reusable next key. Pins/anchors from earlier epochs continue to verify under the keys then in force.

## Historical legacy→format-1 migration

<!-- Source OPERATOR.md:71-71; migration-command-contract-condensed -->

`irontrellis migrate <legacy.jsonl> <new.jsonl>` re-records legacy into format 1 with `migratedFrom`, default next-key commitment, same decisions and preserved source. `--no-next-key` omits that commitment. The source must have pinned status `MATCHES`; otherwise `MIGRATION_UNSUPPORTED` names `SOURCE_UNPINNED` or `SOURCE_PIN_MISMATCH`, unless `--accept-unpinned-source` is explicitly selected after independent checking. A refused migration removes files it created. A format-1 source is unsupported. Existing target key files are `KEY_EXISTS`; `--reuse-existing-key` is deliberate adoption, not automatic recovery. See [complete migration API](api-migration-store.md).

## Signer-reference options

<!-- Source OPERATOR.md:102-108; signer-command-contracts-condensed -->

| Command / option | Contract |
|---|---|
| `irontrellis init --signer ssh-agent --public-key "<public key>" --next-public-key "<next public key>"` | Uses selected external keys; `ssh-add -L` lists candidate SSH public keys |
| `irontrellis init --owner-key-ref <file>` | Uses a reference produced by `irontrellis signer ref` |
| `irontrellis init --signer vault-transit --vault-addr https://vault.example:8200 --vault-key <name> --vault-token-file <file>` | Reads the public key and pins its latest version; token is not stored in the reference |
| `irontrellis signer to-ssh` | Existing-history migration described in [CUSTODY](../CUSTODY.md) |
| `irontrellis signer test --key current` | Produces and verifies one signature |
| `irontrellis doctor <history> [--as-agent]` | Read-only audit; exit 1 on any FAIL; evaluate as the actual agent OS user |
| `irontrellis owner rotate-key --next-key-ref <file> --new-next-public-key <key after it>` | Reveals the committed reference-backed key and selects the following commitment |

`OWNER_KEY_FILE_ON_HOST`, `NEXT_KEY_ON_HOST` and `NEXT_KEY_SAME_SIGNER` are custody warnings. Vault token lookup is `--vault-token-file`, `VAULT_TOKEN`, then `~/.vault-token`; the reference pins a key version. Cloud command-signer examples use Google `EC_SIGN_ED25519` and AWS `ECC_NIST_EDWARDS25519`, but are not live-service-tested.

A missing selected key/version/public-key match yields `KEY_UNAVAILABLE`; an unavailable, declined, timed-out or wrong-signature backend yields `SIGNER_FAILED`. Before signing the control event those failures append nothing. A later pin-attestation failure leaves the event recorded; `repin` repairs attestation after the signer recovers. Each ordinary owner write asks the signer twice, with additional witness statements/cache seals when applicable.
