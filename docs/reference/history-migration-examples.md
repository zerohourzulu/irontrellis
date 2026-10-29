# Legacy migration and worked history reference

> Reference from `HISTORY-FORMAT.md` at `00ca4c0` (SHA-256 `aecc62db80fda785ca06b60107097316cdc453416d0fa61baef42c6e903bc35b`). Established scope: the retained field, byte, code, limit and ordered-check contracts below. Not established: a new engine audit, deployment test or broader edition coverage.

Source section numbers are retained for cross-reference with [HISTORY-FORMAT.md](../HISTORY-FORMAT.md). Operational guidance stays in the narrative page. Format-2 owner-policy rules remain in the unchanged [owner-policy reference](owner-policy.md).

**Edition boundary:** Historical legacy-to-format-1 migration and read-only format-1 byte example. Current 1.0.0-rc.2 migration targets format 2 with plan, fence and resume; these commands are not a current writer recipe.

<!-- source: HISTORY-FORMAT.md:490-532; exact text except relative Markdown links -->

## 11. Migration and the legacy shadow

`migrateHistory` turns a legacy history into a format-1 history whose genesis carries `migratedFrom` and whose events 1..n re-record the source events 1..n **verbatim** (same ids, types, timestamps and data), with two additions the format-1 schema requires: control events gain `controlAuthorization` (signed by the new owner key over the *format-1* heads) and `RUNTIME_SESSION_ADMITTED` gains `credentialScheme` (the source's scheme). Positions are preserved, so the migrated state has the same agents, grants and duties and answers the same decisions (the v1 vectors include a migrated copy of the legacy handover fixture with identical answers).

`migratedFrom`:

| field | value |
|---|---|
| `format` | `"continuity-event/0.2"` |
| `historyHash`, `position` | the source head |
| `recordHash` | the `recordHash` of the source's last line |
| `genesis` | the source genesis `data`, verbatim (validated under the legacy schema) |
| `genesisEventId`, `genesisTimestamp` | the source genesis envelope |

The migrated genesis keeps the source's `id` and `timestamp`, `canonicalLineageId`, `globalPolicySourceId`, `adapterPolicyHash` and `signatureScheme`; its domain is `{protocol:"irontrellis", version:"1", deploymentId: <source deploymentId>}`; `policyVersion` becomes `irontrellis-local-owner/1` when the source used the local-owner literal.

**The shadow rule.** Runtime-signed events inside the migrated prefix (admissions, receipts, obligations, attempt records) bind the *legacy* domain, hash algorithm and head hashes. A verifier therefore keeps a second, legacy hasher while replaying positions 1..`migratedFrom.position`: it is seeded with the legacy genesis rebuilt from `migratedFrom` (`{id: genesisEventId, type: "DEPLOYMENT_INITIALIZED", timestamp: genesisTimestamp, data: genesis}`), and at each position it absorbs the **legacy projection** of the event (the event without `controlAuthorization` and, for sessions, without `credentialScheme`). Transition validation of those positions runs against a *view* of the state whose `head`, `genesis`, `domain`, `format`, hash algorithm and prefix hashes are the shadow's, so a legacy runtime signature verifies exactly as it did in the source. At position `migratedFrom.position` the shadow hash must equal `migratedFrom.historyHash` (`TRANSITION_INVALID: the re-recorded prefix does not reproduce migratedFrom.historyHash` otherwise), and a history that ends before that position is rejected when its replay completes (`TRANSITION_INVALID: migrated prefix incomplete`; the store refuses such a file on open with `INVALID_HISTORY`). Event-by-event application stays incremental, so the prefix can still be written one event at a time. The format-1 control authorizations, the format-1 heads and everything after the prefix use the real state. Nested domains and signatures inside re-recorded events keep their legacy shapes (`shadow` validation mode).

Because an intent admitted before the migration binds the legacy domain, `--intent` re-evaluation of such an intent in the migrated copy is refused (`MIGRATED_INTENT` in the CLI); the source archive answers it.

## 12. Worked example

Owner key from the Ed25519 seed `0x1111…11` (32 bytes of `0x11`): credential `0xd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737`, `keyId` `owner:1`. Genesis: the record in §3.2, `id` `example:genesis`, `timestamp` 1. Its canonical text is 1,113 bytes; the head after it is

```
hash 0x8cbbc04d19cd600c9306ee2f7a0beb2d451cf75d3c7f4fb33be5324b5921ff9a, position 0, canonicalTime 1
```

Second event: `PRINCIPAL_CREATED`, `id` `example:principal`, `timestamp` 2, effect `{"principalId":"operations"}` (`effectHash` `0x7edba99b…339b`). Challenge and challenge hash as in §7; the Ed25519 signature of the 32 hash bytes is `0xe3b080a8…1608` (§3.2). The head after it is

```
hash 0x43068a8d9750c77026e1123951f8ee88dacde234f99a768e4a00d4846daed4da, position 1, canonicalTime 2
```

The two store lines are the ones printed in §3.2; the pinned head has the shape shown in §9, with `hash` `0x43068a8d…ed4da`, `recordHash` `0xdbd1bc16…6ffd9` and an owner `attestation`. The Python verifier reads the same file and reports the same head:

```
$ python -m irontrellis verify worked.jsonl
{ "status": "ACCEPTED", "format": "irontrellis-event/1", "head": { "hash": "0x43068a8d…ed4da", "position": 1, "canonicalTime": 2 }, … }
```

The script that produced these values is reproducible with `keyPairFromPrivateKey("ed25519", "owner:1", "0x" + "11".repeat(32))`, `signHashWith`, `createReplayState` / `applyEvent` (the head after the genesis), `signControlEvent`, `controlAuthorizationHash` and `createHistoryStore` from `@ramex-labs/irontrellis`: build the genesis record of §3.2 (`versions` = `TRELLIS_VERSIONS` plus `signatureScheme: "ed25519"`, `adapterPolicyHash` = `ADAPTER_POLICY_HASH`), sign the principal event over the head after the genesis, and hand both to `createHistoryStore`. The store lines above are its output byte for byte.


