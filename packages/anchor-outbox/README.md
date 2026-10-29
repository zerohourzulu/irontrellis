# IronTrellis anchor outbox

IronTrellis (formerly Continuity) keeps a checkable record of who may act for whom, and which duties survive when an AI agent is replaced. This package publishes commitments to that record on a public chain. It checks each anchor statement against the actual history, then drives one transaction for it through your signer and your node: one signer call and one first send per attempt, and after a crash it reconciles instead of sending again.

It is new in 1.0.0-rc.2, for installers who bring their own signer, chain node and trust root, on Node.js 22.18 or later:

```sh
npm install @ramex-labs/irontrellis-anchor-outbox@next
```

## Why an outbox

An anchor statement (`irontrellis-anchor-statement/1`) is a small canonical JSON object. It names a history, an owner-attested head, the head's state root and the digest of the owner's head attestation, and it chains to the previous statement. Anchoring is meant to make a later rollback or fork of that prefix visible to anyone who can read the chain. Publishing a statement means signing a transaction with a publisher key and handing it to a node, and that is where things go wrong:

| Risk | What the outbox does |
| --- | --- |
| The process crashes after signing, or after sending, and a naive retry signs twice or sends twice | It fsyncs a start record before the signer call and before the one send, and never re-signs or re-sends on its own |
| A node is wrong, slow or out of date | It keeps everything a node reports as `UNVERIFIED` evidence; a contradiction halts until an operator signs a clearance |
| The history doesn't support the statement, or an unqualified key attested the head | It replays the actual history and checks the head, the roots and the attestation before queueing, before and after the signer call, and just before the send |

These guarantees hold on one installer-controlled host with local POSIX files and fsync. They do not hold against a hostile operating system, and they are not a distributed lease.

## What this release does not do

| | In 1.0.0-rc.2 |
| --- | --- |
| Replace the fee of a stuck transaction | No |
| Produce an anchor verification report | No. Both `verifyAnchor` functions return `report: null`, in mode `UNVERIFIED`. A report must come from a separately installed producer ([known issue 54](../../docs/records/KNOWN-ISSUES-r2.5.md)). |
| Verify chain anchors in IronTrellis's own `verify` | No ([known issues 54, 56 and 71](../../docs/records/KNOWN-ISSUES-r2.5.md)) |
| Check consensus-verified finality | No code in this release checks it, and the gateway's barrier takes a report's declared mode as given ([known issue 71](../../docs/records/KNOWN-ISSUES-r2.5.md)). The separate anchoring tools used for the demonstration records report `TRUSTED_NODE` only, never consensus-verified. |

`TRUSTED_NODE` evidence rests on a chain node the operator relies on. `CONSENSUS_VERIFIED` would also need an independently administered, validating node of the settlement chain. This release makes no production-anchoring claim. Anchoring on a public mainnet in consensus-verified mode is defined in the [anchoring profiles specification](../../docs/spec/SPEC-IRONTRELLIS-ANCHORING-PROFILES-r2.md) (§7, §8) and deferred past this release.

## One statement, step by step

```js
import { openAnchorOutbox } from "@ramex-labs/irontrellis-anchor-outbox";

const outbox = await openAnchorOutbox(options);   // see "Configure"
const job = outbox.enqueueAnchor({ statementBytes, attestationBytes });
const prepared = outbox.prepareTransaction({
  statementDigest: job.statementDigest, nonce: 0,
  gas: 500000n, gasPrice: 1n
});
const attempt = outbox.claimAttempt({
  statementDigest: job.statementDigest,
  transaction: prepared.transaction
});
await outbox.advanceAttempt(attempt.attemptId);    // one signer call, one first send
await outbox.reconcileAttempt(attempt.attemptId);  // read-only; repeat as needed
```

| Step | Call | Durable record | What stops it |
| --- | --- | --- | --- |
| Queue | `enqueueAnchor`: the exact statement and attestation bytes, never a caller's verdict | The job; identical bytes are idempotent | A replay mismatch; an unqualified attestation signer (`ATTESTATION_SIGNER_UNQUALIFIED`); another statement at the same sequence or predecessor (`OUTBOX_CONFLICT`) |
| Prepare | `prepareTransaction`: an EIP-155 legacy transaction calling `publish(bytes)`, returned with your fee policy and `replacementAllowed: false` | None | A replay mismatch, a superseded job (`SUPERSEDED_LOCAL`) or a halt (`OUTBOX_HALTED`) |
| Claim | `claimAttempt` | Account generation, nonce reservation, attempt | `ACCOUNT_BUSY` until the previous attempt has finished; `PUBLISHER_EXPOSED` |
| Sign | `advanceAttempt` | `SIGN_STARTED`, then `SIGNED` | A stop from `assertCurrent`; after `SIGN_STARTED` the next call then halts `SIGNING_UNCERTAIN`, since the outbox cannot tell whether the signer ran. A signer error halts the account (`SIGNING_UNCERTAIN`), and so does signer output that fails validation (`SIGNER_RESULT_INVALID`). |
| Send | The same call | `SUBMISSION_STARTED` | A stop after this record is synced: `OUTCOME_UNKNOWN`, nothing sent |
| Reconcile | `reconcileAttempt` | Each observation | Nothing: it never sends, and a contradiction halts |
| Clear | `clearHalt` | The signed clearance, before any read | See "Halts and clearances" |

The attestation's signer must qualify under the owner approval policy in force at that head: under `DECLARED`, not an `AGENT` key; under `ATTESTED`, a `HUMAN` key at the head's time. Without a policy, every key qualifies. So nothing unqualified is published. A conflicting statement halts that history's namespace, and both validated jobs are kept for the operator. A predecessor's head must remain a prefix of the same actual replay.

`status(attemptId)` gives `RESERVED`, `SIGNING_UNCERTAIN`, `SIGNED_READY_FIRST_SEND`, `OUTCOME_UNKNOWN` (the send started: reconcile only from now on), `HALTED`, or a terminal status, whose record names the next nonce: `INCLUDED_SUCCESS`, `INCLUDED_REVERTED`, `CONSUMED_BY_SELF`, `CLEARED_RECLAIM`, `FAILED_NONCE_CONSUMED`, `CLEARED_CONFLICT` or `SUPERSEDED_LOCAL`. Every status carries `mode: "UNVERIFIED"` and `dispatchAllowed: false`. `INCLUDED_SUCCESS` means your node reported our exact bytes in a block with a success receipt; it is not finality.

## Configure

`openAnchorOutbox(options)` captures its options before its first await:

| Option | What it is |
| --- | --- |
| `directory` | The journal: an existing owner-only (0700) directory on a canonical path, with no symbolic links |
| `trustRootBytes` | The exact canonical trust root (`irontrellis-profile-trust-root/1`) |
| `adapterIdentity` | Your chain adapter's identifier, part of every attempt's identity |
| `feePolicy` | Your fee policy, disclosed with every prepared transaction |
| `historySource` | Returns the history, which Core replays at every check; format 2 only |
| `observeImmutables` | Your one read of the deployed instance: destination, namespace id, publisher and chain |
| `connector` | `encodeStatementCall`, `submitOnce`, `reconcile`, `reconcileClearance`, and optionally `verifyAnchor`; `createObservedConnector` builds one |
| `signTransaction` | Your signer; it returns the signed raw transaction |
| `assertCurrent` | Your stop and authority check: it returns `undefined`, and throws when the installation is stopped or its authority is stale |
| `boundaryHook` | Optional, for fault tests: called at each durable boundary |

At open, the trust root must be consistent in itself (payload, payload hash, namespace and destination), name this history's genesis, match your read of the deployed instance, and name one of Core's two anchoring profiles: Etherlink mainnet (`eip155:42793`, production) or Etherlink Shadownet (`eip155:127823`, test). Anything else is refused with a `TRUST_ROOT_INVALID:…` code, whose suffix names the failed check. The outbox keeps your instance read, marked `UNVERIFIED`: matching values do not authenticate the installer, the node or the deployed code.

| Role | Key | Signs |
| --- | --- | --- |
| Owner | An owner key in the history | The head attestation the statement carries |
| Publisher | An Ethereum account named in the trust root | The transaction, through `signTransaction` |
| Operator | An Ed25519 key in the trust root's `operatorKeys` | Clearances |

The publisher and operator keys must not appear as credentials in the replayed history (`PUBLISHER_CREDENTIAL_CLASH`, `OPERATOR_CREDENTIAL_CLASH`). Comparing public keys cannot show that the private keys are held apart. Your callbacks and adapters are trusted code in the same process: the outbox checks what they return, but cannot contain them.

## Journal and recovery

Every record is an exclusive-create, fsynced, owner-only file, and its parent directory entries are synced too. Numbered account generations serialize claims on a publisher account: a new generation needs the previous attempt's validated terminal record. No reservation or attempt is ever deleted or taken over.

| Found after a crash | What happens next |
| --- | --- |
| A partial reservation or attempt | The identical records are completed before any callback |
| A reservation, no `SIGN_STARTED` | One signing, after fresh history, fence and `assertCurrent` checks |
| `SIGN_STARTED`, no `SIGNED` | A halt, `SIGNING_UNCERTAIN`: an operator clearance is required |
| `SIGNED`, no `SUBMISSION_STARTED` | The signed custody is validated, then those exact bytes are sent for the first time |
| `SUBMISSION_STARTED` | Read-only reconciliation; never another send |
| A terminal record | No callback; a new attempt starts at the recorded next nonce |
| Partial clearance effects | `clearHalt` with the same clearance completes them, with no signer call and no send |

`assertCurrent` runs before signing, after signing and before sending, and replay and generation checks surround each call. The last call follows the `SUBMISSION_STARTED` fsync and comes just before the only send. The signed transaction is kept in a 0600 file with a single hard link, read under the gateway's private-file rules, as ordered hex chunks that give back the exact bytes. It is validated with viem: canonical RLP, a low-s signature, the publisher as the recovered sender, and exactly the prepared chain, nonce, recipient, value, calldata, gas and gas price.

## The observed connector

`createObservedConnector({ profile, endpoint, fetchFn, reads })` uses viem 2.55.19 with one HTTP transport: `retryCount: 0` on the transport and on each request, no batching, no fallback, no wallet or signing client, redirects refused and credentials omitted. The endpoint must be an `https:` URL, or `http:` on `localhost`, `127.0.0.1` or `[::1]`, with path `/` and no credentials, query or fragment. Only `eth_sendRawTransaction` sends anything, and a hash acknowledgement is `UNKNOWN`, not inclusion. Before each request it re-derives the signed bytes, the call, the statement and profile bindings and the attempt identity. Its timeout covers the response headers, not a streamed body.

You supply six read adapters, each returning canonical JSON bytes: `transactionByHash`, `receiptByHash`, `latestNonce` (mined; a pending-pool nonce is not consumption), `minedTransactionAtNonce` (from a bounded index you provide; no RPC method is invented for it), `retainedStatementDigest`, and `l1Level`, a separate read, because an L2 block number is not an L1 level. Reconciliation compares every required legacy field and the signed bytes, treats a typed-transaction field (EIP-1559 fees, access lists, blobs, authorizations) as a contradiction, and needs a matching receipt. Extra fields a node adds are accepted but not validated.

| Observation | Meaning | The outbox |
| --- | --- | --- |
| `PENDING` | Our exact bytes, not yet in a block | Records it |
| `INCLUDED_SUCCESS`, `INCLUDED_REVERTED` | Our exact bytes in a block, with a matching receipt | Finishes the attempt if a separate nonce read agrees |
| `UNKNOWN` | Anything missing, incomplete or ambiguous | Records it |
| `CONSUMED_BY_OTHER` | The mined nonce has passed ours, and the transaction at our nonce is another, validly signed one | Halts; never signs, sends, replaces or reuses the nonce |
| `CONFLICT` | The node's transaction, or the hash it acknowledged, contradicts our signed bytes | Halts (`OUTBOX_CONFLICT`) |

**Signature values.** A node may write the signature values `r` and `s` as a 32-byte word or as a canonical QUANTITY (no leading zero digit). The connector accepts either form, in any mix, and compares values. Re-serializing the expected transaction with the reported `v`, `r` and `s` must still give exactly the signed bytes. Any other spelling is incomplete, so `UNKNOWN`, never a match: a leading zero digit, a zero byte before a shorter value, 33 bytes, uppercase hex, an empty value, a number or a missing field. Values count, not spellings, because nodes write these numbers differently, and about one signature in 85 has an `r` or `s` that begins with a zero byte.

## Halts and clearances

A halt stops new work on the publisher account (for conflicting statements, on that history's namespace) until an operator signs a clearance, an `irontrellis-outbox-clearance/1` record. No success flag clears a halt.

| Halt | Clearance | Effect |
| --- | --- | --- |
| `SIGNING_UNCERTAIN` | `RECLAIM_SAME_NONCE_SAME_BYTES` | One re-claim of the nonce for the same statement and the same unsigned transaction, with no fee change. If our own bytes already used the nonce: `CONSUMED_BY_SELF`. |
| `CONSUMED_BY_OTHER` | `NONCE_FOREIGN_CONSUMED`, with `keyExposure` | `FAILED_NONCE_CONSUMED`. `KNOWN_OWN_USE` allows the next nonce. `COMPROMISE_SUSPECTED` refuses the publisher for good (`PUBLISHER_EXPOSED`), even if a later read disagrees or a crash comes first. |
| `OUTBOX_CONFLICT` | `CONFLICT_RESOLVED` | Names the surviving statement, the one on chain when that is known; the others become `SUPERSEDED_LOCAL`. An outstanding nonce that was never signed may be reused once, for the survivor; a signed, unconsumed one stays uncertain. |
| `SIGNER_RESULT_INVALID` | None in this release | The account stays halted. The outbox sent nothing for that attempt; to publish again, load a new trust root with a new publisher (see "A new trust root"; [known issue 80](../../docs/records/KNOWN-ISSUES-r2.5.md)). |

`clearHalt({ clearanceBytes })` needs the full closed record, every nullable field present (`keyExposure` included). An operator key listed in the trust root must sign the 32-byte hash of the record without its signature; owner, publisher and agent signatures are refused. The record is appended at `clearances/<chainId>/<publisher>/<nonce>-<n>.json` before any read. The outbox's own read-only observation must then agree on the account nonce, the transaction at that nonce, byte equality, the retained statement digest and the L1 level. Otherwise it returns `CLEARANCE_OBSERVATION_MISMATCH`: the record stays as evidence and the halt stands. Without signed custody, the built-in connector cannot tell whether a transaction that used the nonce was ours, so it refuses that read, and the halt stands too.

**A new trust root.** A change of profile, destination or publisher is a new trust root whose `supersedes` names the old instance. Its first statement is checked against the old root's stored profile, the old last statement and the actual history prefix. A new publisher gets a new account; the same publisher continues at its finished account's next nonce. Whether the migration is authentic, on the chain and for the installer, is outside the outbox.

## What `verifyAnchor` tells you

`outbox.verifyAnchor({ statementDigest })` replays the actual history and confirms the statement's head, roots and owner attestation. `connector.verifyAnchor({ statementBytes })` checks only that the statement is canonical and matches the trust root. Neither checks inclusion, node identity or finality. Both return `report: null`, mode `UNVERIFIED` and `dispatchAllowed: false`, with a list of the evidence still missing: installer authentication, node identity, the deployed contract's agreement with the call, chain inclusion, kernel evidence, L1 finality and a production profile. Neither is a qualified report producer, and neither sets the live-anchoring default. The gateway's pre-dispatch barrier, which reads reports, is described in [LIVE-ANCHORING.md](../mcp-gateway/docs/LIVE-ANCHORING.md).

## Reference

| Export | What it is |
| --- | --- |
| `openAnchorOutbox(options)` | Opens the outbox |
| `createObservedConnector(...)` | The viem connector above |
| `createSingleHttpSender({ endpoint, fetchFn })` | Its one-request sender |
| `encodeRawStatementCall(bytes)`, `RAW_STATEMENT_ABI` | The `publish(bytes)` call, carrying the exact canonical statement bytes |
| `decodeClearance(bytes, profile)` | Decodes a clearance and checks its operator signature |
| `OutboxError` | The outbox's own refusals; its `code` names the check (storage and history errors keep the gateway's or Core's code) |
| `LIMITS` | Statements up to 32,768 bytes, attestations up to 16,384, signed transactions up to 49,152; 128 observations per attempt |

`publish(bytes)` is a new raw-byte interface proposal. The earlier tuple interface does not qualify under the namespace contract's rules, and a deployed contract's agreement with the canonical bytes is still to be shown.

An attempt is identified by eight fields: `statementDigest`, `profileManifestHash`, `adapterIdentity`, `chainId`, `destination`, `publisherAddress`, `nonce` and `unsignedTxDigest`. `attemptId` is Core's SHA-256 of their canonical encoding. The nonce is a safe integer (U53), the chain is written `eip155:<decimal>`, and `unsignedTxDigest` is the Keccak-256 of the canonical unsigned EIP-155 legacy RLP, which includes gas and gas price. So the fee is part of the attempt's identity but not of the statement's digest, and a change of gas price alone is a new attempt, reachable only through an operator clearance and a fresh claim. The transaction hash and the attempt's ordinal are separate fields.

Dependencies: `@ramex-labs/irontrellis`, `@ramex-labs/irontrellis-mcp-gateway` (its profile codecs, and `durableCreate` and `readPrivate` from its `./data` subpath) and `viem` 2.55.19, pinned exactly. Apache-2.0.

## Check it yourself

The tests run on a synthetic local profile with a mock fetch. Eight processes race for one account claim: one wins, and no signer or send runs. A stop right after `SUBMISSION_STARTED`: `OUTCOME_UNKNOWN`, nothing sent. Substituted signer bytes: the account halts, and the signer is not called again. A failed send (a network error, HTTP 429 or 503, a JSON-RPC error, malformed JSON): exactly one request, `UNKNOWN`. A clearance signed by the owner, the publisher or a session, or a reclaim with another gas price: refused.

From a checkout of the repository, after `pnpm install` and `pnpm -r build`:

```sh
pnpm --filter @ramex-labs/irontrellis-anchor-outbox build
pnpm --filter @ramex-labs/irontrellis-anchor-outbox test
node conformance/anchor-attempt/generate.mjs --check
```

The vector in `conformance/anchor-attempt/` is `SYNTHETIC_TEST_ONLY`, on the local test chain 31337, and signed offline with fixed public test inputs: no operational key, wallet, funding, RPC or publication is involved. The public `openAnchorOutbox` refuses that chain; the fixtures open through a test-only entry point.

The test commands above check this package as it ships. They do not test your deployment or qualify a production one, and the limits stated above still apply.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
