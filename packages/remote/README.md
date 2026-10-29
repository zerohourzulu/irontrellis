# IronTrellis remote SDK

IronTrellis (formerly Continuity) keeps a checkable record of who may act for whom, and which duties survive when an AI agent is replaced. `@ramex-labs/irontrellis-remote` is the public SDK for the format-2 cooperative remote executor: it lets an agent's tool call run at a remote service that cooperates with that record. The service, called the destination, receives the history itself and checks each operation against it before acting.

This 1.0.0-rc.2 port requires Node.js 22.18 or later and the exact 1.0.0-rc.2 Core and remote-tools packages named in `package.json`.

## One call, start to finish

An application lets an agent open a ticket at a remote service. The agent supplies only the ticket's title. The application fixed everything else beforehand: the history, the agent's session and role, the keys, and the destination's address.

| Step | What happens |
| --- | --- |
| 1 | The history records the admission of the operation. |
| 2 | The executor sends the history to the destination, which accepts it only as a verified extension of the history it accepted before. Under the destination's default `REQUIRE_OWNER`, that needs an owner-attested head: give the executor the owner signer, or use `COORDINATOR_AUTHENTICATED` (see the remote-tools README). |
| 3 | The destination checks the admission in that history, prepares the operation, commits it once and signs a report. |
| 4 | If the connection drops, the outcome is unknown. Recovery looks up or cancels the operation; it never sends it again. |

## What you import

| Import | Surface |
| --- | --- |
| `@ramex-labs/irontrellis-remote` | Tool registry, pinned cooperative client, synthetic destination, executor, recovery and protected evidence |
| `@ramex-labs/irontrellis-remote/langchain` | LangChain tool wrappers; requires the optional pinned peers `@langchain/core` 1.2.12 and `zod` 4.6.5 |
| `@ramex-labs/irontrellis-remote/local` | Core privileged local owner and execution APIs |
| `@ramex-labs/irontrellis-remote/runtime` | Core runtime session APIs |
| `@ramex-labs/irontrellis-remote/attempts` | Core durable attempt APIs |

The first two come from `@ramex-labs/irontrellis-remote-tools`; the latter three are direct Core re-exports.

Keep owner handles, paths, clocks, signers, trusted registries and all of their configuration outside agent control. Supplying a tool argument does not select an identity or grant authority.

## How the destination trusts a history

The destination selects an expected history ID and format-2 authorization domain. Checkpoint transfer uses Core's complete export view and accepts only an extension of the previously accepted history. `checkpointHistory` takes a verified Core store or history, not an arbitrary event array.

The destination then authenticates the head of that history under one of two policies:

| Policy | Accepts | Claims |
| --- | --- | --- |
| `REQUIRE_OWNER` (the default) | A head the owner authenticated | Owner authentication of the head |
| `COORDINATOR_AUTHENTICATED` (selected explicitly) | A history sent in a transfer request signed by the pinned coordinator (the application's key); the destination still checks the native history's signatures and replay | No owner attestation of that head |

Runtime writes normally leave a head unattested and unwitnessed until the next owner write. Under the default, the destination refuses such a head (`CHECKPOINT_CONFLICT`) until a new owner checkpoint or head attestation covers it. A trusted host that wants the destination to accept a coordinator-signed runtime tail without a new owner checkpoint can select `COORDINATOR_AUTHENTICATED` explicitly. The selection is bound into durable destination identity and cannot change on reopen.

## Not in this port

This port intentionally has no segmented-history or inline-checkpoint path. The old `migrateDestinationHistory` export is not provided: no reviewed native format-2 mapping exists for that legacy storage operation. This is a known API parity exception, not an interchangeable storage migration.

## Limits

| Topic | Limit |
| --- | --- |
| Revocation | Effective at the destination's acknowledged checkpoint. A disconnected destination cannot infer an unseen revocation. |
| Reports | The supplied destination records synthetic effects. A signed destination report is evidence of its report, not proof of an external effect. |
| Recovery | It looks up or cancels an existing operation; it never blindly resubmits an uncertain effect. |
| PHL, Proof of Human Lineage | Core ships the PHL attestation policy; this adapter's retained tests do not establish additional PHL coverage. |

No exactly-once external execution, public deployment or whole-Core verification claim is made.

## Check it yourself

In the repository, run `pnpm install` and `pnpm -r build`, then `node --test test/*.test.mjs` in `packages/remote`. `test/verify-install.py` packs Core, remote-tools and this SDK, installs the three tarballs in a clean project, runs the SDK tests there and type-checks all five imports strictly. The release check (`scripts/verify-install.mjs`) also exercises these imports and declarations in an isolated installation made from the actual packed tarballs.

The executable API and the precise recovery limits are in the [remote-tools README](../remote-tools/README.md).

The test commands above check this package as it ships. They do not test your deployment, and the limits stated above still apply.

Apache-2.0. The package carries the repository NOTICE; see [LICENSING.md](LICENSING.md) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). The optional peers `@langchain/core` and `zod` keep their own licenses.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
