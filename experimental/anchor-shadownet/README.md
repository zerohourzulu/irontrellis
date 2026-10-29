# Experimental: the anchored-record reader

This folder holds one experimental tool, `tools/read-record.mjs`. It reads an anchored IronTrellis record from an Etherlink chain at one pinned block, rebuilds the history from the chain alone and checks it. [The chapter 1 record](../../docs/examples/chapter-1-record.md) shows how to run it.

It is not one of the published packages and makes no stability promise. The sending tool that wrote the chapter 1 record is not in this repository yet. `src/chain.mjs` and `src/durable.mjs` hold parts of that tool, which the reader does not run.

**What it needs:** a clone of this repository with `pnpm install --frozen-lockfile && pnpm build` (for `packages/core` and `packages/mcp-gateway`), and Node.js 22.18 or later. Its one outside library is viem 2.55.19, the copy `packages/anchor-outbox` already pins. It uses no keys, no account and no configuration, and it writes nothing.

**What it checks:** that every event body is present on the chain, that every statement the history's owner signed matches the history, and that the history closes. It prints `VERIFIED` only when all three hold. With `--statements`, the record must also hold exactly that many statements at the block.

**Its limits:**
- It reads by block hash where the node accepts that, and by block number otherwise. After its reads it reads the pinned block's hash again, and if the hash has changed nothing verifies. A change that reverses between the first and the last read is not excluded.
- It checks that each statement is included on Etherlink. It does not check finality on Tezos: its result says `L2_INCLUDED`, mode `UNVERIFIED`.
- It trusts the node it reads from to answer for the chain. To check independently, use a node of your own choosing.
