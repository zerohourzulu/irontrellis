/**
 * Where things are, and the built modules the harness drives (build first:
 * `pnpm -r build`). The harness imports the compiled `dist/` of each package,
 * exactly as the conformance adapters do.
 */
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const FUZZ = dirname(dirname(fileURLToPath(import.meta.url)));
export const ROOT = dirname(FUZZ);
export const REGRESSIONS = join(FUZZ, 'regressions');

const load = async (relative) => {
  const file = join(ROOT, relative);
  if (!existsSync(file)) throw new Error(`missing ${relative}: build first (pnpm -r build)`);
  return import(pathToFileURL(file).href);
};

export const core = await load('packages/core/dist/index.js');
export const signerLib = await load('packages/core/dist/signer.js');
export const t = await load('packages/core/dist/transparency/index.js');
/** A-185.3 / A-194: the legacy and format-1 writers are test tooling (`@ramex-labs/irontrellis/internal-format1`). */
export const internal = await load('packages/core/dist/internal-format1.js');

let witnessLib, cliLib;
export const witness = async () => (witnessLib ??= await load('packages/witness/dist/index.js'));
export const cli = async () => (cliLib ??= await load('packages/cli/dist/cli.js'));

/** The wire form: bigints as `{"$continuity.bigint":"…"}` markers (what the adapters exchange). */
export const plain = (value) => JSON.parse(core.jsonStringifyWithBigints(value));
/** Wire form → engine values (markers → bigints, strict). */
export const revive = (value) => core.jsonParseWithBigints(JSON.stringify(value));
