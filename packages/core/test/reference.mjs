/**
 * The single door to the frozen Continuity reference (packages/reference-0.2).
 *
 * Every differential test imports the reference engine, its fixtures and the legacy
 * conformance vectors through this module, so no test knows where the reference lives
 * and the suite runs from a fresh clone. The reference sources are TypeScript run under
 * Node's type stripping; they are never built.
 *
 *   referenceRoot              absolute path of packages/reference-0.2 (trailing slash)
 *   referencePath(rel)         absolute path of a file inside the reference package
 *   fixturesRoot               absolute path of the reference fixtures directory (trailing slash)
 *   fixturePath(name)          absolute path of a fixture, e.g. fixturePath("handover-history.jsonl")
 *   fixture(name, revive)      parsed JSON fixture; bigint markers revived unless revive === false
 *   loadJson(path, revive)     parsed JSON at an absolute path, same revival rule
 *   vectors                    the 34 legacy conformance vectors (conformance/legacy/vectors.json), revived
 *   vectorsPath                absolute path of that file
 *   cryptoVectorsPath          absolute path of conformance/crypto-vectors.json (spec 04)
 *   cryptoVectors              parsed spec-04 crypto vectors (no bigint markers inside)
 *   referenceCore              core-0.2/src/core/index.ts (the public Core 0.2.2 surface)
 *   referenceModule(rel)       dynamic import of any reference source, e.g. referenceModule("core-0.2/src/core/canonical.ts")
 *   referenceCore02(rel)       shorthand for referenceModule(`core-0.2/src/${rel}`)
 *   referenceCore03(rel)       shorthand for referenceModule(`core-0.3/src/${rel}`)
 *   viemAccounts               `viem/accounts` resolved from the reference package (privateKeyToAccount, generatePrivateKey)
 *   DEMO_CASE                  absolute path of the demo case directory (history.jsonl, export/history.json)
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

export const referenceRoot = fileURLToPath(new URL("../../reference-0.2/", import.meta.url));
export const referencePath = (relative) => `${referenceRoot}${relative}`;

export const fixturesRoot = referencePath("tests/fixtures/");
export const fixturePath = (name) => `${fixturesRoot}${name}`;

export const DEMO_CASE = referencePath("integrations/core-0.2-reference/cases/demo-08f957452f74/");

const conformanceRoot = fileURLToPath(new URL("../../../conformance/", import.meta.url));
export const vectorsPath = `${conformanceRoot}legacy/vectors.json`;
export const cryptoVectorsPath = `${conformanceRoot}crypto-vectors.json`;

/** Amounts are written as {"$continuity.bigint":"…"} because JSON has no BigInt. */
export const reviveBigints = (_key, value) =>
  value !== null && typeof value === "object" && typeof value["$continuity.bigint"] === "string" ? BigInt(value["$continuity.bigint"]) : value;

export const loadJson = (path, revive = true) => JSON.parse(readFileSync(path, "utf8"), revive ? reviveBigints : undefined);
export const fixture = (name, revive = true) => loadJson(fixturePath(name), revive);

export const vectors = loadJson(vectorsPath);
export const cryptoVectors = loadJson(cryptoVectorsPath, false);

export const referenceModule = (relative) => import(pathToFileURL(referencePath(relative)).href);
export const referenceCore02 = (relative) => referenceModule(`core-0.2/src/${relative}`);
export const referenceCore03 = (relative) => referenceModule(`core-0.3/src/${relative}`);
export const referenceCore = await referenceCore02("core/index.ts");

export const viemAccounts = createRequire(referencePath("package.json"))("viem/accounts");
