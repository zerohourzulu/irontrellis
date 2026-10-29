// The shared witness scenario (conformance/transparency/scenario.mjs) built
// against the core sources, for the transparency tests.
import { fileURLToPath, pathToFileURL } from "node:url";

export const transparency = await import("../src/transparency/index.ts");
export const suites = await import("../src/crypto/suites.ts");
export const signer = await import("../src/signer.ts");
export const events = await import("../src/events.ts");
export const editions = await import("../src/adapter-editions.ts");
export const hash = await import("../src/hash.ts");
export const replayModule = await import("../src/replay.ts");

export const conformanceTransparencyRoot = fileURLToPath(new URL("../../../conformance/transparency/", import.meta.url));
const scenarioModule = await import(pathToFileURL(`${conformanceTransparencyRoot}scenario.mjs`).href);
export const { DOMAIN, ORIGIN, keysAt } = scenarioModule;

export const lib = {
  ...transparency,
  keyPairFromPrivateKey: suites.keyPairFromPrivateKey,
  signHashWith: suites.signHashWith,
  signControlEvent: signer.signControlEvent,
  HistoryHasher: hash.HistoryHasher,
  TRELLIS_VERSIONS: events.TRELLIS_VERSIONS,
  ADAPTER_POLICY_HASHES: editions.ADAPTER_POLICY_HASHES,
  ownerKeyDigest: (await import("../src/owner-keys.ts")).ownerKeyDigest,
  controlAuthorizationHash: events.controlAuthorizationHash,
  controlEffectHash: events.controlEffectHash,
};

export const buildScenario = () => scenarioModule.buildScenario(lib);
