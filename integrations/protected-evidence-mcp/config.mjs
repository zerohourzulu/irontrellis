import {
  openSync,
  closeSync,
  fstatSync,
  readFileSync,
  constants,
  lstatSync,
} from "node:fs";
import { keyPairFromPrivateKey, openHistoryStore, signHashWith } from "@ramex-labs/irontrellis";
import { openLocalEvidenceTool } from "@ramex-labs/irontrellis/evidence";
import { parseStrictJson } from "./strict-json.mjs";
const fail = () => {
  throw Error("CONFIG_UNAVAILABLE");
};
function privateFile(path, maximum) {
  if (typeof path !== "string") fail();
  const before = lstatSync(path);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    (before.mode & 0o077) !== 0 ||
    before.size > maximum
  )
    fail();
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.dev !== before.dev ||
      stat.ino !== before.ino ||
      stat.nlink !== 1 ||
      (stat.mode & 0o077) !== 0 ||
      stat.size > maximum
    )
      fail();
    const bytes = readFileSync(fd);
    if (bytes.length > maximum) fail();
    return bytes;
  } finally {
    closeSync(fd);
  }
}
export function loadGateway(configFile, { additionalPolicy } = {}) {
  const config = parseStrictJson(privateFile(configFile, 16384), {
    maxBytes: 16384,
    maxDepth: 12,
    maxNodes: 2048,
  });
  const fields = [
    "historyFile",
    "domain",
    "owner",
    "controller",
    "session",
    "role",
    "tenure",
    "resource",
    "inputDirectory",
    "outputDirectory",
    "selection",
    "keyFile",
  ];
  if (
    !config ||
    Array.isArray(config) ||
    Object.keys(config).length !== fields.length ||
    fields.some((k) => !Object.hasOwn(config, k))
  )
    fail();
  const key = privateFile(config.keyFile, 128).toString("utf8").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) fail();
  const store = openHistoryStore(config.historyFile);
  let session;
  try { session = store.state().runtimeSessions.get(config.session); } finally { store.close(); }
  if (!session) fail();
  const pair = keyPairFromPrivateKey(session.credentialScheme, session.credentialKeyId, key);
  if (pair.credential.toLowerCase() !== session.credentialAddressKey.toLowerCase()) fail();
  return openLocalEvidenceTool({
    ...config,
    ...(additionalPolicy ? { additionalPolicy } : {}),
    now: Date.now,
    signHash: signHashWith(pair),
  });
}
