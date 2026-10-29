// A-183.1 / A-195.2 / A-195.3: the closed anchoring-profile class table (one module for the outbox, the gateway and verify).
import test from "node:test";
import assert from "node:assert/strict";

const { anchoringProfileClass, ANCHORING_PROFILE_CLASSES, PRODUCTION_ANCHORING_PROFILE, TEST_ANCHORING_PROFILE, TEST_PROFILE_LABEL, TEST_TRUSTED_NODE_BARRIER_LABEL, isIdentifier } = await import("../src/index.ts");

test("A-195.3: the two literals; A-183.1: exactly two rows, and any other pair has no class", () => {
  assert.deepEqual(PRODUCTION_ANCHORING_PROFILE, { chainId: "eip155:42793", profileId: "irontrellis-anchoring-profile/etherlink-mainnet/1" });
  assert.deepEqual(TEST_ANCHORING_PROFILE, { chainId: "eip155:127823", profileId: "irontrellis-anchoring-profile/etherlink-shadownet-test/1" });
  assert.equal(TEST_ANCHORING_PROFILE.profileId, PRODUCTION_ANCHORING_PROFILE.profileId.replace("etherlink-mainnet", "etherlink-shadownet-test"), "A-183.1's substitution");
  assert.ok(isIdentifier(PRODUCTION_ANCHORING_PROFILE.profileId) && isIdentifier(TEST_ANCHORING_PROFILE.profileId), "§3.3 Identifiers");
  assert.equal(ANCHORING_PROFILE_CLASSES.length, 2);
  assert.ok(Object.isFrozen(ANCHORING_PROFILE_CLASSES) && ANCHORING_PROFILE_CLASSES.every(Object.isFrozen));
  assert.equal(anchoringProfileClass(PRODUCTION_ANCHORING_PROFILE.chainId, PRODUCTION_ANCHORING_PROFILE.profileId), "PRODUCTION");
  assert.equal(anchoringProfileClass(TEST_ANCHORING_PROFILE.chainId, TEST_ANCHORING_PROFILE.profileId), "TEST");
  for (const [chainId, profileId] of [
    [TEST_ANCHORING_PROFILE.chainId, PRODUCTION_ANCHORING_PROFILE.profileId], // shadownet-chain-refused: the production id on Shadownet
    [PRODUCTION_ANCHORING_PROFILE.chainId, TEST_ANCHORING_PROFILE.profileId],
    ["eip155:31337", "synthetic-local-anchor"],
    ["eip155:42793", "synthetic-offline-gateway"],
    [undefined, undefined],
  ]) assert.equal(anchoringProfileClass(chainId, profileId), undefined, `${chainId} ${profileId}`);
});

test("J77-06: the two class labels, pinned by hand to the rulings' words (A-183.2 (iii), A-195.1)", () => {
  assert.equal(TEST_PROFILE_LABEL, "test network; no production finality claim");
  assert.equal(TEST_TRUSTED_NODE_BARRIER_LABEL, "test network; trusted-node barrier; no production finality claim");
});
