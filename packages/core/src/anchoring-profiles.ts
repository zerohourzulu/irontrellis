/**
 * A-183.1 with A-195.2 and A-195.3: the closed table of anchoring-profile classes. A profile's class is derived from the
 * pair `(manifest.chain.id, manifest.id)` (no manifest field carries it; a `class` field is E-39), and a pair outside this
 * table is not an anchoring profile of this release: trust-root load refuses it with `TRUST_ROOT_INVALID` (rule T6 of
 * A-167.3). The outbox and the gateway both read this one module, so each literal exists once; `verify` does not read it in
 * this release (independent review J77-11).
 *
 * The production id is A-195.3's pin (no R9 literal was produced); the TEST id is the same id with
 * `etherlink-shadownet-test` in place of its mainnet segment (A-183.1). Before IronTrellisLiveChainAnchor (the milestone at
 * which histories are first anchored on a live public chain in consensus-verified mode) no mainnet instance exists.
 */
export type AnchoringProfileClass = "PRODUCTION" | "TEST";
export type AnchoringProfilePair = Readonly<{ chainId: string; profileId: string }>;

/** Etherlink mainnet (eip155:42793): the production profile. */
export const PRODUCTION_ANCHORING_PROFILE: AnchoringProfilePair = Object.freeze({ chainId: "eip155:42793", profileId: "irontrellis-anchoring-profile/etherlink-mainnet/1" });
/** Etherlink Shadownet (eip155:127823): the TEST profile; the gateway's barrier admits it only with `anchoring.allowTestProfile` (A-183.2), while the outbox loads either class. */
export const TEST_ANCHORING_PROFILE: AnchoringProfilePair = Object.freeze({ chainId: "eip155:127823", profileId: "irontrellis-anchoring-profile/etherlink-shadownet-test/1" });

export const ANCHORING_PROFILE_CLASSES: readonly Readonly<AnchoringProfilePair & { class: AnchoringProfileClass }>[] = Object.freeze([
  Object.freeze({ ...PRODUCTION_ANCHORING_PROFILE, class: "PRODUCTION" as const }),
  Object.freeze({ ...TEST_ANCHORING_PROFILE, class: "TEST" as const }),
]);

/** The class of `(chainId, profileId)`, or `undefined` for a pair outside the table (T6: `TRUST_ROOT_INVALID`). */
export function anchoringProfileClass(chainId: unknown, profileId: unknown): AnchoringProfileClass | undefined {
  return ANCHORING_PROFILE_CLASSES.find((row) => row.chainId === chainId && row.profileId === profileId)?.class;
}

/** A-183.2 (iii): the label `status()`, printed reports, evidence bundles and `verify` listings carry for a TEST-class profile. */
export const TEST_PROFILE_LABEL = "test network; no production finality claim";
/** A-195.1: the label under `anchoring.testBarrierMode: "TRUSTED_NODE"` (TEST class only). */
export const TEST_TRUSTED_NODE_BARRIER_LABEL = "test network; trusted-node barrier; no production finality claim";
