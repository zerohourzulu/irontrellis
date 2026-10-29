import { anchoringProfileClass, canonicalEncode, eventHash, historyIdOfGenesis, type ReplayState } from "@ramex-labs/irontrellis";
import { encodeTrustRoot } from "@ramex-labs/irontrellis-mcp-gateway";
import { bytes, canonicalInput, digest, fields, need, OutboxError, profile, validateRoleSeparation, unchunk, type SelectedProfile } from "./validation.ts";
export type ImmutableRead = Readonly<{destination:string;namespaceId:string;publisher:string;chainId:string}>;
export type ProfileLoad = Readonly<{selected:SelectedProfile;rootBytes:Buffer;observationBytes:Buffer;observationDigest:string}>;
/**
 * A-195.2: the one pair outside the A-183.1 table that the outbox's own test fixtures may load, and only through
 * `openAnchorOutboxInternalForTests` (conformance/anchor-attempt is a synthetic local profile; its vectors stay byte-unchanged).
 */
export const SYNTHETIC_TEST_PAIR = Object.freeze({chainId:"eip155:31337",profileId:"synthetic-local-anchor"});
/** T6 (A-195.2): `(manifest.chain.id, manifest.id)` is a pair of Core's class table, checked before the instance read. */
export function profilePairAdmitted(chainId:string,profileId:string,syntheticTestPair:boolean):boolean {
  return anchoringProfileClass(chainId,profileId)!==undefined || (syntheticTestPair && chainId===SYNTHETIC_TEST_PAIR.chainId && profileId===SYNTHETIC_TEST_PAIR.profileId);
}
/** The adapter is installer-selected read integration; its supplied observations
 * are retained as UNVERIFIED evidence, never authenticated chain proof. */
export async function loadProfile(rootInput:unknown,adapterIdentity:unknown,feePolicy:unknown,state:ReplayState,
  observe:(request:Readonly<{destination:string;chainId:string}>)=>Promise<unknown>,syntheticTestPair=false):Promise<ProfileLoad> {
  const raw=bytes(rootInput,32768);canonicalInput(raw,32768);
  let root;
  try {root=encodeTrustRoot(raw).value;} catch {throw new OutboxError("TRUST_ROOT_INVALID:T1_T4");}
  need(profilePairAdmitted(root.manifest.chain.id,root.manifest.id,syntheticTestPair),"TRUST_ROOT_INVALID:T6");
  const p=profile({id:root.manifest.id,manifestHash:root.manifestHash,chainId:root.manifest.chain.id,destination:root.destination,
    publisher:root.manifest.publisher,adapterIdentity,feePolicy,trustRoot:root});
  need(digest(root.manifest.domain)===digest(state.genesis.domain) && root.manifest.historyId===historyIdOfGenesis(state.events[0]!) &&
    root.manifest.genesisEventHash===eventHash(state.events[0]!),"TRUST_ROOT_INVALID:HISTORY");
  validateRoleSeparation(state,p);
  let observed:Buffer;
  try {observed=bytes(await observe(Object.freeze({destination:p.destination,chainId:p.chainId})),16384);}
  catch {throw new OutboxError("TRUST_ROOT_INVALID:T5_READ");}
  const o=fields(canonicalInput(observed,16384),["destination","namespaceId","publisher","chainId"]);
  need(o.destination===p.destination && o.namespaceId===root.namespaceId && o.publisher===p.publisher && o.chainId===p.chainId,"TRUST_ROOT_INVALID:T5");
  need(Buffer.from(canonicalEncode(root)).equals(raw),"TRUST_ROOT_INVALID:CANONICAL");
  return Object.freeze({selected:p,rootBytes:raw,observationBytes:observed,observationDigest:digest(o)});
}

export function restoreProfile(input:unknown):SelectedProfile {
 const r=fields(input,["version","rootChunks","adapterIdentity","feePolicy"]);need(r.version==="irontrellis-outbox-profile/1","PROFILE_RECORD_INVALID");
 const root=encodeTrustRoot(unchunk(r.rootChunks,32768)).value;
 return profile({id:root.manifest.id,manifestHash:root.manifestHash,chainId:root.manifest.chain.id,destination:root.destination,
  publisher:root.manifest.publisher,adapterIdentity:r.adapterIdentity,feePolicy:r.feePolicy,trustRoot:root});
}
