import { canonicalEncode, captureValue, eventHash, hashCanonical, historyIdOfGenesis, isIdentifier, isProtocolString, isU53,
  projectionHeadAt, replayHistory, rootAt, TRELLIS2_FORMAT, unqualifiedHeadSigner, verifyHeadAttestationFacts, type ContentHash, type ReplayState } from "@ramex-labs/irontrellis";
import { data, exact } from "@ramex-labs/irontrellis-mcp-gateway/data";
import { types } from "node:util";
import type { ProfileTrustRoot } from "@ramex-labs/irontrellis-mcp-gateway";

export class OutboxError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.name = "OutboxError"; this.code = code; }
}
export function need(value: unknown, code: string): asserts value { if (!value) throw new OutboxError(code); }
export const hash = (value: unknown): value is ContentHash => typeof value === "string" && value.length === 66 && /^0x[0-9a-f]{64}$/.test(value);
export const address = (value: unknown): value is `0x${string}` => typeof value === "string" && value.length === 42 && /^0x[0-9a-f]{40}$/.test(value) && value !== `0x${"00".repeat(20)}`;
export const digest = (value: unknown): ContentHash => hashCanonical(value, "sha256");
export const LIMITS = Object.freeze({ statementBytes: 32768, attestationBytes: 16384, rawTransactionBytes: 49152, observations: 128 });
/** Own data fields; byte buffers and explicitly trusted callback values are captured by their callers. */
export function fields(input: unknown, required: readonly string[], optional: readonly string[] = []): Record<string,unknown> {
  need(input !== null && typeof input === "object" && !types.isProxy(input) && !Array.isArray(input),"INVALID_INPUT");
  const obj=input as object, proto=Object.getPrototypeOf(obj), keys=Reflect.ownKeys(obj);
  need((proto===Object.prototype || proto===null) && keys.every(k=>typeof k==="string" && [...required,...optional].includes(k)) && required.every(k=>keys.includes(k)),"INVALID_INPUT");
  const copy: Record<string,unknown>={};
  for (const key of keys as string[]) {const d=Object.getOwnPropertyDescriptor(obj,key);need(d && d.enumerable && Object.hasOwn(d,"value"),"INVALID_INPUT");copy[key]=d!.value;}
  return Object.freeze(copy);
}
export function bytes(value: unknown, limit: number): Buffer {
  need(value instanceof Uint8Array && !types.isProxy(value) && [Uint8Array.prototype,Buffer.prototype].includes(Object.getPrototypeOf(value)),"OUTBOX_INPUT_LIMIT");
  const typed=Object.getPrototypeOf(Uint8Array.prototype),length=Object.getOwnPropertyDescriptor(typed,"byteLength")!.get!,buffer=Object.getOwnPropertyDescriptor(typed,"buffer")!.get!,offset=Object.getOwnPropertyDescriptor(typed,"byteOffset")!.get!;
  const n=length.call(value) as number,backing=buffer.call(value) as ArrayBuffer,at=offset.call(value) as number;
  need(n<=limit && !(typeof SharedArrayBuffer!=="undefined" && backing instanceof SharedArrayBuffer),"OUTBOX_INPUT_LIMIT");
  return Buffer.from(new Uint8Array(backing,at,n));
}
export function canonicalInput(value: unknown, limit: number): unknown {
  const raw = bytes(value, limit);
  let text: string, parsed: unknown;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw); parsed = JSON.parse(text); }
  catch { throw new OutboxError("INVALID_CANONICAL_BYTES"); }
  const captured = captureValue(parsed);
  need(Buffer.from(canonicalEncode(captured)).equals(raw), "INVALID_CANONICAL_BYTES");
  return captured;
}
export type Head = Readonly<{ hash: ContentHash; position: number; canonicalTime: number }>;
export type Statement = Readonly<{
  version: "irontrellis-anchor-statement/1"; domain: Readonly<{ protocol: string; version: string; deploymentId: string }>;
  historyId: ContentHash; genesisEventHash: ContentHash; profile: Readonly<{ id: string; manifestHash: ContentHash }>;
  head: Head; stateRoot: ContentHash; projectionHead: ContentHash | null; attestationDigest: ContentHash; sequence: number;
  predecessor: ContentHash | null; previousHead: Readonly<{ hash: ContentHash; position: number }> | null;
  chain: Readonly<{ id: string; destination: string }>;
  evidence: Readonly<{ manifestDigest: ContentHash | null; certificateDigest: ContentHash | null; checkpointEventId: string | null }>;
  availability: "ANCHOR_ONLY" | "BODIES" | "BODIES_AND_ARTIFACTS";
}>;
export type SelectedProfile = Readonly<{ id: string; manifestHash: ContentHash; chainId: string; destination: `0x${string}`; publisher: `0x${string}`; adapterIdentity: string; feePolicy: string; trustRoot: ProfileTrustRoot }>;
export function profile(input: unknown): SelectedProfile {
  const p = fields(input, ["id", "manifestHash", "chainId", "destination", "publisher", "adapterIdentity", "feePolicy","trustRoot"]);
  need(isIdentifier(p.id) && hash(p.manifestHash) && address(p.destination) && address(p.publisher) && isIdentifier(p.adapterIdentity) && isProtocolString(p.feePolicy), "PROFILE_BINDING_INVALID");
  const chain = typeof p.chainId === "string" ? /^eip155:([1-9][0-9]{0,15})$/.exec(p.chainId) : null;
  need(chain !== null && chain[0] === p.chainId && Number.isSafeInteger(Number(chain[1])) && Number(chain[1]) <= Math.floor((Number.MAX_SAFE_INTEGER - 36) / 2), "PROFILE_CHAIN_INVALID");
  return p as unknown as SelectedProfile;
}
export function statement(input: unknown): Statement {
  const s = exact(input, ["version","domain","historyId","genesisEventHash","profile","head","stateRoot","projectionHead","attestationDigest","sequence","predecessor","previousHead","chain","evidence","availability"]);
  const domain = exact(s.domain, ["protocol","version","deploymentId"]), p = exact(s.profile,["id","manifestHash"]), h = exact(s.head,["hash","position","canonicalTime"]);
  need(s.version === "irontrellis-anchor-statement/1" && domain.protocol === "irontrellis" && domain.version === "2" && isIdentifier(domain.deploymentId), "STATEMENT_DOMAIN_INVALID");
  need(hash(s.historyId) && hash(s.genesisEventHash) && isIdentifier(p.id) && hash(p.manifestHash) && hash(h.hash) && isU53(h.position) && isU53(h.canonicalTime), "STATEMENT_HEAD_INVALID");
  need(hash(s.stateRoot) && (s.projectionHead === null || hash(s.projectionHead)) && hash(s.attestationDigest) && isU53(s.sequence), "STATEMENT_ROOT_INVALID");
  need(s.predecessor === null || hash(s.predecessor), "STATEMENT_PREDECESSOR_INVALID");
  if (s.previousHead !== null) { const old = exact(s.previousHead,["hash","position"]); need(hash(old.hash) && isU53(old.position), "STATEMENT_PREVIOUS_HEAD_INVALID"); }
  need((s.sequence === 0) === (s.predecessor === null) && (s.sequence === 0) === (s.previousHead === null), "STATEMENT_LINK_INVALID");
  const chain = exact(s.chain,["id","destination"]), evidence = exact(s.evidence,["manifestDigest","certificateDigest","checkpointEventId"]);
  need(isProtocolString(chain.id) && isProtocolString(chain.destination), "STATEMENT_CHAIN_INVALID");
  need((evidence.manifestDigest === null || hash(evidence.manifestDigest)) && (evidence.certificateDigest === null || hash(evidence.certificateDigest)) &&
    (evidence.checkpointEventId === null || isIdentifier(evidence.checkpointEventId)), "STATEMENT_EVIDENCE_INVALID");
  need(["ANCHOR_ONLY","BODIES","BODIES_AND_ARTIFACTS"].includes(s.availability as string), "STATEMENT_AVAILABILITY_INVALID");
  return s as unknown as Statement;
}
export function replaySnapshot(input: unknown): ReplayState {
  const state = replayHistory(input);
  need(state.format === TRELLIS2_FORMAT, "FORMAT2_HISTORY_REQUIRED");
  return state;
}
export function validateReplayBindings(s: Statement, attestation: unknown, state: ReplayState, p: SelectedProfile): ContentHash {
  const genesis = state.events[0]!;
  need(digest(s.domain) === digest(state.genesis.domain) && s.historyId === historyIdOfGenesis(genesis) && s.genesisEventHash === eventHash(genesis), "GENESIS_BINDING_INVALID");
  need(s.profile.id === p.id && s.profile.manifestHash === p.manifestHash && s.chain.id === p.chainId && s.chain.destination === p.destination, "PROFILE_BINDING_INVALID");
  need(s.head.position <= state.head.position && state.eventHistoryHashes[s.head.position] === s.head.hash && state.events[s.head.position]?.timestamp === s.head.canonicalTime, "HEAD_NOT_PREFIX");
  need(rootAt(state,s.head.position) === s.stateRoot && projectionHeadAt(state,s.head.position) === s.projectionHead, "ROOT_BINDING_INVALID");
  const a = exact(attestation,["version","domain","head","stateRoot","projectionHead","keyId","scheme","signature"]), facts = verifyHeadAttestationFacts(a,state);
  need(a.version === "irontrellis-head-attestation/2" && digest(a.head) === digest(s.head) && digest(a) === s.attestationDigest &&
    facts.valid && facts.signatureValid && facts.prefix && facts.stateRootValid && facts.projectionValid, "ATTESTATION_BINDING_INVALID");
  validateRoleSeparation(state,p);
  const namespaceId=digest({version:"irontrellis-anchor-namespace/1",domain:s.domain,historyId:s.historyId,genesisEventHash:s.genesisEventHash,
    profile:s.profile,chain:{id:s.chain.id},publisher:p.publisher});
  need(namespaceId===p.trustRoot.namespaceId,"NAMESPACE_BINDING_INVALID");
  return namespaceId;
}
/**
 * A-185.2 (profile MUST): A-111.3's signer test on the `/2` attestation a statement carries, before it is enqueued. Under the
 * owner approval policy in force at the head, `DECLARED` refuses an `AGENT` signer and `ATTESTED` anything but `HUMAN` at
 * `head.canonicalTime`; Core's `unqualifiedHeadSigner` decides. Without a policy every key is `HUMAN` and nothing changes.
 */
export function validateAttestationSigner(s: Statement, attestation: Readonly<{ keyId: string }>, state: ReplayState): void {
  need(unqualifiedHeadSigner(state, s.head.position, s.head.canonicalTime, attestation.keyId) === undefined, "ATTESTATION_SIGNER_UNQUALIFIED");
}
/** Compare public identities actually present in the replay. External custody
 * independence cannot be inferred by comparing public strings. */
export function validateRoleSeparation(state:ReplayState,p:SelectedProfile):void {
  const operators=p.trustRoot.manifest.operatorKeys.map(k=>k.credential.toLowerCase());
  const credentials=new Set<string>();
  const visit = (v: unknown): void => {
    if (Array.isArray(v)) { for (const item of v) visit(item); return; }
    if (v === null || typeof v !== "object") return;
    for (const [key,value] of Object.entries(v)) {
      if (/credential/i.test(key) && typeof value === "string") credentials.add(value.toLowerCase());
      visit(value);
    }
  };
  visit(state.events);
  for (const set of state.credentialAddressKeysByAgent.values()) for (const credential of set) credentials.add(credential.toLowerCase());
  need(!credentials.has(p.publisher),"PUBLISHER_CREDENTIAL_CLASH");
  need(operators.every(k=>k!==p.publisher && !credentials.has(k)),"OPERATOR_CREDENTIAL_CLASH");
}
export function chunks(raw: Uint8Array): readonly string[] {
  const hex = Buffer.from(raw).toString("hex"), out: string[] = [];
  for (let i=0;i<hex.length;i+=4096) out.push(hex.slice(i,i+4096));
  return Object.freeze(out);
}
export function unchunk(input: unknown, limit: number): Buffer {
  need(Array.isArray(input) && input.length > 0 && input.length <= Math.ceil(limit/2048), "STORED_BYTES_INVALID");
  const list = input as string[];
  need(list.every((x,i)=>typeof x === "string" && x.length > 0 && x.length <= 4096 && x.length%2 === 0 && /^[0-9a-f]+$/.exec(x)?.[0] === x && (i===list.length-1 || x.length===4096)), "STORED_BYTES_INVALID");
  const raw = Buffer.from(list.join(""),"hex"); need(raw.length <= limit,"STORED_BYTES_INVALID"); return raw;
}
