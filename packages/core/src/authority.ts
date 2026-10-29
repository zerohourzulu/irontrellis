/**
 * The authorization engine: corpus, delegation paths, attenuation, the
 * authority algebra, proofs, failures, runtime challenges and the signed
 * transition validators used by replay (spec 02, spec 03 §F/§I).
 *
 * Decisions are reproduced bit-for-bit from the legacy engine. The only
 * behavioural additions are the format-1 hooks: the history's hash algorithm
 * selects the challenge hash, the session's credential scheme selects the
 * signature suite, and format-1 domains are compared as opaque records.
 *
 * Performance: everything derived from the replay state that does not depend
 * on the request (the validated corpus with every delegation path, the
 * per-actor candidate index, the prohibition indexes and the evidence
 * references) is memoised per state object and invalidated by head hash, so a
 * decision costs O(candidates of the actor), not O(history).
 */
import type {
  ActionRequest, AdministrativeRequirements, AgentRecord, Amount, AuthorityConstraints, AuthorityEvidence, AuthorityGrant, AuthorityRecord,
  AuthorityUsage, AuthorizationDomain, AuthorizationProof, AuthorizationResult, AuthorizeInput, CanonicalEvent, ConsequentialBinding, ContentHash,
  DenialCode, DenialEvidence, EvidenceReference, GlobalProhibitionGrant, HashAlgorithm, HexSignature, HistoryHead, IntentAdmissionRecord,
  IntersectionProof, PermissionGrant, PrincipalRecord, ProhibitionGrant, RecognizedRoot, ReplayResult, ReplayState, RootProhibitionGrant,
  RuntimeAuthorizationChallenge, RuntimeSessionRecord, ScopeAssurance, TransactionIntent, U53, UsageCounter
} from "./types.ts";
import { CanonicalError, amountOf, canonicalEncode, captureValue, isAmount, isAmountString, isChainId, isContentHash, isEthereumAddress, isIdentifier, isU53, wireAmounts } from "./canonical.ts";
import { budgetCheckAfterAllow } from "./budgets.ts";
import { hashCanonical } from "./hash.ts";
import { suiteFor } from "./crypto/suites.ts";
import {
  agentLifecycleEvidence, boundedResult, collidingEventEvidence, compareIds, compareIdSequences, createEvidenceContext, decisionEvidence, decisionEvidenceLength,
  denialResult, eventReference, indeterminate, intentDecisionEvidence, MAX_RESULT_EVIDENCE, narrowedDecisionEvidence, noteEvidenceEvent,
  sessionLifecycleEvidence, simpleDenial, tenureLifecycleEvidence, type EvidenceContext
} from "./authority-evidence.ts";

export const AUTHORIZATION_VERSION = "continuity-authorization/0.2";
export const AUTHORITY_EVALUATION_VERSION = "continuity-authority-evaluation/0.2";
export const INTENT_ADMISSION_VERSION = "continuity-intent-admission/0.2";
export const AUTHORIZATION_PROOF_VERSION = "continuity-authorization-proof/0.2";
export const RUNTIME_AUTHORIZATION_VERSION = "continuity-runtime-authorization/0.2";
/** Format 2 literals (SPEC §8.2–8.3); a state's genesis `versions` block names the one in force. */
export const AUTHORIZATION_PROOF_VERSION_2 = "irontrellis-authorization-proof/2";
export const RUNTIME_AUTHORIZATION_VERSION_2 = "irontrellis-runtime-authorization/2";
/** The history edition the authority engine adapts its shapes to: amounts, domains, signatures and literals. */
type Edition = "0.2" | "1" | "2";
const editionOf = (state: ReplayState): Edition => (state.format === "continuity-event/0.2" ? "0.2" : state.format === "irontrellis-event/2" ? "2" : "1");
const editionOfDomain = (domain: AuthorizationDomain): Edition => (domain.protocol === "irontrellis" ? (domain.version === "2" ? "2" : "1") : "0.2");
const runtimeVersionOf = (state: ReplayState): { version?: string } => {
  const version = state.genesis.versions.runtimeAuthorizationVersion;
  return version === undefined ? {} : { version };
};
export const ROOT_RECOGNITION_POLICY = "declared-principal-root/0.2";

const MAX_IDENTIFIER_BYTES = 256;
const MAX_PROTOCOL_STRING_BYTES = 4096;
const MAX_AUTHORITIES = 1024;
const MAX_PATH_DEPTH = 32;
const MAX_REQUIRED_INTERSECTIONS = 32;
const MAX_SET_MEMBERS = 256;
const MAX_BIGINT = (1n << 256n) - 1n;
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const MAX_LOW_S = (SECP256K1_ORDER - 1n) / 2n;
/** Adapter policy editions that enable the attempt-duty events (spec 01 F.3). */
const ADAPTER_POLICY_E5_HASH = "0x32c2a5608c7110f1a291517e136cedf62d59a2cb81be1141dd2705bce307ab29";
const ADAPTER_POLICY_E6_HASH = "0xa90baac702f22f5a5f71141318a7651c1d963bbbee28138bbea835d942d0114c";
const LEGACY_HASH: HashAlgorithm = "keccak256";

const NO_IDS: readonly string[] = Object.freeze([]);
type Rec = Readonly<Record<string, unknown>>;

// ---------------------------------------------------------------- scalar helpers

const isPlainRecord = (value: unknown): value is Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
};

/** Optional-field read. Captured records never carry undefined-valued keys, so a plain read equals the legacy own-property check. */
const own = <T extends object, K extends keyof T>(value: T, key: K): T[K] | undefined => value[key];

/** UTF-8 length, or undefined for a lone surrogate. */
const utf8Length = (value: string): number | undefined => {
  let bytes = 0;
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit < 0xdc00) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next < 0xe000)) return undefined;
      bytes += 4;
      i += 1;
    } else if (unit >= 0xdc00 && unit < 0xe000) return undefined;
    else bytes += 3;
  }
  return bytes;
};

type Status = "VALID" | "INVALID" | "LIMIT";
const merge = (a: Status, b: Status): Status => (a === "LIMIT" || b === "LIMIT" ? "LIMIT" : a === "INVALID" || b === "INVALID" ? "INVALID" : "VALID");

const identifierStatus = (value: unknown): Status => {
  if (typeof value !== "string") return "INVALID";
  if (value.length > MAX_IDENTIFIER_BYTES) return "LIMIT";
  const bytes = utf8Length(value);
  if (bytes !== undefined && bytes > MAX_IDENTIFIER_BYTES) return "LIMIT";
  return isIdentifier(value) ? "VALID" : "INVALID";
};
const amountStatus = (value: unknown): Status =>
  typeof value === "bigint" && (value < -MAX_BIGINT || value > MAX_BIGINT) ? "LIMIT" : isAmount(value) ? "VALID" : "INVALID";
const identifierListStatus = (value: unknown, maximum: number, nonempty = false): Status => {
  if (!Array.isArray(value)) return "INVALID";
  if (value.length > maximum) return "LIMIT";
  if (nonempty && value.length === 0) return "INVALID";
  const seen = new Set<string>();
  let status: Status = "VALID";
  for (const member of value as unknown[]) {
    const s = identifierStatus(member);
    status = merge(status, s);
    if (s === "VALID") {
      if (seen.has(member as string)) status = merge(status, "INVALID");
      seen.add(member as string);
    }
  }
  return status;
};

/** Legacy `Signature65`: lowercase hex, low-s, recovery byte 1b/1c (spec 02 §0.3). */
export function isSignature65(value: unknown): value is HexSignature {
  if (typeof value !== "string" || !/^0x[0-9a-f]{130}$/.test(value)) return false;
  const r = BigInt(`0x${value.slice(2, 66)}`);
  const s = BigInt(`0x${value.slice(66, 130)}`);
  const v = value.slice(130);
  return r > 0n && r < SECP256K1_ORDER && s > 0n && s <= MAX_LOW_S && (v === "1b" || v === "1c");
}
const isEd25519Signature = (value: unknown): value is HexSignature => typeof value === "string" && /^0x[0-9a-f]{128}$/.test(value);
const signatureShapeValid = (value: unknown, legacy: boolean): value is HexSignature =>
  isSignature65(value) || (!legacy && isEd25519Signature(value));

/** Exact key set: every key is required or optional, every required key present (undefined counts as absent). */
const exactRecord = (value: unknown, required: readonly string[], optional: readonly string[] = NO_IDS): value is Record<string, unknown> => {
  if (!isPlainRecord(value)) return false;
  let present = 0;
  for (const key of Object.keys(value)) {
    if (value[key] === undefined) continue;
    if (required.includes(key)) present += 1;
    else if (!optional.includes(key)) return false;
  }
  return present === required.length;
};

const LEGACY_DOMAIN_KEYS = ["protocol", "version", "deploymentId", "chainId", "verifyingContract"] as const;
const TRELLIS_DOMAIN_KEYS = ["protocol", "version", "deploymentId"] as const;
const domainIsValid = (value: unknown, edition: Edition): value is AuthorizationDomain =>
  edition === "0.2"
    ? exactRecord(value, LEGACY_DOMAIN_KEYS) &&
      value.protocol === "continuity" &&
      value.version === "0.2" &&
      isIdentifier(value.deploymentId) &&
      isChainId(value.chainId) &&
      isEthereumAddress(value.verifyingContract)
    : exactRecord(value, TRELLIS_DOMAIN_KEYS) && value.protocol === "irontrellis" && value.version === edition && isIdentifier(value.deploymentId);
const headIsValid = (value: unknown): value is HistoryHead =>
  exactRecord(value, ["hash", "position", "canonicalTime"]) && isContentHash(value.hash) && isU53(value.position) && isU53(value.canonicalTime);
const REQUEST_REQUIRED = ["actorId", "action", "resource", "claimedAt"] as const;
const REQUEST_OPTIONAL = ["amount", "counterpartyId", "termsCommitment"] as const;
/** Format 2 (SPEC §8.2): a request may name its `metric`. */
const REQUEST_OPTIONAL_2 = ["amount", "counterpartyId", "termsCommitment", "metric"] as const;
const requestHasExactShape = (value: unknown, edition: Edition): value is Record<string, unknown> => exactRecord(value, REQUEST_REQUIRED, edition === "2" ? REQUEST_OPTIONAL_2 : REQUEST_OPTIONAL);

/** Value validation of a structurally exact request (spec 02 §4 step 5). In format 2 the amount was captured already (A-134.1), so `INVALID_AMOUNT` is reached only by the legacy and format-1 rules. */
const requestProblem = (request: Record<string, unknown>, edition: Edition): "INVALID_REQUEST" | "INVALID_AMOUNT" | undefined => {
  if (
    !isIdentifier(request.actorId) ||
    !isIdentifier(request.action) ||
    !isIdentifier(request.resource) ||
    !isU53(request.claimedAt) ||
    (request.counterpartyId !== undefined && !isIdentifier(request.counterpartyId)) ||
    (request.termsCommitment !== undefined && !isContentHash(request.termsCommitment)) ||
    (request.metric !== undefined && !isIdentifier(request.metric))
  ) return "INVALID_REQUEST";
  return request.amount !== undefined && !(isAmount(request.amount) || (edition === "2" && isAmountString(request.amount))) ? "INVALID_AMOUNT" : undefined;
};
/** The request with the engine's bigint amount (format 2 requests may arrive with the wire string). */
const engineRequest = (request: ActionRequest): ActionRequest => {
  const amount = (request as { amount?: unknown }).amount;
  return typeof amount === "string" ? Object.freeze({ ...request, amount: amountOf(amount) as Amount }) : request;
};

const bindingIsStructurallyValid = (value: unknown, legacy: boolean): value is ConsequentialBinding =>
  exactRecord(value, ["runtimeSessionId", "controlEpoch", "roleId", "roleTenureId"], ["credentialKeyId", "intentId", "nonce", "runtimeSignature"]) &&
  isIdentifier(value.runtimeSessionId) &&
  isU53(value.controlEpoch) &&
  isIdentifier(value.roleId) &&
  isIdentifier(value.roleTenureId) &&
  (value.credentialKeyId === undefined || isIdentifier(value.credentialKeyId)) &&
  (value.intentId === undefined || isIdentifier(value.intentId)) &&
  (value.nonce === undefined || isIdentifier(value.nonce)) &&
  (value.runtimeSignature === undefined || signatureShapeValid(value.runtimeSignature, legacy));

/** Domains compare field-wise; a legacy `verifyingContract` compares case-insensitively. */
export function sameDomain(left: Rec, right: Rec): boolean {
  const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
  for (const key of keys) {
    const l = left[key];
    const r = right[key];
    if (key === "verifyingContract") {
      if (typeof l !== "string" || typeof r !== "string" || l.toLowerCase() !== r.toLowerCase()) return false;
    } else if (l !== r) return false;
  }
  return true;
}
const sameHead = (a: HistoryHead, b: HistoryHead): boolean => a.hash === b.hash && a.position === b.position && a.canonicalTime === b.canonicalTime;

const sortedIds = (values: readonly string[]): readonly string[] => Object.freeze([...values].sort(compareIds));
const leastId = (values: ReadonlySet<string>): string | undefined => {
  let least: string | undefined;
  for (const v of values) if (least === undefined || compareIds(v, least) < 0) least = v;
  return least;
};

// ---------------------------------------------------------------- normalisation

const optionalFields = <T extends object>(source: T, keys: readonly (keyof T)[]): Partial<T> => {
  const out: Partial<T> = {};
  for (const key of keys) if (own(source, key) !== undefined) out[key] = source[key];
  return out;
};

export function normalizedConstraints(c: AuthorityConstraints): AuthorityConstraints {
  return Object.freeze({
    actions: sortedIds(c.actions),
    resources: sortedIds(c.resources),
    quantitative: c.quantitative,
    ...optionalFields(c, ["notBefore", "expiresAt", "maxAmount", "maxCumulativeAmount", "maxTransactions"]),
    maxDelegationDepth: c.maxDelegationDepth,
    requiredIntersectionIds: sortedIds(c.requiredIntersectionIds),
  });
}

const normalizedPermission = (g: PermissionGrant): PermissionGrant =>
  Object.freeze({
    kind: "PERMISSION",
    authorityId: g.authorityId,
    grantorId: g.grantorId,
    granteeId: g.granteeId,
    rootAuthorityId: g.rootAuthorityId,
    ...optionalFields(g, ["parentAuthorityId"]),
    independent: g.independent,
    constraints: normalizedConstraints(g.constraints),
  });

/** A grant with its constraint arrays sorted (as written into proofs); unknown keys dropped. */
export function normalizedGrant(grant: AuthorityGrant): AuthorityGrant {
  if (grant.kind === "PERMISSION") return normalizedPermission(grant);
  const base = { kind: "PROHIBITION" as const, authorityId: grant.authorityId, grantorId: grant.grantorId, ...optionalFields(grant, ["subjectActorId"]) };
  return grant.scope === "GLOBAL"
    ? Object.freeze({ ...base, scope: "GLOBAL", constraints: normalizedConstraints(grant.constraints) })
    : Object.freeze({
        ...base,
        scope: "ROOT",
        rootAuthorityId: grant.rootAuthorityId,
        ...optionalFields(grant, ["parentAuthorityId"]),
        constraints: normalizedConstraints(grant.constraints),
      });
}

const normalizedRequest = (r: ActionRequest): ActionRequest =>
  Object.freeze({
    actorId: r.actorId,
    action: r.action,
    resource: r.resource,
    claimedAt: r.claimedAt,
    ...optionalFields(r, ["amount", "counterpartyId", "termsCommitment", "metric"]),
  });

const normalizedDomain = (d: AuthorizationDomain): AuthorizationDomain =>
  "chainId" in d
    ? Object.freeze({ protocol: d.protocol, version: d.version, deploymentId: d.deploymentId, chainId: d.chainId, verifyingContract: d.verifyingContract })
    : Object.freeze({ protocol: d.protocol, version: d.version, deploymentId: d.deploymentId });

// ---------------------------------------------------------------- attenuation and constraint algebra

const subset = (child: readonly string[], parent: readonly string[]): boolean => child.every((v) => parent.includes(v));
const boundKept = <T extends number | bigint>(parent: T | undefined, child: T | undefined): boolean =>
  parent === undefined || (child !== undefined && child <= parent);

/** Engine-side attenuation (spec 02 §3.3): a child may only narrow, never drop a bound, and loses one delegation level. */
export function constraintsAreAttenuated(parent: AuthorityConstraints, child: AuthorityConstraints): boolean {
  if (
    !subset(child.actions, parent.actions) ||
    !subset(child.resources, parent.resources) ||
    !subset(parent.requiredIntersectionIds, child.requiredIntersectionIds) ||
    parent.maxDelegationDepth === 0 ||
    child.maxDelegationDepth > parent.maxDelegationDepth - 1 ||
    (parent.quantitative && !child.quantitative)
  ) return false;
  const parentNotBefore = own(parent, "notBefore");
  const childNotBefore = own(child, "notBefore");
  if (parentNotBefore !== undefined && (childNotBefore === undefined || childNotBefore < parentNotBefore)) return false;
  return (
    boundKept(own(parent, "expiresAt"), own(child, "expiresAt")) &&
    boundKept(own(parent, "maxAmount"), own(child, "maxAmount")) &&
    boundKept(own(parent, "maxCumulativeAmount"), own(child, "maxCumulativeAmount")) &&
    boundKept(own(parent, "maxTransactions"), own(child, "maxTransactions"))
  );
}

const minOf = <T extends number | bigint>(cur: T | undefined, next: T | undefined): T | undefined =>
  next === undefined ? cur : cur === undefined || next < cur ? next : cur;
const maxOf = (cur: number | undefined, next: number | undefined): number | undefined =>
  next === undefined ? cur : cur === undefined || next > cur ? next : cur;

/** Effective constraints of a grant sequence (spec 02 §3.6): intersections narrow, bounds take the tighter value. */
export function combineConstraints(grants: readonly PermissionGrant[]): AuthorityConstraints {
  let actions: readonly string[] | undefined;
  let resources: readonly string[] | undefined;
  let quantitative = false;
  let notBefore: number | undefined;
  let expiresAt: number | undefined;
  let maxAmount: bigint | undefined;
  let maxCumulativeAmount: bigint | undefined;
  let maxTransactions: number | undefined;
  let maxDelegationDepth: number | undefined;
  const required = new Set<string>();
  for (const { constraints: c } of grants) {
    actions = actions === undefined ? sortedIds(c.actions) : actions.filter((a) => c.actions.includes(a));
    resources = resources === undefined ? sortedIds(c.resources) : resources.filter((r) => c.resources.includes(r));
    quantitative = quantitative || c.quantitative;
    notBefore = maxOf(notBefore, own(c, "notBefore"));
    expiresAt = minOf(expiresAt, own(c, "expiresAt"));
    maxAmount = minOf(maxAmount, own(c, "maxAmount"));
    maxCumulativeAmount = minOf(maxCumulativeAmount, own(c, "maxCumulativeAmount"));
    maxTransactions = minOf(maxTransactions, own(c, "maxTransactions"));
    maxDelegationDepth = minOf(maxDelegationDepth, c.maxDelegationDepth);
    for (const id of c.requiredIntersectionIds) required.add(id);
  }
  return Object.freeze({
    actions: actions ?? NO_IDS,
    resources: resources ?? NO_IDS,
    quantitative,
    ...(notBefore === undefined ? {} : { notBefore }),
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...(maxAmount === undefined ? {} : { maxAmount }),
    ...(maxCumulativeAmount === undefined ? {} : { maxCumulativeAmount }),
    ...(maxTransactions === undefined ? {} : { maxTransactions }),
    maxDelegationDepth: maxDelegationDepth ?? 0,
    requiredIntersectionIds: sortedIds([...required]),
  });
}

// ---------------------------------------------------------------- corpus, paths and validation

type Corpus = Readonly<{
  permissions: Map<string, PermissionGrant>;
  prohibitions: Map<string, ProhibitionGrant>;
  roots: ReadonlyMap<string, RecognizedRoot>;
  /** Raw path: supplied evidence records. Replay path: derived from `records` on demand. */
  evidence?: ReadonlyMap<string, AuthorityEvidence>;
  revoked: Set<string>;
  usage: ReadonlyMap<string, AuthorityUsage>;
  globalPolicySourceId: string;
  /** Replay path only: terminated parties fail a grant, roots are cross-checked against records. */
  agents?: ReadonlyMap<string, AgentRecord>;
  principals?: ReadonlyMap<string, PrincipalRecord>;
  records?: ReadonlyMap<string, AuthorityRecord>;
}>;
type Path = Readonly<{
  rootAuthorityId: string;
  grants: readonly PermissionGrant[];
  authorityIds: readonly string[];
  effectivelyIndependent: boolean;
  /** Spec 02 §3.5, fixed at grant time: the chain starts at a parent-less permission by the root's principal. */
  recognizedRoot: RecognizedRoot | undefined;
}>;
type Intersection = Readonly<{ requiredAuthorityId: string; requiredByAuthorityIds: readonly string[]; path: Path; recognizedRoot: RecognizedRoot }>;
type Graph = Readonly<{ main: Path; paths: readonly Path[]; intersections: readonly Intersection[]; missingIntersectionIds: readonly string[] }>;
/** The validated corpus plus every request-independent index; grown in place as an append-only state grows. */
type Validated = Readonly<{
  corpus: Corpus;
  paths: Map<string, Path>;
  /** Independent paths whose terminal grantee is the actor, in permission order. */
  candidatesByActor: Map<string, Path[]>;
  /**
   * For actors with many candidates (built on first use, then kept up to date by `indexCandidate`): the actor's
   * candidates per resource their terminal grant names, in permission order. Only a lookup aid for `evaluateAlgebra`.
   */
  candidatesByResource: Map<string, Map<string, Path[]>>;
  /** GLOBAL prohibitions sorted by id; ROOT prohibitions per root, sorted by id. */
  globals: GlobalProhibitionGrant[];
  rootProhibitions: Map<string, RootProhibitionGrant[]>;
  /** Candidate graphs per path (a graph depends only on the paths, so it is invalid only when a permission is added). */
  graphs: Map<Path, Graph>;
}>;
type CorpusValidation = Readonly<{ status: "INVALID_INPUT" }> | Readonly<{ status: "INVALID_DELEGATION" }> | Readonly<{ status: "VALID"; validated: Validated }>;

const evidenceOf = (corpus: Corpus, id: string): AuthorityEvidence | undefined => {
  if (corpus.evidence !== undefined) return corpus.evidence.get(id);
  const record = corpus.records?.get(id);
  return record === undefined ? undefined : { authorityId: id, grantEventId: record.grantEventId, grantEventPosition: record.grantEventPosition };
};

const replayCorpus = (state: ReplayState): Corpus => {
  const permissions = new Map<string, PermissionGrant>();
  const prohibitions = new Map<string, ProhibitionGrant>();
  const revoked = new Set<string>();
  for (const [id, record] of state.authorities) {
    if (record.grant.kind === "PERMISSION") permissions.set(id, record.grant);
    else prohibitions.set(id, record.grant);
    if (record.revocationEventId !== undefined) revoked.add(id);
  }
  return {
    permissions,
    prohibitions,
    roots: state.recognizedRoots,
    revoked,
    usage: state.authorityUsage,
    globalPolicySourceId: state.genesis.globalPolicySourceId,
    agents: state.agents,
    principals: state.principals,
    records: state.authorities,
  };
};

type PathBuild = Readonly<{ status: "VALID"; path: Path }> | Readonly<{ status: "INVALID_INPUT" }> | Readonly<{ status: "INVALID_DELEGATION" }>;
const INVALID_DELEGATION: PathBuild = Object.freeze({ status: "INVALID_DELEGATION" });
const INVALID_INPUT: PathBuild = Object.freeze({ status: "INVALID_INPUT" });

const recognizedRootOf = (corpus: Corpus, rootAuthorityId: string, first: PermissionGrant): RecognizedRoot | undefined => {
  const root = corpus.roots.get(rootAuthorityId);
  return root !== undefined &&
    first.authorityId === root.rootAuthorityId &&
    first.rootAuthorityId === root.rootAuthorityId &&
    first.grantorId === root.principalId &&
    own(first, "parentAuthorityId") === undefined
    ? root
    : undefined;
};

/** Walk parent links to the root; cycles and dangling parents are delegation faults, depth > 32 an input limit. */
const buildPermissionPath = (terminal: PermissionGrant, corpus: Corpus): PathBuild => {
  const permissions = corpus.permissions;
  if (own(terminal, "parentAuthorityId") === undefined) {
    const grants = [terminal];
    return {
      status: "VALID",
      path: { rootAuthorityId: terminal.rootAuthorityId, grants, authorityIds: [terminal.authorityId], effectivelyIndependent: terminal.independent, recognizedRoot: recognizedRootOf(corpus, terminal.rootAuthorityId, terminal) },
    };
  }
  const reverse: PermissionGrant[] = [];
  const visited = new Set<string>();
  let current: PermissionGrant | undefined = terminal;
  while (current !== undefined) {
    if (visited.has(current.authorityId)) return INVALID_DELEGATION;
    if (reverse.length === MAX_PATH_DEPTH) return INVALID_INPUT;
    visited.add(current.authorityId);
    reverse.push(current);
    const parentId = own(current, "parentAuthorityId");
    if (parentId === undefined) break;
    current = permissions.get(parentId);
    if (current === undefined) return INVALID_DELEGATION;
  }
  const grants = reverse.reverse();
  let effectivelyIndependent = true;
  for (let i = 0; i < grants.length; i += 1) {
    const grant = grants[i] as PermissionGrant;
    if (!grant.independent) effectivelyIndependent = false;
    if (i === 0) continue;
    const parent = grants[i - 1] as PermissionGrant;
    if (grant.grantorId !== parent.granteeId || grant.rootAuthorityId !== parent.rootAuthorityId || !constraintsAreAttenuated(parent.constraints, grant.constraints)) {
      return INVALID_DELEGATION;
    }
  }
  const first = grants[0] as PermissionGrant;
  return { status: "VALID", path: { rootAuthorityId: first.rootAuthorityId, grants, authorityIds: grants.map((g) => g.authorityId), effectivelyIndependent, recognizedRoot: recognizedRootOf(corpus, first.rootAuthorityId, first) } };
};

/** DFS over `requiredIntersectionIds` edges between permissions; a cycle is a delegation fault. */
const intersectionGraphIsAcyclic = (permissions: ReadonlyMap<string, PermissionGrant>, starts: readonly string[]): boolean => {
  const done = new Set<string>();
  for (const start of starts) {
    if (done.has(start)) continue;
    const active = new Set<string>([start]);
    const stack: { id: string; next: number }[] = [{ id: start, next: 0 }];
    while (stack.length > 0) {
      const frame = stack[stack.length - 1] as { id: string; next: number };
      const deps = (permissions.get(frame.id) as PermissionGrant).constraints.requiredIntersectionIds;
      if (frame.next >= deps.length) {
        stack.pop();
        active.delete(frame.id);
        done.add(frame.id);
        continue;
      }
      const dep = deps[frame.next] as string;
      frame.next += 1;
      if (!permissions.has(dep) || done.has(dep)) continue;
      if (active.has(dep)) return false;
      active.add(dep);
      stack.push({ id: dep, next: 0 });
    }
  }
  return true;
};

const rootIsValid = (corpus: Corpus, root: RecognizedRoot): boolean => {
  const id = root.rootAuthorityId;
  const grant = corpus.permissions.get(id);
  // The replay path reads the record directly (its evidence is derived from it, so the position check is tautological).
  const evidence = corpus.records !== undefined ? corpus.records.get(id) : corpus.evidence?.get(id);
  if (
    grant === undefined ||
    evidence === undefined ||
    own(grant, "parentAuthorityId") !== undefined ||
    grant.authorityId !== id ||
    grant.rootAuthorityId !== id ||
    grant.grantorId !== root.principalId ||
    evidence.grantEventId !== root.rootGrantEventId
  ) return false;
  return corpus.principals === undefined || root.principalRecognitionEventId === corpus.principals.get(root.principalId)?.creationEventId;
};

const prohibitionIsValid = (corpus: Corpus, paths: ReadonlyMap<string, Path>, p: ProhibitionGrant): boolean => {
  if (p.scope === "GLOBAL") return p.grantorId === corpus.globalPolicySourceId;
  const root = corpus.roots.get(p.rootAuthorityId);
  if (root === undefined) return false;
  const parentId = own(p, "parentAuthorityId");
  if (p.grantorId === root.principalId) {
    const rootGrant = corpus.permissions.get(root.rootAuthorityId);
    return parentId === undefined && rootGrant !== undefined && constraintsAreAttenuated(rootGrant.constraints, p.constraints);
  }
  const parent = parentId === undefined ? undefined : corpus.permissions.get(parentId);
  const path = parentId === undefined ? undefined : paths.get(parentId);
  return parent !== undefined && path !== undefined && parent.granteeId === p.grantorId && path.rootAuthorityId === p.rootAuthorityId && constraintsAreAttenuated(parent.constraints, p.constraints);
};

const isCapped = (g: PermissionGrant): boolean => own(g.constraints, "maxTransactions") !== undefined || own(g.constraints, "maxCumulativeAmount") !== undefined;
const byAuthorityId = (a: ProhibitionGrant, b: ProhibitionGrant): number => compareIds(a.authorityId, b.authorityId);

const addByResource = (byResource: Map<string, Path[]>, path: Path): void => {
  for (const resource of new Set((path.grants[path.grants.length - 1] as PermissionGrant).constraints.resources)) {
    const list = byResource.get(resource);
    if (list === undefined) byResource.set(resource, [path]);
    else list.push(path);
  }
};
const indexCandidate = (v: Validated, path: Path): void => {
  if (!path.effectivelyIndependent) return;
  const grantee = (path.grants[path.grants.length - 1] as PermissionGrant).granteeId;
  const list = v.candidatesByActor.get(grantee);
  if (list === undefined) v.candidatesByActor.set(grantee, [path]);
  else list.push(path);
  const byResource = v.candidatesByResource.get(grantee);
  if (byResource !== undefined) addByResource(byResource, path);
};
/** Actors with more candidates than this get a per-resource index (`candidatesByResource`). */
let resourceIndexMinCandidates = 32;
/**
 * Tests only: the candidate count above which `evaluateAlgebra` looks at the plausible candidates first (0: every
 * actor; `Infinity`: never). Returns the previous value. Decisions must be identical whatever the value.
 */
export function setCandidateIndexThresholdForTests(threshold: number): number {
  const previous = resourceIndexMinCandidates;
  resourceIndexMinCandidates = threshold;
  return previous;
}
/**
 * The candidates that can possibly succeed for `request`: a SUCCESS needs every grant of the candidate's graph, so in
 * particular the main path's terminal grant, to name the action and the resource (`evaluateCandidate` hits ACTION /
 * RESOURCE otherwise). Returned in the order of `candidatesByActor`; `undefined` when the actor has few candidates.
 */
const plausibleCandidates = (validated: Validated, request: ActionRequest, all: readonly Path[]): readonly Path[] | undefined => {
  if (all.length <= resourceIndexMinCandidates) return undefined;
  let byResource = validated.candidatesByResource.get(request.actorId);
  if (byResource === undefined) {
    byResource = new Map();
    for (const path of all) addByResource(byResource, path);
    validated.candidatesByResource.set(request.actorId, byResource);
  }
  return (byResource.get(request.resource) ?? NO_PATHS).filter((path) => (path.grants[path.grants.length - 1] as PermissionGrant).constraints.actions.includes(request.action));
};
const NO_PATHS: readonly Path[] = Object.freeze([]);
/** Adds one already-built path; false when a recognized root record disagrees with its grant. */
const indexPermission = (v: Validated, path: Path): boolean => {
  const id = (path.grants[path.grants.length - 1] as PermissionGrant).authorityId;
  v.paths.set(id, path);
  indexCandidate(v, path);
  const root = v.corpus.roots.get(id);
  return root === undefined || rootIsValid(v.corpus, root);
};
const indexProhibition = (v: Validated, p: ProhibitionGrant): boolean => {
  if (!prohibitionIsValid(v.corpus, v.paths, p)) return false;
  if (p.scope === "GLOBAL") {
    v.globals.push(p);
    v.globals.sort(byAuthorityId);
  } else {
    const list = v.rootProhibitions.get(p.rootAuthorityId);
    if (list === undefined) v.rootProhibitions.set(p.rootAuthorityId, [p]);
    else list.push(p), list.sort(byAuthorityId);
  }
  return true;
};

/** Spec 02 §3.4 over a whole corpus. */
const validateCorpus = (corpus: Corpus): CorpusValidation => {
  const v: Validated = { corpus, paths: new Map(), candidatesByActor: new Map(), candidatesByResource: new Map(), globals: [], rootProhibitions: new Map(), graphs: new Map() };
  const withIntersections: string[] = [];
  let capped = 0;
  for (const [id, permission] of corpus.permissions) {
    const built = buildPermissionPath(permission, corpus);
    if (built.status !== "VALID") return { status: built.status };
    v.paths.set(id, built.path);
    if (permission.constraints.requiredIntersectionIds.length > 0) withIntersections.push(id);
    if (isCapped(permission)) capped += 1;
  }
  if (withIntersections.length > 0 && !intersectionGraphIsAcyclic(corpus.permissions, withIntersections)) return { status: "INVALID_DELEGATION" };
  let valid = capped === corpus.usage.size;
  if (corpus.evidence !== undefined) {
    valid &&= corpus.evidence.size === corpus.permissions.size + corpus.prohibitions.size;
    for (const id of corpus.evidence.keys()) if (!corpus.permissions.has(id) && !corpus.prohibitions.has(id)) valid = false;
    for (const id of corpus.permissions.keys()) if (!corpus.evidence.has(id)) valid = false;
    for (const id of corpus.prohibitions.keys()) if (!corpus.evidence.has(id)) valid = false;
  }
  for (const root of corpus.roots.values()) if (!rootIsValid(corpus, root)) valid = false;
  for (const id of corpus.revoked) if (!corpus.permissions.has(id) && !corpus.prohibitions.has(id)) valid = false;
  for (const [id, permission] of corpus.permissions) if (isCapped(permission) && !corpus.usage.has(id)) valid = false;
  for (const p of corpus.prohibitions.values()) if (!prohibitionIsValid(corpus, v.paths, p)) valid = false;
  if (!valid) return { status: "INVALID_DELEGATION" };
  for (const path of v.paths.values()) indexCandidate(v, path);
  for (const p of corpus.prohibitions.values()) indexProhibition(v, p);
  return { status: "VALID", validated: v };
};

/**
 * Per-state memo of everything request-independent. A state that grew (same
 * prefix, more events) is extended event by event; anything else is rebuilt.
 */
type StateMemo = { position: number; hash: ContentHash; validation: CorpusValidation; evidence?: EvidenceContext };
const MEMO = new WeakMap<ReplayState, StateMemo>();

/** Applies events (memo.position, head] to the memo; false when the grown corpus needs a full validation. */
const extendMemo = (memo: StateMemo, state: ReplayState): boolean => {
  if (memo.validation.status !== "VALID") return false;
  const v = memo.validation.validated;
  for (let i = memo.position + 1; i <= state.head.position; i += 1) {
    const event = state.events[i] as CanonicalEvent;
    if (memo.evidence !== undefined) noteEvidenceEvent(memo.evidence, i);
    if (event.type === "AUTHORITY_REVOKED") {
      v.corpus.revoked.add(event.data.authorityId as string);
    } else if (event.type === "AUTHORITY_GRANTED") {
      const granted = event.data.grant as AuthorityGrant | undefined;
      const record = granted === undefined ? undefined : state.authorities.get(granted.authorityId);
      if (record === undefined || record.grantEventPosition !== i) return false;
      const grant = record.grant;
      if (grant.kind === "PERMISSION") {
        if (grant.constraints.requiredIntersectionIds.some((id) => !v.corpus.permissions.has(id))) return false;
        v.corpus.permissions.set(grant.authorityId, grant);
        const built = buildPermissionPath(grant, v.corpus);
        if (built.status !== "VALID" || (isCapped(grant) && !v.corpus.usage.has(grant.authorityId)) || !indexPermission(v, built.path)) return false;
        v.graphs.clear();
      } else {
        v.corpus.prohibitions.set(grant.authorityId, grant);
        if (!indexProhibition(v, grant)) return false;
      }
    }
  }
  memo.position = state.head.position;
  memo.hash = state.head.hash;
  return true;
};

const memoFor = (state: ReplayState): StateMemo => {
  const memo = MEMO.get(state);
  const head = state.head;
  if (memo !== undefined && memo.position <= head.position && state.eventHistoryHashes[memo.position] === memo.hash) {
    if (memo.position === head.position || extendMemo(memo, state)) return memo;
  }
  const fresh: StateMemo = { position: head.position, hash: head.hash, validation: validateCorpus(replayCorpus(state)) };
  MEMO.set(state, fresh);
  return fresh;
};
const evidenceFor = (state: ReplayState): EvidenceContext => {
  const memo = memoFor(state);
  if (memo.evidence === undefined) memo.evidence = createEvidenceContext(state);
  return memo.evidence;
};

// ---------------------------------------------------------------- intersection graph

/** Ids a grant introduces itself (inherited requirements are attributed to the ancestor that declared them). */
const directRequiredIds = (path: Path, index: number): readonly string[] => {
  const grant = path.grants[index] as PermissionGrant;
  if (index === 0) return grant.constraints.requiredIntersectionIds;
  const inherited = (path.grants[index - 1] as PermissionGrant).constraints.requiredIntersectionIds;
  return grant.constraints.requiredIntersectionIds.filter((id) => !inherited.includes(id));
};

const NO_INTERSECTIONS: readonly Intersection[] = Object.freeze([]);

/** Spec 02 §4.7: BFS over required intersections; a partner must be dependent and held by the actor. */
const selectCandidateGraph = (validated: Validated, main: Path, actorId: string): Graph => {
  if (main.grants.every((g) => g.constraints.requiredIntersectionIds.length === 0)) return { main, paths: [main], intersections: NO_INTERSECTIONS, missingIntersectionIds: NO_IDS };
  const requiredBy = new Map<string, Set<string>>();
  const queue: string[] = [];
  const selected = new Map<string, Intersection>();
  const missing = new Set<string>();
  const collect = (path: Path): void => {
    for (let i = 0; i < path.grants.length; i += 1) {
      const grant = path.grants[i] as PermissionGrant;
      for (const id of directRequiredIds(path, i)) {
        let declarers = requiredBy.get(id);
        if (declarers === undefined) {
          requiredBy.set(id, (declarers = new Set()));
          queue.push(id);
        }
        declarers.add(grant.authorityId);
      }
    }
  };
  collect(main);
  for (let q = 0; q < queue.length; q += 1) {
    const id = queue[q] as string;
    const path = validated.paths.get(id);
    const root = path?.recognizedRoot;
    const terminal = path?.grants[path.grants.length - 1];
    if (path === undefined || root === undefined || terminal === undefined || path.effectivelyIndependent || terminal.granteeId !== actorId) {
      missing.add(id);
      continue;
    }
    if (!selected.has(id)) {
      selected.set(id, { requiredAuthorityId: id, requiredByAuthorityIds: NO_IDS, path, recognizedRoot: root });
      collect(path);
    }
  }
  const ids = [...selected.keys()].sort(compareIds);
  const intersections: Intersection[] = [];
  const paths: Path[] = [main];
  for (const id of ids) {
    const sel = selected.get(id) as Intersection;
    paths.push(sel.path);
    intersections.push(Object.freeze({ ...sel, requiredByAuthorityIds: sortedIds([...(requiredBy.get(id) as Set<string>)]) }));
  }
  return { main, paths: Object.freeze(paths), intersections: Object.freeze(intersections), missingIntersectionIds: sortedIds([...missing]) };
};

/** The graph of a path whose terminal grantee is the actor (every caller guarantees that), memoised per corpus. */
const graphFor = (validated: Validated, main: Path): Graph => {
  let graph = validated.graphs.get(main);
  if (graph === undefined) validated.graphs.set(main, (graph = selectCandidateGraph(validated, main, (main.grants[main.grants.length - 1] as PermissionGrant).granteeId)));
  return graph;
};

const graphGrants = (graph: Graph): readonly PermissionGrant[] => (graph.paths.length === 1 ? graph.main.grants : graph.paths.flatMap((p) => p.grants));

// ---------------------------------------------------------------- prohibitions

const prohibitionRequestRelevant = (p: ProhibitionGrant, request: ActionRequest): boolean => {
  const subject = own(p, "subjectActorId");
  return (
    (subject === undefined || subject === request.actorId) &&
    p.constraints.actions.includes(request.action) &&
    p.constraints.resources.includes(request.resource) &&
    (!p.constraints.quantitative || own(request, "amount") !== undefined)
  );
};
const withinTime = (c: AuthorityConstraints, t: number): boolean => {
  const notBefore = own(c, "notBefore");
  const expiresAt = own(c, "expiresAt");
  return (notBefore === undefined || t >= notBefore) && (expiresAt === undefined || t < expiresAt);
};
const dependsOnTerminatedAgent = (corpus: Corpus, g: PermissionGrant): boolean =>
  corpus.agents !== undefined && (corpus.agents.get(g.grantorId)?.terminated === true || corpus.agents.get(g.granteeId)?.terminated === true);
/** Every grant from the root down to (and including) `terminalId` is live. */
const pathActiveThrough = (corpus: Corpus, path: Path, t: number, terminalId: string): boolean => {
  for (const g of path.grants) {
    if (corpus.revoked.has(g.authorityId) || !withinTime(g.constraints, t) || dependsOnTerminatedAgent(corpus, g)) return false;
    if (g.authorityId === terminalId) return true;
  }
  return false;
};
/** A prohibition's `maxAmount` is an inclusive upper bound on what it blocks (spec 02 §4.5). */
const prohibitionMatchesAmount = (p: ProhibitionGrant, request: ActionRequest): boolean => {
  const amount = own(request, "amount");
  const maxAmount = own(p.constraints, "maxAmount");
  return maxAmount === undefined || (amount !== undefined && amount <= maxAmount);
};
const prohibitionIsActive = (validated: Validated, p: ProhibitionGrant, t: number): boolean => {
  if (validated.corpus.revoked.has(p.authorityId) || !withinTime(p.constraints, t)) return false;
  if (p.scope === "GLOBAL") return true;
  const anchorId = own(p, "parentAuthorityId");
  if (anchorId === undefined) return true;
  const anchor = validated.paths.get(anchorId);
  return anchor !== undefined && pathActiveThrough(validated.corpus, anchor, t, anchorId);
};
const relevantGlobalProhibitions = (validated: Validated, request: ActionRequest): readonly GlobalProhibitionGrant[] =>
  validated.globals.length === 0 ? validated.globals : validated.globals.filter((p) => prohibitionRequestRelevant(p, request));
const NO_ROOT_PROHIBITIONS: readonly RootProhibitionGrant[] = Object.freeze([]);
/** ROOT prohibitions applying to any path of the graph (anchored ones need their anchor on such a path), sorted by id. */
const relevantCandidateProhibitions = (validated: Validated, graph: Graph, request: ActionRequest): readonly RootProhibitionGrant[] => {
  if (validated.rootProhibitions.size === 0) return NO_ROOT_PROHIBITIONS;
  let relevant: RootProhibitionGrant[] | undefined;
  let roots = 0;
  for (const path of graph.paths) {
    const bucket = validated.rootProhibitions.get(path.rootAuthorityId);
    if (bucket === undefined || graph.paths.slice(0, graph.paths.indexOf(path)).some((x) => x.rootAuthorityId === path.rootAuthorityId)) continue;
    roots += 1;
    for (const p of bucket) {
      const anchorId = own(p, "parentAuthorityId");
      const anchored = anchorId === undefined || graph.paths.some((x) => x.rootAuthorityId === p.rootAuthorityId && x.authorityIds.includes(anchorId));
      if (anchored && prohibitionRequestRelevant(p, request)) (relevant ??= []).push(p);
    }
  }
  if (relevant === undefined) return NO_ROOT_PROHIBITIONS;
  if (roots > 1) relevant.sort(byAuthorityId);
  return relevant;
};

// ---------------------------------------------------------------- candidate evaluation

type FailureCode =
  | "PROHIBITED"
  | "REVOKED"
  | "NOT_YET_VALID"
  | "EXPIRED"
  | "MISSING_INTERSECTION"
  | "ACTION_NOT_ALLOWED"
  | "RESOURCE_NOT_ALLOWED"
  | "AMOUNT_REQUIRED"
  | "AMOUNT_EXCEEDED"
  | "CUMULATIVE_AMOUNT_EXCEEDED"
  | "AMOUNT_OVERFLOW"
  | "TRANSACTION_COUNT_EXCEEDED"
  | "NO_AUTHORITY";
type Evaluation =
  | Readonly<{ status: "SUCCESS"; graph: Graph; checkedProhibitionIds: readonly string[] }>
  | Readonly<{ status: "FAILURE"; code: FailureCode; failingAuthorityId: string; graph?: Graph }>;

/**
 * The failure sets in precedence order (spec 02 §4.2 step 5 as amended by G6.5 A-135.1: twelve, `AMOUNT_OVERFLOW`
 * after `CUMULATIVE_AMOUNT_EXCEEDED`); PROHIBITED is decided before them.
 */
const FAILURE_ORDER: readonly FailureCode[] = [
  "REVOKED",
  "NOT_YET_VALID",
  "EXPIRED",
  "MISSING_INTERSECTION",
  "ACTION_NOT_ALLOWED",
  "RESOURCE_NOT_ALLOWED",
  "AMOUNT_REQUIRED",
  "AMOUNT_EXCEEDED",
  "CUMULATIVE_AMOUNT_EXCEEDED",
  "AMOUNT_OVERFLOW",
  "TRANSACTION_COUNT_EXCEEDED",
  "NO_AUTHORITY",
];
const [REVOKED, NOT_YET_VALID, EXPIRED, MISSING, ACTION, RESOURCE, AMOUNT_REQUIRED, AMOUNT_EXCEEDED, CUMULATIVE, OVERFLOW, COUNT, INACTIVE] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

/**
 * The §4.2 `overflow` set over one usage record (G6.5 A-135.1, A-156.1): `admittedCumulativeAmount + amount > MAX` when
 * the request carries an amount, or `admittedTransactionCount ≥ 2^53 − 1`, tested without forming `count + 1`. Fed by
 * the §7.2 counters of a format-2 state, and (G6.9 A-166) by the supplied usage on the raw path.
 */
const usageOverflows = (counter: Readonly<{ admittedTransactionCount: U53; admittedCumulativeAmount: Amount }>, amount: Amount | undefined): boolean =>
  (amount !== undefined && counter.admittedCumulativeAmount + amount > MAX_BIGINT) || counter.admittedTransactionCount >= Number.MAX_SAFE_INTEGER;

/**
 * Spec 02 §4.2. Only the least member of each failure set matters, so the
 * sets are tracked as running minima. With `collect` given (receipt policy)
 * every decisive id is also reported and usage is not rechecked.
 *
 * `counters` (format 2 only: the §7.2 `usage` records of the state the decision is about) feeds the `overflow` set
 * (G6.5 A-135.1): a grant of the graph whose `usage.admittedCumulativeAmount + amount` would exceed MAX (§3.3) fails
 * the candidate with `AMOUNT_OVERFLOW`, so another successful candidate wins. The same set carries the U53 closure
 * of `admittedTransactionCount` (DEVIATIONS 103), which was decided after winner selection before G6.5. On the raw
 * path (spec02 §7.1) `counters` is the supplied `usage` (G6.9 A-166).
 */
const evaluateCandidate = (
  validated: Validated,
  main: Path,
  request: ActionRequest,
  t: number,
  globalIds: readonly string[],
  collect?: (authorityId: string) => void,
  counters?: ReadonlyMap<string, UsageCounter>,
): Evaluation => {
  if (main.recognizedRoot === undefined) return { status: "FAILURE", code: "NO_AUTHORITY", failingAuthorityId: main.rootAuthorityId };
  const graph = graphFor(validated, main);
  const rootProhibitions = relevantCandidateProhibitions(validated, graph, request);
  let prohibitedBy: string | undefined;
  for (const p of rootProhibitions) {
    if (!prohibitionIsActive(validated, p, t) || !prohibitionMatchesAmount(p, request)) continue;
    collect?.(p.authorityId);
    if (prohibitedBy === undefined || compareIds(p.authorityId, prohibitedBy) < 0) prohibitedBy = p.authorityId;
  }
  if (prohibitedBy !== undefined && collect === undefined) return { status: "FAILURE", code: "PROHIBITED", failingAuthorityId: prohibitedBy, graph };

  const least: (string | undefined)[] = [undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined];
  const hit = (index: number, id: string): void => {
    collect?.(id);
    const current = least[index];
    if (current === undefined || compareIds(id, current) < 0) least[index] = id;
  };
  for (const id of graph.missingIntersectionIds) hit(MISSING, id);
  const amount = own(request, "amount");
  const checkCapacity = collect === undefined;
  for (const path of graph.paths) {
    for (const g of path.grants) {
      const c = g.constraints;
      const id = g.authorityId;
      if (validated.corpus.revoked.has(id)) hit(REVOKED, id);
      const notBefore = own(c, "notBefore");
      if (notBefore !== undefined && t < notBefore) hit(NOT_YET_VALID, id);
      const expiresAt = own(c, "expiresAt");
      if (expiresAt !== undefined && t >= expiresAt) hit(EXPIRED, id);
      if (!c.actions.includes(request.action)) hit(ACTION, id);
      if (!c.resources.includes(request.resource)) hit(RESOURCE, id);
      if (c.quantitative && amount === undefined) hit(AMOUNT_REQUIRED, id);
      const maxAmount = own(c, "maxAmount");
      if (maxAmount !== undefined && amount !== undefined && amount > maxAmount) hit(AMOUNT_EXCEEDED, id);
      if (checkCapacity) {
        const usage = validated.corpus.usage.get(id);
        const maxCumulative = own(c, "maxCumulativeAmount");
        if (usage !== undefined && maxCumulative !== undefined && amount !== undefined && usage.admittedCumulativeAmount + amount > maxCumulative) hit(CUMULATIVE, id);
        const counter = counters?.get(id);
        if (counter !== undefined && usageOverflows(counter, amount)) hit(OVERFLOW, id);
        const maxTransactions = own(c, "maxTransactions");
        if (usage !== undefined && maxTransactions !== undefined && usage.admittedTransactionCount >= maxTransactions) hit(COUNT, id);
      }
      if (dependsOnTerminatedAgent(validated.corpus, g)) hit(INACTIVE, id);
    }
  }
  if (prohibitedBy !== undefined) return { status: "FAILURE", code: "PROHIBITED", failingAuthorityId: prohibitedBy, graph };
  for (let i = 0; i < FAILURE_ORDER.length; i += 1) {
    const failingAuthorityId = least[i];
    if (failingAuthorityId !== undefined) return { status: "FAILURE", code: FAILURE_ORDER[i] as FailureCode, failingAuthorityId, graph };
  }
  const checkedProhibitionIds = rootProhibitions.length === 0 ? globalIds : sortedIds([...globalIds, ...rootProhibitions.map((p) => p.authorityId)]);
  return { status: "SUCCESS", graph, checkedProhibitionIds };
};

// ---------------------------------------------------------------- the algebra

type Context = Readonly<{
  operationVersion: string;
  assurance: ScopeAssurance;
  validated: Validated;
  domain: AuthorizationDomain;
  policyVersion: string;
  historyHead: HistoryHead;
  evaluationTime: U53;
  request: ActionRequest;
  consequential: boolean;
  binding?: ConsequentialBinding;
  evidence?: EvidenceContext;
  administrative?: AdministrativeRequirements;
  hashAlgorithm: HashAlgorithm;
  /** The `proofVersion` literal the state's genesis declares (`continuity-authorization-proof/0.2` or the `/2` literal). */
  proofVersion: string;
  /** The state the decision is about (format 2: the budget procedure of SPEC §8.1 runs after an ALLOW); absent for a supplied scope. */
  state?: ReplayState;
  /** The raw path (spec02 §7.1, G6.9 A-166): the supplied usage, fed to the §4.2 `overflow` set. */
  suppliedUsage?: ReadonlyMap<string, AuthorityUsage>;
}>;
type Plan = { readonly selection: Intersection; readonly effective: AuthorityConstraints; hash?: ContentHash };
type Candidate = {
  readonly decision: "ALLOW_CANDIDATE";
  readonly context: Context;
  readonly evaluation: Extract<Evaluation, { status: "SUCCESS" }>;
  readonly recognizedRoot: RecognizedRoot;
  readonly plans: readonly Plan[];
  readonly effective: AuthorityConstraints;
  /** Constraint hashes are the last tie-breaker; computed lazily because ties are rare. */
  hash?: ContentHash;
};
type AlgebraResult = AuthorizationResult | Candidate;

const planFor = (context: Context, evaluation: Extract<Evaluation, { status: "SUCCESS" }>): Candidate => ({
  decision: "ALLOW_CANDIDATE",
  context,
  evaluation,
  recognizedRoot: evaluation.graph.main.recognizedRoot as RecognizedRoot,
  plans: evaluation.graph.intersections.map((selection) => ({ selection, effective: combineConstraints(selection.path.grants) })),
  effective: combineConstraints(graphGrants(evaluation.graph)),
});
const planHash = (context: Context, plan: Plan): ContentHash => (plan.hash ??= hashCanonical(plan.effective, context.hashAlgorithm));
const candidateHash = (c: Candidate): ContentHash => (c.hash ??= hashCanonical(c.effective, c.context.hashAlgorithm));

const comparePlans = (context: Context, a: Plan, b: Plan): number => {
  let c = compareIds(a.selection.requiredAuthorityId, b.selection.requiredAuthorityId);
  if (c !== 0) return c;
  c = compareIdSequences(a.selection.requiredByAuthorityIds, b.selection.requiredByAuthorityIds);
  if (c !== 0) return c;
  c = compareIds(a.selection.recognizedRoot.rootAuthorityId, b.selection.recognizedRoot.rootAuthorityId);
  if (c !== 0) return c;
  c = compareIdSequences(a.selection.path.authorityIds, b.selection.path.authorityIds);
  return c !== 0 ? c : compareIds(planHash(context, a), planHash(context, b));
};
/** Spec 02 §4.6: root id, main path ids (prefix first), intersections, then the constraint hash. */
const compareCandidates = (a: Candidate, b: Candidate): number => {
  let c = compareIds(a.recognizedRoot.rootAuthorityId, b.recognizedRoot.rootAuthorityId);
  if (c !== 0) return c;
  c = compareIdSequences(a.evaluation.graph.main.authorityIds, b.evaluation.graph.main.authorityIds);
  if (c !== 0) return c;
  const shared = Math.min(a.plans.length, b.plans.length);
  for (let i = 0; i < shared; i += 1) {
    c = comparePlans(a.context, a.plans[i] as Plan, b.plans[i] as Plan);
    if (c !== 0) return c;
  }
  if (a.plans.length !== b.plans.length) return a.plans.length - b.plans.length;
  return compareIds(candidateHash(a), candidateHash(b));
};

const meetsAdministrativeRequirements = (validated: Validated, path: Path, req: AdministrativeRequirements): boolean => {
  if (path.recognizedRoot?.principalId !== req.requiredPrincipalId) return false;
  const controlling = graphGrants(graphFor(validated, path)).map((g) => g.authorityId);
  return req.requiredAuthorityIds.every((id) => controlling.includes(id));
};

const NO_EVIDENCE: readonly EvidenceReference[] = Object.freeze([]);

/**
 * Formats 1 and 2: the authority events relevant to one decision — grant and
 * revocation events of every authority on the actor's candidate paths, of
 * their selected and missing intersection partners, and of every prohibition
 * considered (relevant GLOBAL ones, candidate ROOT ones) — handed to
 * `narrowedDecisionEvidence` with the actor and the consequential binding.
 */
const narrowedAlgebraEvidence = (
  context: Context,
  ctx: EvidenceContext,
  globals: readonly GlobalProhibitionGrant[],
  candidates: readonly Path[],
): readonly EvidenceReference[] => {
  const { validated, request } = context;
  const records = ctx.state.authorities;
  const cited = new Set<string>();
  const positions: number[] = [];
  const cite = (id: string): void => {
    if (cited.has(id)) return;
    cited.add(id);
    const record = records.get(id);
    if (record === undefined) return;
    positions.push(record.grantEventPosition);
    const revoked = own(record, "revocationEventPosition");
    if (revoked !== undefined) positions.push(revoked);
  };
  for (const p of globals) cite(p.authorityId);
  for (const main of candidates) {
    for (const id of main.authorityIds) cite(id);
    // A candidate without a recognized root fails NO_AUTHORITY before its graph and prohibitions are considered.
    if (main.recognizedRoot === undefined) continue;
    const graph = graphFor(validated, main);
    for (let i = 1; i < graph.paths.length; i += 1) for (const id of (graph.paths[i] as Path).authorityIds) cite(id);
    for (const id of graph.missingIntersectionIds) cite(id);
    for (const p of relevantCandidateProhibitions(validated, graph, request)) cite(p.authorityId);
  }
  const binding = context.consequential ? context.binding : undefined;
  return narrowedDecisionEvidence(ctx, request.actorId, positions, binding);
};

/**
 * Tests only (G6.5 A-133.7, A-116.6): an observer told, for every evaluation of the §4 algebra, whether it yielded a
 * successful candidate, i.e. the A-116.4 `allow` as re-scoped by A-133.2 before the step-10 nonce check and the §6.3
 * proof-size preflight. Not exported from the package; `undefined` (the default) costs one comparison.
 */
let algebraObserver: ((candidateFound: boolean) => void) | undefined;
export function observeAlgebraForTests(observer?: (candidateFound: boolean) => void): void {
  algebraObserver = observer;
}
const evaluateAlgebra = (context: Context): AlgebraResult => {
  const result = evaluateAlgebraUnobserved(context);
  algebraObserver?.(result.decision === "ALLOW_CANDIDATE");
  return result;
};
const evaluateAlgebraUnobserved = (context: Context): AlgebraResult => {
  const { validated, request, evaluationTime: t, operationVersion, assurance } = context;
  const limit = (): AuthorizationResult => indeterminate(operationVersion, "OUTPUT_LIMIT_EXCEEDED", assurance);
  const globals = relevantGlobalProhibitions(validated, request);
  const all: readonly Path[] = validated.candidatesByActor.get(request.actorId) ?? NO_PATHS;
  // The actor's candidates (administrative requests: those meeting the requirements), computed only when needed: a
  // decision the plausible candidates below settle never looks at the others.
  let filtered: readonly Path[] | undefined;
  const candidatesOf = (): readonly Path[] => {
    const req = context.administrative;
    return (filtered ??= req === undefined ? all : all.filter((p) => meetsAdministrativeRequirements(validated, p, req)));
  };
  // The evidence list is shared by every failure, so the output budget is known before any failure is built.
  // Legacy states cite every authority event (spec 02 §6.2, memoised per state); format-1 states only the relevant ones.
  let narrowed: readonly EvidenceReference[] | undefined;
  const evidence = (): readonly EvidenceReference[] => {
    const ctx = context.evidence;
    if (ctx === undefined) return NO_EVIDENCE;
    return ctx.narrowed ? (narrowed ??= narrowedAlgebraEvidence(context, ctx, globals, candidatesOf())) : decisionEvidence(ctx);
  };
  const overBudget = (failures: number): boolean => {
    const ctx = context.evidence;
    return ctx !== undefined && failures * (ctx.narrowed ? evidence().length : decisionEvidenceLength(ctx)) > MAX_RESULT_EVIDENCE;
  };
  let globalFailure: string | undefined;
  for (const p of globals) {
    if (prohibitionIsActive(validated, p, t) && prohibitionMatchesAmount(p, request) && (globalFailure === undefined || compareIds(p.authorityId, globalFailure) < 0)) globalFailure = p.authorityId;
  }
  if (globalFailure !== undefined) {
    if (overBudget(1)) return limit();
    const failure: DenialEvidence = Object.freeze({ authorityPathIds: NO_IDS, code: "PROHIBITED", evidence: evidence(), failingAuthorityId: globalFailure, subjectId: request.actorId });
    return boundedResult(denialResult(operationVersion, assurance, [failure]), operationVersion, assurance);
  }
  const globalIds = globals.length === 0 ? NO_IDS : globals.map((p) => p.authorityId);
  // Format 2: the §7.2 usage counters for the candidate-local AMOUNT_OVERFLOW set (G6.5 A-135); on the raw path, the
  // supplied usage (G6.9 A-166).
  const counters = context.state !== undefined && editionOf(context.state) === "2" ? context.state.usageCounters : context.suppliedUsage;
  let winner: Candidate | undefined;
  // An actor with many candidates (a long-lived worker holding a grant per job): look for the winner among the
  // candidates that can succeed first. They are every candidate that can yield SUCCESS, in the same relative order, so
  // the successes are compared in the same sequence and the winner is the one the full loop below would pick. Without
  // a winner the full loop runs as always (a refusal lists every candidate's failure).
  const plausible = plausibleCandidates(validated, request, all);
  if (plausible !== undefined) {
    const req = context.administrative;
    for (const path of plausible) {
      if (req !== undefined && !meetsAdministrativeRequirements(validated, path, req)) continue;
      const evaluation = evaluateCandidate(validated, path, request, t, globalIds, undefined, counters);
      if (evaluation.status !== "SUCCESS") continue;
      const candidate = planFor(context, evaluation);
      if (winner === undefined || compareCandidates(candidate, winner) < 0) winner = candidate;
    }
    if (winner !== undefined) return winner;
  }
  const failures: { evaluation: Extract<Evaluation, { status: "FAILURE" }>; path: Path }[] = [];
  for (const path of candidatesOf()) {
    const evaluation = evaluateCandidate(validated, path, request, t, globalIds, undefined, counters);
    if (evaluation.status === "SUCCESS") {
      const candidate = planFor(context, evaluation);
      if (winner === undefined || compareCandidates(candidate, winner) < 0) winner = candidate;
    } else failures.push({ evaluation, path });
  }
  if (winner !== undefined) return winner;
  if (overBudget(Math.max(1, failures.length))) return limit();
  if (failures.length === 0) return boundedResult(simpleDenial(operationVersion, assurance, "NO_AUTHORITY", evidence(), request.actorId), operationVersion, assurance);
  const shared = evidence();
  const denials: DenialEvidence[] = failures.map(({ evaluation, path }) =>
    Object.freeze({
      authorityPathIds: path.authorityIds,
      code: evaluation.code,
      evidence: shared,
      failingAuthorityId: evaluation.failingAuthorityId,
      rootAuthorityId: path.rootAuthorityId,
      terminalAuthorityId: (path.grants[path.grants.length - 1] as PermissionGrant).authorityId,
    }),
  );
  return boundedResult(denialResult(operationVersion, assurance, denials), operationVersion, assurance);
};

// ---------------------------------------------------------------- proofs

const fitsProofLimits = (c: AuthorityConstraints, maxRequired: number): boolean =>
  c.actions.length <= MAX_SET_MEMBERS && c.resources.length <= MAX_SET_MEMBERS && c.requiredIntersectionIds.length <= maxRequired;

type ProofProjection = Readonly<{ controllingAuthorityIds: readonly string[]; evidenceAuthorityIds: readonly string[] }>;

/** Spec 02 §6.3 preflight: any oversized component makes the result OUTPUT_LIMIT_EXCEEDED rather than a truncated proof. */
const preflightProof = (candidate: Candidate): ProofProjection | undefined => {
  const graph = candidate.evaluation.graph;
  const corpus = candidate.context.validated.corpus;
  if (
    graph.main.grants.length === 0 ||
    graph.main.grants.length > MAX_PATH_DEPTH ||
    graph.intersections.length > MAX_SET_MEMBERS ||
    candidate.evaluation.checkedProhibitionIds.length > MAX_SET_MEMBERS ||
    !fitsProofLimits(candidate.effective, MAX_SET_MEMBERS)
  ) return undefined;
  const controlling = new Set<string>();
  for (const path of graph.paths) {
    if (path.grants.length === 0 || path.grants.length > MAX_PATH_DEPTH) return undefined;
    for (const g of path.grants) {
      if (!fitsProofLimits(g.constraints, MAX_REQUIRED_INTERSECTIONS)) return undefined;
      controlling.add(g.authorityId);
      if (controlling.size > MAX_SET_MEMBERS) return undefined;
    }
  }
  for (const plan of candidate.plans) {
    const n = plan.selection.requiredByAuthorityIds.length;
    if (n === 0 || n > MAX_SET_MEMBERS || !fitsProofLimits(plan.effective, MAX_SET_MEMBERS)) return undefined;
  }
  const controllingAuthorityIds = sortedIds([...controlling]);
  let usageCount = 0;
  for (const id of controllingAuthorityIds) if (corpus.usage.has(id) && (usageCount += 1) > MAX_SET_MEMBERS) return undefined;
  const evidenceIds = new Set([...controllingAuthorityIds, ...candidate.evaluation.checkedProhibitionIds]);
  const evidenceAuthorityIds: string[] = [];
  for (const id of evidenceIds) if (evidenceOf(corpus, id) !== undefined && evidenceAuthorityIds.push(id) > MAX_AUTHORITIES) return undefined;
  return { controllingAuthorityIds, evidenceAuthorityIds: sortedIds(evidenceAuthorityIds) };
};

const proofForCandidate = (candidate: Candidate, projection: ProofProjection): AuthorizationProof => {
  const { context, evaluation } = candidate;
  const corpus = context.validated.corpus;
  const memo = new Map<string, PermissionGrant>();
  const normalize = (g: PermissionGrant): PermissionGrant => {
    let n = memo.get(g.authorityId);
    if (n === undefined) memo.set(g.authorityId, (n = normalizedPermission(g)));
    return n;
  };
  const intersections: IntersectionProof[] = candidate.plans.map((plan) =>
    Object.freeze({
      requiredAuthorityId: plan.selection.requiredAuthorityId,
      requiredByAuthorityIds: plan.selection.requiredByAuthorityIds,
      recognizedRoot: plan.selection.recognizedRoot,
      path: Object.freeze(plan.selection.path.grants.map(normalize)),
      effectiveConstraints: plan.effective,
    }),
  );
  intersections.sort((a, b) => {
    let c = compareIds(a.requiredAuthorityId, b.requiredAuthorityId);
    if (c !== 0) return c;
    c = compareIdSequences(a.requiredByAuthorityIds, b.requiredByAuthorityIds);
    if (c !== 0) return c;
    c = compareIds(a.recognizedRoot.rootAuthorityId, b.recognizedRoot.rootAuthorityId);
    if (c !== 0) return c;
    c = compareIdSequences(a.path.map((g) => g.authorityId), b.path.map((g) => g.authorityId));
    return c !== 0 ? c : compareIds(hashCanonical(a.effectiveConstraints, context.hashAlgorithm), hashCanonical(b.effectiveConstraints, context.hashAlgorithm));
  });
  const usageSnapshot: AuthorityUsage[] = [];
  for (const id of projection.controllingAuthorityIds) {
    const usage = corpus.usage.get(id);
    if (usage !== undefined) {
      usageSnapshot.push(Object.freeze({ authorityId: usage.authorityId, admittedTransactionCount: usage.admittedTransactionCount, admittedCumulativeAmount: usage.admittedCumulativeAmount }));
    }
  }
  const authorityEvidence: AuthorityEvidence[] = [];
  for (const id of projection.evidenceAuthorityIds) {
    const e = evidenceOf(corpus, id);
    if (e !== undefined) authorityEvidence.push(Object.freeze({ authorityId: e.authorityId, grantEventId: e.grantEventId, grantEventPosition: e.grantEventPosition }));
  }
  authorityEvidence.sort((a, b) => compareIds(a.authorityId, b.authorityId) || compareIds(a.grantEventId, b.grantEventId) || a.grantEventPosition - b.grantEventPosition);
  const binding = context.consequential ? context.binding : undefined;
  const proof: AuthorizationProof = Object.freeze({
    proofVersion: context.proofVersion,
    domain: context.domain,
    policyVersion: context.policyVersion,
    rootRecognitionPolicy: ROOT_RECOGNITION_POLICY,
    historyHead: context.historyHead,
    evaluationTime: context.evaluationTime,
    request: normalizedRequest(context.request),
    recognizedRoot: candidate.recognizedRoot,
    permissionPath: Object.freeze(evaluation.graph.main.grants.map(normalize)),
    intersections: Object.freeze(intersections),
    effectiveConstraints: candidate.effective,
    controllingAuthorityIds: projection.controllingAuthorityIds,
    usageSnapshot: Object.freeze(usageSnapshot),
    authorityEvidence: Object.freeze(authorityEvidence),
    checkedProhibitionIds: evaluation.checkedProhibitionIds,
    consequential: context.consequential,
    ...(binding === undefined
      ? {}
      : {
          runtimeSessionId: binding.runtimeSessionId,
          credentialKeyId: binding.credentialKeyId as string,
          controlEpoch: binding.controlEpoch,
          roleId: binding.roleId,
          roleTenureId: binding.roleTenureId,
          intentId: binding.intentId as string,
          nonce: binding.nonce as string,
        }),
  });
  // Format 2 (SPEC §8.3, §16.2 step 2(a)): every Amount of the emitted proof is a decimal string.
  return editionOfDomain(context.domain) === "2" ? wireAmounts(proof) : proof;
};

const finalizeCandidate = (candidate: Candidate): AuthorizationResult => {
  const { operationVersion, assurance, consequential, state, request, evaluationTime } = candidate.context;
  const projection = preflightProof(candidate);
  if (projection === undefined) return indeterminate(operationVersion, "OUTPUT_LIMIT_EXCEEDED", assurance);
  if (state !== undefined && editionOf(state) === "2") {
    const deny = (code: DenialCode, budgetId: string | null): AuthorizationResult =>
      Object.freeze({ consequential: false as const, decision: "DENY" as const, operationVersion, scopeAssurance: assurance, code, failures: Object.freeze([Object.freeze({ code, authorityPathIds: NO_IDS, evidence: Object.freeze([]) })]), budgetId });
    // SPEC §8.1 / §3.3 closure (`AMOUNT_OVERFLOW`, and the U53 bound of `admittedTransactionCount`) is decided per
    // candidate in `evaluateCandidate` (G6.5 A-135): a winner never overflows a §7.2 `usage` counter here.
    // SPEC §8.1 step 2: the budget procedure runs only after an ALLOW and turns it into a DENY with the budget's code.
    const verdict = budgetCheckAfterAllow(state, request, evaluationTime);
    if (verdict !== null) return deny(verdict.code, verdict.budgetId);
  }
  return Object.freeze({ consequential, decision: "ALLOW", operationVersion, proof: proofForCandidate(candidate, projection), scopeAssurance: assurance });
};

// ---------------------------------------------------------------- runtime challenge and intents

export type RuntimeChallengeInput = Readonly<{
  domain: AuthorizationDomain;
  request: ActionRequest;
  evaluationTime: U53;
  policyVersion: string;
  historyHead: HistoryHead;
  binding: ConsequentialBinding;
  /** The literal the genesis `versions.runtimeAuthorizationVersion` declares; defaults by the domain's edition. */
  version?: string;
}>;

/**
 * Spec 02 §5.1 / SPEC §8.2. The signed structure; `canonicalTime` and `runtimeSignature` are deliberately absent. In
 * format 2 the literal is `irontrellis-runtime-authorization/2`, the request keeps `metric?` and spells its amount as
 * a decimal string (SPEC §3.4).
 */
export function createRuntimeAuthorizationChallenge(input: RuntimeChallengeInput): RuntimeAuthorizationChallenge {
  const b = input.binding;
  const credentialKeyId = own(b, "credentialKeyId");
  const intentId = own(b, "intentId");
  const nonce = own(b, "nonce");
  if (credentialKeyId === undefined || intentId === undefined || nonce === undefined) {
    throw new TypeError("Runtime authorization challenge requires credential, intent, and nonce identifiers.");
  }
  const format2 = editionOfDomain(input.domain) === "2";
  return Object.freeze({
    version: input.version ?? (format2 ? RUNTIME_AUTHORIZATION_VERSION_2 : RUNTIME_AUTHORIZATION_VERSION),
    domain: normalizedDomain(input.domain),
    request: format2 ? wireAmounts(normalizedRequest(input.request)) : normalizedRequest(input.request),
    authoritative: true,
    consequential: true,
    evaluationTime: input.evaluationTime,
    policyVersion: input.policyVersion,
    rootRecognitionPolicy: ROOT_RECOGNITION_POLICY,
    eventHistoryHash: input.historyHead.hash,
    eventHistoryPosition: input.historyHead.position,
    runtimeSessionId: b.runtimeSessionId,
    credentialKeyId,
    controlEpoch: b.controlEpoch,
    roleId: b.roleId,
    roleTenureId: b.roleTenureId,
    intentId,
    nonce,
  });
}

export const hashRuntimeAuthorizationChallenge = (challenge: RuntimeAuthorizationChallenge, algorithm: HashAlgorithm): ContentHash =>
  hashCanonical(challenge, algorithm);

/** Verifies with the session's own suite (legacy: EIP-191 recovery to the lowercased address). */
export function verifyRuntimeAuthorizationSignature(
  session: RuntimeSessionRecord,
  challenge: RuntimeAuthorizationChallenge,
  signature: unknown,
  algorithm: HashAlgorithm,
): boolean {
  try {
    const suite = suiteFor(session.credentialScheme);
    if (!suite.isSignature(signature) || !suite.isCredential(session.credentialAddressKey)) return false;
    return suite.verify(hashRuntimeAuthorizationChallenge(challenge, algorithm), signature, session.credentialAddressKey);
  } catch {
    return false;
  }
}

/** Verifies a signature over an arbitrary hashed structure with the session's suite (administrative challenges). */
/** A session credential's signature over a content hash, through the session's suite (ed25519 or EIP-191); never throws. */
export const verifySessionSignature = (session: RuntimeSessionRecord, hash: ContentHash, signature: unknown): boolean => {
  try {
    const suite = suiteFor(session.credentialScheme);
    return suite.isSignature(signature) && suite.isCredential(session.credentialAddressKey) && suite.verify(hash, signature, session.credentialAddressKey);
  } catch {
    return false;
  }
};

/** Spec 02 §7.8: the immutable intent content; `claimedAt` is intentionally absent. */
export function intentProjection(request: ActionRequest, binding: ConsequentialBinding, adapterProfile: TransactionIntent["adapterProfile"]): TransactionIntent {
  const intentId = own(binding, "intentId");
  const nonce = own(binding, "nonce");
  if (intentId === undefined || nonce === undefined) throw new TypeError("Intent projection requires intent and nonce identifiers.");
  return Object.freeze({
    adapterProfile,
    intentId,
    nonce,
    actorId: request.actorId,
    action: request.action,
    resource: request.resource,
    roleId: binding.roleId,
    roleTenureId: binding.roleTenureId,
    ...optionalFields(request, ["amount", "counterpartyId", "termsCommitment"]),
  });
}

const sameOptional = <K extends keyof TransactionIntent>(a: TransactionIntent, b: TransactionIntent, key: K): boolean =>
  Object.hasOwn(a, key) === Object.hasOwn(b, key) && (!Object.hasOwn(a, key) || a[key] === b[key]);

export const sameIntent = (a: TransactionIntent, b: TransactionIntent): boolean =>
  a.intentId === b.intentId &&
  a.nonce === b.nonce &&
  a.actorId === b.actorId &&
  a.action === b.action &&
  a.resource === b.resource &&
  a.roleId === b.roleId &&
  a.roleTenureId === b.roleTenureId &&
  sameOptional(a, b, "amount") &&
  sameOptional(a, b, "counterpartyId") &&
  sameOptional(a, b, "termsCommitment");

// ---------------------------------------------------------------- replay-bound decision procedure

export type AuthorizeBody = Omit<AuthorizeInput, "events" | "operationVersion" | "authoritative">;
export type AuthorizeOptions = Readonly<{ administrativeRequirements?: AdministrativeRequirements }>;


/** Over-long identifiers at designated slots are an input limit, not a request fault (spec 02 §2.2). */
const requestWithinLimits = (request: Record<string, unknown>): boolean =>
  ["actorId", "action", "resource", "counterpartyId"].every((key) => identifierStatus(request[key]) !== "LIMIT");

/**
 * G6.5 A-134.1 (format 2): the request's Amount slot is captured under the §3.3 type, before causal time. A JSON
 * number, `null`, a marker, a string failing the grammar, longer than 78 characters or above MAX is a limit error
 * (`INDETERMINATE / INVALID_INPUT`), never `DENY INVALID_AMOUNT` (unreachable in format 2; kept for the shadow
 * re-derivation of migrated prefixes) and never a throw. The engine API may hand the Amount as its bigint.
 */
const format2AmountCaptured = (request: Record<string, unknown>): boolean => {
  const amount = own(request, "amount");
  return amount === undefined || isAmountString(amount) || isAmount(amount);
};
const bodyIsStructurallyValid = (body: Rec, edition: Edition): boolean =>
  domainIsValid(body.domain, edition) &&
  headIsValid(body.expectedHistoryHead) &&
  identifierStatus(body.policyVersion) === "VALID" &&
  identifierStatus(body.rootRecognitionPolicy) === "VALID" &&
  requestHasExactShape(body.request, edition) &&
  requestWithinLimits(body.request) &&
  (edition !== "2" || format2AmountCaptured(body.request)) &&
  typeof body.consequential === "boolean" &&
  (body.binding !== undefined) === body.consequential &&
  (body.binding === undefined || bindingIsStructurallyValid(body.binding, edition === "0.2"));

/** Spec 02 §4: everything before the algebra, in the exact order; `CANDIDATE` means "went to the algebra and won". */
const stage = (state: ReplayState, body: Rec, administrative?: AdministrativeRequirements): AlgebraResult => {
  const operationVersion = AUTHORIZATION_VERSION;
  const ctx = evidenceFor(state);
  const headEvidence = Object.freeze([eventReference(ctx, state.events.length - 1)]);
  const expected = body.expectedHistoryHead as HistoryHead;
  if (!sameHead(expected, state.head)) return indeterminate(operationVersion, "HISTORY_RELATION_UNVERIFIED", "SUPPLIED_SCOPE", headEvidence);
  const evaluationTime = body.evaluationTime;
  if (!isU53(evaluationTime) || evaluationTime < state.head.canonicalTime) {
    return indeterminate(operationVersion, "CAUSAL_TIME_INVALID", "SUPPLIED_SCOPE", headEvidence);
  }
  const assurance: ScopeAssurance = "REPLAY_VERIFIED";
  const deny = (code: DenialCode, evidence?: readonly EvidenceReference[], subjectId?: string): AuthorizationResult =>
    boundedResult(simpleDenial(operationVersion, assurance, code, evidence, subjectId), operationVersion, assurance);
  const genesisEvidence = Object.freeze([eventReference(ctx, 0)]);
  const domain = body.domain as AuthorizationDomain;
  const policyVersion = body.policyVersion as string;
  if (!sameDomain(domain, state.genesis.domain)) return deny("DOMAIN_MISMATCH", genesisEvidence);
  if (policyVersion !== state.genesis.policyVersion || body.rootRecognitionPolicy !== state.genesis.rootRecognitionPolicy) return deny("POLICY_MISMATCH", genesisEvidence);
  const requestValue = body.request as Record<string, unknown>;
  const edition = editionOf(state);
  const requestFailure = requestProblem(requestValue, edition);
  if (requestFailure !== undefined) return deny(requestFailure);
  const request = engineRequest(requestValue as unknown as ActionRequest);

  const validation = memoFor(state).validation;
  if (validation.status === "INVALID_INPUT") return indeterminate(operationVersion, "STATE_NOT_AUTHORITATIVE", "SUPPLIED_SCOPE");
  if (validation.status === "INVALID_DELEGATION") return deny("INVALID_DELEGATION", decisionEvidence(ctx));
  const validated = validation.validated;

  const agent = state.agents.get(request.actorId);
  if (agent === undefined || agent.terminated) return deny("AGENT_INACTIVE", agentLifecycleEvidence(ctx, request.actorId), request.actorId);

  const consequential = body.consequential as boolean;
  const binding = body.binding as ConsequentialBinding | undefined;
  if (consequential && binding !== undefined) {
    const sessionId = binding.runtimeSessionId;
    const sessionEvidence = (): readonly EvidenceReference[] => sessionLifecycleEvidence(ctx, request.actorId, sessionId);
    const session = state.runtimeSessions.get(sessionId);
    if (session === undefined || session.agentId !== agent.id) return deny("SESSION_NOT_FOUND", sessionEvidence(), sessionId);
    // A-52.2: in a format-2 state a session without expiresAt (a migrated prefix session) is expired after the prefix.
    if (session.expiresAt === undefined ? state.format === "irontrellis-event/2" : evaluationTime >= session.expiresAt) return deny("SESSION_EXPIRED", sessionEvidence(), sessionId);
    const credentialKeyId = own(binding, "credentialKeyId");
    const runtimeSignature = own(binding, "runtimeSignature");
    if (credentialKeyId === undefined || runtimeSignature === undefined) return deny("SESSION_CREDENTIAL_REQUIRED", sessionEvidence(), sessionId);
    if (credentialKeyId !== session.credentialKeyId) return deny("SESSION_CREDENTIAL_INVALID", sessionEvidence(), sessionId);
    const intentId = own(binding, "intentId");
    const nonce = own(binding, "nonce");
    if (intentId !== undefined && nonce !== undefined) {
      const challenge = createRuntimeAuthorizationChallenge({ domain, request, evaluationTime, policyVersion, historyHead: state.head, binding, ...runtimeVersionOf(state) });
      if (!verifyRuntimeAuthorizationSignature(session, challenge, runtimeSignature, state.hashAlgorithm)) {
        return deny("SESSION_CREDENTIAL_INVALID", sessionEvidence(), sessionId);
      }
    }
    if (session.controlEpoch < agent.currentControlEpoch) return deny("SESSION_FENCED", sessionEvidence(), sessionId);
    if (binding.controlEpoch !== session.controlEpoch || binding.controlEpoch !== agent.currentControlEpoch) return deny("STALE_EPOCH", sessionEvidence(), sessionId);
    const role = state.roles.get(binding.roleId);
    const tenure = state.tenures.get(binding.roleTenureId);
    if (role === undefined || tenure === undefined || role.currentTenureId !== binding.roleTenureId || tenure.closed || tenure.roleId !== binding.roleId || tenure.agentId !== agent.id) {
      return deny("ROLE_TENURE_NOT_CURRENT", tenureLifecycleEvidence(ctx, binding.roleId, binding.roleTenureId), binding.roleTenureId);
    }
    // Legacy cites every intent the actor declared or had admitted (parity); format 1 names no intent, so it cites the genesis, the actor's lifecycle and the head.
    if (intentId === undefined || nonce === undefined) {
      return deny("INTENT_REQUIRED", ctx.narrowed ? narrowedDecisionEvidence(ctx, request.actorId, []) : intentDecisionEvidence(ctx, request.actorId), request.actorId);
    }
    const intentEvidence = (): readonly EvidenceReference[] => intentDecisionEvidence(ctx, request.actorId, intentId, nonce);
    const declaration = state.intentDeclarations.get(intentId);
    if (declaration === undefined) return deny("INTENT_NOT_DECLARED", intentEvidence(), intentId);
    if (!sameIntent(declaration.data, intentProjection(request, binding, declaration.data.adapterProfile))) return deny("INTENT_MISMATCH", intentEvidence(), intentId);
    if (state.intentAdmissions.has(intentId)) return deny("INTENT_REPLAY", intentEvidence(), intentId);
  }
  return evaluateAlgebra({
    operationVersion,
    assurance,
    validated,
    domain,
    policyVersion,
    historyHead: state.head,
    evaluationTime,
    request,
    consequential,
    ...(binding === undefined ? {} : { binding }),
    evidence: ctx,
    ...(administrative === undefined ? {} : { administrative }),
    hashAlgorithm: state.hashAlgorithm,
    proofVersion: state.genesis.versions.authorizationProofVersion ?? AUTHORIZATION_PROOF_VERSION,
    state,
  });
};

/** Spec 02 §4 step 10: an ALLOW candidate whose nonce is already reserved for the actor is denied. */
const occupiedNonceDenial = (state: ReplayState, candidate: Candidate): AuthorizationResult | undefined => {
  const { context } = candidate;
  const binding = context.consequential ? context.binding : undefined;
  const nonce = binding === undefined ? undefined : own(binding, "nonce");
  if (binding === undefined || nonce === undefined || !state.nonceReservationsByActor.get(context.request.actorId)?.has(nonce)) return undefined;
  const evidence = intentDecisionEvidence(evidenceFor(state), context.request.actorId, own(binding, "intentId"), nonce);
  return boundedResult(simpleDenial(context.operationVersion, context.assurance, "NONCE_ALREADY_ADMITTED", evidence, nonce), context.operationVersion, context.assurance);
};

/**
 * Spec 02 §4–§6 against an already replayed state, no replay inside. The body
 * is checked structurally first (format-aware), then staged and finalised.
 */
export function authorizeState(state: ReplayState, body: AuthorizeBody | Rec, options?: AuthorizeOptions): AuthorizationResult {
  const raw = body as Rec;
  if (!bodyIsStructurallyValid(raw, editionOf(state))) return indeterminate(AUTHORIZATION_VERSION, "INVALID_INPUT");
  const staged = stage(state, raw, options?.administrativeRequirements);
  if (staged.decision !== "ALLOW_CANDIDATE") return staged;
  return occupiedNonceDenial(state, staged) ?? finalizeCandidate(staged);
}

/**
 * Stages a consequential authorization for the admission façade (spec 02
 * §7.3 step 6/7): the winning candidate without finalisation, so the caller
 * can interleave its own checks before the proof is built.
 */
export type StagedAuthorization = Readonly<{ status: "ALLOW_CANDIDATE"; finalize: () => AuthorizationResult }> | Readonly<{ status: "RESULT"; result: AuthorizationResult }>;
export function stageAuthorization(state: ReplayState, body: AuthorizeBody | Rec): StagedAuthorization {
  const raw = body as Rec;
  if (!bodyIsStructurallyValid(raw, editionOf(state))) return { status: "RESULT", result: indeterminate(AUTHORIZATION_VERSION, "INVALID_INPUT") };
  const staged = stage(state, raw);
  if (staged.decision !== "ALLOW_CANDIDATE") return { status: "RESULT", result: staged };
  const nonceDenial = occupiedNonceDenial(state, staged);
  if (nonceDenial !== undefined) return { status: "RESULT", result: nonceDenial };
  return { status: "ALLOW_CANDIDATE", finalize: () => finalizeCandidate(staged) };
}

/** Evidence for an admission event id that already exists in the history (spec 02 §7.3 step 9). */
export const admissionEventCollision = (state: ReplayState, eventId: string): AuthorizationResult | undefined =>
  state.eventPositionsById.has(eventId) || state.events.some((e) => e.id === eventId)
    ? indeterminate(AUTHORIZATION_VERSION, "INVALID_INPUT", "REPLAY_VERIFIED", collidingEventEvidence(evidenceFor(state), eventId), eventId)
    : undefined;

// ---------------------------------------------------------------- façade: outer capture

type CaptureKind = "AUTHORIZE" | "AUTHORITY_PATH_EVALUATION" | "INTENT_ADMISSION";
const OUTER_KEYS: Readonly<Record<CaptureKind, readonly string[]>> = {
  AUTHORIZE: ["operationVersion", "events", "expectedHistoryHead", "domain", "policyVersion", "rootRecognitionPolicy", "request", "evaluationTime", "authoritative", "consequential"],
  AUTHORITY_PATH_EVALUATION: ["operationVersion", "scope", "request", "permissions", "prohibitions", "authorityEvidence", "revokedAuthorityIds", "usage"],
  INTENT_ADMISSION: ["operationVersion", "events", "expectedHistoryHead", "admissionEventId", "domain", "policyVersion", "request", "evaluationTime", "binding"],
};
const EXPECTED_VERSION: Readonly<Record<CaptureKind, string>> = {
  AUTHORIZE: AUTHORIZATION_VERSION,
  AUTHORITY_PATH_EVALUATION: AUTHORITY_EVALUATION_VERSION,
  INTENT_ADMISSION: INTENT_ADMISSION_VERSION,
};

export type OperationCapture = Readonly<{ status: "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "STATE_NOT_AUTHORITATIVE" }> | Readonly<{ status: "CAPTURED"; body: Rec }>;

/** Spec 02 §2.2: outer key discipline then a bounded deep capture. Non-plain input throws, as in the legacy engine. */
export function captureAuthorityOperation(input: unknown, kind: CaptureKind): OperationCapture {
  if (!isPlainRecord(input)) throw new TypeError("Portable authority input must be a plain record.");
  if (Object.getOwnPropertySymbols(input).length > 0) throw new TypeError("Portable authority input has a symbol key.");
  const keys = Object.keys(input);
  if (!keys.includes("operationVersion")) return { status: "INVALID_INPUT" };
  const version = input.operationVersion;
  if (typeof version !== "string" || version.length > MAX_PROTOCOL_STRING_BYTES || (utf8Length(version) ?? Infinity) > MAX_PROTOCOL_STRING_BYTES) return { status: "INVALID_INPUT" };
  if (version !== EXPECTED_VERSION[kind]) return { status: "UNSUPPORTED_VERSION" };
  const required = OUTER_KEYS[kind];
  const optional = kind === "AUTHORIZE" ? ["binding"] : NO_IDS;
  if (keys.length < required.length || keys.length > required.length + optional.length) return { status: "INVALID_INPUT" };
  for (const key of required) if (!keys.includes(key)) return { status: "INVALID_INPUT" };
  const body: Record<string, unknown> = {};
  for (const key of keys) {
    if (!required.includes(key) && !optional.includes(key)) return { status: "INVALID_INPUT" };
    const value = input[key];
    if (value === undefined) {
      if (optional.includes(key)) continue;
      return { status: "INVALID_INPUT" };
    }
    body[key] = value;
  }
  try {
    return { status: "CAPTURED", body: captureValue(body) as Rec };
  } catch (error) {
    if (!(error instanceof CanonicalError)) throw error;
    if (error.limit) return { status: "INVALID_INPUT" };
    // A malformed value inside the history is a schema failure of the state, not of the caller's request.
    if (kind !== "AUTHORITY_PATH_EVALUATION" && /^\$\.events(\[|$)/.test(error.location)) return { status: "STATE_NOT_AUTHORITATIVE" };
    throw new TypeError(error.message);
  }
}

const detectEdition = (events: unknown): Edition => {
  if (!Array.isArray(events) || !isPlainRecord(events[0]) || !isPlainRecord(events[0].data)) return "0.2";
  const versions = events[0].data.versions;
  if (!isPlainRecord(versions)) return "0.2";
  return versions.eventSchemaVersion === "irontrellis-event/1" ? "1" : versions.eventSchemaVersion === "irontrellis-event/2" ? "2" : "0.2";
};

const replayIndeterminate = (result: Extract<ReplayResult, { status: "REJECTED" }>): AuthorizationResult =>
  indeterminate(
    AUTHORIZATION_VERSION,
    result.code === "UNSUPPORTED_VERSION" || result.code === "UNSUPPORTED_EVENT_SCHEMA" || result.code === "UNSUPPORTED_EVENT_TYPE" ? "UNSUPPORTED_VERSION" : "STATE_NOT_AUTHORITATIVE",
  );

/** Spec 02 §2.3: capture, structural check, replay, then `authorizeState`. The structural check runs before replay is consulted. */
const portableAmountIsString = (input: unknown): boolean => {
  const request = isPlainRecord(input) ? own(input, "request") : undefined;
  const amount = isPlainRecord(request) ? own(request, "amount") : undefined;
  return amount === undefined || typeof amount === "string";
};
export function authorizePortable(input: unknown, replayFn: (events: readonly unknown[]) => ReplayResult): AuthorizationResult {
  const captured = captureAuthorityOperation(input, "AUTHORIZE");
  if (captured.status !== "CAPTURED") return indeterminate(AUTHORIZATION_VERSION, captured.status);
  const body = captured.body;
  const edition = detectEdition(body.events);
  if (!Array.isArray(body.events) || body.authoritative !== true || !bodyIsStructurallyValid(body, edition)) return indeterminate(AUTHORIZATION_VERSION, "INVALID_INPUT");
  // G6.5 A-134.1: a format-2 transport Amount is a decimal string; the capture above decodes the legacy
  // `$continuity.bigint` marker, so a marker (or any other non-string) at `request.amount` is refused here.
  if (edition === "2" && !portableAmountIsString(input)) return indeterminate(AUTHORIZATION_VERSION, "INVALID_INPUT");
  const replayed = replayFn(body.events as readonly unknown[]);
  if (replayed.status === "REJECTED") return replayIndeterminate(replayed);
  return authorizeState(replayed.state, body);
}

// ---------------------------------------------------------------- raw path evaluation (supplied scope)

const CONSTRAINT_KEYS = ["actions", "resources", "quantitative", "maxDelegationDepth", "requiredIntersectionIds"] as const;
const CONSTRAINT_OPTIONAL = ["notBefore", "expiresAt", "maxAmount", "maxCumulativeAmount", "maxTransactions"] as const;
const constraintsStatus = (value: unknown): Status => {
  if (!exactRecord(value, CONSTRAINT_KEYS, CONSTRAINT_OPTIONAL)) return "INVALID";
  let status = merge(identifierListStatus(value.actions, MAX_SET_MEMBERS, true), identifierListStatus(value.resources, MAX_SET_MEMBERS, true));
  status = merge(status, identifierListStatus(value.requiredIntersectionIds, MAX_REQUIRED_INTERSECTIONS));
  if (typeof value.quantitative !== "boolean" || !isU53(value.maxDelegationDepth)) status = merge(status, "INVALID");
  for (const key of ["notBefore", "expiresAt", "maxTransactions"] as const) if (value[key] !== undefined && !isU53(value[key])) status = merge(status, "INVALID");
  if (value.maxAmount !== undefined) status = merge(status, amountStatus(value.maxAmount));
  if (value.maxCumulativeAmount !== undefined) status = merge(status, amountStatus(value.maxCumulativeAmount));
  if (value.quantitative === false && (value.maxAmount !== undefined || value.maxCumulativeAmount !== undefined)) status = merge(status, "INVALID");
  if (isU53(value.notBefore) && isU53(value.expiresAt) && value.notBefore >= value.expiresAt) status = merge(status, "INVALID");
  return status;
};
const permissionStatus = (value: unknown): Status => {
  if (!exactRecord(value, ["kind", "authorityId", "grantorId", "granteeId", "rootAuthorityId", "independent", "constraints"], ["parentAuthorityId"])) return "INVALID";
  let status: Status = value.kind === "PERMISSION" && typeof value.independent === "boolean" ? "VALID" : "INVALID";
  for (const key of ["authorityId", "grantorId", "granteeId", "rootAuthorityId"]) status = merge(status, identifierStatus(value[key]));
  if (value.parentAuthorityId !== undefined) status = merge(status, identifierStatus(value.parentAuthorityId));
  return merge(status, constraintsStatus(value.constraints));
};
const prohibitionStatus = (value: unknown): Status => {
  if (!isPlainRecord(value) || value.kind !== "PROHIBITION") return "INVALID";
  const root = value.scope === "ROOT";
  if (!root && value.scope !== "GLOBAL") return "INVALID";
  const required = root ? ["kind", "scope", "authorityId", "grantorId", "rootAuthorityId", "constraints"] : ["kind", "scope", "authorityId", "grantorId", "constraints"];
  if (!exactRecord(value, required, root ? ["subjectActorId", "parentAuthorityId"] : ["subjectActorId"])) return "INVALID";
  let status = merge(identifierStatus(value.authorityId), identifierStatus(value.grantorId));
  if (root) status = merge(status, identifierStatus(value.rootAuthorityId));
  if (value.subjectActorId !== undefined) status = merge(status, identifierStatus(value.subjectActorId));
  if (value.parentAuthorityId !== undefined) status = merge(status, identifierStatus(value.parentAuthorityId));
  status = merge(status, constraintsStatus(value.constraints));
  if (status === "VALID") {
    const c = value.constraints as AuthorityConstraints;
    if (c.requiredIntersectionIds.length !== 0 || c.maxDelegationDepth !== 0 || own(c, "maxCumulativeAmount") !== undefined || own(c, "maxTransactions") !== undefined) status = "INVALID";
  }
  return status;
};
const idsStatus = (value: Record<string, unknown>, keys: readonly string[]): Status => keys.reduce<Status>((s, k) => merge(s, identifierStatus(value[k])), "VALID");
const rootStatus = (value: unknown): Status =>
  exactRecord(value, ["rootAuthorityId", "principalId", "principalRecognitionEventId", "rootGrantEventId"])
    ? idsStatus(value, ["rootAuthorityId", "principalId", "principalRecognitionEventId", "rootGrantEventId"])
    : "INVALID";
const evidenceStatus = (value: unknown): Status =>
  exactRecord(value, ["authorityId", "grantEventId", "grantEventPosition"])
    ? merge(idsStatus(value, ["authorityId", "grantEventId"]), isU53(value.grantEventPosition) ? "VALID" : "INVALID")
    : "INVALID";
const usageStatus = (value: unknown): Status =>
  exactRecord(value, ["authorityId", "admittedTransactionCount", "admittedCumulativeAmount"])
    ? merge(merge(identifierStatus(value.authorityId), isU53(value.admittedTransactionCount) ? "VALID" : "INVALID"), amountStatus(value.admittedCumulativeAmount))
    : "INVALID";

const hasDuplicateIdentity = (values: readonly unknown[], field?: string): boolean => {
  const seen = new Set<string>();
  for (const v of values) {
    const id = field === undefined ? v : isPlainRecord(v) ? v[field] : undefined;
    if (!isIdentifier(id)) continue;
    if (seen.has(id)) return true;
    seen.add(id);
  }
  return false;
};
/** Phase-1 depth check by id; malformed members are ignored and duplicated ids are dead ends. */
const permissionPathsFit = (permissions: readonly unknown[]): boolean => {
  const byId = new Map<string, Record<string, unknown> | null>();
  for (const p of permissions) {
    if (!isPlainRecord(p) || !isIdentifier(p.authorityId)) continue;
    byId.set(p.authorityId, byId.has(p.authorityId) ? null : p);
  }
  for (const p of permissions) {
    if (!isPlainRecord(p)) continue;
    let current: Record<string, unknown> | null | undefined = p;
    const visited = new Set<string>();
    let depth = 0;
    while (current !== undefined && current !== null) {
      const id: unknown = current.authorityId;
      if (!isIdentifier(id) || visited.has(id)) break;
      if (depth === MAX_PATH_DEPTH) return false;
      visited.add(id);
      depth += 1;
      const parentId: unknown = current.parentAuthorityId;
      if (!isIdentifier(parentId)) break;
      current = byId.get(parentId);
    }
  }
  return true;
};

const rawCollectionsAreValid = (body: Rec): boolean => {
  const scope = body.scope;
  const roots = isPlainRecord(scope) ? scope.recognizedRoots : undefined;
  const lists = [roots, body.permissions, body.prohibitions, body.authorityEvidence, body.revokedAuthorityIds, body.usage];
  if (!lists.every(Array.isArray)) return false;
  const [r, permissions, prohibitions, evidence, revoked, usage] = lists as unknown[][];
  if ((permissions as unknown[]).length + (prohibitions as unknown[]).length > MAX_AUTHORITIES) return false;
  return (
    !hasDuplicateIdentity(r as unknown[], "rootAuthorityId") &&
    !hasDuplicateIdentity(evidence as unknown[], "authorityId") &&
    !hasDuplicateIdentity(usage as unknown[], "authorityId") &&
    !hasDuplicateIdentity(revoked as unknown[]) &&
    permissionPathsFit(permissions as unknown[])
  );
};

type CorpusConstruction = Readonly<{ status: "INVALID_INPUT" }> | Readonly<{ status: "INVALID_DELEGATION" }> | Readonly<{ status: "VALID"; corpus: Corpus }>;
const rawCorpus = (body: Rec): CorpusConstruction => {
  const scope = body.scope as Rec;
  const permissions = new Map<string, PermissionGrant>();
  const prohibitions = new Map<string, ProhibitionGrant>();
  const roots = new Map<string, RecognizedRoot>();
  const evidence = new Map<string, AuthorityEvidence>();
  const usage = new Map<string, AuthorityUsage>();
  const revoked = new Set<string>();
  let status: Status = "VALID";
  let collision = false;
  let duplicate = false;
  const addUnique = <T>(map: Map<string, T>, id: string, value: T): void => {
    if (map.has(id)) duplicate = true;
    else map.set(id, value);
  };
  for (const value of body.permissions as unknown[]) {
    const s = permissionStatus(value);
    status = merge(status, s);
    if (s !== "VALID") continue;
    const grant = value as PermissionGrant;
    if (permissions.has(grant.authorityId) || prohibitions.has(grant.authorityId)) collision = true;
    else permissions.set(grant.authorityId, grant);
  }
  for (const value of body.prohibitions as unknown[]) {
    const s = prohibitionStatus(value);
    status = merge(status, s);
    if (s !== "VALID") continue;
    const grant = value as ProhibitionGrant;
    if (permissions.has(grant.authorityId) || prohibitions.has(grant.authorityId)) collision = true;
    else prohibitions.set(grant.authorityId, grant);
  }
  for (const value of scope.recognizedRoots as unknown[]) {
    const s = rootStatus(value);
    status = merge(status, s);
    if (s === "VALID") addUnique(roots, (value as RecognizedRoot).rootAuthorityId, value as RecognizedRoot);
  }
  for (const value of body.authorityEvidence as unknown[]) {
    const s = evidenceStatus(value);
    status = merge(status, s);
    if (s === "VALID") addUnique(evidence, (value as AuthorityEvidence).authorityId, value as AuthorityEvidence);
  }
  for (const value of body.usage as unknown[]) {
    const s = usageStatus(value);
    status = merge(status, s);
    if (s === "VALID") addUnique(usage, (value as AuthorityUsage).authorityId, value as AuthorityUsage);
  }
  for (const value of body.revokedAuthorityIds as unknown[]) {
    const s = identifierStatus(value);
    status = merge(status, s);
    if (s === "VALID") {
      if (revoked.has(value as string)) duplicate = true;
      else revoked.add(value as string);
    }
  }
  if (status === "LIMIT" || duplicate) return { status: "INVALID_INPUT" };
  if (status === "INVALID" || collision) return { status: "INVALID_DELEGATION" };
  return { status: "VALID", corpus: { permissions, prohibitions, roots, evidence, revoked, usage, globalPolicySourceId: scope.globalPolicySourceId as string } };
};

/** Spec 02 §7.1: supplied-scope evaluation with no replay, no agents, no evidence. */
export function evaluateAuthorityPath(input: unknown): AuthorizationResult {
  const operationVersion = AUTHORITY_EVALUATION_VERSION;
  const captured = captureAuthorityOperation(input, "AUTHORITY_PATH_EVALUATION");
  if (captured.status !== "CAPTURED") return indeterminate(operationVersion, captured.status === "UNSUPPORTED_VERSION" ? "UNSUPPORTED_VERSION" : "INVALID_INPUT");
  const body = captured.body;
  const scope = body.scope;
  if (
    !rawCollectionsAreValid(body) ||
    !exactRecord(scope, ["domain", "policyVersion", "rootRecognitionPolicy", "historyHead", "evaluationTime", "recognizedRoots", "globalPolicySourceId"]) ||
    !domainIsValid(scope.domain, "0.2") ||
    !headIsValid(scope.historyHead) ||
    !Array.isArray(scope.recognizedRoots) ||
    identifierStatus(scope.policyVersion) !== "VALID" ||
    identifierStatus(scope.rootRecognitionPolicy) !== "VALID" ||
    identifierStatus(scope.globalPolicySourceId) !== "VALID" ||
    !requestHasExactShape(body.request, "0.2") ||
    !requestWithinLimits(body.request)
  ) return indeterminate(operationVersion, "INVALID_INPUT");
  const evaluationTime = scope.evaluationTime;
  const historyHead = scope.historyHead as HistoryHead;
  if (!isU53(evaluationTime) || evaluationTime < historyHead.canonicalTime) return indeterminate(operationVersion, "CAUSAL_TIME_INVALID");
  if (scope.rootRecognitionPolicy !== ROOT_RECOGNITION_POLICY) return simpleDenial(operationVersion, "SUPPLIED_SCOPE", "POLICY_MISMATCH");
  const requestFailure = requestProblem(body.request, "0.2");
  if (requestFailure !== undefined) return simpleDenial(operationVersion, "SUPPLIED_SCOPE", requestFailure);
  const construction = rawCorpus(body);
  if (construction.status === "INVALID_INPUT") return indeterminate(operationVersion, "INVALID_INPUT");
  if (construction.status === "INVALID_DELEGATION") return simpleDenial(operationVersion, "SUPPLIED_SCOPE", "INVALID_DELEGATION");
  const validation = validateCorpus(construction.corpus);
  if (validation.status === "INVALID_INPUT") return indeterminate(operationVersion, "INVALID_INPUT");
  if (validation.status === "INVALID_DELEGATION") return simpleDenial(operationVersion, "SUPPLIED_SCOPE", "INVALID_DELEGATION");
  const result = evaluateAlgebra({
    operationVersion,
    assurance: "SUPPLIED_SCOPE",
    proofVersion: AUTHORIZATION_PROOF_VERSION,
    validated: validation.validated,
    domain: scope.domain as AuthorizationDomain,
    policyVersion: scope.policyVersion as string,
    historyHead,
    evaluationTime,
    request: body.request as unknown as ActionRequest,
    consequential: false,
    hashAlgorithm: LEGACY_HASH,
    suppliedUsage: validation.validated.corpus.usage,
  });
  return result.decision === "ALLOW_CANDIDATE" ? finalizeCandidate(result) : result;
}

// ---------------------------------------------------------------- receipt policy (spec 02 §7.7)

export type ReceiptPolicyEvaluation = Readonly<{ live: boolean; checkedProhibitionIds: readonly string[]; decisiveAuthorityIds: readonly string[]; decisiveAgentIds: readonly string[] }>;

/**
 * Re-checks an admitted proof's graph identity and policy at `evaluationTime`; usage is not rechecked. A format-2 proof
 * carries its Amounts as decimal strings (SPEC §3.4, as `authorizationProofOf` emits it): the recomputed graph is compared
 * in that form and the request is evaluated with engine Amounts.
 */
export function evaluateReceiptPolicy(state: ReplayState, proof: AuthorizationProof, evaluationTime: number): ReceiptPolicyEvaluation {
  const checked = new Set<string>();
  const decisiveAuthorities = new Set<string>();
  const decisiveAgents = new Set<string>();
  const result = (live: boolean): ReceiptPolicyEvaluation =>
    Object.freeze({ live, checkedProhibitionIds: sortedIds([...checked]), decisiveAuthorityIds: sortedIds([...decisiveAuthorities]), decisiveAgentIds: sortedIds([...decisiveAgents]) });
  if (
    !isU53(evaluationTime) ||
    !sameDomain(proof.domain, state.genesis.domain) ||
    proof.policyVersion !== state.genesis.policyVersion ||
    proof.rootRecognitionPolicy !== state.genesis.rootRecognitionPolicy ||
    proof.rootRecognitionPolicy !== ROOT_RECOGNITION_POLICY
  ) return result(false);
  const validation = memoFor(state).validation;
  if (validation.status !== "VALID") return result(false);
  const validated = validation.validated;
  const terminal = proof.permissionPath[proof.permissionPath.length - 1];
  const main = terminal === undefined ? undefined : validated.paths.get(terminal.authorityId);
  if (terminal === undefined || main === undefined || !main.effectivelyIndependent || terminal.granteeId !== proof.request.actorId) {
    if (terminal !== undefined) decisiveAuthorities.add(terminal.authorityId);
    return result(false);
  }
  const format2 = editionOfDomain(proof.domain) === "2";
  const proofForm = <T>(value: T): T => (format2 ? wireAmounts(value) : value);
  const request = format2 && proof.request.amount !== undefined ? { ...proof.request, amount: amountOf(proof.request.amount) as Amount } : proof.request;
  const graph = graphFor(validated, main);
  const root = main.recognizedRoot;
  const samePath = (actual: readonly PermissionGrant[], expected: readonly PermissionGrant[]): boolean =>
    actual.length === expected.length && actual.every((g, i) => canonicalEncode(proofForm(normalizedPermission(g))) === canonicalEncode(expected[i]));
  let identity =
    root !== undefined &&
    canonicalEncode(proofForm(root)) === canonicalEncode(proof.recognizedRoot) &&
    samePath(main.grants, proof.permissionPath) &&
    graph.intersections.length === proof.intersections.length;
  if (!identity) decisiveAuthorities.add(main.rootAuthorityId);
  graph.intersections.forEach((actual, i) => {
    const expected = proof.intersections[i];
    if (
      expected === undefined ||
      actual.requiredAuthorityId !== expected.requiredAuthorityId ||
      canonicalEncode(actual.requiredByAuthorityIds) !== canonicalEncode(expected.requiredByAuthorityIds) ||
      canonicalEncode(proofForm(actual.recognizedRoot)) !== canonicalEncode(expected.recognizedRoot) ||
      !samePath(actual.path.grants, expected.path) ||
      canonicalEncode(proofForm(combineConstraints(actual.path.grants))) !== canonicalEncode(expected.effectiveConstraints)
    ) {
      identity = false;
      decisiveAuthorities.add(actual.requiredAuthorityId);
    }
  });
  if (canonicalEncode(proofForm(combineConstraints(graphGrants(graph)))) !== canonicalEncode(proof.effectiveConstraints)) {
    identity = false;
    decisiveAuthorities.add(terminal.authorityId);
  }
  for (const g of graphGrants(graph)) {
    if (state.agents.get(g.grantorId)?.terminated === true) decisiveAgents.add(g.grantorId);
    if (state.agents.get(g.granteeId)?.terminated === true) decisiveAgents.add(g.granteeId);
  }
  const globals = relevantGlobalProhibitions(validated, request);
  for (const p of relevantCandidateProhibitions(validated, graph, request)) checked.add(p.authorityId);
  let globalBlocked = false;
  for (const p of globals) {
    checked.add(p.authorityId);
    if (prohibitionIsActive(validated, p, evaluationTime) && prohibitionMatchesAmount(p, request)) {
      globalBlocked = true;
      decisiveAuthorities.add(p.authorityId);
    }
  }
  const evaluation = evaluateCandidate(validated, main, request, evaluationTime, globals.map((p) => p.authorityId), (id) => decisiveAuthorities.add(id));
  return result(evaluationTime >= state.head.canonicalTime && identity && !globalBlocked && evaluation.status === "SUCCESS");
}

// ---------------------------------------------------------------- intent admission transition (spec 02 §7.4)

export type AdmissionTransitionValidation =
  | Readonly<{ ok: true; admission: IntentAdmissionRecord; usage: readonly AuthorityUsage[] }>
  | Readonly<{ ok: false; reason: string }>;

const ADAPTER_IDEMPOTENCY_VERSION = "continuity-adapter-idempotency/0.2";
const ADAPTER_SUBMISSION_VERSION = "continuity-adapter-submission/0.2";
const ADAPTER_NO_EFFECT_VERSION = "continuity-adapter-no-effect/0.2";

/**
 * Spec 01 D.11. A legacy domain keys the idempotency key on its five fields
 * (verifyingContract lowercased); a format-1 domain on its three.
 */
export function deriveAdapterIdentityForAcceptedAdmission(
  admissionEvent: CanonicalEvent,
  admissionHead: HistoryHead,
  adapterProfile: TransactionIntent["adapterProfile"],
  algorithm: HashAlgorithm,
): Readonly<Record<string, unknown>> {
  const data = admissionEvent.data as { intentId: string; authorizationProof: { domain: AuthorizationDomain } };
  const domain = data.authorizationProof.domain;
  const intentId = data.intentId;
  const idempotencyKey = hashCanonical(
    "chainId" in domain
      ? [ADAPTER_IDEMPOTENCY_VERSION, domain.protocol, domain.version, domain.deploymentId, domain.chainId, domain.verifyingContract.toLowerCase(), intentId]
      : [ADAPTER_IDEMPOTENCY_VERSION, domain.protocol, domain.version, domain.deploymentId, intentId],
    algorithm,
  );
  const submissionFingerprint = hashCanonical({ version: ADAPTER_SUBMISSION_VERSION, intentId, admissionEvent, durableEventHistoryHash: admissionHead.hash }, algorithm);
  return Object.freeze({
    idempotencyKey,
    submissionFingerprint,
    durableEventHistoryHash: admissionHead.hash,
    adapterNoEffectReference: hashCanonical([ADAPTER_NO_EFFECT_VERSION, "adapter:simulated", idempotencyKey, submissionFingerprint], algorithm),
    adapterProfile,
    domain,
    intentId,
    admissionHead,
  });
}

/**
 * Replay-side validation of a stored admission at its exact pre-event state.
 * Usage accumulates only here, per controlling authority, only for the
 * dimension each authority caps. `nextHead` is the head including the event.
 */
export function validateIntentAdmissionTransition(state: ReplayState, event: CanonicalEvent, position: U53, nextHead: HistoryHead): AdmissionTransitionValidation {
  const fail = (reason: string): AdmissionTransitionValidation => ({ ok: false, reason });
  if (event.type !== "TRANSACTION_INTENT_ADMITTED") return fail("not an admission");
  const data = event.data;
  const proof = data.authorizationProof as AuthorizationProof | undefined;
  if (!isPlainRecord(proof) || !isPlainRecord(proof.request) || !isPlainRecord(proof.historyHead) || !Array.isArray(proof.controllingAuthorityIds)) return fail("proof malformed");
  if (
    event.timestamp !== data.evaluationTime ||
    data.evaluationTime !== proof.evaluationTime ||
    data.intentId !== proof.intentId ||
    !isPlainRecord(data.expectedHistoryHead) ||
    !sameHead(data.expectedHistoryHead as HistoryHead, state.head) ||
    !sameHead(proof.historyHead, state.head) ||
    proof.consequential !== true ||
    proof.rootRecognitionPolicy !== ROOT_RECOGNITION_POLICY
  ) return fail("admission does not bind the pre-event head and proof");
  const runtimeSignature = data.runtimeSignature;
  if (!signatureShapeValid(runtimeSignature, editionOf(state) === "0.2")) return fail("runtime signature malformed");
  if (
    !isIdentifier(proof.runtimeSessionId) ||
    !isIdentifier(proof.credentialKeyId) ||
    !isU53(proof.controlEpoch) ||
    !isIdentifier(proof.roleId) ||
    !isIdentifier(proof.roleTenureId) ||
    !isIdentifier(proof.intentId) ||
    !isIdentifier(proof.nonce)
  ) return fail("proof runtime fields incomplete");
  const binding: ConsequentialBinding = Object.freeze({
    runtimeSessionId: proof.runtimeSessionId,
    credentialKeyId: proof.credentialKeyId,
    controlEpoch: proof.controlEpoch,
    roleId: proof.roleId,
    roleTenureId: proof.roleTenureId,
    intentId: proof.intentId,
    nonce: proof.nonce,
    runtimeSignature,
  });
  const challenge = createRuntimeAuthorizationChallenge({
    domain: proof.domain,
    request: proof.request,
    evaluationTime: proof.evaluationTime,
    policyVersion: proof.policyVersion,
    historyHead: state.head,
    binding,
    ...runtimeVersionOf(state),
  });
  if (data.runtimeAuthorizationHash !== hashRuntimeAuthorizationChallenge(challenge, state.hashAlgorithm)) return fail("runtime authorization hash mismatch");
  const actor = state.agents.get(proof.request.actorId);
  const session = state.runtimeSessions.get(proof.runtimeSessionId);
  if (actor === undefined || session === undefined || session.agentId !== actor.id || session.credentialKeyId !== proof.credentialKeyId) return fail("session does not belong to the actor");
  if (!verifyRuntimeAuthorizationSignature(session, challenge, runtimeSignature, state.hashAlgorithm)) return fail("runtime signature does not verify");
  const authorization = authorizeState(state, {
    expectedHistoryHead: state.head,
    domain: proof.domain,
    policyVersion: proof.policyVersion,
    rootRecognitionPolicy: proof.rootRecognitionPolicy,
    request: proof.request,
    evaluationTime: proof.evaluationTime,
    consequential: true,
    binding,
  });
  if (authorization.decision !== "ALLOW") return fail(`re-authorization ${authorization.decision} ${authorization.code}`);
  if (canonicalEncode(authorization.proof) !== canonicalEncode(proof)) return fail("stored proof differs from the derived proof");
  const declaration = state.intentDeclarations.get(proof.intentId);
  // Format 2 proofs spell the amount as a string; the declaration holds the engine amount.
  if (declaration === undefined || !sameIntent(declaration.data, intentProjection(engineRequest(proof.request), binding, declaration.data.adapterProfile))) return fail("declaration mismatch");
  if (state.intentAdmissions.has(proof.intentId)) return fail("intent already admitted");
  if (state.nonceReservationsByActor.get(proof.request.actorId)?.has(proof.nonce)) return fail("nonce already reserved");
  if (editionOf(state) === "2") {
    // SPEC §8.3: the metric rule (request.metric ≡ "amount" when absent must equal the declared metric), then the budget
    // procedure (`budgetCheckAfterAllow`, applied inside `authorizeState` above: a budget refusal is already a DENY).
    if ((own(proof.request, "metric") ?? "amount") !== (own(declaration.data, "metric") ?? "amount")) return fail("admission metric differs from the declared intent's metric");
  }

  const usage: AuthorityUsage[] = [];
  const amount = proof.request.amount === undefined ? undefined : amountOf(proof.request.amount);
  for (const authorityId of proof.controllingAuthorityIds) {
    const authority = state.authorities.get(authorityId);
    if (authority === undefined || authority.grant.kind !== "PERMISSION") return fail("controlling authority is not a permission");
    const maxTransactions = own(authority.grant.constraints, "maxTransactions");
    const maxCumulativeAmount = own(authority.grant.constraints, "maxCumulativeAmount");
    if (maxTransactions === undefined && maxCumulativeAmount === undefined) continue;
    const current = state.authorityUsage.get(authorityId);
    if (current === undefined || (maxCumulativeAmount !== undefined && amount === undefined)) return fail("usage record unavailable");
    const admittedTransactionCount = current.admittedTransactionCount + (maxTransactions === undefined ? 0 : 1);
    const admittedCumulativeAmount = current.admittedCumulativeAmount + (maxCumulativeAmount === undefined ? 0n : (amount as Amount));
    if (
      !Number.isSafeInteger(admittedTransactionCount) ||
      admittedTransactionCount > (maxTransactions ?? admittedTransactionCount) ||
      admittedCumulativeAmount > (maxCumulativeAmount ?? admittedCumulativeAmount) ||
      admittedCumulativeAmount > MAX_BIGINT
    ) return fail("capacity exceeded");
    usage.push(Object.freeze({ authorityId, admittedTransactionCount, admittedCumulativeAmount }));
  }
  const admission: IntentAdmissionRecord = Object.freeze({
    intentId: proof.intentId,
    actorId: proof.request.actorId,
    nonce: proof.nonce,
    admissionEventId: event.id,
    admissionEventPosition: position,
    admissionHead: nextHead,
    runtimeSessionId: proof.runtimeSessionId,
    credentialKeyId: proof.credentialKeyId,
    controlEpoch: proof.controlEpoch,
    roleId: proof.roleId,
    roleTenureId: proof.roleTenureId,
    adapterIdentity: deriveAdapterIdentityForAcceptedAdmission(event, nextHead, declaration.data.adapterProfile, state.hashAlgorithm),
  });
  return { ok: true, admission, usage: Object.freeze(usage) };
}

// ---------------------------------------------------------------- administrative authorization (spec 03 §I)

const ADMINISTRATIVE_TYPES: ReadonlySet<string> = new Set([
  "OBLIGATION_CREATED",
  "OBLIGATION_PERFORMANCE_ASSIGNED",
  "OBLIGATION_STATUS_RECORDED",
  "OUTCOME_OBSERVATION_RECORDED",
  "ATTEMPT_DUTY_CREATED",
  "ATTEMPT_DUTY_ASSIGNED",
  "ATTEMPT_DUTY_REVIEW_CLOSED",
  // SPEC §13 (E4): the ported duty-policy events (`portable-authority-engine.ts:4248-4249`); their requirements come from the reducer (`duty-policy.ts`).
  "ATTEMPT_DUTY_POLICY_ACTIVATED",
  "ATTEMPT_DUTY_DISPOSITION_RECORDED",
  "ATTEMPT_DUTY_CONTEST_RECORDED",
]);
const ATTEMPT_ACTIONS: Readonly<Record<string, string>> = {
  OUTCOME_OBSERVATION_RECORDED: "OBSERVE_OUTCOME",
  ATTEMPT_DUTY_CREATED: "CREATE_ATTEMPT_DUTY",
  ATTEMPT_DUTY_ASSIGNED: "ASSIGN_ATTEMPT_DUTY",
  ATTEMPT_DUTY_REVIEW_CLOSED: "CLOSE_ATTEMPT_DUTY",
};

/** Spec 03 §I.1: the event's data minus the wrapper, with `transitionEventType` first. */
export function administrativeTransitionEffect(event: CanonicalEvent): Readonly<Record<string, unknown>> {
  const d = event.data;
  const pick = (keys: readonly string[]): Readonly<Record<string, unknown>> => {
    const out: Record<string, unknown> = { transitionEventType: event.type };
    for (const key of keys) out[key] = d[key];
    return Object.freeze(out);
  };
  switch (event.type) {
    case "OUTCOME_OBSERVATION_RECORDED":
      return pick(["intentId", "sourceAdmissionEventId", "acknowledgment", "actorId"]);
    case "ATTEMPT_DUTY_CREATED":
    case "OBLIGATION_CREATED":
      return pick(["record", "actorId"]);
    case "ATTEMPT_DUTY_REVIEW_CLOSED":
      return pick(["dutyId", "actorId", "observationEventIds", "summaryDigest"]);
    case "ATTEMPT_DUTY_ASSIGNED":
      return pick(["dutyId", "fromAgentId", "toAgentId", "actorId"]);
    case "OBLIGATION_PERFORMANCE_ASSIGNED":
      return pick(["obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId"]);
    case "OBLIGATION_STATUS_RECORDED":
      return pick(["obligationId", "fromStatus", "toStatus", "actorId", "action", "attesterId", "evidenceReference"]);
    // SPEC §13 (E4), `portable-administration-codec.ts:168-173`: the activation effect and the disposition/contest effect (the finding included).
    case "ATTEMPT_DUTY_POLICY_ACTIVATED":
      return pick(["actorId", "descriptor", "descriptorHash", "activationAuthorityId"]);
    case "ATTEMPT_DUTY_DISPOSITION_RECORDED":
    case "ATTEMPT_DUTY_CONTEST_RECORDED":
      return pick(["version", "rulesHash", "dutyId", "actorId", "dispositionAuthorityId", "finding"]);
    default:
      throw new TypeError("Event is not a supported administrative transition.");
  }
}

/**
 * Spec 03 §I.2: the request and control tuple an administrative event must be
 * authorized for, derived from the pre-event state. Undefined when the
 * referenced records are missing (replay rejects such events anyway).
 */
export function deriveAdministrativeRequirements(state: ReplayState, event: CanonicalEvent): AdministrativeRequirements | undefined {
  const d = event.data;
  const actorId = d.actorId;
  if (typeof actorId !== "string") return undefined;
  const claimedAt = event.timestamp;
  const requirements = (
    request: ActionRequest,
    requiredPrincipalId: string,
    roleId: string,
    roleTenureId: string,
    requiredAuthorityIds: readonly string[] = NO_IDS,
  ): AdministrativeRequirements => Object.freeze({ request: Object.freeze(request), requiredPrincipalId, requiredAuthorityIds, roleId, roleTenureId });
  switch (event.type) {
    case "OBLIGATION_CREATED": {
      const record = d.record as Rec | undefined;
      if (!isPlainRecord(record)) return undefined;
      const intent = state.intentDeclarations.get(record.sourceIntentId as string)?.data;
      const role = state.roles.get(record.durableRoleId as string);
      const tenure = state.tenures.get(record.creationRoleTenureId as string);
      if (intent === undefined || role === undefined || tenure === undefined) return undefined;
      const counterpartyId = record.counterpartyId;
      return requirements(
        {
          actorId,
          action: "OBLIGATE",
          resource: intent.resource,
          claimedAt,
          termsCommitment: record.termsCommitment as ContentHash,
          ...(counterpartyId === undefined ? {} : { counterpartyId: counterpartyId as string }),
        },
        role.principalId,
        role.id,
        tenure.id,
      );
    }
    case "OBLIGATION_PERFORMANCE_ASSIGNED": {
      const obligation = state.obligations.get(d.obligationId as string);
      const rule = state.successionRules.get(d.successionRuleId as string)?.data;
      const role = obligation === undefined ? undefined : state.roles.get(obligation.record.durableRoleId);
      const tenure = role?.currentTenureId === undefined ? undefined : state.tenures.get(role.currentTenureId);
      if (obligation === undefined || rule === undefined || role === undefined || tenure === undefined) return undefined;
      return requirements({ actorId, action: "ASSIGN_PERFORMANCE", resource: obligation.record.obligationId, claimedAt }, rule.principalId, role.id, tenure.id);
    }
    case "OBLIGATION_STATUS_RECORDED": {
      const obligation = state.obligations.get(d.obligationId as string);
      if (obligation === undefined) return undefined;
      const policy = obligation.record.transitionPolicies.find((p) => p.fromStatus === d.fromStatus && p.toStatus === d.toStatus && p.action === d.action);
      const role = state.roles.get(obligation.record.durableRoleId);
      if (policy === undefined || role === undefined || role.currentTenureId === undefined || typeof d.action !== "string") return undefined;
      return requirements({ actorId, action: d.action, resource: obligation.record.obligationId, claimedAt }, role.principalId, role.id, role.currentTenureId, policy.requiredAuthorityIds);
    }
    case "OUTCOME_OBSERVATION_RECORDED":
    case "ATTEMPT_DUTY_CREATED":
    case "ATTEMPT_DUTY_ASSIGNED":
    case "ATTEMPT_DUTY_REVIEW_CLOSED": {
      const intentId =
        event.type === "OUTCOME_OBSERVATION_RECORDED"
          ? d.intentId
          : event.type === "ATTEMPT_DUTY_CREATED"
            ? (d.record as Rec | undefined)?.sourceIntentId
            : state.attemptDuties.get(d.dutyId as string)?.record.sourceIntentId;
      const intent = typeof intentId === "string" ? state.intentDeclarations.get(intentId)?.data : undefined;
      const role = intent === undefined ? undefined : state.roles.get(intent.roleId);
      const tenure = role?.currentTenureId === undefined ? undefined : state.tenures.get(role.currentTenureId);
      if (intent === undefined || role === undefined || tenure === undefined) return undefined;
      const termsCommitment = own(intent, "termsCommitment");
      return requirements(
        { actorId, action: ATTEMPT_ACTIONS[event.type] as string, resource: intent.intentId, claimedAt, ...(termsCommitment === undefined ? {} : { termsCommitment }) },
        role.principalId,
        role.id,
        tenure.id,
      );
    }
    // SPEC §13 (E4): the duty-policy events' requirements are resolved by the reducer (`state.ts` ← `duty-policy.ts`), which always supplies them.
    default:
      return undefined;
  }
}

/** Spec 03 §I.2 / spec 02 §7.5: a non-consequential proof restricted to the required principal and authorities. */
export function createAdministrativePolicyProof(state: ReplayState, requirements: AdministrativeRequirements, evaluationTime: U53): AuthorizationProof | undefined {
  if (Object.hasOwn(requirements.request, "amount")) return undefined;
  const body: Rec = {
    expectedHistoryHead: state.head,
    domain: state.genesis.domain,
    policyVersion: state.genesis.policyVersion,
    rootRecognitionPolicy: state.genesis.rootRecognitionPolicy,
    request: requirements.request,
    evaluationTime,
    consequential: false,
  };
  if (!bodyIsStructurallyValid(body, editionOf(state))) return undefined;
  const candidate = stage(state, body, requirements);
  if (candidate.decision !== "ALLOW_CANDIDATE") return undefined;
  // The restriction applies to the canonical winner: a capped winner never falls through to another candidate.
  for (const { constraints: c } of graphGrants(candidate.evaluation.graph)) {
    if (c.quantitative || Object.hasOwn(c, "maxAmount") || Object.hasOwn(c, "maxCumulativeAmount") || Object.hasOwn(c, "maxTransactions")) return undefined;
  }
  const authorization = finalizeCandidate(candidate);
  if (authorization.decision !== "ALLOW" || authorization.scopeAssurance !== "REPLAY_VERIFIED" || authorization.consequential || authorization.proof.usageSnapshot.length !== 0) return undefined;
  return authorization.proof;
}

export type AdministrativeTransitionValidation = Readonly<{ ok: true; requirements: AdministrativeRequirements }> | Readonly<{ ok: false; reason: string }>;

/**
 * Spec 03 §I.3. `requirements` may be supplied by the reducer that already
 * resolved the records; otherwise they are derived from `state` here.
 */
export function validateAdministrativeTransition(
  state: ReplayState,
  event: CanonicalEvent,
  _position: U53,
  requirements?: AdministrativeRequirements,
): AdministrativeTransitionValidation {
  const fail = (reason: string): AdministrativeTransitionValidation => ({ ok: false, reason });
  if (!ADMINISTRATIVE_TYPES.has(event.type)) return fail("not an administrative event");
  const policy = state.genesis.adapterPolicyHash;
  // `portable-authority-engine.ts:4251-4253`: the attempt types and the duty-policy activation need an E5/E6 genesis (dispositions presuppose an activation).
  const attemptType = event.type === "OUTCOME_OBSERVATION_RECORDED" || event.type === "ATTEMPT_DUTY_CREATED" || event.type === "ATTEMPT_DUTY_ASSIGNED" || event.type === "ATTEMPT_DUTY_POLICY_ACTIVATED";
  if (attemptType && policy !== ADAPTER_POLICY_E5_HASH && policy !== ADAPTER_POLICY_E6_HASH) return fail("adapter policy edition lacks attempt duties");
  if (event.type === "ATTEMPT_DUTY_REVIEW_CLOSED" && policy !== ADAPTER_POLICY_E6_HASH) return fail("adapter policy edition lacks duty review");
  const req = requirements ?? deriveAdministrativeRequirements(state, event);
  if (req === undefined) return fail("requirements cannot be derived");
  const wrapper = event.data.administrativeAuthorization as Rec | undefined;
  if (!isPlainRecord(wrapper) || !isPlainRecord(wrapper.challenge) || !isPlainRecord(wrapper.authorityProof)) return fail("administrative authorization malformed");
  const challenge = wrapper.challenge as Rec & { request: Rec };
  const proof = wrapper.authorityProof as AuthorizationProof;
  if (!isPlainRecord(challenge.request) || !isPlainRecord(challenge.domain) || !isPlainRecord(proof.domain)) return fail("challenge malformed");
  if (
    canonicalEncode(challenge.domain) !== canonicalEncode(state.genesis.domain) ||
    canonicalEncode(proof.domain) !== canonicalEncode(state.genesis.domain) ||
    canonicalEncode(challenge.request) !== canonicalEncode(req.request) ||
    challenge.request.actorId !== event.data.actorId ||
    challenge.policyVersion !== state.genesis.policyVersion ||
    challenge.rootRecognitionPolicy !== state.genesis.rootRecognitionPolicy ||
    challenge.eventHistoryHash !== state.head.hash ||
    challenge.eventHistoryPosition !== state.head.position ||
    challenge.evaluationTime !== event.timestamp ||
    challenge.transitionEventId !== event.id ||
    challenge.transitionEventType !== event.type ||
    challenge.transitionEffectHash !== hashCanonical(administrativeTransitionEffect(event), state.hashAlgorithm) ||
    challenge.authorityProofHash !== hashCanonical(proof, state.hashAlgorithm) ||
    challenge.roleId !== req.roleId ||
    challenge.roleTenureId !== req.roleTenureId
  ) return fail("challenge does not bind the event, head and requirements");
  const actor = state.agents.get(req.request.actorId);
  const session = typeof challenge.runtimeSessionId === "string" ? state.runtimeSessions.get(challenge.runtimeSessionId) : undefined;
  const role = state.roles.get(req.roleId);
  const tenure = state.tenures.get(req.roleTenureId);
  if (
    actor === undefined ||
    actor.terminated ||
    session === undefined ||
    session.agentId !== actor.id ||
    (session.expiresAt === undefined ? state.format === "irontrellis-event/2" : event.timestamp >= session.expiresAt) ||
    session.credentialKeyId !== challenge.credentialKeyId ||
    session.controlEpoch !== challenge.controlEpoch ||
    actor.currentControlEpoch !== challenge.controlEpoch ||
    role === undefined ||
    role.currentTenureId !== req.roleTenureId ||
    tenure === undefined ||
    tenure.closed ||
    tenure.roleId !== req.roleId ||
    tenure.agentId !== actor.id
  ) return fail("control tuple is not current");
  if (!verifySessionSignature(session, hashCanonical(challenge, state.hashAlgorithm), wrapper.runtimeSignature)) return fail("administrative signature does not verify");
  const expected = createAdministrativePolicyProof(state, req, event.timestamp);
  if (expected === undefined || canonicalEncode(expected) !== canonicalEncode(proof)) return fail("authority proof differs from the derived policy proof");
  return { ok: true, requirements: req };
}
