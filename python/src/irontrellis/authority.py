"""The authorization engine: corpus, delegation paths, attenuation, the
authority algebra, proofs, failures, runtime challenges and the signed
transition validators used by replay (spec 02, spec 03 §F/§I).

Decisions are reproduced bit-for-bit from the legacy engine; the only
format-1 additions are the history's hash algorithm selecting the challenge
hash, the session's credential scheme selecting the signature suite, and
format-1 domains compared as opaque records.

Everything derived from the replay state that does not depend on the request
(the validated corpus with every delegation path, the per-actor candidate
index, the prohibition indexes and the evidence references) is memoised per
state object and keyed by head hash, so a decision costs O(candidates of the
actor), not O(history).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .adapters import derive_adapter_identity_for_accepted_admission
from .canonical import (
    MAX_PROTOCOL_BIGINT, BigInt, CanonicalError, canonical_encode, capture_value, is_amount, is_chain_id, is_content_hash, is_ethereum_address,
    is_identifier, is_u53, utf8_length,
)
from .crypto.suites import is_signature_65, suite_for
from .evidence import (
    EvidenceContext, agent_lifecycle_evidence, bounded_result, compare_id_sequences, compare_ids, create_evidence_context,
    decision_evidence, decision_evidence_length, denial_result, event_reference, indeterminate, intent_decision_evidence, MAX_RESULT_EVIDENCE, narrowed_decision_evidence,
    note_evidence_event,
    session_lifecycle_evidence, simple_denial, tenure_lifecycle_evidence,
)
from .hashing import LEGACY_FORMAT, hash_canonical
from .replay import ReplayResult
from .state import AdministrativeRequirements, IntentAdmissionRecord, ReplayState, RuntimeSessionRecord

AUTHORIZATION_VERSION = "continuity-authorization/0.2"
AUTHORITY_EVALUATION_VERSION = "continuity-authority-evaluation/0.2"
INTENT_ADMISSION_VERSION = "continuity-intent-admission/0.2"
AUTHORIZATION_PROOF_VERSION = "continuity-authorization-proof/0.2"
RUNTIME_AUTHORIZATION_VERSION = "continuity-runtime-authorization/0.2"
ROOT_RECOGNITION_POLICY = "declared-principal-root/0.2"

_MAX_IDENTIFIER_BYTES = 256
_MAX_PROTOCOL_STRING_BYTES = 4096
_MAX_AUTHORITIES = 1024
_MAX_PATH_DEPTH = 32
_MAX_REQUIRED_INTERSECTIONS = 32
_MAX_SET_MEMBERS = 256
ADAPTER_POLICY_E5_HASH = "0x32c2a5608c7110f1a291517e136cedf62d59a2cb81be1141dd2705bce307ab29"
ADAPTER_POLICY_E6_HASH = "0xa90baac702f22f5a5f71141318a7651c1d963bbbee28138bbea835d942d0114c"
_NO_IDS: list[str] = []
Rec = dict[str, Any]


# ---------------------------------------------------------------- scalar helpers


def _is_record(value: Any) -> bool:
    return isinstance(value, dict)


def _merge(a: str, b: str) -> str:
    if a == "LIMIT" or b == "LIMIT":
        return "LIMIT"
    return "INVALID" if a == "INVALID" or b == "INVALID" else "VALID"


def _identifier_status(value: Any) -> str:
    if not isinstance(value, str):
        return "INVALID"
    if len(value) > _MAX_IDENTIFIER_BYTES:
        return "LIMIT"
    length = utf8_length(value, 10**9)
    if length is not None and length > _MAX_IDENTIFIER_BYTES:
        return "LIMIT"
    return "VALID" if is_identifier(value) else "INVALID"


def _amount_status(value: Any) -> str:
    if isinstance(value, BigInt) and (value.value < -MAX_PROTOCOL_BIGINT or value.value > MAX_PROTOCOL_BIGINT):
        return "LIMIT"
    return "VALID" if is_amount(value) else "INVALID"


def _identifier_list_status(value: Any, maximum: int, nonempty: bool = False) -> str:
    if not isinstance(value, list):
        return "INVALID"
    if len(value) > maximum:
        return "LIMIT"
    if nonempty and len(value) == 0:
        return "INVALID"
    seen: set[str] = set()
    status = "VALID"
    for member in value:
        s = _identifier_status(member)
        status = _merge(status, s)
        if s == "VALID":
            if member in seen:
                status = _merge(status, "INVALID")
            seen.add(member)
    return status


def _is_ed25519_signature(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 130 and value.startswith("0x") and all(c in "0123456789abcdef" for c in value[2:])


def _signature_shape_valid(value: Any, legacy: bool) -> bool:
    return is_signature_65(value) or (not legacy and _is_ed25519_signature(value))


def _exact_record(value: Any, required: tuple[str, ...], optional: tuple[str, ...] = ()) -> bool:
    """Exact key set: every key is required or optional, every required key present."""
    if not _is_record(value):
        return False
    present = 0
    for key in value:
        if key in required:
            present += 1
        elif key not in optional:
            return False
    return present == len(required)


_LEGACY_DOMAIN_KEYS = ("protocol", "version", "deploymentId", "chainId", "verifyingContract")
_TRELLIS_DOMAIN_KEYS = ("protocol", "version", "deploymentId")


def _domain_is_valid(value: Any, legacy: bool) -> bool:
    if legacy:
        return (_exact_record(value, _LEGACY_DOMAIN_KEYS) and value["protocol"] == "continuity" and value["version"] == "0.2" and is_identifier(value["deploymentId"])
                and is_chain_id(value["chainId"]) and is_ethereum_address(value["verifyingContract"]))
    return _exact_record(value, _TRELLIS_DOMAIN_KEYS) and value["protocol"] == "irontrellis" and value["version"] == "1" and is_identifier(value["deploymentId"])


def _head_is_valid(value: Any) -> bool:
    return _exact_record(value, ("hash", "position", "canonicalTime")) and is_content_hash(value["hash"]) and is_u53(value["position"]) and is_u53(value["canonicalTime"])


_REQUEST_REQUIRED = ("actorId", "action", "resource", "claimedAt")
_REQUEST_OPTIONAL = ("amount", "counterpartyId", "termsCommitment")


def _request_has_exact_shape(value: Any) -> bool:
    return _exact_record(value, _REQUEST_REQUIRED, _REQUEST_OPTIONAL)


def _request_problem(request: Rec) -> str | None:
    """Value validation of a structurally exact request (spec 02 §4 step 5)."""
    if (not is_identifier(request["actorId"]) or not is_identifier(request["action"]) or not is_identifier(request["resource"]) or not is_u53(request["claimedAt"])
            or ("counterpartyId" in request and not is_identifier(request["counterpartyId"]))
            or ("termsCommitment" in request and not is_content_hash(request["termsCommitment"]))):
        return "INVALID_REQUEST"
    return "INVALID_AMOUNT" if "amount" in request and not is_amount(request["amount"]) else None


def _binding_is_structurally_valid(value: Any, legacy: bool) -> bool:
    return (_exact_record(value, ("runtimeSessionId", "controlEpoch", "roleId", "roleTenureId"), ("credentialKeyId", "intentId", "nonce", "runtimeSignature"))
            and is_identifier(value["runtimeSessionId"]) and is_u53(value["controlEpoch"]) and is_identifier(value["roleId"]) and is_identifier(value["roleTenureId"])
            and ("credentialKeyId" not in value or is_identifier(value["credentialKeyId"])) and ("intentId" not in value or is_identifier(value["intentId"]))
            and ("nonce" not in value or is_identifier(value["nonce"])) and ("runtimeSignature" not in value or _signature_shape_valid(value["runtimeSignature"], legacy)))


def same_domain(left: Rec, right: Rec) -> bool:
    """Domains compare field-wise; a legacy ``verifyingContract`` compares case-insensitively."""
    for key in set(left) | set(right):
        a, b = left.get(key), right.get(key)
        if key == "verifyingContract":
            if not isinstance(a, str) or not isinstance(b, str) or a.lower() != b.lower():
                return False
        elif a != b or type(a) is not type(b):
            return False
    return True


def _same_head(a: Rec, b: Rec) -> bool:
    return a["hash"] == b["hash"] and a["position"] == b["position"] and a["canonicalTime"] == b["canonicalTime"]


# ---------------------------------------------------------------- normalisation


def _optional_fields(source: Rec, keys: tuple[str, ...]) -> Rec:
    return {key: source[key] for key in keys if key in source}


def normalized_constraints(c: Rec) -> Rec:
    return {
        "actions": sorted(c["actions"]), "resources": sorted(c["resources"]), "quantitative": c["quantitative"],
        **_optional_fields(c, ("notBefore", "expiresAt", "maxAmount", "maxCumulativeAmount", "maxTransactions")),
        "maxDelegationDepth": c["maxDelegationDepth"], "requiredIntersectionIds": sorted(c["requiredIntersectionIds"]),
    }


def _normalized_permission(g: Rec) -> Rec:
    return {
        "kind": "PERMISSION", "authorityId": g["authorityId"], "grantorId": g["grantorId"], "granteeId": g["granteeId"], "rootAuthorityId": g["rootAuthorityId"],
        **_optional_fields(g, ("parentAuthorityId",)), "independent": g["independent"], "constraints": normalized_constraints(g["constraints"]),
    }


def normalized_grant(grant: Rec) -> Rec:
    """A grant with its constraint arrays sorted (as written into proofs); unknown keys dropped."""
    if grant["kind"] == "PERMISSION":
        return _normalized_permission(grant)
    base = {"kind": "PROHIBITION", "authorityId": grant["authorityId"], "grantorId": grant["grantorId"], **_optional_fields(grant, ("subjectActorId",))}
    if grant["scope"] == "GLOBAL":
        return {**base, "scope": "GLOBAL", "constraints": normalized_constraints(grant["constraints"])}
    return {**base, "scope": "ROOT", "rootAuthorityId": grant["rootAuthorityId"], **_optional_fields(grant, ("parentAuthorityId",)), "constraints": normalized_constraints(grant["constraints"])}


def _normalized_request(r: Rec) -> Rec:
    return {"actorId": r["actorId"], "action": r["action"], "resource": r["resource"], "claimedAt": r["claimedAt"], **_optional_fields(r, _REQUEST_OPTIONAL)}


def _normalized_domain(d: Rec) -> Rec:
    if "chainId" in d:
        return {"protocol": d["protocol"], "version": d["version"], "deploymentId": d["deploymentId"], "chainId": d["chainId"], "verifyingContract": d["verifyingContract"]}
    return {"protocol": d["protocol"], "version": d["version"], "deploymentId": d["deploymentId"]}


# ---------------------------------------------------------------- attenuation and constraint algebra


def _subset(child: list[str], parent: list[str]) -> bool:
    return all(v in parent for v in child)


def _bound_kept(parent: Any, child: Any) -> bool:
    return parent is None or (child is not None and child <= parent)


def constraints_are_attenuated(parent: Rec, child: Rec) -> bool:
    """Engine-side attenuation (spec 02 §3.3): a child may only narrow, never drop a bound, and loses one delegation level."""
    if (not _subset(child["actions"], parent["actions"]) or not _subset(child["resources"], parent["resources"])
            or not _subset(parent["requiredIntersectionIds"], child["requiredIntersectionIds"]) or parent["maxDelegationDepth"] == 0
            or child["maxDelegationDepth"] > parent["maxDelegationDepth"] - 1 or (parent["quantitative"] and not child["quantitative"])):
        return False
    parent_not_before, child_not_before = parent.get("notBefore"), child.get("notBefore")
    if parent_not_before is not None and (child_not_before is None or child_not_before < parent_not_before):
        return False
    return (_bound_kept(parent.get("expiresAt"), child.get("expiresAt")) and _bound_kept(parent.get("maxAmount"), child.get("maxAmount"))
            and _bound_kept(parent.get("maxCumulativeAmount"), child.get("maxCumulativeAmount")) and _bound_kept(parent.get("maxTransactions"), child.get("maxTransactions")))


def _min_of(cur: Any, nxt: Any) -> Any:
    return cur if nxt is None else nxt if cur is None or nxt < cur else cur


def _max_of(cur: Any, nxt: Any) -> Any:
    return cur if nxt is None else nxt if cur is None or nxt > cur else cur


def combine_constraints(grants: list[Rec]) -> Rec:
    """Effective constraints of a grant sequence (spec 02 §3.6): intersections narrow, bounds take the tighter value."""
    actions: list[str] | None = None
    resources: list[str] | None = None
    quantitative = False
    not_before = expires_at = max_amount = max_cumulative = max_transactions = max_depth = None
    required: set[str] = set()
    for grant in grants:
        c = grant["constraints"]
        actions = sorted(c["actions"]) if actions is None else [a for a in actions if a in c["actions"]]
        resources = sorted(c["resources"]) if resources is None else [r for r in resources if r in c["resources"]]
        quantitative = quantitative or c["quantitative"]
        not_before = _max_of(not_before, c.get("notBefore"))
        expires_at = _min_of(expires_at, c.get("expiresAt"))
        max_amount = _min_of(max_amount, c.get("maxAmount"))
        max_cumulative = _min_of(max_cumulative, c.get("maxCumulativeAmount"))
        max_transactions = _min_of(max_transactions, c.get("maxTransactions"))
        max_depth = _min_of(max_depth, c["maxDelegationDepth"])
        required.update(c["requiredIntersectionIds"])
    out: Rec = {"actions": actions if actions is not None else [], "resources": resources if resources is not None else [], "quantitative": quantitative}
    if not_before is not None:
        out["notBefore"] = not_before
    if expires_at is not None:
        out["expiresAt"] = expires_at
    if max_amount is not None:
        out["maxAmount"] = max_amount
    if max_cumulative is not None:
        out["maxCumulativeAmount"] = max_cumulative
    if max_transactions is not None:
        out["maxTransactions"] = max_transactions
    out["maxDelegationDepth"] = max_depth if max_depth is not None else 0
    out["requiredIntersectionIds"] = sorted(required)
    return out


# ---------------------------------------------------------------- corpus, paths and validation


@dataclass
class Corpus:
    permissions: dict[str, Rec]
    prohibitions: dict[str, Rec]
    roots: dict[str, Rec]
    revoked: set[str]
    usage: dict[str, Rec]
    global_policy_source_id: str
    evidence: dict[str, Rec] | None = None  # raw path: supplied evidence records
    agents: dict[str, Any] | None = None  # replay path only
    principals: dict[str, Any] | None = None
    records: dict[str, Any] | None = None


@dataclass(frozen=True)
class Path:
    root_authority_id: str
    grants: tuple[Rec, ...]
    authority_ids: tuple[str, ...]
    effectively_independent: bool
    recognized_root: Rec | None  # spec 02 §3.5, fixed at grant time


@dataclass(frozen=True)
class Intersection:
    required_authority_id: str
    required_by_authority_ids: tuple[str, ...]
    path: Path
    recognized_root: Rec


@dataclass(frozen=True)
class Graph:
    main: Path
    paths: tuple[Path, ...]
    intersections: tuple[Intersection, ...]
    missing_intersection_ids: tuple[str, ...]


@dataclass
class Validated:
    corpus: Corpus
    paths: dict[str, Path] = field(default_factory=dict)
    candidates_by_actor: dict[str, list[Path]] = field(default_factory=dict)
    # For actors with many candidates (built on first use, then kept up to date by _index_candidate): the actor's
    # candidates per resource their terminal grant names, in permission order (the TypeScript ``candidatesByResource``).
    candidates_by_resource: dict[str, dict[str, list[Path]]] = field(default_factory=dict)
    globals: list[Rec] = field(default_factory=list)
    root_prohibitions: dict[str, list[Rec]] = field(default_factory=dict)
    graphs: dict[int, Graph] = field(default_factory=dict)


def _evidence_of(corpus: Corpus, identifier: str) -> Rec | None:
    if corpus.evidence is not None:
        return corpus.evidence.get(identifier)
    record = None if corpus.records is None else corpus.records.get(identifier)
    return None if record is None else {"authorityId": identifier, "grantEventId": record.grant_event_id, "grantEventPosition": record.grant_event_position}


def _replay_corpus(state: ReplayState) -> Corpus:
    permissions: dict[str, Rec] = {}
    prohibitions: dict[str, Rec] = {}
    revoked: set[str] = set()
    for identifier, record in state.authorities.items():
        if record.grant["kind"] == "PERMISSION":
            permissions[identifier] = record.grant
        else:
            prohibitions[identifier] = record.grant
        if record.revocation_event_id is not None:
            revoked.add(identifier)
    return Corpus(permissions, prohibitions, state.recognized_roots, revoked, state.authority_usage, state.genesis["globalPolicySourceId"],
                  None, state.agents, state.principals, state.authorities)


def _recognized_root_of(corpus: Corpus, root_authority_id: str, first: Rec) -> Rec | None:
    root = corpus.roots.get(root_authority_id)
    if (root is not None and first["authorityId"] == root["rootAuthorityId"] and first["rootAuthorityId"] == root["rootAuthorityId"]
            and first["grantorId"] == root["principalId"] and first.get("parentAuthorityId") is None):
        return root
    return None


def _build_permission_path(terminal: Rec, corpus: Corpus) -> tuple[str, Path | None]:
    """Walk parent links to the root; cycles and dangling parents are delegation faults, depth > 32 an input limit."""
    permissions = corpus.permissions
    if terminal.get("parentAuthorityId") is None:
        return "VALID", Path(terminal["rootAuthorityId"], (terminal,), (terminal["authorityId"],), terminal["independent"],
                             _recognized_root_of(corpus, terminal["rootAuthorityId"], terminal))
    reverse: list[Rec] = []
    visited: set[str] = set()
    current: Rec | None = terminal
    while current is not None:
        if current["authorityId"] in visited:
            return "INVALID_DELEGATION", None
        if len(reverse) == _MAX_PATH_DEPTH:
            return "INVALID_INPUT", None
        visited.add(current["authorityId"])
        reverse.append(current)
        parent_id = current.get("parentAuthorityId")
        if parent_id is None:
            break
        current = permissions.get(parent_id)
        if current is None:
            return "INVALID_DELEGATION", None
    grants = list(reversed(reverse))
    effectively_independent = True
    for i, grant in enumerate(grants):
        if not grant["independent"]:
            effectively_independent = False
        if i == 0:
            continue
        parent = grants[i - 1]
        if grant["grantorId"] != parent["granteeId"] or grant["rootAuthorityId"] != parent["rootAuthorityId"] or not constraints_are_attenuated(parent["constraints"], grant["constraints"]):
            return "INVALID_DELEGATION", None
    first = grants[0]
    return "VALID", Path(first["rootAuthorityId"], tuple(grants), tuple(g["authorityId"] for g in grants), effectively_independent,
                         _recognized_root_of(corpus, first["rootAuthorityId"], first))


def _intersection_graph_is_acyclic(permissions: dict[str, Rec], starts: list[str]) -> bool:
    """DFS over ``requiredIntersectionIds`` edges between permissions; a cycle is a delegation fault."""
    done: set[str] = set()
    for start in starts:
        if start in done:
            continue
        active = {start}
        stack: list[list[Any]] = [[start, 0]]
        while stack:
            frame = stack[-1]
            deps = permissions[frame[0]]["constraints"]["requiredIntersectionIds"]
            if frame[1] >= len(deps):
                stack.pop()
                active.discard(frame[0])
                done.add(frame[0])
                continue
            dep = deps[frame[1]]
            frame[1] += 1
            if dep not in permissions or dep in done:
                continue
            if dep in active:
                return False
            active.add(dep)
            stack.append([dep, 0])
    return True


def _root_is_valid(corpus: Corpus, root: Rec) -> bool:
    identifier = root["rootAuthorityId"]
    grant = corpus.permissions.get(identifier)
    if corpus.records is not None:
        record = corpus.records.get(identifier)
        evidence_grant_event_id = None if record is None else record.grant_event_id
    else:
        evidence = None if corpus.evidence is None else corpus.evidence.get(identifier)
        evidence_grant_event_id = None if evidence is None else evidence["grantEventId"]
    if (grant is None or evidence_grant_event_id is None or grant.get("parentAuthorityId") is not None or grant["authorityId"] != identifier
            or grant["rootAuthorityId"] != identifier or grant["grantorId"] != root["principalId"] or evidence_grant_event_id != root["rootGrantEventId"]):
        return False
    if corpus.principals is None:
        return True
    principal = corpus.principals.get(root["principalId"])
    return principal is not None and root["principalRecognitionEventId"] == principal.creation_event_id


def _prohibition_is_valid(corpus: Corpus, paths: dict[str, Path], p: Rec) -> bool:
    if p["scope"] == "GLOBAL":
        return p["grantorId"] == corpus.global_policy_source_id
    root = corpus.roots.get(p["rootAuthorityId"])
    if root is None:
        return False
    parent_id = p.get("parentAuthorityId")
    if p["grantorId"] == root["principalId"]:
        root_grant = corpus.permissions.get(root["rootAuthorityId"])
        return parent_id is None and root_grant is not None and constraints_are_attenuated(root_grant["constraints"], p["constraints"])
    parent = None if parent_id is None else corpus.permissions.get(parent_id)
    path = None if parent_id is None else paths.get(parent_id)
    return (parent is not None and path is not None and parent["granteeId"] == p["grantorId"] and path.root_authority_id == p["rootAuthorityId"]
            and constraints_are_attenuated(parent["constraints"], p["constraints"]))


def _is_capped(g: Rec) -> bool:
    return "maxTransactions" in g["constraints"] or "maxCumulativeAmount" in g["constraints"]


def _add_by_resource(by_resource: dict[str, list[Path]], path: Path) -> None:
    for resource in dict.fromkeys(path.grants[-1]["constraints"]["resources"]):
        by_resource.setdefault(resource, []).append(path)


def _index_candidate(v: Validated, path: Path) -> None:
    if not path.effectively_independent:
        return
    grantee = path.grants[-1]["granteeId"]
    v.candidates_by_actor.setdefault(grantee, []).append(path)
    by_resource = v.candidates_by_resource.get(grantee)
    if by_resource is not None:
        _add_by_resource(by_resource, path)


_RESOURCE_INDEX_MIN_CANDIDATES = 32


def _plausible_candidates(validated: Validated, request: Rec, candidates: list[Path]) -> list[Path] | None:
    """The candidates that can possibly succeed (the terminal grant names the action and the resource: every grant of a
    successful candidate's graph must), in candidate order; None when the actor has few candidates (TypeScript parity)."""
    if len(candidates) <= _RESOURCE_INDEX_MIN_CANDIDATES:
        return None
    actor = request["actorId"]
    by_resource = validated.candidates_by_resource.get(actor)
    if by_resource is None:
        by_resource = {}
        for path in candidates:
            _add_by_resource(by_resource, path)
        validated.candidates_by_resource[actor] = by_resource
    action = request["action"]
    return [p for p in by_resource.get(request["resource"], ()) if action in p.grants[-1]["constraints"]["actions"]]


def _index_permission(v: Validated, path: Path) -> bool:
    """Adds one already-built path; False when a recognized root record disagrees with its grant."""
    identifier = path.grants[-1]["authorityId"]
    v.paths[identifier] = path
    _index_candidate(v, path)
    root = v.corpus.roots.get(identifier)
    return root is None or _root_is_valid(v.corpus, root)


def _index_prohibition(v: Validated, p: Rec) -> bool:
    if not _prohibition_is_valid(v.corpus, v.paths, p):
        return False
    if p["scope"] == "GLOBAL":
        v.globals.append(p)
        v.globals.sort(key=lambda x: x["authorityId"])
    else:
        bucket = v.root_prohibitions.setdefault(p["rootAuthorityId"], [])
        bucket.append(p)
        bucket.sort(key=lambda x: x["authorityId"])
    return True


def _validate_corpus(corpus: Corpus) -> tuple[str, Validated | None]:
    """Spec 02 §3.4 over a whole corpus."""
    v = Validated(corpus)
    with_intersections: list[str] = []
    capped = 0
    for identifier, permission in corpus.permissions.items():
        status, path = _build_permission_path(permission, corpus)
        if path is None:
            return status, None
        v.paths[identifier] = path
        if len(permission["constraints"]["requiredIntersectionIds"]) > 0:
            with_intersections.append(identifier)
        if _is_capped(permission):
            capped += 1
    if with_intersections and not _intersection_graph_is_acyclic(corpus.permissions, with_intersections):
        return "INVALID_DELEGATION", None
    valid = capped == len(corpus.usage)
    if corpus.evidence is not None:
        valid = valid and len(corpus.evidence) == len(corpus.permissions) + len(corpus.prohibitions)
        for identifier in corpus.evidence:
            if identifier not in corpus.permissions and identifier not in corpus.prohibitions:
                valid = False
        for identifier in corpus.permissions:
            if identifier not in corpus.evidence:
                valid = False
        for identifier in corpus.prohibitions:
            if identifier not in corpus.evidence:
                valid = False
    for root in corpus.roots.values():
        if not _root_is_valid(corpus, root):
            valid = False
    for identifier in corpus.revoked:
        if identifier not in corpus.permissions and identifier not in corpus.prohibitions:
            valid = False
    for identifier, permission in corpus.permissions.items():
        if _is_capped(permission) and identifier not in corpus.usage:
            valid = False
    for p in corpus.prohibitions.values():
        if not _prohibition_is_valid(corpus, v.paths, p):
            valid = False
    if not valid:
        return "INVALID_DELEGATION", None
    for path in v.paths.values():
        _index_candidate(v, path)
    for p in corpus.prohibitions.values():
        _index_prohibition(v, p)
    return "VALID", v


@dataclass
class _StateMemo:
    position: int
    hash: str
    status: str
    validated: Validated | None
    evidence: EvidenceContext | None = None


def _extend_memo(memo: _StateMemo, state: ReplayState) -> bool:
    """Applies events (memo.position, head] to the memo; False when the grown corpus needs a full validation.

    The TypeScript engine's ``extendMemo`` step for step: a replay re-derives a proof at every admission and
    administrative event, and rebuilding the whole corpus each time made replay quadratic in the number of grants."""
    if memo.status != "VALID" or memo.validated is None:
        return False
    v = memo.validated
    events = state.events
    for i in range(memo.position + 1, state.head["position"] + 1):
        event = events[i]
        if memo.evidence is not None:
            note_evidence_event(memo.evidence, i)
        if event["type"] == "AUTHORITY_REVOKED":
            v.corpus.revoked.add(event["data"]["authorityId"])
        elif event["type"] == "AUTHORITY_GRANTED":
            granted = event["data"].get("grant")
            record = None if not isinstance(granted, dict) else state.authorities.get(granted.get("authorityId"))
            if record is None or record.grant_event_position != i:
                return False
            grant = record.grant
            if grant["kind"] == "PERMISSION":
                if any(dep not in v.corpus.permissions for dep in grant["constraints"]["requiredIntersectionIds"]):
                    return False
                v.corpus.permissions[grant["authorityId"]] = grant
                status, path = _build_permission_path(grant, v.corpus)
                if status != "VALID" or path is None or (_is_capped(grant) and grant["authorityId"] not in v.corpus.usage) or not _index_permission(v, path):
                    return False
                v.graphs.clear()
            else:
                v.corpus.prohibitions[grant["authorityId"]] = grant
                if not _index_prohibition(v, grant):
                    return False
    memo.position = state.head["position"]
    memo.hash = state.head["hash"]
    return True


def _memo_for(state: ReplayState) -> _StateMemo:
    """Per-state memo of everything request-independent: a state that grew (same prefix, more events) is extended
    event by event (``_extend_memo``); anything else is rebuilt."""
    memo = state.memo
    head = state.head
    if isinstance(memo, _StateMemo) and memo.position <= head["position"] and state.event_history_hashes[memo.position] == memo.hash:
        if memo.position == head["position"] or _extend_memo(memo, state):
            return memo
    status, validated = _validate_corpus(_replay_corpus(state))
    fresh = _StateMemo(head["position"], head["hash"], status, validated)
    state.memo = fresh
    return fresh


def _evidence_for(state: ReplayState) -> EvidenceContext:
    memo = _memo_for(state)
    if memo.evidence is None:
        memo.evidence = create_evidence_context(state)
    return memo.evidence


# ---------------------------------------------------------------- intersection graph


def _direct_required_ids(path: Path, index: int) -> list[str]:
    grant = path.grants[index]
    if index == 0:
        return list(grant["constraints"]["requiredIntersectionIds"])
    inherited = path.grants[index - 1]["constraints"]["requiredIntersectionIds"]
    return [i for i in grant["constraints"]["requiredIntersectionIds"] if i not in inherited]


def _select_candidate_graph(validated: Validated, main: Path, actor_id: str) -> Graph:
    """Spec 02 §4.7: BFS over required intersections; a partner must be dependent and held by the actor."""
    if all(len(g["constraints"]["requiredIntersectionIds"]) == 0 for g in main.grants):
        return Graph(main, (main,), (), ())
    required_by: dict[str, set[str]] = {}
    queue: list[str] = []
    selected: dict[str, Intersection] = {}
    missing: set[str] = set()

    def collect(path: Path) -> None:
        for i, grant in enumerate(path.grants):
            for identifier in _direct_required_ids(path, i):
                declarers = required_by.get(identifier)
                if declarers is None:
                    declarers = required_by[identifier] = set()
                    queue.append(identifier)
                declarers.add(grant["authorityId"])

    collect(main)
    q = 0
    while q < len(queue):
        identifier = queue[q]
        q += 1
        path = validated.paths.get(identifier)
        root = None if path is None else path.recognized_root
        terminal = None if path is None else path.grants[-1]
        if path is None or root is None or terminal is None or path.effectively_independent or terminal["granteeId"] != actor_id:
            missing.add(identifier)
            continue
        if identifier not in selected:
            selected[identifier] = Intersection(identifier, (), path, root)
            collect(path)
    intersections: list[Intersection] = []
    paths: list[Path] = [main]
    for identifier in sorted(selected):
        sel = selected[identifier]
        paths.append(sel.path)
        intersections.append(Intersection(identifier, tuple(sorted(required_by[identifier])), sel.path, sel.recognized_root))
    return Graph(main, tuple(paths), tuple(intersections), tuple(sorted(missing)))


def _graph_for(validated: Validated, main: Path) -> Graph:
    graph = validated.graphs.get(id(main))
    if graph is None:
        graph = validated.graphs[id(main)] = _select_candidate_graph(validated, main, main.grants[-1]["granteeId"])
    return graph


def _graph_grants(graph: Graph) -> list[Rec]:
    return list(graph.main.grants) if len(graph.paths) == 1 else [g for p in graph.paths for g in p.grants]


# ---------------------------------------------------------------- prohibitions


def _prohibition_request_relevant(p: Rec, request: Rec) -> bool:
    subject = p.get("subjectActorId")
    c = p["constraints"]
    return ((subject is None or subject == request["actorId"]) and request["action"] in c["actions"] and request["resource"] in c["resources"]
            and (not c["quantitative"] or "amount" in request))


def _within_time(c: Rec, t: int) -> bool:
    return ("notBefore" not in c or t >= c["notBefore"]) and ("expiresAt" not in c or t < c["expiresAt"])


def _depends_on_terminated_agent(corpus: Corpus, g: Rec) -> bool:
    if corpus.agents is None:
        return False
    grantor, grantee = corpus.agents.get(g["grantorId"]), corpus.agents.get(g["granteeId"])
    return (grantor is not None and grantor.terminated) or (grantee is not None and grantee.terminated)


def _path_active_through(corpus: Corpus, path: Path, t: int, terminal_id: str) -> bool:
    for g in path.grants:
        if g["authorityId"] in corpus.revoked or not _within_time(g["constraints"], t) or _depends_on_terminated_agent(corpus, g):
            return False
        if g["authorityId"] == terminal_id:
            return True
    return False


def _prohibition_matches_amount(p: Rec, request: Rec) -> bool:
    amount = request.get("amount")
    max_amount = p["constraints"].get("maxAmount")
    return max_amount is None or (amount is not None and amount <= max_amount)


def _prohibition_is_active(validated: Validated, p: Rec, t: int) -> bool:
    if p["authorityId"] in validated.corpus.revoked or not _within_time(p["constraints"], t):
        return False
    if p["scope"] == "GLOBAL":
        return True
    anchor_id = p.get("parentAuthorityId")
    if anchor_id is None:
        return True
    anchor = validated.paths.get(anchor_id)
    return anchor is not None and _path_active_through(validated.corpus, anchor, t, anchor_id)


def _relevant_global_prohibitions(validated: Validated, request: Rec) -> list[Rec]:
    return [p for p in validated.globals if _prohibition_request_relevant(p, request)]


def _relevant_candidate_prohibitions(validated: Validated, graph: Graph, request: Rec) -> list[Rec]:
    """ROOT prohibitions applying to any path of the graph (anchored ones need their anchor on such a path), sorted by id."""
    if not validated.root_prohibitions:
        return []
    relevant: list[Rec] = []
    roots = 0
    seen_roots: set[str] = set()
    for path in graph.paths:
        bucket = validated.root_prohibitions.get(path.root_authority_id)
        if bucket is None or path.root_authority_id in seen_roots:
            seen_roots.add(path.root_authority_id)
            continue
        seen_roots.add(path.root_authority_id)
        roots += 1
        for p in bucket:
            anchor_id = p.get("parentAuthorityId")
            anchored = anchor_id is None or any(x.root_authority_id == p["rootAuthorityId"] and anchor_id in x.authority_ids for x in graph.paths)
            if anchored and _prohibition_request_relevant(p, request):
                relevant.append(p)
    if roots > 1:
        relevant.sort(key=lambda x: x["authorityId"])
    return relevant


# ---------------------------------------------------------------- candidate evaluation

_FAILURE_ORDER = ("REVOKED", "NOT_YET_VALID", "EXPIRED", "MISSING_INTERSECTION", "ACTION_NOT_ALLOWED", "RESOURCE_NOT_ALLOWED", "AMOUNT_REQUIRED",
                  "AMOUNT_EXCEEDED", "CUMULATIVE_AMOUNT_EXCEEDED", "TRANSACTION_COUNT_EXCEEDED", "NO_AUTHORITY")
_REVOKED, _NOT_YET_VALID, _EXPIRED, _MISSING, _ACTION, _RESOURCE, _AMOUNT_REQUIRED, _AMOUNT_EXCEEDED, _CUMULATIVE, _COUNT, _INACTIVE = range(11)


@dataclass(frozen=True)
class Evaluation:
    status: str  # SUCCESS | FAILURE
    graph: Graph | None = None
    checked_prohibition_ids: tuple[str, ...] = ()
    code: str | None = None
    failing_authority_id: str | None = None


def _evaluate_candidate(validated: Validated, main: Path, request: Rec, t: int, global_ids: list[str], collect: Any = None) -> Evaluation:
    """Spec 02 §4.2. Only the least member of each failure set matters, so the sets are tracked as running minima.
    With ``collect`` given (receipt policy) every decisive id is also reported and usage is not rechecked."""
    if main.recognized_root is None:
        return Evaluation("FAILURE", code="NO_AUTHORITY", failing_authority_id=main.root_authority_id)
    graph = _graph_for(validated, main)
    root_prohibitions = _relevant_candidate_prohibitions(validated, graph, request)
    prohibited_by: str | None = None
    for p in root_prohibitions:
        if not _prohibition_is_active(validated, p, t) or not _prohibition_matches_amount(p, request):
            continue
        if collect is not None:
            collect(p["authorityId"])
        if prohibited_by is None or p["authorityId"] < prohibited_by:
            prohibited_by = p["authorityId"]
    if prohibited_by is not None and collect is None:
        return Evaluation("FAILURE", graph, code="PROHIBITED", failing_authority_id=prohibited_by)
    least: list[str | None] = [None] * 11

    def hit(index: int, identifier: str) -> None:
        if collect is not None:
            collect(identifier)
        current = least[index]
        if current is None or identifier < current:
            least[index] = identifier

    for identifier in graph.missing_intersection_ids:
        hit(_MISSING, identifier)
    amount = request.get("amount")
    check_capacity = collect is None
    for path in graph.paths:
        for g in path.grants:
            c = g["constraints"]
            identifier = g["authorityId"]
            if identifier in validated.corpus.revoked:
                hit(_REVOKED, identifier)
            if "notBefore" in c and t < c["notBefore"]:
                hit(_NOT_YET_VALID, identifier)
            if "expiresAt" in c and t >= c["expiresAt"]:
                hit(_EXPIRED, identifier)
            if request["action"] not in c["actions"]:
                hit(_ACTION, identifier)
            if request["resource"] not in c["resources"]:
                hit(_RESOURCE, identifier)
            if c["quantitative"] and amount is None:
                hit(_AMOUNT_REQUIRED, identifier)
            if "maxAmount" in c and amount is not None and amount > c["maxAmount"]:
                hit(_AMOUNT_EXCEEDED, identifier)
            if check_capacity:
                usage = validated.corpus.usage.get(identifier)
                if usage is not None and "maxCumulativeAmount" in c and amount is not None and usage["admittedCumulativeAmount"] + amount > c["maxCumulativeAmount"]:
                    hit(_CUMULATIVE, identifier)
                if usage is not None and "maxTransactions" in c and usage["admittedTransactionCount"] >= c["maxTransactions"]:
                    hit(_COUNT, identifier)
            if _depends_on_terminated_agent(validated.corpus, g):
                hit(_INACTIVE, identifier)
    if prohibited_by is not None:
        return Evaluation("FAILURE", graph, code="PROHIBITED", failing_authority_id=prohibited_by)
    for i, code in enumerate(_FAILURE_ORDER):
        if least[i] is not None:
            return Evaluation("FAILURE", graph, code=code, failing_authority_id=least[i])
    checked = tuple(global_ids) if not root_prohibitions else tuple(sorted([*global_ids, *(p["authorityId"] for p in root_prohibitions)]))
    return Evaluation("SUCCESS", graph, checked)


# ---------------------------------------------------------------- the algebra


@dataclass
class Context:
    operation_version: str
    assurance: str
    validated: Validated
    domain: Rec
    policy_version: str
    history_head: Rec
    evaluation_time: int
    request: Rec
    consequential: bool
    hash_algorithm: str
    binding: Rec | None = None
    evidence: EvidenceContext | None = None
    administrative: AdministrativeRequirements | None = None


@dataclass
class Plan:
    selection: Intersection
    effective: Rec
    hash: str | None = None


@dataclass
class Candidate:
    context: Context
    evaluation: Evaluation
    recognized_root: Rec
    plans: list[Plan]
    effective: Rec
    hash: str | None = None
    decision: str = "ALLOW_CANDIDATE"


def _plan_for(context: Context, evaluation: Evaluation) -> Candidate:
    graph = evaluation.graph
    assert graph is not None and graph.main.recognized_root is not None
    return Candidate(context, evaluation, graph.main.recognized_root,
                     [Plan(selection, combine_constraints(list(selection.path.grants))) for selection in graph.intersections],
                     combine_constraints(_graph_grants(graph)))


def _plan_hash(context: Context, plan: Plan) -> str:
    if plan.hash is None:
        plan.hash = hash_canonical(plan.effective, context.hash_algorithm)
    return plan.hash


def _candidate_hash(c: Candidate) -> str:
    if c.hash is None:
        c.hash = hash_canonical(c.effective, c.context.hash_algorithm)
    return c.hash


def _compare_plans(context: Context, a: Plan, b: Plan) -> int:
    c = compare_ids(a.selection.required_authority_id, b.selection.required_authority_id)
    if c != 0:
        return c
    c = compare_id_sequences(list(a.selection.required_by_authority_ids), list(b.selection.required_by_authority_ids))
    if c != 0:
        return c
    c = compare_ids(a.selection.recognized_root["rootAuthorityId"], b.selection.recognized_root["rootAuthorityId"])
    if c != 0:
        return c
    c = compare_id_sequences(list(a.selection.path.authority_ids), list(b.selection.path.authority_ids))
    return c if c != 0 else compare_ids(_plan_hash(context, a), _plan_hash(context, b))


def _compare_candidates(a: Candidate, b: Candidate) -> int:
    """Spec 02 §4.6: root id, main path ids (prefix first), intersections, then the constraint hash."""
    c = compare_ids(a.recognized_root["rootAuthorityId"], b.recognized_root["rootAuthorityId"])
    if c != 0:
        return c
    assert a.evaluation.graph is not None and b.evaluation.graph is not None
    c = compare_id_sequences(list(a.evaluation.graph.main.authority_ids), list(b.evaluation.graph.main.authority_ids))
    if c != 0:
        return c
    for pa, pb in zip(a.plans, b.plans):
        c = _compare_plans(a.context, pa, pb)
        if c != 0:
            return c
    if len(a.plans) != len(b.plans):
        return len(a.plans) - len(b.plans)
    return compare_ids(_candidate_hash(a), _candidate_hash(b))


def _meets_administrative_requirements(validated: Validated, path: Path, req: AdministrativeRequirements) -> bool:
    if path.recognized_root is None or path.recognized_root["principalId"] != req.required_principal_id:
        return False
    controlling = [g["authorityId"] for g in _graph_grants(_graph_for(validated, path))]
    return all(identifier in controlling for identifier in req.required_authority_ids)


def _narrowed_algebra_evidence(context: Context, ctx: EvidenceContext, globals_: list[Rec], candidates: list[Path]) -> list[Rec]:
    """Format 1: the authority events relevant to one decision — grant and revocation events of every authority on
    the actor's candidate paths, of their selected and missing intersection partners, and of every prohibition
    considered (relevant GLOBAL ones, candidate ROOT ones) — handed to :func:`narrowed_decision_evidence`."""
    validated, request = context.validated, context.request
    records = ctx.state.authorities
    cited: set[str] = set()
    positions: list[int] = []

    def cite(identifier: str) -> None:
        if identifier in cited:
            return
        cited.add(identifier)
        record = records.get(identifier)
        if record is None:
            return
        positions.append(record.grant_event_position)
        if record.revocation_event_position is not None:
            positions.append(record.revocation_event_position)

    for p in globals_:
        cite(p["authorityId"])
    for main in candidates:
        for identifier in main.authority_ids:
            cite(identifier)
        # A candidate without a recognized root fails NO_AUTHORITY before its graph and prohibitions are considered.
        if main.recognized_root is None:
            continue
        graph = _graph_for(validated, main)
        for path in graph.paths[1:]:
            for identifier in path.authority_ids:
                cite(identifier)
        for identifier in graph.missing_intersection_ids:
            cite(identifier)
        for p in _relevant_candidate_prohibitions(validated, graph, request):
            cite(p["authorityId"])
    return narrowed_decision_evidence(ctx, request["actorId"], positions, context.binding if context.consequential else None)


def _evaluate_algebra(context: Context) -> Any:
    validated, request, t, operation_version, assurance = context.validated, context.request, context.evaluation_time, context.operation_version, context.assurance
    globals_ = _relevant_global_prohibitions(validated, request)
    all_candidates = validated.candidates_by_actor.get(request["actorId"], [])
    # The actor's candidates (administrative requests: those meeting the requirements), computed only when needed.
    filtered: list[list[Path]] = []

    def candidates_of() -> list[Path]:
        if not filtered:
            req = context.administrative
            filtered.append(all_candidates if req is None else [p for p in all_candidates if _meets_administrative_requirements(validated, p, req)])
        return filtered[0]
    # The evidence list is shared by every failure, so the output budget is known before any failure is built.
    # Legacy states cite every authority event (spec 02 §6.2); format-1 states only the ones relevant to the request.
    narrowed: list[list[Rec]] = []

    def evidence() -> list[Rec]:
        ctx = context.evidence
        if ctx is None:
            return []
        if not ctx.narrowed:
            return decision_evidence(ctx)
        if not narrowed:
            narrowed.append(_narrowed_algebra_evidence(context, ctx, globals_, candidates_of()))
        return narrowed[0]

    def over_budget(failures: int) -> bool:
        ctx = context.evidence
        return ctx is not None and failures * (len(evidence()) if ctx.narrowed else decision_evidence_length(ctx)) > MAX_RESULT_EVIDENCE

    def limit() -> Rec:
        return indeterminate(operation_version, "OUTPUT_LIMIT_EXCEEDED", assurance)

    global_failure: str | None = None
    for p in globals_:
        if _prohibition_is_active(validated, p, t) and _prohibition_matches_amount(p, request) and (global_failure is None or p["authorityId"] < global_failure):
            global_failure = p["authorityId"]
    if global_failure is not None:
        if over_budget(1):
            return limit()
        failure = {"authorityPathIds": [], "code": "PROHIBITED", "evidence": evidence(), "failingAuthorityId": global_failure, "subjectId": request["actorId"]}
        return bounded_result(denial_result(operation_version, assurance, [failure]), operation_version, assurance)
    global_ids = [p["authorityId"] for p in globals_]
    winner: Candidate | None = None
    # Many candidates: the plausible ones first (all that can succeed, same relative order, so the same winner); without
    # a winner the full loop runs as always.
    plausible = _plausible_candidates(validated, request, all_candidates)
    if plausible is not None:
        req = context.administrative
        for path in plausible:
            if req is not None and not _meets_administrative_requirements(validated, path, req):
                continue
            evaluation = _evaluate_candidate(validated, path, request, t, global_ids)
            if evaluation.status == "SUCCESS":
                candidate = _plan_for(context, evaluation)
                if winner is None or _compare_candidates(candidate, winner) < 0:
                    winner = candidate
        if winner is not None:
            return winner
    failures: list[tuple[Evaluation, Path]] = []
    for path in candidates_of():
        evaluation = _evaluate_candidate(validated, path, request, t, global_ids)
        if evaluation.status == "SUCCESS":
            candidate = _plan_for(context, evaluation)
            if winner is None or _compare_candidates(candidate, winner) < 0:
                winner = candidate
        else:
            failures.append((evaluation, path))
    if winner is not None:
        return winner
    if over_budget(max(1, len(failures))):
        return limit()
    if not failures:
        return bounded_result(simple_denial(operation_version, assurance, "NO_AUTHORITY", evidence(), request["actorId"]), operation_version, assurance)
    shared = evidence()
    denials = [{
        "authorityPathIds": list(path.authority_ids), "code": evaluation.code, "evidence": shared, "failingAuthorityId": evaluation.failing_authority_id,
        "rootAuthorityId": path.root_authority_id, "terminalAuthorityId": path.grants[-1]["authorityId"],
    } for evaluation, path in failures]
    return bounded_result(denial_result(operation_version, assurance, denials), operation_version, assurance)


# ---------------------------------------------------------------- proofs


def _fits_proof_limits(c: Rec, max_required: int) -> bool:
    return len(c["actions"]) <= _MAX_SET_MEMBERS and len(c["resources"]) <= _MAX_SET_MEMBERS and len(c["requiredIntersectionIds"]) <= max_required


def _preflight_proof(candidate: Candidate) -> tuple[list[str], list[str]] | None:
    """Spec 02 §6.3 preflight: any oversized component makes the result OUTPUT_LIMIT_EXCEEDED rather than a truncated proof."""
    graph = candidate.evaluation.graph
    assert graph is not None
    corpus = candidate.context.validated.corpus
    if (len(graph.main.grants) == 0 or len(graph.main.grants) > _MAX_PATH_DEPTH or len(graph.intersections) > _MAX_SET_MEMBERS
            or len(candidate.evaluation.checked_prohibition_ids) > _MAX_SET_MEMBERS or not _fits_proof_limits(candidate.effective, _MAX_SET_MEMBERS)):
        return None
    controlling: set[str] = set()
    for path in graph.paths:
        if len(path.grants) == 0 or len(path.grants) > _MAX_PATH_DEPTH:
            return None
        for g in path.grants:
            if not _fits_proof_limits(g["constraints"], _MAX_REQUIRED_INTERSECTIONS):
                return None
            controlling.add(g["authorityId"])
            if len(controlling) > _MAX_SET_MEMBERS:
                return None
    for plan in candidate.plans:
        n = len(plan.selection.required_by_authority_ids)
        if n == 0 or n > _MAX_SET_MEMBERS or not _fits_proof_limits(plan.effective, _MAX_SET_MEMBERS):
            return None
    controlling_ids = sorted(controlling)
    usage_count = 0
    for identifier in controlling_ids:
        if identifier in corpus.usage:
            usage_count += 1
            if usage_count > _MAX_SET_MEMBERS:
                return None
    evidence_ids = list(dict.fromkeys([*controlling_ids, *candidate.evaluation.checked_prohibition_ids]))
    evidence_authority_ids: list[str] = []
    for identifier in evidence_ids:
        if _evidence_of(corpus, identifier) is not None:
            evidence_authority_ids.append(identifier)
            if len(evidence_authority_ids) > _MAX_AUTHORITIES:
                return None
    return controlling_ids, sorted(evidence_authority_ids)


def _proof_for_candidate(candidate: Candidate, projection: tuple[list[str], list[str]]) -> Rec:
    context, evaluation = candidate.context, candidate.evaluation
    graph = evaluation.graph
    assert graph is not None
    corpus = context.validated.corpus
    memo: dict[str, Rec] = {}

    def normalize(g: Rec) -> Rec:
        n = memo.get(g["authorityId"])
        if n is None:
            n = memo[g["authorityId"]] = _normalized_permission(g)
        return n

    intersections = [{
        "requiredAuthorityId": plan.selection.required_authority_id, "requiredByAuthorityIds": list(plan.selection.required_by_authority_ids),
        "recognizedRoot": plan.selection.recognized_root, "path": [normalize(g) for g in plan.selection.path.grants], "effectiveConstraints": plan.effective,
    } for plan in candidate.plans]
    intersections.sort(key=lambda a: (a["requiredAuthorityId"], tuple(a["requiredByAuthorityIds"]), a["recognizedRoot"]["rootAuthorityId"],
                                      tuple(g["authorityId"] for g in a["path"]), hash_canonical(a["effectiveConstraints"], context.hash_algorithm)))
    controlling_ids, evidence_ids = projection
    usage_snapshot = []
    for identifier in controlling_ids:
        usage = corpus.usage.get(identifier)
        if usage is not None:
            usage_snapshot.append({"authorityId": usage["authorityId"], "admittedTransactionCount": usage["admittedTransactionCount"], "admittedCumulativeAmount": usage["admittedCumulativeAmount"]})
    authority_evidence = []
    for identifier in evidence_ids:
        e = _evidence_of(corpus, identifier)
        if e is not None:
            authority_evidence.append({"authorityId": e["authorityId"], "grantEventId": e["grantEventId"], "grantEventPosition": e["grantEventPosition"]})
    authority_evidence.sort(key=lambda a: (a["authorityId"], a["grantEventId"], a["grantEventPosition"]))
    proof: Rec = {
        "proofVersion": AUTHORIZATION_PROOF_VERSION, "domain": context.domain, "policyVersion": context.policy_version, "rootRecognitionPolicy": ROOT_RECOGNITION_POLICY,
        "historyHead": context.history_head, "evaluationTime": context.evaluation_time, "request": _normalized_request(context.request),
        "recognizedRoot": candidate.recognized_root, "permissionPath": [normalize(g) for g in graph.main.grants], "intersections": intersections,
        "effectiveConstraints": candidate.effective, "controllingAuthorityIds": controlling_ids, "usageSnapshot": usage_snapshot,
        "authorityEvidence": authority_evidence, "checkedProhibitionIds": list(evaluation.checked_prohibition_ids), "consequential": context.consequential,
    }
    binding = context.binding if context.consequential else None
    if binding is not None:
        proof.update({"runtimeSessionId": binding["runtimeSessionId"], "credentialKeyId": binding.get("credentialKeyId"), "controlEpoch": binding["controlEpoch"],
                      "roleId": binding["roleId"], "roleTenureId": binding["roleTenureId"], "intentId": binding.get("intentId"), "nonce": binding.get("nonce")})
    return proof


def _finalize_candidate(candidate: Candidate) -> Rec:
    ctx = candidate.context
    projection = _preflight_proof(candidate)
    if projection is None:
        return indeterminate(ctx.operation_version, "OUTPUT_LIMIT_EXCEEDED", ctx.assurance)
    return {"consequential": ctx.consequential, "decision": "ALLOW", "operationVersion": ctx.operation_version, "proof": _proof_for_candidate(candidate, projection), "scopeAssurance": ctx.assurance}


# ---------------------------------------------------------------- runtime challenge and intents


def create_runtime_authorization_challenge(domain: Rec, request: Rec, evaluation_time: int, policy_version: str, history_head: Rec, binding: Rec) -> Rec:
    """Spec 02 §5.1. The signed structure; ``canonicalTime`` and ``runtimeSignature`` are deliberately absent."""
    if binding.get("credentialKeyId") is None or binding.get("intentId") is None or binding.get("nonce") is None:
        raise TypeError("Runtime authorization challenge requires credential, intent, and nonce identifiers.")
    return {
        "version": RUNTIME_AUTHORIZATION_VERSION, "domain": _normalized_domain(domain), "request": _normalized_request(request), "authoritative": True,
        "consequential": True, "evaluationTime": evaluation_time, "policyVersion": policy_version, "rootRecognitionPolicy": ROOT_RECOGNITION_POLICY,
        "eventHistoryHash": history_head["hash"], "eventHistoryPosition": history_head["position"], "runtimeSessionId": binding["runtimeSessionId"],
        "credentialKeyId": binding["credentialKeyId"], "controlEpoch": binding["controlEpoch"], "roleId": binding["roleId"], "roleTenureId": binding["roleTenureId"],
        "intentId": binding["intentId"], "nonce": binding["nonce"],
    }


def hash_runtime_authorization_challenge(challenge: Rec, algorithm: str) -> str:
    return hash_canonical(challenge, algorithm)


def _verify_session_signature(session: RuntimeSessionRecord, content_hash: str, signature: Any) -> bool:
    try:
        suite = suite_for(session.credential_scheme)
        return suite.is_signature(signature) and suite.is_credential(session.credential_address_key) and suite.verify(content_hash, signature, session.credential_address_key)
    except Exception:
        return False


def verify_runtime_authorization_signature(session: RuntimeSessionRecord, challenge: Rec, signature: Any, algorithm: str) -> bool:
    return _verify_session_signature(session, hash_runtime_authorization_challenge(challenge, algorithm), signature)


def intent_projection(request: Rec, binding: Rec, adapter_profile: Rec) -> Rec:
    """Spec 02 §7.8: the immutable intent content; ``claimedAt`` is intentionally absent."""
    if binding.get("intentId") is None or binding.get("nonce") is None:
        raise TypeError("Intent projection requires intent and nonce identifiers.")
    return {
        "adapterProfile": adapter_profile, "intentId": binding["intentId"], "nonce": binding["nonce"], "actorId": request["actorId"], "action": request["action"],
        "resource": request["resource"], "roleId": binding["roleId"], "roleTenureId": binding["roleTenureId"], **_optional_fields(request, _REQUEST_OPTIONAL),
    }


def _same_optional(a: Rec, b: Rec, key: str) -> bool:
    return (key in a) == (key in b) and (key not in a or a[key] == b[key])


def same_intent(a: Rec, b: Rec) -> bool:
    return (a["intentId"] == b["intentId"] and a["nonce"] == b["nonce"] and a["actorId"] == b["actorId"] and a["action"] == b["action"]
            and a["resource"] == b["resource"] and a["roleId"] == b["roleId"] and a["roleTenureId"] == b["roleTenureId"]
            and _same_optional(a, b, "amount") and _same_optional(a, b, "counterpartyId") and _same_optional(a, b, "termsCommitment"))


# ---------------------------------------------------------------- replay-bound decision procedure


def _is_legacy(state: Any) -> bool:
    return state.format == LEGACY_FORMAT


def _request_within_limits(request: Rec) -> bool:
    return all(_identifier_status(request.get(key)) != "LIMIT" for key in ("actorId", "action", "resource", "counterpartyId") if key in request)


def _body_is_structurally_valid(body: Rec, legacy: bool) -> bool:
    return (_domain_is_valid(body.get("domain"), legacy) and _head_is_valid(body.get("expectedHistoryHead")) and _identifier_status(body.get("policyVersion")) == "VALID"
            and _identifier_status(body.get("rootRecognitionPolicy")) == "VALID" and _request_has_exact_shape(body.get("request")) and _request_within_limits(body["request"])
            and isinstance(body.get("consequential"), bool) and ("binding" in body) == body["consequential"]
            and ("binding" not in body or _binding_is_structurally_valid(body["binding"], legacy)))


def _stage(state: Any, body: Rec, administrative: AdministrativeRequirements | None = None) -> Any:
    """Spec 02 §4: everything before the algebra, in the exact order; a Candidate means "went to the algebra and won"."""
    operation_version = AUTHORIZATION_VERSION
    ctx = _evidence_for(state)
    head_evidence = [event_reference(ctx, len(state.events) - 1)]
    if not _same_head(body["expectedHistoryHead"], state.head):
        return indeterminate(operation_version, "HISTORY_RELATION_UNVERIFIED", "SUPPLIED_SCOPE", head_evidence)
    evaluation_time = body.get("evaluationTime")
    if not is_u53(evaluation_time) or evaluation_time < state.head["canonicalTime"]:
        return indeterminate(operation_version, "CAUSAL_TIME_INVALID", "SUPPLIED_SCOPE", head_evidence)
    assurance = "REPLAY_VERIFIED"

    def deny(code: str, evidence: list[Rec] | None = None, subject_id: str | None = None) -> Rec:
        return bounded_result(simple_denial(operation_version, assurance, code, evidence, subject_id), operation_version, assurance)

    genesis_evidence = [event_reference(ctx, 0)]
    domain, policy_version = body["domain"], body["policyVersion"]
    if not same_domain(domain, state.genesis["domain"]):
        return deny("DOMAIN_MISMATCH", genesis_evidence)
    if policy_version != state.genesis["policyVersion"] or body["rootRecognitionPolicy"] != state.genesis["rootRecognitionPolicy"]:
        return deny("POLICY_MISMATCH", genesis_evidence)
    request = body["request"]
    request_failure = _request_problem(request)
    if request_failure is not None:
        return deny(request_failure)
    memo = _memo_for(state)
    if memo.status == "INVALID_INPUT":
        return indeterminate(operation_version, "STATE_NOT_AUTHORITATIVE", "SUPPLIED_SCOPE")
    if memo.status == "INVALID_DELEGATION":
        return deny("INVALID_DELEGATION", decision_evidence(ctx))
    validated = memo.validated
    assert validated is not None
    agent = state.agents.get(request["actorId"])
    if agent is None or agent.terminated:
        return deny("AGENT_INACTIVE", agent_lifecycle_evidence(ctx, request["actorId"]), request["actorId"])
    consequential = body["consequential"]
    binding = body.get("binding")
    if consequential and binding is not None:
        session_id = binding["runtimeSessionId"]

        def session_evidence() -> list[Rec]:
            return session_lifecycle_evidence(ctx, request["actorId"], session_id)

        session = state.runtime_sessions.get(session_id)
        if session is None or session.agent_id != agent.id:
            return deny("SESSION_NOT_FOUND", session_evidence(), session_id)
        if session.expires_at is not None and evaluation_time >= session.expires_at:
            return deny("SESSION_EXPIRED", session_evidence(), session_id)
        credential_key_id, runtime_signature = binding.get("credentialKeyId"), binding.get("runtimeSignature")
        if credential_key_id is None or runtime_signature is None:
            return deny("SESSION_CREDENTIAL_REQUIRED", session_evidence(), session_id)
        if credential_key_id != session.credential_key_id:
            return deny("SESSION_CREDENTIAL_INVALID", session_evidence(), session_id)
        intent_id, nonce = binding.get("intentId"), binding.get("nonce")
        if intent_id is not None and nonce is not None:
            challenge = create_runtime_authorization_challenge(domain, request, evaluation_time, policy_version, state.head, binding)
            if not verify_runtime_authorization_signature(session, challenge, runtime_signature, state.hash_algorithm):
                return deny("SESSION_CREDENTIAL_INVALID", session_evidence(), session_id)
        if session.control_epoch < agent.current_control_epoch:
            return deny("SESSION_FENCED", session_evidence(), session_id)
        if binding["controlEpoch"] != session.control_epoch or binding["controlEpoch"] != agent.current_control_epoch:
            return deny("STALE_EPOCH", session_evidence(), session_id)
        role, tenure = state.roles.get(binding["roleId"]), state.tenures.get(binding["roleTenureId"])
        if (role is None or tenure is None or role.current_tenure_id != binding["roleTenureId"] or tenure.closed or tenure.role_id != binding["roleId"]
                or tenure.agent_id != agent.id):
            return deny("ROLE_TENURE_NOT_CURRENT", tenure_lifecycle_evidence(ctx, binding["roleId"], binding["roleTenureId"]), binding["roleTenureId"])
        if intent_id is None or nonce is None:
            # Legacy cites every intent of the actor (parity); format 1 names no intent: the genesis, the actor's lifecycle and the head.
            return deny("INTENT_REQUIRED", narrowed_decision_evidence(ctx, request["actorId"], []) if ctx.narrowed else intent_decision_evidence(ctx, request["actorId"]), request["actorId"])

        def intent_evidence() -> list[Rec]:
            return intent_decision_evidence(ctx, request["actorId"], intent_id, nonce)

        declaration = state.intent_declarations.get(intent_id)
        if declaration is None:
            return deny("INTENT_NOT_DECLARED", intent_evidence(), intent_id)
        if not same_intent(declaration, intent_projection(request, binding, declaration["adapterProfile"])):
            return deny("INTENT_MISMATCH", intent_evidence(), intent_id)
        if intent_id in state.intent_admissions:
            return deny("INTENT_REPLAY", intent_evidence(), intent_id)
    return _evaluate_algebra(Context(operation_version, assurance, validated, domain, policy_version, state.head, evaluation_time, request, consequential,
                                     state.hash_algorithm, binding, ctx, administrative))


def _occupied_nonce_denial(state: Any, candidate: Candidate) -> Rec | None:
    """Spec 02 §4 step 10: an ALLOW candidate whose nonce is already reserved for the actor is denied."""
    context = candidate.context
    binding = context.binding if context.consequential else None
    nonce = None if binding is None else binding.get("nonce")
    reservations = state.nonce_reservations_by_actor.get(context.request["actorId"])
    if binding is None or nonce is None or reservations is None or nonce not in reservations:
        return None
    evidence = intent_decision_evidence(_evidence_for(state), context.request["actorId"], binding.get("intentId"), nonce)
    return bounded_result(simple_denial(context.operation_version, context.assurance, "NONCE_ALREADY_ADMITTED", evidence, nonce), context.operation_version, context.assurance)


def authorize_state(state: Any, body: Rec, administrative: AdministrativeRequirements | None = None) -> Rec:
    """Spec 02 §4–§6 against an already replayed state, no replay inside."""
    if not _body_is_structurally_valid(body, _is_legacy(state)):
        return indeterminate(AUTHORIZATION_VERSION, "INVALID_INPUT")
    staged = _stage(state, body, administrative)
    if not isinstance(staged, Candidate):
        return staged
    denial = _occupied_nonce_denial(state, staged)
    return denial if denial is not None else _finalize_candidate(staged)


# ---------------------------------------------------------------- façade: outer capture

_OUTER_KEYS = {
    "AUTHORIZE": ("operationVersion", "events", "expectedHistoryHead", "domain", "policyVersion", "rootRecognitionPolicy", "request", "evaluationTime", "authoritative", "consequential"),
}
_EXPECTED_VERSION = {"AUTHORIZE": AUTHORIZATION_VERSION}


def capture_authority_operation(value: Any, kind: str = "AUTHORIZE") -> tuple[str, Rec | None]:
    """Spec 02 §2.2: outer key discipline then a bounded deep capture."""
    if not _is_record(value):
        raise TypeError("Portable authority input must be a plain record.")
    keys = list(value.keys())
    if "operationVersion" not in keys:
        return "INVALID_INPUT", None
    version = value["operationVersion"]
    if not isinstance(version, str) or len(version) > _MAX_PROTOCOL_STRING_BYTES or utf8_length(version, _MAX_PROTOCOL_STRING_BYTES) is None:
        return "INVALID_INPUT", None
    if version != _EXPECTED_VERSION[kind]:
        return "UNSUPPORTED_VERSION", None
    required = _OUTER_KEYS[kind]
    optional = ("binding",) if kind == "AUTHORIZE" else ()
    if len(keys) < len(required) or len(keys) > len(required) + len(optional):
        return "INVALID_INPUT", None
    for key in required:
        if key not in keys:
            return "INVALID_INPUT", None
    body: Rec = {}
    for key in keys:
        if key not in required and key not in optional:
            return "INVALID_INPUT", None
        body[key] = value[key]
    try:
        return "CAPTURED", capture_value(body)
    except CanonicalError as error:
        if error.limit:
            return "INVALID_INPUT", None
        # A malformed value inside the history is a schema failure of the state, not of the caller's request.
        if error.location == "$.events" or error.location.startswith("$.events["):
            return "STATE_NOT_AUTHORITATIVE", None
        raise TypeError(error.reason) from error


def _detect_legacy(events: Any) -> bool:
    if not isinstance(events, list) or not events or not _is_record(events[0]) or not _is_record(events[0].get("data")):
        return True
    versions = events[0]["data"].get("versions")
    return not _is_record(versions) or versions.get("eventSchemaVersion") != "irontrellis-event/1"


def _replay_indeterminate(result: ReplayResult) -> Rec:
    code = "UNSUPPORTED_VERSION" if result.code in ("UNSUPPORTED_VERSION", "UNSUPPORTED_EVENT_SCHEMA", "UNSUPPORTED_EVENT_TYPE") else "STATE_NOT_AUTHORITATIVE"
    return indeterminate(AUTHORIZATION_VERSION, code)


def authorize_portable(value: Any, replay_fn: Any = None) -> Rec:
    """Spec 02 §2.3: capture, structural check, replay, then :func:`authorize_state`."""
    from .replay import replay as default_replay

    status, body = capture_authority_operation(value, "AUTHORIZE")
    if body is None:
        return indeterminate(AUTHORIZATION_VERSION, status)
    legacy = _detect_legacy(body.get("events"))
    if not isinstance(body.get("events"), list) or body.get("authoritative") is not True or not _body_is_structurally_valid(body, legacy):
        return indeterminate(AUTHORIZATION_VERSION, "INVALID_INPUT")
    replayed = (replay_fn or default_replay)(body["events"])
    if not replayed.accepted:
        return _replay_indeterminate(replayed)
    return authorize_state(replayed.state, body)


# ---------------------------------------------------------------- intent admission transition (spec 02 §7.4)


def validate_intent_admission_transition(state: Any, event: Rec, position: int, next_head: Rec) -> Any:
    """Replay-side validation of a stored admission at its exact pre-event state; returns ``(admission, usage)`` or a reason."""
    if event["type"] != "TRANSACTION_INTENT_ADMITTED":
        return "not an admission"
    data = event["data"]
    proof = data.get("authorizationProof")
    if not _is_record(proof) or not _is_record(proof.get("request")) or not _is_record(proof.get("historyHead")) or not isinstance(proof.get("controllingAuthorityIds"), list):
        return "proof malformed"
    if (event["timestamp"] != data["evaluationTime"] or data["evaluationTime"] != proof["evaluationTime"] or data["intentId"] != proof.get("intentId")
            or not _is_record(data["expectedHistoryHead"]) or not _same_head(data["expectedHistoryHead"], state.head) or not _same_head(proof["historyHead"], state.head)
            or proof["consequential"] is not True or proof["rootRecognitionPolicy"] != ROOT_RECOGNITION_POLICY):
        return "admission does not bind the pre-event head and proof"
    runtime_signature = data["runtimeSignature"]
    if not _signature_shape_valid(runtime_signature, _is_legacy(state)):
        return "runtime signature malformed"
    if (not is_identifier(proof.get("runtimeSessionId")) or not is_identifier(proof.get("credentialKeyId")) or not is_u53(proof.get("controlEpoch"))
            or not is_identifier(proof.get("roleId")) or not is_identifier(proof.get("roleTenureId")) or not is_identifier(proof.get("intentId")) or not is_identifier(proof.get("nonce"))):
        return "proof runtime fields incomplete"
    binding = {"runtimeSessionId": proof["runtimeSessionId"], "credentialKeyId": proof["credentialKeyId"], "controlEpoch": proof["controlEpoch"], "roleId": proof["roleId"],
               "roleTenureId": proof["roleTenureId"], "intentId": proof["intentId"], "nonce": proof["nonce"], "runtimeSignature": runtime_signature}
    challenge = create_runtime_authorization_challenge(proof["domain"], proof["request"], proof["evaluationTime"], proof["policyVersion"], state.head, binding)
    if data["runtimeAuthorizationHash"] != hash_runtime_authorization_challenge(challenge, state.hash_algorithm):
        return "runtime authorization hash mismatch"
    actor, session = state.agents.get(proof["request"]["actorId"]), state.runtime_sessions.get(proof["runtimeSessionId"])
    if actor is None or session is None or session.agent_id != actor.id or session.credential_key_id != proof["credentialKeyId"]:
        return "session does not belong to the actor"
    if not verify_runtime_authorization_signature(session, challenge, runtime_signature, state.hash_algorithm):
        return "runtime signature does not verify"
    authorization = authorize_state(state, {
        "expectedHistoryHead": state.head, "domain": proof["domain"], "policyVersion": proof["policyVersion"], "rootRecognitionPolicy": proof["rootRecognitionPolicy"],
        "request": proof["request"], "evaluationTime": proof["evaluationTime"], "consequential": True, "binding": binding,
    })
    if authorization["decision"] != "ALLOW":
        return f"re-authorization {authorization['decision']} {authorization.get('code')}"
    if canonical_encode(authorization["proof"]) != canonical_encode(proof):
        return "stored proof differs from the derived proof"
    declaration = state.intent_declarations.get(proof["intentId"])
    if declaration is None or not same_intent(declaration, intent_projection(proof["request"], binding, declaration["adapterProfile"])):
        return "declaration mismatch"
    if proof["intentId"] in state.intent_admissions:
        return "intent already admitted"
    reservations = state.nonce_reservations_by_actor.get(proof["request"]["actorId"])
    if reservations is not None and proof["nonce"] in reservations:
        return "nonce already reserved"
    usage: list[Rec] = []
    amount = proof["request"].get("amount")
    for authority_id in proof["controllingAuthorityIds"]:
        authority = state.authorities.get(authority_id)
        if authority is None or authority.grant["kind"] != "PERMISSION":
            return "controlling authority is not a permission"
        c = authority.grant["constraints"]
        max_transactions, max_cumulative = c.get("maxTransactions"), c.get("maxCumulativeAmount")
        if max_transactions is None and max_cumulative is None:
            continue
        current = state.authority_usage.get(authority_id)
        if current is None or (max_cumulative is not None and amount is None):
            return "usage record unavailable"
        count = current["admittedTransactionCount"] + (0 if max_transactions is None else 1)
        cumulative = current["admittedCumulativeAmount"] + (BigInt(0) if max_cumulative is None else amount)
        if (count > 2**53 - 1 or (max_transactions is not None and count > max_transactions) or (max_cumulative is not None and cumulative > max_cumulative)
                or cumulative.value > MAX_PROTOCOL_BIGINT):
            return "capacity exceeded"
        usage.append({"authorityId": authority_id, "admittedTransactionCount": count, "admittedCumulativeAmount": cumulative})
    admission = IntentAdmissionRecord(
        proof["intentId"], proof["request"]["actorId"], proof["nonce"], event["id"], position, next_head, proof["runtimeSessionId"], proof["credentialKeyId"],
        proof["controlEpoch"], proof["roleId"], proof["roleTenureId"],
        derive_adapter_identity_for_accepted_admission(event, next_head, declaration["adapterProfile"], state.genesis["adapterPolicyHash"]))
    return admission, usage


# ---------------------------------------------------------------- administrative authorization (spec 03 §I)

_ADMINISTRATIVE_TYPES = frozenset(("OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED", "OUTCOME_OBSERVATION_RECORDED",
                                   "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED"))


def administrative_transition_effect(event: Rec) -> Rec:
    """Spec 03 §I.1: the event's data minus the wrapper, with ``transitionEventType`` first."""
    d = event["data"]
    keys = {
        "OUTCOME_OBSERVATION_RECORDED": ("intentId", "sourceAdmissionEventId", "acknowledgment", "actorId"),
        "ATTEMPT_DUTY_CREATED": ("record", "actorId"), "OBLIGATION_CREATED": ("record", "actorId"),
        "ATTEMPT_DUTY_REVIEW_CLOSED": ("dutyId", "actorId", "observationEventIds", "summaryDigest"),
        "ATTEMPT_DUTY_ASSIGNED": ("dutyId", "fromAgentId", "toAgentId", "actorId"),
        "OBLIGATION_PERFORMANCE_ASSIGNED": ("obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId"),
        "OBLIGATION_STATUS_RECORDED": ("obligationId", "fromStatus", "toStatus", "actorId", "action", "attesterId", "evidenceReference"),
    }.get(event["type"])
    if keys is None:
        raise TypeError("Event is not a supported administrative transition.")
    out: Rec = {"transitionEventType": event["type"]}
    for key in keys:
        out[key] = d[key]
    return out


def create_administrative_policy_proof(state: Any, requirements: AdministrativeRequirements, evaluation_time: int) -> Rec | None:
    """Spec 03 §I.2 / spec 02 §7.5: a non-consequential proof restricted to the required principal and authorities."""
    if "amount" in requirements.request:
        return None
    body = {"expectedHistoryHead": state.head, "domain": state.genesis["domain"], "policyVersion": state.genesis["policyVersion"],
            "rootRecognitionPolicy": state.genesis["rootRecognitionPolicy"], "request": requirements.request, "evaluationTime": evaluation_time, "consequential": False}
    if not _body_is_structurally_valid(body, _is_legacy(state)):
        return None
    candidate = _stage(state, body, requirements)
    if not isinstance(candidate, Candidate):
        return None
    assert candidate.evaluation.graph is not None
    # The restriction applies to the canonical winner: a capped winner never falls through to another candidate.
    for g in _graph_grants(candidate.evaluation.graph):
        c = g["constraints"]
        if c["quantitative"] or "maxAmount" in c or "maxCumulativeAmount" in c or "maxTransactions" in c:
            return None
    authorization = _finalize_candidate(candidate)
    if (authorization["decision"] != "ALLOW" or authorization["scopeAssurance"] != "REPLAY_VERIFIED" or authorization["consequential"]
            or len(authorization["proof"]["usageSnapshot"]) != 0):
        return None
    return authorization["proof"]


def validate_administrative_transition(state: Any, event: Rec, _position: int, req: AdministrativeRequirements) -> str | None:
    """Spec 03 §I.3; ``req`` is supplied by the reducer that already resolved the records. None on success."""
    if event["type"] not in _ADMINISTRATIVE_TYPES:
        return "not an administrative event"
    policy = state.genesis["adapterPolicyHash"]
    attempt_type = event["type"] in ("OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED")
    if attempt_type and policy not in (ADAPTER_POLICY_E5_HASH, ADAPTER_POLICY_E6_HASH):
        return "adapter policy edition lacks attempt duties"
    if event["type"] == "ATTEMPT_DUTY_REVIEW_CLOSED" and policy != ADAPTER_POLICY_E6_HASH:
        return "adapter policy edition lacks duty review"
    wrapper = event["data"].get("administrativeAuthorization")
    if not _is_record(wrapper) or not _is_record(wrapper.get("challenge")) or not _is_record(wrapper.get("authorityProof")):
        return "administrative authorization malformed"
    challenge, proof = wrapper["challenge"], wrapper["authorityProof"]
    if not _is_record(challenge.get("request")) or not _is_record(challenge.get("domain")) or not _is_record(proof.get("domain")):
        return "challenge malformed"
    if (canonical_encode(challenge["domain"]) != canonical_encode(state.genesis["domain"]) or canonical_encode(proof["domain"]) != canonical_encode(state.genesis["domain"])
            or canonical_encode(challenge["request"]) != canonical_encode(req.request) or challenge["request"].get("actorId") != event["data"].get("actorId")
            or challenge.get("policyVersion") != state.genesis["policyVersion"] or challenge.get("rootRecognitionPolicy") != state.genesis["rootRecognitionPolicy"]
            or challenge.get("eventHistoryHash") != state.head["hash"] or challenge.get("eventHistoryPosition") != state.head["position"]
            or challenge.get("evaluationTime") != event["timestamp"] or challenge.get("transitionEventId") != event["id"] or challenge.get("transitionEventType") != event["type"]
            or challenge.get("transitionEffectHash") != hash_canonical(administrative_transition_effect(event), state.hash_algorithm)
            or challenge.get("authorityProofHash") != hash_canonical(proof, state.hash_algorithm)
            or challenge.get("roleId") != req.role_id or challenge.get("roleTenureId") != req.role_tenure_id):
        return "challenge does not bind the event, head and requirements"
    actor = state.agents.get(req.request["actorId"])
    session = state.runtime_sessions.get(challenge["runtimeSessionId"]) if isinstance(challenge.get("runtimeSessionId"), str) else None
    role, tenure = state.roles.get(req.role_id), state.tenures.get(req.role_tenure_id)
    if (actor is None or actor.terminated or session is None or session.agent_id != actor.id
            or (session.expires_at is not None and event["timestamp"] >= session.expires_at) or session.credential_key_id != challenge.get("credentialKeyId")
            or session.control_epoch != challenge.get("controlEpoch") or actor.current_control_epoch != challenge.get("controlEpoch") or role is None
            or role.current_tenure_id != req.role_tenure_id or tenure is None or tenure.closed or tenure.role_id != req.role_id or tenure.agent_id != actor.id):
        return "control tuple is not current"
    if not _verify_session_signature(session, hash_canonical(challenge, state.hash_algorithm), wrapper.get("runtimeSignature")):
        return "administrative signature does not verify"
    expected = create_administrative_policy_proof(state, req, event["timestamp"])
    if expected is None or canonical_encode(expected) != canonical_encode(proof):
        return "authority proof differs from the derived policy proof"
    return None
