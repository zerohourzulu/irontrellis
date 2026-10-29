"""Replay state model and the per-type transitions (spec 01 §D.4, §D.7, §D.8, §D.10–D.13; spec 03 §K).

The state is mutated in place by the reducer in ``replay.py``; every transition
checks all of its preconditions before writing, so a rejected event leaves the
state untouched. Records inside the maps are replaced, never mutated.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any, Callable

from .adapters import (
    REMOTE_SERVICE_REPORT_ADAPTER_ID, SIMULATED_ADAPTER_ID, evaluate_adapter_acknowledgment, evaluate_adapter_no_effect,
    policy_enables_attempt_duties, policy_enables_attempt_reviews, resolve_adapter_policy, same_adapter_evidence, validate_adapter_acknowledgment,
    validate_adapter_profile_for_policy,
)
from .canonical import BigInt, canonical_encode
from .events import MAX_BOUND_WITNESSES, control_effect, hash_algorithm_of, session_credential
from .hashing import LEGACY_FORMAT, TRELLIS_FORMAT, HistoryHasher, hash_canonical
from .owner_keys import owner_key_event_transition
from .transparency import verify_witness_receipt

Result = str | None  # None = accepted, otherwise the reason
Head = dict[str, Any]


@dataclass(frozen=True)
class PrincipalRecord:
    id: str
    creation_event_id: str
    creation_event_position: int


@dataclass(frozen=True)
class AgentRecord:
    id: str
    principal_id: str
    controller_id: str
    current_control_epoch: int
    terminated: bool


@dataclass(frozen=True)
class RoleRecord:
    id: str
    principal_id: str
    latest_tenure_number: int
    current_tenure_id: str | None = None


@dataclass(frozen=True)
class SuccessionLock:
    agent_id: str
    principal_id: str
    succession_rule_id: str
    role_id: str
    role_tenure_id: str


@dataclass(frozen=True)
class RoleTenureRecord:
    id: str
    role_id: str
    agent_id: str
    principal_id: str
    tenure_number: int
    closed: bool
    succession_rule_id: str | None = None
    succession_lock: SuccessionLock | None = None


@dataclass(frozen=True)
class RuntimeSessionRecord:
    id: str
    agent_id: str
    controller_id: str
    control_epoch: int
    credential_key_id: str
    credential_address_key: str
    credential_scheme: str
    admission_event_id: str
    admission_event_position: int
    expires_at: int | None = None


@dataclass(frozen=True)
class AuthorityRecord:
    grant: dict[str, Any]
    grant_event_id: str
    grant_event_position: int
    revocation_event_id: str | None = None
    revocation_event_position: int | None = None
    revoker_id: str | None = None


@dataclass(frozen=True)
class IntentAdmissionRecord:
    intent_id: str
    actor_id: str
    nonce: str
    admission_event_id: str
    admission_event_position: int
    admission_head: Head
    runtime_session_id: str
    credential_key_id: str
    control_epoch: int
    role_id: str
    role_tenure_id: str
    adapter_identity: dict[str, Any]


@dataclass(frozen=True)
class NonceReservation:
    intent_id: str
    admission_event_id: str
    admission_event_position: int
    admission_head: Head


@dataclass(frozen=True)
class IntentConsumptionRecord:
    intent_id: str
    event_id: str
    event_position: int
    head: Head
    adapter_id: str
    idempotency_key: str
    submission_fingerprint: str
    transaction_reference: str
    acknowledgment: dict[str, Any]
    evidence_reference: dict[str, Any]


@dataclass(frozen=True)
class OutcomeRecord:
    intent_id: str
    event_id: str
    event_position: int
    head: Head
    status: str
    attester_id: str
    evidence_reference: dict[str, Any]
    no_effect: dict[str, Any] | None = None


@dataclass(frozen=True)
class IntentOutcomeState:
    latest: OutcomeRecord
    terminal: OutcomeRecord | None = None


@dataclass(frozen=True)
class ReceiptCommitmentRecord:
    data: dict[str, Any]
    event_id: str
    event_position: int
    head: Head

    @property
    def intent_id(self) -> str:
        return self.data["intentId"]

    @property
    def receipt_content_hash(self) -> str:
        return self.data["receiptContentHash"]


@dataclass(frozen=True)
class ObligationState:
    record: dict[str, Any]
    status: str
    performance_assignee_id: str
    creation_event_id: str
    creation_event_position: int
    creation_head: Head


@dataclass(frozen=True)
class OutcomeObservationRecord:
    intent_id: str
    source_admission_event_id: str
    acknowledgment: dict[str, Any]
    actor_id: str
    event_id: str
    event_position: int
    observed_at: int


@dataclass(frozen=True)
class AttemptDutyAssignment:
    from_agent_id: str
    to_agent_id: str
    actor_id: str
    event_id: str
    event_position: int
    assigned_at: int


@dataclass(frozen=True)
class AttemptDutyState:
    record: dict[str, Any]
    creation_event_id: str
    creation_event_position: int
    creation_actor_id: str
    current_assignee_id: str
    assignments: tuple[AttemptDutyAssignment, ...]


@dataclass(frozen=True)
class AttemptDutyReview:
    duty_id: str
    actor_id: str
    observation_event_ids: list[str]
    summary_digest: str
    event_id: str
    event_position: int
    reviewed_at: int


@dataclass(frozen=True)
class AnchorRecord:
    head: Head
    anchor: str
    event_id: str
    event_position: int


@dataclass(frozen=True)
class AdministrativeRequirements:
    request: dict[str, Any]
    required_principal_id: str
    required_authority_ids: list[str]
    role_id: str
    role_tenure_id: str


EMPTY_HEAD: Head = {"hash": "0x" + "0" * 64, "position": 0, "canonicalTime": 0}


class ReplayState:
    """The mutable replay state; ``events`` and the hash lists grow in lockstep with ``head``.

    A migrated format-1 history additionally carries a legacy ``shadow`` view (see
    :class:`ShadowContext`) sharing every map with the real state."""

    def __init__(self, history_format: str) -> None:
        self.format = history_format
        self.hash_algorithm = hash_algorithm_of(history_format)
        self.signature_scheme = "eip191-personal-sign-keccak256"
        self.events: list[dict[str, Any]] = []
        self.event_history_hashes: list[str] = []
        self.event_positions_by_id: dict[str, int] = {}
        self.head: Head = EMPTY_HEAD
        self.genesis: dict[str, Any] = {}
        self.hasher = HistoryHasher(history_format)
        self.last_timestamp: int | None = None
        self.principals: dict[str, PrincipalRecord] = {}
        self.agents: dict[str, AgentRecord] = {}
        self.reserved_agent_ids: dict[str, set[str]] = {}
        self.roles: dict[str, RoleRecord] = {}
        self.succession_rules: dict[str, dict[str, Any]] = {}
        self.tenures: dict[str, RoleTenureRecord] = {}
        self.current_tenure_ids_by_agent: dict[str, set[str]] = {}
        self.runtime_sessions: dict[str, RuntimeSessionRecord] = {}
        self.runtime_session_ids_by_agent: dict[str, list[str]] = {}
        self.credential_key_ids: set[str] = set()
        self.credential_address_keys_by_agent: dict[str, set[str]] = {}
        self.intent_declarations: dict[str, dict[str, Any]] = {}
        self.intent_admissions: dict[str, IntentAdmissionRecord] = {}
        self.intent_consumptions: dict[str, IntentConsumptionRecord] = {}
        self.intent_outcome_states: dict[str, IntentOutcomeState] = {}
        self.outcome_observations: dict[str, list[OutcomeObservationRecord]] = {}
        self.attempt_duties: dict[str, AttemptDutyState] = {}
        self.attempt_duty_reviews: dict[str, list[AttemptDutyReview]] = {}
        self.attempt_duty_ids_by_source_intent: dict[str, str] = {}
        self.receipt_commitments: dict[str, ReceiptCommitmentRecord] = {}
        self.obligations: dict[str, ObligationState] = {}
        self.obligation_ids_by_source_intent: dict[str, str] = {}
        self.nonce_reservations_by_actor: dict[str, dict[str, NonceReservation]] = {}
        self.authorities: dict[str, AuthorityRecord] = {}
        self.recognized_roots: dict[str, dict[str, Any]] = {}
        self.authority_usage: dict[str, dict[str, Any]] = {}
        self.anchors: list[AnchorRecord] = []
        # Format 1: the owner key sets in force, oldest first ({"fromPosition", "keys"}); read through owner_keys_at.
        self.owner_key_epochs: list[dict[str, Any]] = []
        # Format 1: the remote witnesses the history binds (WITNESSES_BOUND / WITNESSES_UNBOUND applied in turn), in binding
        # order: {"url", "verifierKey", "name"?, "allowInsecureHttp"?, "registration"?: {"receipt", "index"}, "eventId", "eventPosition"}.
        # Replaced (never mutated) by each binding event.
        self.bound_witnesses: list[dict[str, Any]] = []
        # Format 1: the owner-signed witness policy minimum of the newest binding event, or None.
        self.bound_policy: dict[str, Any] | None = None
        self.declaration_positions: dict[str, int] = {}
        self.shadow: ShadowContext | None = None
        self.shadow_hashes: list[str] | None = None
        self.memo: Any = None  # the authority engine's per-state cache


class ShadowView:
    """A view of a migrated state whose head, domain, genesis, format and hash algorithm
    are the legacy source's; every map is the real state's (docs/HISTORY-FORMAT.md §11)."""

    def __init__(self, base: ReplayState, head: Head, genesis: dict[str, Any], hashes: list[str]) -> None:
        object.__setattr__(self, "_base", base)
        object.__setattr__(self, "head", head)
        object.__setattr__(self, "genesis", genesis)
        object.__setattr__(self, "format", LEGACY_FORMAT)
        object.__setattr__(self, "hash_algorithm", hash_algorithm_of(LEGACY_FORMAT))
        object.__setattr__(self, "signature_scheme", genesis["versions"]["signatureScheme"])
        object.__setattr__(self, "event_history_hashes", hashes)
        object.__setattr__(self, "memo", None)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._base, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("head", "memo"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._base, name, value)


@dataclass
class ShadowContext:
    view: ShadowView
    hasher: HistoryHasher
    hashes: list[str]
    until: int
    expected_hash: str


def _open_shadow(state: ReplayState, migrated: dict[str, Any]) -> None:
    if migrated["position"] == 0:
        return
    hasher = HistoryHasher(LEGACY_FORMAT)
    hash_ = hasher.push({"id": migrated["genesisEventId"], "type": "DEPLOYMENT_INITIALIZED", "timestamp": migrated["genesisTimestamp"], "data": migrated["genesis"]})
    hashes = [hash_]
    view = ShadowView(state, {"hash": hash_, "position": 0, "canonicalTime": migrated["genesisTimestamp"]}, migrated["genesis"], hashes)
    state.shadow = ShadowContext(view, hasher, hashes, migrated["position"], migrated["historyHash"])
    state.shadow_hashes = hashes


# ---------------------------------------------------------------- small helpers


def _active_agent(s: ReplayState, agent_id: str) -> AgentRecord | None:
    agent = s.agents.get(agent_id)
    return None if agent is None or agent.terminated else agent


def _endpoint_exists(s: ReplayState, identifier: str) -> bool:
    return identifier in s.principals or identifier in s.agents


def _permission(s: ReplayState, authority_id: Any) -> dict[str, Any] | None:
    record = s.authorities.get(authority_id)
    return record.grant if record is not None and record.grant["kind"] == "PERMISSION" else None


def _add_to_set(mapping: dict[str, set[str]], key: str, member: str) -> None:
    mapping.setdefault(key, set()).add(member)


def _strictly_sorted(ids: list[str]) -> bool:
    return len(ids) > 0 and all(ids[i - 1] < ids[i] for i in range(1, len(ids)))


# ---------------------------------------------------------------- tenures


def _open_tenure(s: ReplayState, role_id: str, agent_id: str, tenure_id: str, tenure_number: int, principal_id: str, succession_rule_id: str | None) -> None:
    role = s.roles[role_id]
    tenure = RoleTenureRecord(tenure_id, role_id, agent_id, principal_id, tenure_number, False, succession_rule_id)
    s.tenures[tenure_id] = tenure
    s.roles[role.id] = replace(role, current_tenure_id=tenure_id, latest_tenure_number=tenure_number)
    _add_to_set(s.current_tenure_ids_by_agent, agent_id, tenure_id)


def _close_tenure(s: ReplayState, role: RoleRecord, tenure: RoleTenureRecord) -> None:
    s.tenures[tenure.id] = replace(tenure, closed=True)
    s.roles[role.id] = RoleRecord(role.id, role.principal_id, role.latest_tenure_number)
    current = s.current_tenure_ids_by_agent.get(tenure.agent_id)
    if current is not None:
        current.discard(tenure.id)
        if not current:
            del s.current_tenure_ids_by_agent[tenure.agent_id]


# ---------------------------------------------------------------- lifecycle transitions


def _apply_principal_created(s: ReplayState, d: dict[str, Any], event: dict[str, Any], position: int) -> Result:
    principal_id = d["principalId"]
    if principal_id in s.principals or principal_id in s.agents or principal_id in s.reserved_agent_ids:
        return "principal id is not free"
    s.principals[principal_id] = PrincipalRecord(principal_id, event["id"], position)
    return None


def _apply_agent_created(s: ReplayState, d: dict[str, Any]) -> Result:
    if d["agentId"] in s.agents or d["agentId"] in s.principals or d["principalId"] not in s.principals or d["initialControlEpoch"] != 1:
        return "agent cannot be created"
    s.agents[d["agentId"]] = AgentRecord(d["agentId"], d["principalId"], d["controllerId"], 1, False)
    return None


def _apply_role_created(s: ReplayState, d: dict[str, Any]) -> Result:
    if d["roleId"] in s.roles or d["principalId"] not in s.principals:
        return "role cannot be created"
    s.roles[d["roleId"]] = RoleRecord(d["roleId"], d["principalId"], 0)
    return None


def _apply_succession_rule_declared(s: ReplayState, d: dict[str, Any]) -> Result:
    role = s.roles.get(d["roleId"])
    if (d["ruleId"] in s.succession_rules or d["principalId"] not in s.principals or role is None or role.principal_id != d["principalId"]
            or d["predecessorAgentId"] not in s.agents or d["successorAgentId"] in s.principals):
        return "succession rule cannot be declared"
    s.succession_rules[d["ruleId"]] = d
    _add_to_set(s.reserved_agent_ids, d["successorAgentId"], d["ruleId"])
    return None


def _apply_agent_appointed(s: ReplayState, d: dict[str, Any]) -> Result:
    role = s.roles.get(d["roleId"])
    rule_id = d.get("successionRuleId")
    if (_active_agent(s, d["agentId"]) is None or role is None or role.current_tenure_id is not None or role.principal_id != d["principalId"]
            or d["roleTenureId"] in s.tenures or d["tenureNumber"] != role.latest_tenure_number + 1):
        return "appointment preconditions failed"
    if rule_id is not None:
        rule = s.succession_rules.get(rule_id)
        if rule is None or rule["predecessorAgentId"] != d["agentId"] or rule["roleId"] != d["roleId"] or rule["principalId"] != d["principalId"]:
            return "succession rule does not match"
    _open_tenure(s, d["roleId"], d["agentId"], d["roleTenureId"], d["tenureNumber"], d["principalId"], rule_id)
    return None


def _apply_agent_unappointed(s: ReplayState, d: dict[str, Any]) -> Result:
    role, tenure = s.roles.get(d["roleId"]), s.tenures.get(d["roleTenureId"])
    if (role is None or tenure is None or role.current_tenure_id != d["roleTenureId"] or tenure.closed or tenure.agent_id != d["agentId"]
            or tenure.role_id != d["roleId"] or role.principal_id != d["principalId"] or tenure.principal_id != d["principalId"] or tenure.succession_lock is not None):
        return "unappointment preconditions failed"
    _close_tenure(s, role, tenure)
    return None


def _apply_role_transferred(s: ReplayState, d: dict[str, Any]) -> Result:
    role, tenure = s.roles.get(d["roleId"]), s.tenures.get(d["fromRoleTenureId"])
    lock = None if tenure is None else tenure.succession_lock
    rule_id = d.get("successionRuleId")
    if (role is None or tenure is None or role.current_tenure_id != d["fromRoleTenureId"] or tenure.closed or tenure.agent_id != d["fromAgentId"]
            or tenure.role_id != d["roleId"] or role.principal_id != d["principalId"] or _active_agent(s, d["toAgentId"]) is None
            or d["toRoleTenureId"] in s.tenures or d["toTenureNumber"] != role.latest_tenure_number + 1):
        return "transfer preconditions failed"
    if d["transferKind"] == "REASSIGNMENT":
        if rule_id is not None or lock is not None:
            return "reassignment cannot carry a succession rule or lock"
    else:
        if rule_id is None or lock is None:
            return "succession requires a rule and a locked tenure"
        rule = s.succession_rules.get(rule_id)
        if (lock.agent_id != d["fromAgentId"] or lock.principal_id != d["principalId"] or lock.succession_rule_id != rule_id or lock.role_id != d["roleId"]
                or lock.role_tenure_id != d["fromRoleTenureId"] or rule is None or rule["predecessorAgentId"] != d["fromAgentId"] or rule["successorAgentId"] != d["toAgentId"]
                or rule["roleId"] != d["roleId"] or rule["principalId"] != d["principalId"] or "ROLE_TRANSFERRED" not in rule["permittedEventTypes"]):
            return "succession rule does not match the lock"
    _close_tenure(s, role, tenure)
    # The new tenure carries no rule: only an appointment-declared rule constrains a later termination.
    _open_tenure(s, d["roleId"], d["toAgentId"], d["toRoleTenureId"], d["toTenureNumber"], d["principalId"], None)
    return None


def _apply_runtime_session_admitted(s: ReplayState, event: dict[str, Any], position: int) -> Result:
    d = event["data"]
    agent = _active_agent(s, d["agentId"])
    scheme, key = session_credential(d, s.format)
    used_keys = s.credential_address_keys_by_agent.get(d["agentId"], set())
    if (agent is None or d["controllerId"] != agent.controller_id or d["controlEpoch"] != agent.current_control_epoch or d["sessionId"] in s.runtime_sessions
            or d["credentialKeyId"] in s.credential_key_ids or key in used_keys):
        return "session admission preconditions failed"
    for session_id in s.runtime_session_ids_by_agent.get(d["agentId"], []):
        prior = s.runtime_sessions[session_id]
        # At most one unexpired session per agent per epoch; a session expires at `expiresAt` inclusive.
        if prior.control_epoch == agent.current_control_epoch and (prior.expires_at is None or event["timestamp"] < prior.expires_at):
            return "agent already has a live session in this epoch"
    session = RuntimeSessionRecord(d["sessionId"], d["agentId"], d["controllerId"], d["controlEpoch"], d["credentialKeyId"], key, scheme, event["id"], position, d.get("expiresAt"))
    s.runtime_sessions[session.id] = session
    s.credential_key_ids.add(session.credential_key_id)
    used_keys.add(key)
    s.credential_address_keys_by_agent[d["agentId"]] = used_keys
    s.runtime_session_ids_by_agent.setdefault(d["agentId"], []).append(session.id)
    return None


def _apply_control_epoch_advanced(s: ReplayState, d: dict[str, Any]) -> Result:
    agent = _active_agent(s, d["agentId"])
    if (agent is None or d["controllerId"] != agent.controller_id or d["fromEpoch"] != agent.current_control_epoch or d["toEpoch"] != d["fromEpoch"] + 1
            or d["fromEpoch"] + 1 > 2**53 - 1):
        return "epoch advance preconditions failed"
    s.agents[agent.id] = replace(agent, current_control_epoch=d["toEpoch"])
    return None


def _apply_agent_terminated(s: ReplayState, d: dict[str, Any]) -> Result:
    agent, role, tenure = _active_agent(s, d["agentId"]), s.roles.get(d["roleId"]), s.tenures.get(d["roleTenureId"])
    rule, current = s.succession_rules.get(d["successionRuleId"]), s.current_tenure_ids_by_agent.get(d["agentId"])
    tenure_rule_id = None if tenure is None else tenure.succession_rule_id
    if (agent is None or role is None or tenure is None or rule is None or current is None or len(current) != 1 or d["roleTenureId"] not in current
            or role.current_tenure_id != d["roleTenureId"] or tenure.closed or tenure.agent_id != d["agentId"] or tenure.role_id != d["roleId"]
            or agent.principal_id != d["principalId"] or role.principal_id != d["principalId"] or rule["principalId"] != d["principalId"]
            or rule["predecessorAgentId"] != d["agentId"] or rule["roleId"] != d["roleId"] or "AGENT_TERMINATED" not in rule["permittedEventTypes"]
            or (tenure_rule_id is not None and tenure_rule_id != d["successionRuleId"])):
        return "termination preconditions failed"
    s.agents[agent.id] = replace(agent, terminated=True)
    lock = SuccessionLock(d["agentId"], d["principalId"], d["successionRuleId"], d["roleId"], d["roleTenureId"])
    s.tenures[tenure.id] = replace(tenure, succession_lock=lock)
    return None


# ---------------------------------------------------------------- authority transitions (spec 01 §D.7, §D.8)


def _interval_valid(c: dict[str, Any]) -> bool:
    return "notBefore" not in c or "expiresAt" not in c or c["notBefore"] < c["expiresAt"]


def _subset(child: list[str], parent: list[str]) -> bool:
    return all(member in parent for member in child)


def _ceiling_attenuated(parent: Any, child: Any, child_may_exceed: bool) -> bool:
    return parent is None or (child is not None and (child >= parent if child_may_exceed else child <= parent))


def constraints_are_attenuated(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    return (_interval_valid(child) and _subset(child["actions"], parent["actions"]) and _subset(child["resources"], parent["resources"])
            and _subset(parent["requiredIntersectionIds"], child["requiredIntersectionIds"]) and parent["maxDelegationDepth"] != 0
            and child["maxDelegationDepth"] <= parent["maxDelegationDepth"] - 1 and not (parent["quantitative"] and not child["quantitative"])
            and _ceiling_attenuated(parent.get("notBefore"), child.get("notBefore"), True) and _ceiling_attenuated(parent.get("expiresAt"), child.get("expiresAt"), False)
            and _ceiling_attenuated(parent.get("maxAmount"), child.get("maxAmount"), False)
            and _ceiling_attenuated(parent.get("maxCumulativeAmount"), child.get("maxCumulativeAmount"), False)
            and _ceiling_attenuated(parent.get("maxTransactions"), child.get("maxTransactions"), False))


def _within_path_limit(s: ReplayState, parent_authority_id: str) -> bool:
    depth = 2
    current = _permission(s, parent_authority_id)
    while current is not None:
        if depth > 32:
            return False
        if current.get("parentAuthorityId") is None:
            return True
        depth += 1
        current = _permission(s, current.get("parentAuthorityId"))
    return False


def _apply_authority_granted(s: ReplayState, grant: dict[str, Any], event: dict[str, Any], position: int) -> Result:
    if grant["authorityId"] in s.authorities or not _interval_valid(grant["constraints"]):
        return "authority id used or interval invalid"
    if grant["kind"] == "PERMISSION":
        if not _endpoint_exists(s, grant["grantorId"]) or not _endpoint_exists(s, grant["granteeId"]):
            return "grantor or grantee unknown"
        if not all(_permission(s, identifier) is not None for identifier in grant["constraints"]["requiredIntersectionIds"]):
            return "required intersection is not a permission"
        parent_id = grant.get("parentAuthorityId")
        if parent_id is None:
            if grant["grantorId"] not in s.principals:
                return "root grantor must be a principal"
        else:
            parent = _permission(s, parent_id)
            if (parent is None or not _within_path_limit(s, parent_id) or grant["grantorId"] != parent["granteeId"] or grant["rootAuthorityId"] != parent["rootAuthorityId"]
                    or not constraints_are_attenuated(parent["constraints"], grant["constraints"])):
                return "delegation is not attenuated from its parent"
    else:
        c = grant["constraints"]
        if not (_interval_valid(c) and len(c["requiredIntersectionIds"]) == 0 and c["maxDelegationDepth"] == 0 and "maxCumulativeAmount" not in c and "maxTransactions" not in c):
            return "prohibition constraints invalid"
        subject = grant.get("subjectActorId")
        if subject is not None and subject not in s.agents:
            return "prohibition subject unknown"
        if grant["scope"] == "GLOBAL":
            if grant["grantorId"] != s.genesis["globalPolicySourceId"]:
                return "global prohibition grantor is not the policy source"
        else:
            if not _endpoint_exists(s, grant["grantorId"]):
                return "prohibition grantor unknown"
            root = s.recognized_roots.get(grant["rootAuthorityId"])
            if root is None:
                return "prohibition root not recognized"
            parent_id = grant.get("parentAuthorityId")
            if grant["grantorId"] == root["principalId"]:
                root_grant = _permission(s, root["rootAuthorityId"])
                if parent_id is not None or root_grant is None or not constraints_are_attenuated(root_grant["constraints"], c):
                    return "root prohibition not attenuated"
            else:
                parent = None if parent_id is None else _permission(s, parent_id)
                if (parent is None or parent["rootAuthorityId"] != grant["rootAuthorityId"] or parent["granteeId"] != grant["grantorId"]
                        or not constraints_are_attenuated(parent["constraints"], c)):
                    return "delegated prohibition not attenuated"
    s.authorities[grant["authorityId"]] = AuthorityRecord(grant, event["id"], position)
    if grant["kind"] == "PERMISSION":
        if grant.get("parentAuthorityId") is None and grant["authorityId"] == grant["rootAuthorityId"]:
            principal = s.principals.get(grant["grantorId"])
            if principal is not None:
                s.recognized_roots[grant["rootAuthorityId"]] = {
                    "rootAuthorityId": grant["rootAuthorityId"], "principalId": principal.id,
                    "principalRecognitionEventId": principal.creation_event_id, "rootGrantEventId": event["id"],
                }
        if "maxTransactions" in grant["constraints"] or "maxCumulativeAmount" in grant["constraints"]:
            s.authority_usage[grant["authorityId"]] = {"authorityId": grant["authorityId"], "admittedTransactionCount": 0, "admittedCumulativeAmount": BigInt(0)}
    return None


def _apply_authority_revoked(s: ReplayState, d: dict[str, Any], event: dict[str, Any], position: int) -> Result:
    record = s.authorities.get(d["authorityId"])
    if record is None or record.revocation_event_id is not None:
        return "authority unknown or already revoked"
    grant = record.grant
    permitted = False
    if grant["kind"] == "PROHIBITION" and grant["scope"] == "GLOBAL":
        permitted = d["revokerId"] == s.genesis["globalPolicySourceId"]
    else:
        root = s.recognized_roots.get(grant["rootAuthorityId"])
        if root is not None:
            permitted = d["revokerId"] == root["principalId"] or (grant.get("parentAuthorityId") is not None and d["revokerId"] == grant["grantorId"])
    if not permitted:
        return "revoker is not permitted"
    s.authorities[d["authorityId"]] = replace(record, revocation_event_id=event["id"], revocation_event_position=position, revoker_id=d["revokerId"])
    return None


# ---------------------------------------------------------------- intents, admissions, consumptions, outcomes, receipts


def _apply_intent_declared(s: ReplayState, d: dict[str, Any], position: int) -> Result:
    if (d["intentId"] in s.intent_declarations or d["actorId"] not in s.agents or d["roleId"] not in s.roles or d["roleTenureId"] not in s.tenures
            or not validate_adapter_profile_for_policy(s.genesis["adapterPolicyHash"], d["adapterProfile"])):
        return "intent declaration preconditions failed"
    s.intent_declarations[d["intentId"]] = d
    s.declaration_positions[d["intentId"]] = position
    return None


def _apply_intent_admitted(s: ReplayState, event: dict[str, Any], position: int, next_head: Head, hooks: ReplayHooks) -> Result:
    validation = hooks.validate_intent_admission_transition(s, event, position, next_head)
    if validation is None:
        return "not an admission"
    if isinstance(validation, str):
        return validation
    admission, usage = validation
    if admission.intent_id in s.intent_admissions:
        return "intent already admitted"
    reservations = s.nonce_reservations_by_actor.get(admission.actor_id)
    if reservations is not None and admission.nonce in reservations:
        return "nonce already reserved"
    if not all(u["authorityId"] in s.authority_usage for u in usage):
        return "usage update for an uncapped authority"
    if admission.intent_id not in s.intent_declarations:
        return "intent not declared"
    actor_reservations = reservations if reservations is not None else {}
    s.intent_admissions[admission.intent_id] = admission
    actor_reservations[admission.nonce] = NonceReservation(admission.intent_id, event["id"], position, next_head)
    s.nonce_reservations_by_actor[admission.actor_id] = actor_reservations
    for update in usage:
        s.authority_usage[update["authorityId"]] = update
    return None


def admission_control_is_current(state: ReplayState, admission: IntentAdmissionRecord, use_time: int) -> bool:
    """spec 01 §D.10: the control tuple bound at admission is still current at ``use_time``."""
    agent, session = state.agents.get(admission.actor_id), state.runtime_sessions.get(admission.runtime_session_id)
    role, tenure = state.roles.get(admission.role_id), state.tenures.get(admission.role_tenure_id)
    expires_at = None if session is None else session.expires_at
    return (agent is not None and not agent.terminated and session is not None and session.agent_id == admission.actor_id
            and session.credential_key_id == admission.credential_key_id and (expires_at is None or use_time < expires_at)
            and session.control_epoch == admission.control_epoch and agent.current_control_epoch == admission.control_epoch and role is not None and tenure is not None
            and role.current_tenure_id == admission.role_tenure_id and not tenure.closed and tenure.role_id == admission.role_id and tenure.agent_id == admission.actor_id)


def earlier_evidence_is_valid(s: ReplayState, e: dict[str, Any]) -> bool:
    """spec 01 §D.12: evidence that cites earlier history must cite it exactly."""
    kind = e.get("kind")
    if kind == "EVENT":
        position = s.event_positions_by_id.get(e.get("eventId"))
        if position is None:
            return False
        event = s.events[position]
        return e.get("position") == position and e.get("eventType") == event["type"] and e.get("historyHash") == s.event_history_hashes[position]
    if kind == "AUTHORITY":
        a = s.authorities.get(e.get("authorityId"))
        return a is not None and e.get("grantEventId") == a.grant_event_id
    if kind == "RUNTIME_CREDENTIAL":
        session = s.runtime_sessions.get(e.get("sessionId"))
        return session is not None and e.get("keyId") == session.credential_key_id and e.get("admissionEventId") == session.admission_event_id
    if kind == "RECEIPT_COMMITMENT":
        receipt = s.receipt_commitments.get(e.get("receiptContentHash"))
        return receipt is not None and receipt.event_id == e.get("eventId") and receipt.event_position == e.get("position")
    return kind == "EXTERNAL"


def _apply_intent_consumed(s: ReplayState, event: dict[str, Any], position: int, next_head: Head) -> Result:
    d = event["data"]
    admission = s.intent_admissions.get(d["intentId"])
    outcome = s.intent_outcome_states.get(d["intentId"])
    if (admission is None or d["intentId"] in s.intent_consumptions or (outcome is not None and outcome.terminal is not None)
            or not admission_control_is_current(s, admission, event["timestamp"])):
        return "consumption preconditions failed"
    identity = admission.adapter_identity
    if d["adapterId"] != identity["adapterProfile"]["profileId"] or d["idempotencyKey"] != identity["idempotencyKey"] or d["submissionFingerprint"] != identity["submissionFingerprint"]:
        return "consumption does not match the admitted identity"
    evaluation = evaluate_adapter_acknowledgment(d["acknowledgment"], identity)
    if evaluation is None:
        return "acknowledgment does not match the admitted identity"
    if d["transactionReference"] != evaluation["transactionReference"]:
        return "transaction reference mismatch"
    if not same_adapter_evidence(d["evidenceReference"], evaluation["evidence"]):
        return "evidence reference mismatch"
    s.intent_consumptions[d["intentId"]] = IntentConsumptionRecord(
        d["intentId"], event["id"], position, next_head, identity["adapterProfile"]["profileId"], d["idempotencyKey"], d["submissionFingerprint"],
        d["transactionReference"], d["acknowledgment"], d["evidenceReference"])
    return None


def _apply_outcome_recorded(s: ReplayState, event: dict[str, Any], position: int, next_head: Head) -> Result:
    d = event["data"]
    admission = s.intent_admissions.get(d["intentId"])
    if admission is None:
        return "intent not admitted"
    existing = s.intent_outcome_states.get(d["intentId"])
    existing_terminal = None if existing is None else existing.terminal
    if existing_terminal is not None and d["status"] != "DISPUTED":
        return "terminal outcome already recorded"
    no_effect = d.get("noEffect")
    if d["status"] == "FAILED":
        evaluation = None if no_effect is None else evaluate_adapter_no_effect(no_effect, admission.adapter_identity)
        if evaluation is None or d["attesterId"] != SIMULATED_ADAPTER_ID or not same_adapter_evidence(d["evidenceReference"], evaluation["evidence"]):
            return "no-effect proof invalid"
    elif no_effect is not None or not earlier_evidence_is_valid(s, d["evidenceReference"]):
        return "outcome evidence invalid"
    record = OutcomeRecord(d["intentId"], event["id"], position, next_head, d["status"], d["attesterId"], d["evidenceReference"], no_effect)
    terminal = existing_terminal if existing_terminal is not None else (record if d["status"] in ("CONFIRMED", "FAILED") else None)
    s.intent_outcome_states[d["intentId"]] = IntentOutcomeState(record, terminal)
    return None


def _apply_receipt_recorded(s: ReplayState, event: dict[str, Any], position: int, head: Head) -> Result:
    d = event["data"]
    # Typed existence only: no issuer/control/admission/artifact congruence is inferred here (spec 01 §G.26).
    if (d["receiptContentHash"] in s.receipt_commitments or d["intentId"] not in s.intent_declarations or d["issuerAgentId"] not in s.agents
            or d["runtimeSessionId"] not in s.runtime_sessions or d["roleId"] not in s.roles or d["roleTenureId"] not in s.tenures):
        return "receipt cites unknown records"
    s.receipt_commitments[d["receiptContentHash"]] = ReceiptCommitmentRecord(d, event["id"], position, head)
    return None


# ---------------------------------------------------------------- obligations (spec 01 §D.7, §D.13; spec 03 §K.1)

_STATUS_RANK = {"OPEN": 0, "OUTCOME_UNKNOWN": 1, "DISPUTED": 2, "DISCHARGED": 3, "IMPOSSIBLE_OR_ESCALATED": 4}


def _unresolved(status: str) -> bool:
    return status not in ("DISCHARGED", "IMPOSSIBLE_OR_ESCALATED")


def _obligation_policies_are_valid(s: ReplayState, policies: list[dict[str, Any]]) -> bool:
    if len(policies) == 0:
        return False
    for index, policy in enumerate(policies):
        if (not _unresolved(policy["fromStatus"]) or not _strictly_sorted(policy["acceptedAttesterIds"]) or not _strictly_sorted(policy["requiredAuthorityIds"])
                or not all(identifier in s.authorities for identifier in policy["requiredAuthorityIds"])):
            return False
        if index == 0:
            continue
        prior = policies[index - 1]
        from_difference = _STATUS_RANK[policy["fromStatus"]] - _STATUS_RANK[prior["fromStatus"]]
        to_difference = _STATUS_RANK[policy["toStatus"]] - _STATUS_RANK[prior["toStatus"]]
        if from_difference < 0 or (from_difference == 0 and to_difference <= 0):
            return False
    return True


def _administrative(s: ReplayState, event: dict[str, Any], position: int, hooks: ReplayHooks, requirements: AdministrativeRequirements) -> Result:
    return hooks.validate_administrative_transition(s, event, position, requirements)


def _apply_obligation_created(s: ReplayState, event: dict[str, Any], position: int, head: Head, hooks: ReplayHooks) -> Result:
    d = event["data"]
    record = d["record"]
    intent, admission = s.intent_declarations.get(record["sourceIntentId"]), s.intent_admissions.get(record["sourceIntentId"])
    consumption, receipt = s.intent_consumptions.get(record["sourceIntentId"]), s.receipt_commitments.get(record["causalReceiptContentHash"])
    role, tenure, rule = s.roles.get(record["durableRoleId"]), s.tenures.get(record["creationRoleTenureId"]), s.succession_rules.get(record["successionRuleId"])
    if (record["obligationId"] in s.obligations or record["obligationId"] in s.attempt_duties or record["sourceIntentId"] in s.obligation_ids_by_source_intent
            or intent is None or admission is None or consumption is None or receipt is None or role is None or tenure is None or rule is None
            or intent["intentId"] != admission.intent_id or intent["intentId"] != consumption.intent_id or intent["intentId"] != receipt.intent_id
            or not (admission.admission_event_position < consumption.event_position < receipt.event_position < position)
            or record["trigger"] != consumption.event_id or record["durableRoleId"] != intent["roleId"] or record["durableRoleId"] != receipt.data["roleId"]
            or record["creationRoleTenureId"] != intent["roleTenureId"] or record["creationRoleTenureId"] != receipt.data["roleTenureId"]
            or role.current_tenure_id != tenure.id or tenure.closed or tenure.role_id != record["durableRoleId"]
            or record["performanceAssigneeId"] != intent["actorId"] or tenure.agent_id != record["performanceAssigneeId"] or d["actorId"] != record["performanceAssigneeId"]
            or intent.get("termsCommitment") != record["termsCommitment"]
            or ("counterpartyId" in intent) != ("counterpartyId" in record) or intent.get("counterpartyId") != record.get("counterpartyId")
            or rule["roleId"] != record["durableRoleId"] or rule["predecessorAgentId"] != record["performanceAssigneeId"] or rule["principalId"] != role.principal_id
            or rule["trigger"] != "AGENT_TERMINATED"
            or not all(t in rule["permittedEventTypes"] for t in ("AGENT_TERMINATED", "ROLE_TRANSFERRED", "OBLIGATION_PERFORMANCE_ASSIGNED"))
            or not _obligation_policies_are_valid(s, record["transitionPolicies"])):
        return "obligation creation preconditions failed"
    declaration_position = s.declaration_positions.get(intent["intentId"])
    if declaration_position is None or declaration_position >= admission.admission_event_position:
        return "declaration does not precede admission"
    # The receipt must commit to the admission's own proof and control tuple (spec 01 §G.27).
    proof = s.events[admission.admission_event_position]["data"]["authorizationProof"]
    rd = receipt.data
    if (rd["authorizationProofHash"] != hash_canonical(proof, s.hash_algorithm) or rd["issuerAgentId"] != proof["request"]["actorId"]
            or rd["runtimeSessionId"] != proof.get("runtimeSessionId") or rd["controlEpoch"] != proof.get("controlEpoch")
            or rd["roleId"] != proof.get("roleId") or rd["roleTenureId"] != proof.get("roleTenureId")):
        return "receipt does not match the admission proof"
    request: dict[str, Any] = {"actorId": d["actorId"], "action": "OBLIGATE", "resource": intent["resource"], "claimedAt": event["timestamp"], "termsCommitment": record["termsCommitment"]}
    if "counterpartyId" in record:
        request["counterpartyId"] = record["counterpartyId"]
    failure = _administrative(s, event, position, hooks, AdministrativeRequirements(request, role.principal_id, [], role.id, tenure.id))
    if failure is not None:
        return failure
    s.obligations[record["obligationId"]] = ObligationState(record, record["status"], record["performanceAssigneeId"], event["id"], position, head)
    s.obligation_ids_by_source_intent[record["sourceIntentId"]] = record["obligationId"]
    return None


def _apply_obligation_performance_assigned(s: ReplayState, event: dict[str, Any], position: int, hooks: ReplayHooks) -> Result:
    d = event["data"]
    obligation = s.obligations.get(d["obligationId"])
    if obligation is None or not _unresolved(obligation.status) or d["fromAgentId"] != obligation.performance_assignee_id or d["successionRuleId"] != obligation.record["successionRuleId"]:
        return "obligation cannot be reassigned"
    record, role, rule = obligation.record, s.roles.get(obligation.record["durableRoleId"]), s.succession_rules.get(d["successionRuleId"])
    tenure = None if role is None or role.current_tenure_id is None else s.tenures.get(role.current_tenure_id)
    if (role is None or rule is None or tenure is None or tenure.closed or tenure.agent_id != d["toAgentId"] or tenure.role_id != record["durableRoleId"]
            or rule["roleId"] != record["durableRoleId"] or rule["principalId"] != role.principal_id or rule["predecessorAgentId"] != d["fromAgentId"]
            or rule["successorAgentId"] != d["toAgentId"] or rule["trigger"] != "AGENT_TERMINATED" or "OBLIGATION_PERFORMANCE_ASSIGNED" not in rule["permittedEventTypes"]):
        return "succession does not cover the reassignment"
    # The spec asks for the *last* matching termination and succession transfer, so the history is scanned (rare event).
    termination_position: int | None = None
    transfer_position: int | None = None
    for p, earlier in enumerate(s.events):
        e = earlier["data"]
        if earlier["type"] == "AGENT_TERMINATED":
            if (e["agentId"] == d["fromAgentId"] and e["principalId"] == rule["principalId"] and e["successionRuleId"] == d["successionRuleId"]
                    and e["roleId"] == record["durableRoleId"] and e["roleTenureId"] == record["creationRoleTenureId"]):
                termination_position = p
        elif earlier["type"] == "ROLE_TRANSFERRED":
            if (e["transferKind"] == "SUCCESSION" and e.get("successionRuleId") == d["successionRuleId"] and e["principalId"] == rule["principalId"]
                    and e["roleId"] == record["durableRoleId"] and e["fromAgentId"] == d["fromAgentId"] and e["fromRoleTenureId"] == record["creationRoleTenureId"]
                    and e["toAgentId"] == d["toAgentId"] and e["toRoleTenureId"] == tenure.id):
                transfer_position = p
    if termination_position is None or transfer_position is None or termination_position >= transfer_position:
        return "no termination followed by succession"
    request = {"actorId": d["actorId"], "action": "ASSIGN_PERFORMANCE", "resource": d["obligationId"], "claimedAt": event["timestamp"]}
    failure = _administrative(s, event, position, hooks, AdministrativeRequirements(request, rule["principalId"], [], role.id, tenure.id))
    if failure is not None:
        return failure
    s.obligations[d["obligationId"]] = replace(obligation, performance_assignee_id=d["toAgentId"])
    return None


def _evidence_attributes_attester(s: ReplayState, evidence: dict[str, Any], attester_id: str) -> bool:
    if evidence.get("kind") == "EXTERNAL":
        return evidence.get("attesterId") == attester_id
    if evidence.get("kind") != "EVENT" or not earlier_evidence_is_valid(s, evidence):
        return False
    data = s.events[evidence["position"]]["data"]
    if data.get("attesterId") == attester_id:
        return True
    direct = data.get("evidenceReference")
    return isinstance(direct, dict) and direct.get("kind") == "EXTERNAL" and direct.get("attesterId") == attester_id


def _apply_obligation_status_recorded(s: ReplayState, event: dict[str, Any], position: int, hooks: ReplayHooks) -> Result:
    d = event["data"]
    obligation = s.obligations.get(d["obligationId"])
    if obligation is None or not _unresolved(obligation.status) or d["fromStatus"] != obligation.status:
        return "obligation status cannot change"
    policy = next((p for p in obligation.record["transitionPolicies"] if p["fromStatus"] == d["fromStatus"] and p["toStatus"] == d["toStatus"] and p["action"] == d["action"]), None)
    if policy is None or d["attesterId"] not in policy["acceptedAttesterIds"] or not _evidence_attributes_attester(s, d["evidenceReference"], d["attesterId"]):
        return "no policy admits this transition"
    role = s.roles.get(obligation.record["durableRoleId"])
    current_tenure_id = None if role is None else role.current_tenure_id
    if role is None or current_tenure_id is None:
        return "role has no current tenure"
    request = {"actorId": d["actorId"], "action": d["action"], "resource": d["obligationId"], "claimedAt": event["timestamp"]}
    failure = _administrative(s, event, position, hooks, AdministrativeRequirements(request, role.principal_id, list(policy["requiredAuthorityIds"]), role.id, current_tenure_id))
    if failure is not None:
        return failure
    s.obligations[d["obligationId"]] = replace(obligation, status=d["toStatus"])
    return None


# ---------------------------------------------------------------- attempt duties (E5/E6, spec 03 §K.2)


@dataclass(frozen=True)
class _AttemptSource:
    intent: dict[str, Any]
    admission: IntentAdmissionRecord
    role: RoleRecord
    tenure: RoleTenureRecord


def _attempt_source(s: ReplayState, intent_id: str) -> _AttemptSource | None:
    if not policy_enables_attempt_duties(s.genesis["adapterPolicyHash"]):
        return None
    intent, admission = s.intent_declarations.get(intent_id), s.intent_admissions.get(intent_id)
    if intent is None or admission is None or admission.adapter_identity["adapterProfile"]["profileId"] != REMOTE_SERVICE_REPORT_ADAPTER_ID:
        return None
    role = s.roles.get(intent["roleId"])
    tenure = None if role is None or role.current_tenure_id is None else s.tenures.get(role.current_tenure_id)
    if role is None or tenure is None or tenure.closed or _active_agent(s, tenure.agent_id) is None:
        return None
    return _AttemptSource(intent, admission, role, tenure)


def _authorize_attempt(s: ReplayState, event: dict[str, Any], position: int, hooks: ReplayHooks, actor_id: str, source: _AttemptSource, action: str) -> Result:
    if actor_id != source.tenure.agent_id:
        return "actor is not the current role holder"
    request = {"actorId": actor_id, "action": action, "resource": source.intent["intentId"], "claimedAt": event["timestamp"]}
    if "termsCommitment" in source.intent:
        request["termsCommitment"] = source.intent["termsCommitment"]
    return _administrative(s, event, position, hooks, AdministrativeRequirements(request, source.role.principal_id, [], source.role.id, source.tenure.id))


def _apply_outcome_observation_recorded(s: ReplayState, event: dict[str, Any], position: int, hooks: ReplayHooks) -> Result:
    d = event["data"]
    source = _attempt_source(s, d["intentId"])
    if (source is None or source.admission.admission_event_id != d["sourceAdmissionEventId"]
            or not validate_adapter_acknowledgment(d["acknowledgment"], source.admission.adapter_identity) or d["acknowledgment"]["result"].get("kind") != "REMOTE_SERVICE_REPORTED"):
        return "observation does not match an admitted remote-service intent"
    failure = _authorize_attempt(s, event, position, hooks, d["actorId"], source, "OBSERVE_OUTCOME")
    if failure is not None:
        return failure
    observation = OutcomeObservationRecord(d["intentId"], d["sourceAdmissionEventId"], d["acknowledgment"], d["actorId"], event["id"], position, event["timestamp"])
    s.outcome_observations[d["intentId"]] = [*s.outcome_observations.get(d["intentId"], []), observation]
    return None


def _apply_attempt_duty_created(s: ReplayState, event: dict[str, Any], position: int, hooks: ReplayHooks) -> Result:
    d = event["data"]
    record, source = d["record"], _attempt_source(s, d["record"]["sourceIntentId"])
    if (source is None or record["sourceAdmissionEventId"] != source.admission.admission_event_id or record["durableRoleId"] != source.role.id
            or record["creationRoleTenureId"] != source.tenure.id or record["performanceAssigneeId"] != source.tenure.agent_id or record["status"] != "OPEN"
            or record["dutyId"] in s.attempt_duties or record["dutyId"] in s.obligations or record["sourceIntentId"] in s.attempt_duty_ids_by_source_intent):
        return "attempt duty cannot be created"
    failure = _authorize_attempt(s, event, position, hooks, d["actorId"], source, "CREATE_ATTEMPT_DUTY")
    if failure is not None:
        return failure
    s.attempt_duties[record["dutyId"]] = AttemptDutyState(record, event["id"], position, d["actorId"], record["performanceAssigneeId"], ())
    s.attempt_duty_ids_by_source_intent[record["sourceIntentId"]] = record["dutyId"]
    return None


def _apply_attempt_duty_assigned(s: ReplayState, event: dict[str, Any], position: int, hooks: ReplayHooks) -> Result:
    d = event["data"]
    duty = s.attempt_duties.get(d["dutyId"])
    if duty is None:
        return "attempt duty unknown"
    source = _attempt_source(s, duty.record["sourceIntentId"])
    if source is None or d["fromAgentId"] != duty.current_assignee_id or d["toAgentId"] == d["fromAgentId"] or d["toAgentId"] != source.tenure.agent_id:
        return "attempt duty cannot be assigned"
    failure = _authorize_attempt(s, event, position, hooks, d["actorId"], source, "ASSIGN_ATTEMPT_DUTY")
    if failure is not None:
        return failure
    assignment = AttemptDutyAssignment(d["fromAgentId"], d["toAgentId"], d["actorId"], event["id"], position, event["timestamp"])
    s.attempt_duties[d["dutyId"]] = replace(duty, current_assignee_id=d["toAgentId"], assignments=(*duty.assignments, assignment))
    return None


def _apply_attempt_duty_review_closed(s: ReplayState, event: dict[str, Any], position: int, hooks: ReplayHooks) -> Result:
    if not policy_enables_attempt_reviews(s.genesis["adapterPolicyHash"]):
        return "edition does not enable reviews"
    d = event["data"]
    duty = s.attempt_duties.get(d["dutyId"])
    if duty is None or duty.current_assignee_id != d["actorId"]:
        return "actor is not the duty assignee"
    source = _attempt_source(s, duty.record["sourceIntentId"])
    observations = s.outcome_observations.get(duty.record["sourceIntentId"], [])
    if source is None or len(observations) != len(d["observationEventIds"]) or (len(d["observationEventIds"]) > 0 and not _strictly_sorted(d["observationEventIds"])):
        return "review does not list the recorded observations"
    failure = _authorize_attempt(s, event, position, hooks, d["actorId"], source, "CLOSE_ATTEMPT_DUTY")
    if failure is not None:
        return failure
    if not all(o.event_id in d["observationEventIds"] for o in observations):
        return "review omits an observation"
    review = AttemptDutyReview(d["dutyId"], d["actorId"], d["observationEventIds"], d["summaryDigest"], event["id"], position, event["timestamp"])
    s.attempt_duty_reviews[d["dutyId"]] = [*s.attempt_duty_reviews.get(d["dutyId"], []), review]
    return None


# ---------------------------------------------------------------- format-1 anchors and the dispatcher


def _apply_anchor_recorded(s: ReplayState, event: dict[str, Any], position: int) -> Result:
    d = event["data"]
    head = d["anchoredHead"]
    if not head["position"] < position or head["hash"] != s.event_history_hashes[head["position"]]:
        return "anchored head is not a prefix of this history"
    s.anchors.append(AnchorRecord(head, d["anchor"], event["id"], position))
    return None


def _apply_owner_key_event(s: ReplayState, event: dict[str, Any], position: int) -> Result:
    """OWNER_KEYS_ROTATED (format 1): signed under the set in force before the event; the owner-key rules (key-set rules,
    pre-rotation when the epoch being left has a commitment, no commitment-less rotation that keeps every key) decide, and
    the epochs are replaced by the result. Never inside a migrated legacy prefix."""
    if s.format != TRELLIS_FORMAT:
        return "owner key rotation is not allowed inside a migrated legacy prefix"
    outcome = owner_key_event_transition(s.owner_key_epochs, event, s.genesis["domain"],
                                         {"hash": s.event_history_hashes[position - 1], "position": position - 1}, s.hash_algorithm)
    if not outcome["ok"]:
        return outcome["reason"]
    s.owner_key_epochs = list(outcome["epochs"])
    return None


def _policy_failure(policy: dict[str, Any], bound: int) -> Result:
    if policy["quorum"] > max(1, bound):
        return f"witness binding: policy quorum {policy['quorum']} exceeds the {bound} witness(es) bound after the event"
    return None


def _signed_policy(data: dict[str, Any]) -> dict[str, Any]:
    p = data["policy"]
    return {"quorum": p["quorum"], "requireOnOpen": p["requireOnOpen"], "maxUnwitnessedEvents": p["maxUnwitnessedEvents"]}


# The fields a registration receipt may carry (docs/reference/witness-protocol.md §9.5): the record is closed.
_REGISTRATION_FIELDS = ("version", "witness", "entry", "index", "checkpoint", "inclusionProof")
_REGISTRATION_WITNESS_FIELDS = ("origin", "verifierKey")


def _registration_field_failure(receipt: Any) -> str | None:
    def extra(value: Any, allowed: tuple[str, ...]) -> list[str]:
        return [key for key in value if key not in allowed] if isinstance(value, dict) else []
    top = extra(receipt, _REGISTRATION_FIELDS)
    if top:
        return f"has an unknown field {json.dumps(top[0], ensure_ascii=False)}"
    inner = extra(receipt.get("witness") if isinstance(receipt, dict) else None, _REGISTRATION_WITNESS_FIELDS)
    return f"has an unknown witness field {json.dumps(inner[0], ensure_ascii=False)}" if inner else None


def _apply_witnesses_bound(s: ReplayState, event: dict[str, Any], position: int) -> Result:
    """WITNESSES_BOUND (format 1): binds each named witness (a verifier key bound already is re-bound in place). A
    ``registration`` must be the witness's own signed receipt (no fields beyond a receipt's) of the REGISTERED leaf of
    exactly this history's genesis. At most 16 witnesses stay bound, and the policy quorum is at most their number. Never inside a migrated legacy prefix."""
    if s.format != TRELLIS_FORMAT:
        return "a witness binding is not allowed inside a migrated legacy prefix"
    d = control_effect(event["data"])
    bound = list(s.bound_witnesses)
    for w in d["witnesses"]:
        registration = None
        if "registration" in w:
            unknown = _registration_field_failure(w["registration"])
            if unknown is not None:
                return f"witness binding: the registration receipt of {w['verifierKey']} {unknown}"
            verdict = verify_witness_receipt(w["registration"], [w["verifierKey"]])
            if not verdict["ok"]:
                return f"witness binding: the registration receipt of {w['verifierKey']} does not verify ({verdict['reason']}: {verdict['message']})"
            entry = w["registration"]["entry"]
            try:
                same_genesis = canonical_encode(entry.get("genesis")) == canonical_encode(s.events[0])
            except Exception:
                same_genesis = False
            if entry.get("kind") != "REGISTERED" or entry.get("historyId") != s.event_history_hashes[0] or not same_genesis:
                return f"witness binding: the registration receipt of {w['verifierKey']} is not the REGISTERED leaf of this history"
            registration = {"receipt": w["registration"], "index": verdict["index"]}
        record: dict[str, Any] = {"url": w["url"], "verifierKey": w["verifierKey"]}
        if "name" in w:
            record["name"] = w["name"]
        if w.get("allowInsecureHttp") is True:
            record["allowInsecureHttp"] = True
        if registration is not None:
            record["registration"] = registration
        record["eventId"] = event["id"]
        record["eventPosition"] = position
        at = next((index for index, b in enumerate(bound) if b["verifierKey"] == w["verifierKey"]), None)
        if at is None:
            bound.append(record)
        else:
            bound[at] = record
    if len(bound) > MAX_BOUND_WITNESSES:
        return f"witness binding: at most {MAX_BOUND_WITNESSES} remote witnesses can be bound"
    policy = _signed_policy(d)
    failure = _policy_failure(policy, len(bound))
    if failure is not None:
        return failure
    s.bound_witnesses = bound
    s.bound_policy = policy
    return None


def _apply_witnesses_unbound(s: ReplayState, event: dict[str, Any], position: int) -> Result:
    """WITNESSES_UNBOUND (format 1): every named verifier key must be bound; an ``acceptedLoss`` names, for some of them, a
    head the witness holds that is not a prefix of this history. The policy quorum is at most the witnesses that stay
    bound (or 1). Never inside a migrated legacy prefix."""
    if s.format != TRELLIS_FORMAT:
        return "a witness unbinding is not allowed inside a migrated legacy prefix"
    d = control_effect(event["data"])
    keys = d["verifierKeys"]
    for key in keys:
        if not any(b["verifierKey"] == key for b in s.bound_witnesses):
            return f"witness unbinding: {key} is not bound to this history"
    for loss in d.get("acceptedLoss", {}).get("heads", []):
        if loss["verifierKey"] not in keys:
            return f"witness unbinding: the accepted loss names {loss['verifierKey']}, which this event does not unbind"
        head = loss["head"]
        if head["position"] < position and s.event_history_hashes[head["position"]] == head["hash"]:
            return f"witness unbinding: the accepted loss of {loss['verifierKey']} names a head this history contains (position {head['position']}): nothing was lost"
    bound = [b for b in s.bound_witnesses if b["verifierKey"] not in keys]
    policy = _signed_policy(d)
    failure = _policy_failure(policy, len(bound))
    if failure is not None:
        return failure
    s.bound_witnesses = bound
    s.bound_policy = policy
    return None


@dataclass(frozen=True)
class ReplayHooks:
    """The signed-transition validators replay delegates to (spec 02 §7.4, §7.6).

    ``validate_intent_admission_transition`` returns ``(admission, usage)`` or a failure reason;
    ``validate_administrative_transition`` returns None on success or a failure reason."""

    validate_intent_admission_transition: Callable[[Any, dict[str, Any], int, Head], Any]
    validate_administrative_transition: Callable[[Any, dict[str, Any], int, AdministrativeRequirements], Result]


def apply_transition(s: ReplayState, event: dict[str, Any], position: int, next_head: Head, hooks: ReplayHooks) -> Result:
    """Apply one schema-valid event at ``position``; ``next_head`` is the head including it."""
    data = event["data"]
    t = event["type"]
    if t == "DEPLOYMENT_INITIALIZED":
        if position != 0 or len(s.events) != 0 or resolve_adapter_policy(data["adapterPolicyHash"]) is None:
            return "genesis misplaced or policy unknown"
        s.genesis = data
        s.signature_scheme = data["versions"]["signatureScheme"]
        # Epoch 0: the genesis owner keys and, with pre-rotation from the start, their next-key commitment (committed by the history id).
        s.owner_key_epochs = [{"fromPosition": 0, "keys": list(data.get("ownerKeys", [])), **({"nextKeyDigests": list(data["nextKeyDigests"])} if "nextKeyDigests" in data else {})}]
        if "migratedFrom" in data:
            _open_shadow(s, data["migratedFrom"])
        return None
    if t == "PRINCIPAL_CREATED":
        return _apply_principal_created(s, data, event, position)
    if t == "AGENT_CREATED":
        return _apply_agent_created(s, data)
    if t == "ROLE_CREATED":
        return _apply_role_created(s, data)
    if t == "SUCCESSION_RULE_DECLARED":
        return _apply_succession_rule_declared(s, control_effect(data))
    if t == "AGENT_APPOINTED":
        return _apply_agent_appointed(s, data)
    if t == "AGENT_UNAPPOINTED":
        return _apply_agent_unappointed(s, data)
    if t == "ROLE_TRANSFERRED":
        return _apply_role_transferred(s, data)
    if t == "RUNTIME_SESSION_ADMITTED":
        return _apply_runtime_session_admitted(s, event, position)
    if t == "CONTROL_EPOCH_ADVANCED":
        return _apply_control_epoch_advanced(s, data)
    if t == "TRANSACTION_INTENT_DECLARED":
        return _apply_intent_declared(s, data, position)
    if t == "AGENT_TERMINATED":
        return _apply_agent_terminated(s, data)
    if t == "AUTHORITY_GRANTED":
        return _apply_authority_granted(s, data["grant"], event, position)
    if t == "AUTHORITY_REVOKED":
        return _apply_authority_revoked(s, data, event, position)
    if t == "TRANSACTION_INTENT_ADMITTED":
        return _apply_intent_admitted(s, event, position, next_head, hooks)
    if t == "TRANSACTION_INTENT_CONSUMED":
        return _apply_intent_consumed(s, event, position, next_head)
    if t == "TRANSACTION_OUTCOME_RECORDED":
        return _apply_outcome_recorded(s, event, position, next_head)
    if t == "RECEIPT_RECORDED":
        return _apply_receipt_recorded(s, event, position, next_head)
    if t == "OUTCOME_OBSERVATION_RECORDED":
        return _apply_outcome_observation_recorded(s, event, position, hooks)
    if t == "ATTEMPT_DUTY_CREATED":
        return _apply_attempt_duty_created(s, event, position, hooks)
    if t == "ATTEMPT_DUTY_ASSIGNED":
        return _apply_attempt_duty_assigned(s, event, position, hooks)
    if t == "ATTEMPT_DUTY_REVIEW_CLOSED":
        return _apply_attempt_duty_review_closed(s, event, position, hooks)
    if t == "OBLIGATION_CREATED":
        return _apply_obligation_created(s, event, position, next_head, hooks)
    if t == "OBLIGATION_PERFORMANCE_ASSIGNED":
        return _apply_obligation_performance_assigned(s, event, position, hooks)
    if t == "OBLIGATION_STATUS_RECORDED":
        return _apply_obligation_status_recorded(s, event, position, hooks)
    if t == "ANCHOR_RECORDED":
        return _apply_anchor_recorded(s, event, position)
    if t == "OWNER_KEYS_ROTATED":
        return _apply_owner_key_event(s, event, position)
    if t == "WITNESSES_BOUND":
        return _apply_witnesses_bound(s, event, position)
    if t == "WITNESSES_UNBOUND":
        return _apply_witnesses_unbound(s, event, position)
    return f"unsupported event type {t}"
