"""SURVIVES (spec 03 §D): what an agent's departure leaves behind.

The answer rows are derived exactly as the reference engine derives them
(relevance rules, row identity, sorting). This verifier reproduces the *answer*
and the coordinator's failure codes; it does not reproduce the query
envelope's evidence lists, disclosure negotiation or output budget, which are
outside the conformance projection (the adapter contract reports established,
lifecycle, duty, assignment, tenure, invalidated-authority and unresolved-intent
facts).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import BigInt, CanonicalError, capture_value, is_content_hash, is_identifier, is_protocol_string, is_u53, utf8_length
from .events import LEGACY_VERSIONS
from .hashing import LEGACY_FORMAT, TRELLIS_FORMAT
from .replay import ReplayResult, replay
from .state import AuthorityRecord, ReplayState

QUERY_VERSION = "continuity-query-envelope/0.2"
ADAPTER_POLICY_E5_HASH = "0x32c2a5608c7110f1a291517e136cedf62d59a2cb81be1141dd2705bce307ab29"
ADAPTER_POLICY_E6_HASH = "0xa90baac702f22f5a5f71141318a7651c1d963bbbee28138bbea835d942d0114c"
Rec = dict[str, Any]


def _is_attempt_policy(state: ReplayState) -> bool:
    return state.genesis["adapterPolicyHash"] in (ADAPTER_POLICY_E5_HASH, ADAPTER_POLICY_E6_HASH)


def _assignments_by_obligation(state: ReplayState) -> dict[str, list[Rec]]:
    """Every OBLIGATION_PERFORMANCE_ASSIGNED event's data, grouped by obligation id, in history order (one pass).

    Scanning the whole history once per obligation (and per authority, below) would make SURVIVES
    O(obligations x events) for any agent: minutes at 100,000 events. Lookups here give exactly what those scans find.
    """
    result: dict[str, list[Rec]] = {}
    for event in state.events:
        if event["type"] == "OBLIGATION_PERFORMANCE_ASSIGNED":
            result.setdefault(event["data"]["obligationId"], []).append(event["data"])
    return result


def _links_target(state: ReplayState, obligation_id: str, target_agent_id: str, assignments: dict[str, list[Rec]] | None) -> bool:
    obligation = state.obligations.get(obligation_id)
    if obligation is None:
        return False
    record = obligation.record
    declaration = state.intent_declarations.get(record["sourceIntentId"])
    tenure = state.tenures.get(record["creationRoleTenureId"])
    if ((declaration is not None and declaration["actorId"] == target_agent_id) or (tenure is not None and tenure.agent_id == target_agent_id)
            or record["performanceAssigneeId"] == target_agent_id):
        return True
    if assignments is not None:
        return any(data["toAgentId"] == target_agent_id for data in assignments.get(obligation_id, ()))
    return any(e["type"] == "OBLIGATION_PERFORMANCE_ASSIGNED" and e["data"]["obligationId"] == obligation_id and e["data"]["toAgentId"] == target_agent_id for e in state.events)


def obligation_links_target(state: ReplayState, obligation_id: str, target_agent_id: str) -> bool:
    """Relevance includes historical assignments, even after the tenure closed."""
    return _links_target(state, obligation_id, target_agent_id, None)


def attempt_duty_review_status(state: ReplayState, duty_id: str) -> str:
    """Review status is positional: a review at or before the last assignment never counts (spec 03 §D.6)."""
    duty, reviews = state.attempt_duties.get(duty_id), state.attempt_duty_reviews.get(duty_id, [])
    if duty is None or not reviews:
        return "UNREVIEWED"
    latest = reviews[-1]
    if duty.assignments and latest.event_position <= duty.assignments[-1].event_position:
        return "NEEDS_REVIEW"
    ids = sorted(item.event_id for item in state.outcome_observations.get(duty.record["sourceIntentId"], []))
    return "REVIEW_CLOSED" if latest.actor_id == duty.current_assignee_id and ids == list(latest.observation_event_ids) else "NEEDS_REVIEW"


def _parent_path(state: ReplayState, record: AuthorityRecord) -> list[AuthorityRecord]:
    result: list[AuthorityRecord] = []
    cursor: AuthorityRecord | None = record
    while cursor is not None and cursor.grant["kind"] == "PERMISSION":
        result.append(cursor)
        parent_id = cursor.grant.get("parentAuthorityId")
        cursor = None if parent_id is None else state.authorities.get(parent_id)
    return result


def _dependencies(state: ReplayState, path: list[AuthorityRecord]) -> list[AuthorityRecord]:
    """BFS from the path over required-intersection partners (their own parent paths), deduplicated by authority id."""
    result: list[AuthorityRecord] = []
    seen: set[str] = set()
    queue = list(path)
    enqueued = {record.grant["authorityId"] for record in path}
    index = 0
    while index < len(queue):
        record = queue[index]
        index += 1
        if record.grant["authorityId"] in seen:
            continue
        seen.add(record.grant["authorityId"])
        result.append(record)
        for identifier in record.grant["constraints"]["requiredIntersectionIds"]:
            required = state.authorities.get(identifier)
            if required is None or required.grant["kind"] != "PERMISSION":
                continue
            for dependency in _parent_path(state, required):
                if dependency.grant["authorityId"] in enqueued:
                    continue
                enqueued.add(dependency.grant["authorityId"])
                queue.append(dependency)
    return result


class _Writer:
    """Rows keyed by (field, key): the first write of an identity wins, later writes are merged away (as the reference's projection writer)."""

    def __init__(self, skeleton: Rec) -> None:
        self.answer = skeleton
        self.rows: set[tuple[str, str]] = set()

    def row(self, field: str, key: str, members: Rec) -> None:
        identity = (field, key)
        if identity in self.rows:
            return
        self.rows.add(identity)
        self.answer[field].append(members)


def _skeleton(state: ReplayState, target_agent_id: str) -> Rec:
    agent = state.agents.get(target_agent_id)
    skeleton: Rec = {
        "targetAgentId": target_agent_id, "exists": agent is not None, "lifecycleStatus": "ABSENT" if agent is None else "TERMINATED" if agent.terminated else "ACTIVE",
        "currentRoleTenures": [], "transferredRoleTenures": [], "unresolvedIntents": [], "adapterOutcomes": [],
    }
    if _is_attempt_policy(state):
        skeleton.update({"outcomeObservations": [], "attemptDuties": []})
    # `historicalIdentity` and `receiptCommitments` are evidence-only lists in the reference envelope; this verifier does not produce evidence lists.
    skeleton.update({"obligations": [], "currentPerformanceAssignments": [], "invalidatedAuthorityDependencies": []})
    return skeleton


def _outcome_projection(record: Any) -> Rec:
    out: Rec = {"intentId": record.intent_id, "eventId": record.event_id, "eventPosition": record.event_position, "head": record.head, "status": record.status,
                "attesterId": record.attester_id, "evidenceReference": record.evidence_reference}
    if record.no_effect is not None:
        out["noEffect"] = record.no_effect
    return out


def derive_survives(state: ReplayState, target_agent_id: str, evaluation_time: int) -> Rec:
    """The SURVIVES answer for ``target_agent_id`` (rows without their evidence lists)."""
    writer = _Writer(_skeleton(state, target_agent_id))
    agent = state.agents.get(target_agent_id)
    if agent is None:
        return writer.answer
    for tenure in state.tenures.values():
        if tenure.agent_id != target_agent_id:
            continue
        # Any closed tenure lands in "transferred"; the list name is historical.
        writer.row("transferredRoleTenures" if tenure.closed else "currentRoleTenures", tenure.id,
                   {"roleId": tenure.role_id, "agentId": target_agent_id, "roleTenureId": tenure.id, "tenureNumber": tenure.tenure_number, "status": "CLOSED" if tenure.closed else "CURRENT"})
    for intent_id, declaration in state.intent_declarations.items():
        if declaration["actorId"] != target_agent_id:
            continue
        outcome_state = state.intent_outcome_states.get(intent_id)
        latest = None if outcome_state is None else outcome_state.latest
        outcome = None if latest is None else latest.status
        consumption = state.intent_consumptions.get(intent_id)
        if consumption is not None or latest is not None:
            row: Rec = {"intentId": intent_id, "actorId": target_agent_id, "adapterProfile": declaration["adapterProfile"], "state": outcome or "SUBMITTED"}
            if consumption is not None:
                row["acknowledgment"] = consumption.acknowledgment
            if latest is not None:
                row["latestOutcome"] = _outcome_projection(latest)
            writer.row("adapterOutcomes", intent_id, row)
        if outcome in ("CONFIRMED", "FAILED"):
            continue
        intent_state = outcome or ("SUBMITTED" if consumption is not None else "ADMITTED" if intent_id in state.intent_admissions else "DECLARED")
        writer.row("unresolvedIntents", intent_id, {"intentId": intent_id, "actorId": target_agent_id, "nonce": declaration["nonce"], "state": intent_state})
    if _is_attempt_policy(state):
        # The first duty (insertion order) per source intent: what a per-intent search of attempt_duties found.
        first_duty: dict[str, Any] = {}
        for duty in state.attempt_duties.values():
            first_duty.setdefault(duty.record["sourceIntentId"], duty)
        for intent_id, observations in state.outcome_observations.items():
            declaration = state.intent_declarations.get(intent_id)
            original_actor_id = None if declaration is None else declaration["actorId"]
            related = first_duty.get(intent_id)
            linked = related is not None and (related.record["performanceAssigneeId"] == target_agent_id
                                              or any(a.from_agent_id == target_agent_id or a.to_agent_id == target_agent_id for a in related.assignments))
            if original_actor_id != target_agent_id and not any(o.actor_id == target_agent_id for o in observations) and not linked:
                continue
            if intent_id not in state.intent_admissions:
                continue
            digests = {((o.acknowledgment.get("result") or {}).get("reportDigest") or {}).get("value") for o in observations}
            for o in observations:
                writer.row("outcomeObservations", o.event_id, {
                    "observationEventId": o.event_id, "intentId": intent_id, "sourceAdmissionEventId": o.source_admission_event_id, "originalActorId": original_actor_id,
                    "recorderId": o.actor_id, "recordedAt": o.observed_at, "reportDigest": (o.acknowledgment.get("result") or {}).get("reportDigest"),
                    "reportStatus": "DIVERGENT_REPORTS" if len(digests) > 1 else "REPORT_RECORDED", "externalOutcome": "NOT_PROVEN"})
        for duty_id, duty in state.attempt_duties.items():
            record = duty.record
            declaration = state.intent_declarations.get(record["sourceIntentId"])
            original_actor_id = None if declaration is None else declaration["actorId"]
            if record["sourceIntentId"] not in state.intent_admissions or (
                    original_actor_id != target_agent_id and record["performanceAssigneeId"] != target_agent_id
                    and not any(a.from_agent_id == target_agent_id or a.to_agent_id == target_agent_id for a in duty.assignments)):
                continue
            e6 = state.genesis["adapterPolicyHash"] == ADAPTER_POLICY_E6_HASH
            members: Rec = {
                "dutyId": duty_id, "sourceIntentId": record["sourceIntentId"], "sourceAdmissionEventId": record["sourceAdmissionEventId"], "originalActorId": original_actor_id,
                "durableRoleId": record["durableRoleId"], "creationActorId": duty.creation_actor_id, "initialAssigneeId": record["performanceAssigneeId"],
                "currentAssigneeId": duty.current_assignee_id, "deadline": record["deadline"], "status": record["status"], "externalOutcome": "NOT_PROVEN"}
            if e6:
                members["reviewStatus"] = attempt_duty_review_status(state, duty_id)
            writer.row("attemptDuties", duty_id, members)
    assignments = _assignments_by_obligation(state) if state.obligations else {}
    for obligation_id, obligation in state.obligations.items():
        if obligation.status in ("DISCHARGED", "IMPOSSIBLE_OR_ESCALATED") or not _links_target(state, obligation_id, target_agent_id, assignments):
            continue
        record = obligation.record
        if state.receipt_commitments.get(record["causalReceiptContentHash"]) is None:
            continue
        writer.row("obligations", obligation_id, {"obligationId": obligation_id, "durableRoleId": record["durableRoleId"], "performanceAssigneeId": obligation.performance_assignee_id,
                                                 "status": obligation.status, "deadline": record["deadline"]})
        # The last assignment's rule, else the obligation's own.
        assigned = assignments.get(obligation_id)
        succession_rule_id = assigned[-1]["successionRuleId"] if assigned else record["successionRuleId"]
        writer.row("currentPerformanceAssignments", obligation_id, {"obligationId": obligation_id, "assigneeId": obligation.performance_assignee_id, "successionRuleId": succession_rule_id})
    # REVOKED > EXPIRED > AGENT_TERMINATED; only agents (never principals) count as terminated parties.
    terminations: list[Any] | None = None
    for authority_id, record in state.authorities.items():
        if record.grant["kind"] != "PERMISSION":
            continue
        path = _parent_path(state, record)
        if not any(item.grant["kind"] == "PERMISSION" and (item.grant["grantorId"] == target_agent_id or item.grant["granteeId"] == target_agent_id) for item in path):
            continue
        graph = _dependencies(state, path)
        if any(item.revocation_event_position is not None for item in graph):
            writer.row("invalidatedAuthorityDependencies", authority_id, {"authorityId": authority_id, "state": "REVOKED"})
            continue
        if any("expiresAt" in item.grant["constraints"] and evaluation_time >= item.grant["constraints"]["expiresAt"] for item in graph):
            writer.row("invalidatedAuthorityDependencies", authority_id, {"authorityId": authority_id, "state": "EXPIRED"})
            continue
        terminated_ids: set[str] = set()
        for item in graph:
            if item.grant["kind"] != "PERMISSION":
                continue
            for identifier in (item.grant["grantorId"], item.grant["granteeId"]):
                party = state.agents.get(identifier)
                if party is not None and party.terminated:
                    terminated_ids.add(identifier)
        if not terminated_ids:
            continue
        if terminations is None:
            terminations = [e["data"]["agentId"] for e in state.events if e["type"] == "AGENT_TERMINATED"]
        if any(agent_id in terminated_ids for agent_id in terminations):
            writer.row("invalidatedAuthorityDependencies", authority_id, {"authorityId": authority_id, "state": "AGENT_TERMINATED"})
    answer = writer.answer
    tenure_key = lambda t: (t["roleId"], t["tenureNumber"], t["roleTenureId"])  # noqa: E731
    answer["currentRoleTenures"].sort(key=tenure_key)
    answer["transferredRoleTenures"].sort(key=tenure_key)
    answer["unresolvedIntents"].sort(key=lambda r: r["intentId"])
    answer["adapterOutcomes"].sort(key=lambda r: r["intentId"])
    answer["obligations"].sort(key=lambda r: r["obligationId"])
    answer["currentPerformanceAssignments"].sort(key=lambda r: r["obligationId"])
    answer["invalidatedAuthorityDependencies"].sort(key=lambda r: r["authorityId"])
    if "outcomeObservations" in answer:
        answer["outcomeObservations"].sort(key=lambda r: (r["intentId"], r["observationEventId"]))
        answer["attemptDuties"].sort(key=lambda r: r["dutyId"])
    return answer


# ---------------------------------------------------------------- portable façade (spec 03 §A.3–A.5, SURVIVES only)


@dataclass(frozen=True)
class SurvivesResult:
    """``established`` with an ``answer``, or a failure ``code`` with its epistemic status."""

    established: bool
    answer: Rec | None = None
    code: str | None = None
    epistemic_status: str | None = None
    head: Rec | None = None


def _failure(code: str) -> SurvivesResult:
    status = "UNAVAILABLE" if code == "EVIDENCE_UNAVAILABLE" else "DISPUTED" if code == "EVIDENCE_DISPUTED" else "INDETERMINATE"
    return SurvivesResult(False, None, code, status)


def _is_domain(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    keys = set(value)
    if keys == {"protocol", "version", "deploymentId", "chainId", "verifyingContract"}:
        chain = value["chainId"]
        return (value["protocol"] == "continuity" and value["version"] == "0.2" and is_identifier(value["deploymentId"]) and isinstance(chain, str)
                and chain.isdigit() and chain.isascii() and chain[0] != "0" and int(chain) <= (1 << 256) - 1 and isinstance(value["verifyingContract"], str)
                and len(value["verifyingContract"]) == 42 and value["verifyingContract"].startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in value["verifyingContract"][2:]))
    return keys == {"protocol", "version", "deploymentId"} and value["protocol"] == "irontrellis" and value["version"] == "1" and is_identifier(value["deploymentId"])


_GENESIS_KEYS = ("domain", "adapterPolicyHash", "canonicalLineageId", "versions", "policyVersion", "rootRecognitionPolicy", "globalPolicySourceId", "timeSource", "finality")


def _discover(events: list[Any]) -> tuple[bool, str] | None:
    """Base-envelope check of every event plus a structural probe of the genesis; the flag says whether the declared versions are supported."""
    if not events:
        return None
    for event in events:
        if (not isinstance(event, dict) or set(event) != {"id", "type", "timestamp", "data"} or not is_identifier(event["id"]) or not is_protocol_string(event["type"])
                or not is_u53(event["timestamp"]) or not isinstance(event["data"], dict)):
            return None
    data = events[0]["data"]
    if (events[0]["type"] != "DEPLOYMENT_INITIALIZED" or not all(k in data for k in _GENESIS_KEYS) or any(k not in (*_GENESIS_KEYS, "ownerKeys", "nextKeyDigests", "capacity", "migratedFrom") for k in data)
            or not _is_domain(data["domain"]) or not is_content_hash(data["adapterPolicyHash"]) or not is_identifier(data["canonicalLineageId"]) or not isinstance(data["versions"], dict)
            or not all(isinstance(v, str) for v in data["versions"].values()) or not is_identifier(data["policyVersion"]) or data["rootRecognitionPolicy"] != "declared-principal-root/0.2"
            or not is_identifier(data["globalPolicySourceId"]) or data["timeSource"] != "EVENT_TIMESTAMP" or data["finality"] != "LOCAL_ONLY"):
        return None
    versions = data["versions"]
    trellis = versions.get("eventSchemaVersion") == "irontrellis-event/1"
    return (trellis or versions == LEGACY_VERSIONS), (TRELLIS_FORMAT if trellis else LEGACY_FORMAT)


def survives_portable(operation_version: Any, observed_events: Any, target_agent_id: Any, evaluation_time: Any, replay_fn: Any = None) -> SurvivesResult:
    """Capture, discovery, replay and the SAME_HEAD coordinator branch for a SURVIVES question."""
    if not isinstance(operation_version, str):
        return _failure("INVALID_INPUT")
    if operation_version != QUERY_VERSION:
        return _failure("UNSUPPORTED_VERSION")
    if not isinstance(observed_events, list):
        return _failure("INVALID_INPUT")
    try:
        value = capture_value({"observedEvents": observed_events, "targetAgentId": target_agent_id, "evaluationTime": evaluation_time})
    except CanonicalError:
        return _failure("INVALID_INPUT")
    events = value["observedEvents"]
    for event in events:
        if isinstance(event, dict) and isinstance(event.get("id"), str) and utf8_length(event["id"], 256) is None:
            return _failure("INVALID_INPUT")
    time = value["evaluationTime"]
    if not isinstance(time, (str, int, BigInt)) or isinstance(time, bool):
        return _failure("INVALID_INPUT")
    if not is_identifier(value["targetAgentId"]):
        return _failure("INVALID_INPUT")
    probe = _discover(events)
    if probe is None:
        return _failure("STATE_NOT_AUTHORITATIVE")
    supported, _ = probe
    if not supported:
        return _failure("EVIDENCE_UNAVAILABLE")
    replayed: ReplayResult = (replay_fn or replay)(events)
    if not replayed.accepted or replayed.state is None:
        return _failure("STATE_NOT_AUTHORITATIVE")
    state = replayed.state
    if not is_u53(time) or time < state.head["canonicalTime"]:
        return _failure("CAUSAL_TIME_INVALID")
    return SurvivesResult(True, derive_survives(state, value["targetAgentId"], time), None, "ESTABLISHED", state.head)
