import argparse
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Literal, cast
from uuid import uuid4

from security_monitor.coordination import AgentPluginRuntime, CoordinationKernel
from security_monitor.plugins import CrossOrgAlertPlugin, RiskControlPlugin
from security_monitor.swarm.consensus import threshold_for
from security_monitor.swarm.security import sign_payload, verify_payload
from security_monitor.swarm.vertex_consensus import VertexConsensus, make_vertex_event
from security_monitor.track3.protocol import run_acceptance, run_demo
from security_monitor.transports import build_transport


class VerificationPlugin:
    plugin_name = "verification"
    supported_task_types = ("verification",)

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        return str(task_type) == "verification"

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "verified",
            "mission_id": str(task_payload.get("mission_id", "")),
            "evidence_hash": str(task_payload.get("evidence_hash", "unknown")),
        }


class HealthcheckPlugin:
    plugin_name = "healthcheck"
    supported_task_types = ("healthcheck",)

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        return str(task_type) == "healthcheck"

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "ok",
            "agent_id": str(task_payload.get("agent_id", "")),
            "run_id": str(task_payload.get("run_id", "")),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def _normalize_topic_namespace(topic_namespace: str) -> str:
    raw = str(topic_namespace).strip().strip("/")
    if not raw:
        return ""
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "/"} else "-" for ch in raw)


def _compute_standard_metrics(
    task_results: list[Dict[str, Any]],
    started_at: datetime,
    finished_at: datetime,
) -> Dict[str, Any]:
    total_tasks = len(task_results)
    successful_tasks = sum(1 for item in task_results if str(item.get("state", "")).lower() == "success")
    success_rate = float(successful_tasks) / float(total_tasks) if total_tasks > 0 else 0.0
    retry_count = 0
    timeout_count = 0
    for item in task_results:
        result = dict(item.get("result", {}))
        attempts = int(result.get("attempts", 1) or 1)
        retry_count += max(0, attempts - 1)
        reason = str(result.get("reason", "")).strip().lower()
        if reason in {"plugin_timeout", "result_timeout"}:
            timeout_count += 1
    end_to_end_latency_ms = round((finished_at - started_at).total_seconds() * 1000.0, 3)
    return {
        "success_rate": round(success_rate, 6),
        "end_to_end_latency_ms": end_to_end_latency_ms,
        "retry_count": int(retry_count),
        "timeout_count": int(timeout_count),
        "total_tasks": int(total_tasks),
        "successful_tasks": int(successful_tasks),
    }


def _agent_secret(agent_id: str) -> str:
    normalized = "".join(ch if ch.isalnum() else "_" for ch in str(agent_id).strip().upper())
    per_agent_key = f"FOXMQ_AGENT_SECRET_{normalized}"
    return (
        str(os.getenv(per_agent_key, "")).strip()
        or str(os.getenv("FOXMQ_AGENT_SECRET", "")).strip()
        or f"track3-secret-{str(agent_id).strip()}"
    )


def _stage_signature_payload(step: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "mission_id": str(step.get("mission_id", "")).strip(),
        "role_name": str(step.get("role_name", "")).strip().lower(),
        "task_id": str(step.get("task_id", "")).strip(),
        "selected_agent": str(step.get("selected_agent", "")).strip(),
        "state": str(step.get("state", "")).strip().lower(),
        "result": dict(step.get("result", {})),
    }


def _build_kernel(
    node_id: str,
    foxmq_backend: str,
    foxmq_mqtt_addr: str,
    topic_namespace: str = "",
) -> CoordinationKernel:
    transport = build_transport(
        node_id=node_id,
        backend=foxmq_backend,
        mqtt_addr=foxmq_mqtt_addr or None,
        fallback_to_simulated=False,
    )
    namespace = _normalize_topic_namespace(topic_namespace)
    topic_root = "coordination" if not namespace else f"coordination/{namespace}"
    return CoordinationKernel(transport=transport, topic_root=topic_root)


def _role_identity_claim_topic(kernel: CoordinationKernel, role_name: str) -> str:
    return f"{kernel.topic_root}/roles/{str(role_name).strip().lower()}/identity/claim"


def _role_identity_assigned_topic(kernel: CoordinationKernel, role_name: str) -> str:
    return f"{kernel.topic_root}/roles/{str(role_name).strip().lower()}/identity/assigned"


def _run_agent_process(
    agent_id: str,
    role_capabilities: list[str],
    foxmq_backend: str,
    foxmq_mqtt_addr: str,
    run_id: str,
    topic_namespace: str,
    output_dir: str,
    bootstrap_mission: bool,
    bootstrap_ready_timeout_seconds: float,
    bootstrap_pre_guardian_delay_seconds: float,
    bootstrap_wait_timeout_seconds: float,
    exit_on_mission_complete: bool,
) -> int:
    kernel = _build_kernel(
        node_id=agent_id,
        foxmq_backend=foxmq_backend,
        foxmq_mqtt_addr=foxmq_mqtt_addr,
        topic_namespace=topic_namespace,
    )
    normalized_roles = [str(item).strip().lower() for item in role_capabilities if str(item).strip()]
    allowed_roles = {"scout", "guardian", "verifier"}
    normalized_roles = sorted({item for item in normalized_roles if item in allowed_roles})
    if not normalized_roles:
        raise ValueError(f"unsupported agent roles: {role_capabilities}")
    plugin_map: Dict[str, Any] = {"healthcheck": HealthcheckPlugin()}
    if "scout" in normalized_roles or "guardian" in normalized_roles:
        plugin_map["risk_control"] = RiskControlPlugin()
    if "verifier" in normalized_roles:
        plugin_map["cross_org_alert"] = CrossOrgAlertPlugin()
        plugin_map["verification"] = VerificationPlugin()
    plugins: list[Any] = list(plugin_map.values())
    runtime = AgentPluginRuntime(
        agent_id=agent_id,
        kernel=kernel,
        plugins=plugins,
        max_workers=2,
        max_inflight=32,
        plugin_timeout_s=3.0,
        max_retries=1,
    )
    runtime.start()
    stop_event = threading.Event()
    result_events: Dict[str, Dict[str, Any]] = {}
    response_events: Dict[str, Dict[str, Any]] = {}
    response_events_by_correlation: Dict[str, Dict[str, Any]] = {}
    intent_claims: Dict[str, list[Dict[str, Any]]] = {}
    started_intent_evaluations: set[str] = set()
    role_identity_claims: Dict[str, list[Dict[str, Any]]] = {}
    started_role_identity_evaluations: set[str] = set()
    agent_announcements: Dict[str, Dict[str, Any]] = {}
    mission_complete_events: Dict[str, Dict[str, Any]] = {}
    requested_intents: set[str] = set()
    mission_states: Dict[str, Dict[str, Any]] = {}
    mission_states_lock = threading.Lock()
    stage_roles = ("scout", "guardian", "verifier")
    bootstrap_report_lock = threading.Lock()
    bootstrap_report_written = False
    bootstrap_mission_id = f"mission-{run_id}"
    bootstrap_started_at = datetime.now(timezone.utc)
    bootstrap_completion_event = threading.Event()
    lifecycle: Dict[str, int] = {"exit_code": 0}

    def publish_agent_signal(kind: str) -> None:
        metrics = runtime.get_metrics()
        total = float(metrics.get("total_tasks", 0.0))
        completed = float(metrics.get("successful_tasks", 0.0)) + float(metrics.get("failed_tasks", 0.0))
        active_peers: list[str] = []
        try:
            active_peers = kernel.active_peers()
        except Exception:
            active_peers = []
        payload = {
            "kind": kind,
            "agent_id": agent_id,
            "roles": normalized_roles,
            "run_id": run_id,
            "namespace": topic_namespace,
            "metrics": metrics,
            "load": max(0.0, total - completed),
            "active_peers": active_peers,
            "active_peer_count": len(active_peers),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        topic = kernel.agent_announcement_topic() if kind == "announce" else kernel.agent_heartbeat_topic()
        kernel.publish(topic, payload)

    def get_mission_state(mission_id: str, base_payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        with mission_states_lock:
            if mission_id not in mission_states:
                mission_states[mission_id] = {
                    "payload": dict(base_payload or {}),
                    "steps": {},
                    "reported": False,
                    "completed": False,
                    "pre_guardian_delay_seconds": float(base_payload.get("pre_guardian_delay_seconds", 0.0))
                    if base_payload
                    else 0.0,
                }
            return mission_states[mission_id]

    def on_result(message: Dict[str, Any]) -> None:
        task_id = str(message.get("task_id", "")).strip()
        if task_id:
            result_events[task_id] = dict(message)

    def on_response(message: Dict[str, Any]) -> None:
        task_id = str(message.get("task_id", "")).strip()
        correlation_data = str(message.get("__correlation_data", "")).strip()
        if task_id:
            response_events[task_id] = dict(message)
        if correlation_data:
            response_events_by_correlation[correlation_data] = dict(message)

    def on_announcement(message: Dict[str, Any]) -> None:
        announced_agent_id = str(message.get("agent_id", "")).strip()
        if not announced_agent_id:
            return
        agent_announcements[announced_agent_id] = dict(message)

    def readiness_snapshot() -> Dict[str, Dict[str, Any]]:
        snapshot: Dict[str, Dict[str, Any]] = {}
        for announced_agent in sorted(agent_announcements.keys()):
            announcement = dict(agent_announcements.get(announced_agent, {}))
            roles = {
                str(item).strip().lower()
                for item in announcement.get("roles", [])
                if str(item).strip()
            }
            snapshot[announced_agent] = {
                "state": "success",
                "agent_id": announced_agent,
                "roles": sorted(roles),
                "timestamp": str(announcement.get("timestamp", "")),
            }
        return snapshot

    def discovered_roles(readiness: Dict[str, Dict[str, Any]]) -> set[str]:
        return {
            str(role).strip().lower()
            for item in readiness.values()
            for role in item.get("roles", [])
            if str(role).strip()
        }

    def _parse_iso_timestamp(raw: str) -> float:
        value = str(raw).strip()
        if not value:
            return 0.0
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return float(parsed.timestamp())
        except ValueError:
            return 0.0

    def _dedupe_claims_by_agent(claims: list[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        by_agent: Dict[str, Dict[str, Any]] = {}
        for claim in claims:
            claim_agent = str(claim.get("agent_id", "")).strip()
            if not claim_agent:
                continue
            current = by_agent.get(claim_agent)
            if current is None:
                by_agent[claim_agent] = dict(claim)
                continue
            current_ts = _parse_iso_timestamp(str(current.get("timestamp", "")))
            candidate_ts = _parse_iso_timestamp(str(claim.get("timestamp", "")))
            if candidate_ts >= current_ts:
                by_agent[claim_agent] = dict(claim)
        return by_agent

    def _extract_assigned_agent(value: Any) -> str:
        if isinstance(value, dict):
            return str(value.get("assigned_agent", "")).strip()
        return str(value).strip()

    def _known_role_agents(role_name: str) -> list[str]:
        role = str(role_name).strip().lower()
        known: set[str] = set()
        for announced_agent_id, announcement in agent_announcements.items():
            roles = {
                str(item).strip().lower()
                for item in announcement.get("roles", [])
                if str(item).strip()
            }
            if role in roles:
                known.add(str(announced_agent_id).strip())
        return sorted(item for item in known if item)

    def _vertex_pick_winner(
        mission_id: str,
        role_name: str,
        claim_kind: str,
        by_agent: Dict[str, Dict[str, Any]],
    ) -> tuple[str, Dict[str, Any]]:
        if not by_agent:
            return "", {}
        if claim_kind == "role_identity_claim":
            ranked = sorted(
                by_agent.items(),
                key=lambda entry: (
                    -float(dict(entry[1]).get("score", 0.0)),
                    float(dict(entry[1]).get("load", 0.0)),
                    str(entry[0]),
                ),
            )
            winner_agent = str(ranked[0][0]).strip()
            return winner_agent, dict(by_agent.get(winner_agent, {}))
        candidates = sorted(by_agent.keys())
        participants = sorted(set(candidates) | set(_known_role_agents(role_name)))
        if len(participants) < 3:
            winner_agent = min(
                candidates,
                key=lambda item: hashlib.sha256(
                    f"{mission_id}:{role_name}:{claim_kind}:{item}".encode("utf-8")
                ).hexdigest(),
            )
            return winner_agent, dict(by_agent.get(winner_agent, {}))
        vertex_engine = VertexConsensus(participants)
        creator_last_event: Dict[str, str] = {}
        event_ids: list[str] = []
        claim_event_creator: Dict[str, str] = {}
        ordered_claims = sorted(
            by_agent.values(),
            key=lambda item: (
                _parse_iso_timestamp(str(item.get("timestamp", ""))),
                str(item.get("agent_id", "")).strip(),
            ),
        )
        logical_ts = 0
        for claim in ordered_claims:
            creator = str(claim.get("agent_id", "")).strip()
            if not creator:
                continue
            logical_ts += 1
            self_parent = creator_last_event.get(creator, "")
            other_parents = [item for item in event_ids[-max(1, len(participants) * 2) :] if item != self_parent]
            transaction = {
                "mission_id": mission_id,
                "role_name": role_name,
                "claim_kind": claim_kind,
                "claim_id": str(claim.get("claim_id", "")).strip() or str(claim.get("intent_id", "")).strip(),
                "agent_id": creator,
                "score": float(claim.get("score", 0.0)),
                "load": float(claim.get("load", 0.0)),
                "timestamp": str(claim.get("timestamp", "")),
            }
            claim_event = make_vertex_event(
                creator=creator,
                logical_ts=logical_ts,
                transactions=[transaction],
                self_parent=self_parent,
                other_parents=other_parents,
                secret=_agent_secret(creator),
            )
            vertex_engine.add_event(claim_event)
            creator_last_event[creator] = claim_event.event_id
            event_ids.append(claim_event.event_id)
            claim_event_creator[claim_event.event_id] = creator
        for sync_round in range(1, 3):
            for participant in participants:
                logical_ts += 1
                self_parent = creator_last_event.get(participant, "")
                recent_other_parents = [item for item in event_ids[-max(1, len(participants) * 2) :] if item != self_parent]
                sync_event = make_vertex_event(
                    creator=participant,
                    logical_ts=logical_ts,
                    transactions=[
                        {
                            "mission_id": mission_id,
                            "role_name": role_name,
                            "claim_kind": claim_kind,
                            "kind": "consensus_sync",
                            "sync_round": sync_round,
                            "seen_event_count": len(event_ids),
                        }
                    ],
                    self_parent=self_parent,
                    other_parents=recent_other_parents,
                    secret=_agent_secret(participant),
                )
                vertex_engine.add_event(sync_event)
                creator_last_event[participant] = sync_event.event_id
                event_ids.append(sync_event.event_id)
        ordered_event_ids = list(vertex_engine.consensus_order().get("ordered_event_ids", []))
        for event_id in ordered_event_ids:
            selected_creator = claim_event_creator.get(str(event_id))
            if selected_creator:
                return selected_creator, dict(by_agent.get(selected_creator, {}))
        winner_agent = min(
            candidates,
            key=lambda item: hashlib.sha256(
                f"{mission_id}:{role_name}:{claim_kind}:{item}".encode("utf-8")
            ).hexdigest(),
        )
        return winner_agent, dict(by_agent.get(winner_agent, {}))

    def build_mission_chain(mission_id: str, completion_event: Dict[str, Any]) -> list[Dict[str, Any]]:
        chain = list(completion_event.get("steps", []))
        if chain:
            return chain
        state = get_mission_state(mission_id)
        with mission_states_lock:
            steps_map = cast(Dict[str, Dict[str, Any]], state.get("steps", {}))
            return [dict(steps_map[item]) for item in stage_roles if item in steps_map]

    def write_bootstrap_report(mission_id: str, completion_event: Dict[str, Any]) -> None:
        nonlocal bootstrap_report_written
        if not output_dir:
            return
        with bootstrap_report_lock:
            if bootstrap_report_written:
                return
            readiness = readiness_snapshot()
            readiness_ok = bool(readiness) and set(stage_roles).issubset(discovered_roles(readiness))
            chain = build_mission_chain(mission_id, completion_event)
            all_success = bool(completion_event.get("all_success", False))
            if not completion_event:
                all_success = len(chain) == len(stage_roles) and all(
                    str(item.get("state", "")).lower() == "success" for item in chain
                )
            failure_reason = str(completion_event.get("failure_reason", "")).strip()
            if not failure_reason and not all_success:
                failure_reason = "mission_incomplete"
            if not readiness_ok and not failure_reason:
                failure_reason = "agent_not_ready"
            step_metrics = []
            for step in chain:
                result = dict(step.get("result", {}))
                step_metrics.append(
                    {
                        "task_id": str(step.get("task_id", "")),
                        "state": str(step.get("state", "")),
                        "agent_id": str(step.get("selected_agent", "")),
                        "task_type": str(result.get("task_type", "")),
                        "handler_latency_ms": float(result.get("latency_ms", 0.0)),
                        "wait_latency_ms": float(step.get("wait_latency_ms", 0.0)),
                    }
                )
            step_signature_checks: Dict[str, bool] = {}
            valid_signature_agents: set[str] = set()
            committee_agents: set[str] = {
                str(agent_key).strip() for agent_key in readiness.keys() if str(agent_key).strip()
            }
            for step in chain:
                selected_agent = str(step.get("selected_agent", "")).strip()
                if not selected_agent:
                    continue
                committee_agents.add(selected_agent)
                signature = str(step.get("consensus_signature", "")).strip()
                payload = _stage_signature_payload(step)
                signature_ok = bool(signature) and verify_payload(_agent_secret(selected_agent), payload, signature)
                key = f"{selected_agent}:{str(step.get('role_name', '')).strip().lower()}"
                step_signature_checks[key] = signature_ok
                if signature_ok:
                    valid_signature_agents.add(selected_agent)
            vertex_participants = sorted(committee_agents)
            vertex_consensus_payload: Dict[str, Any] = {}
            vertex_proof_checks: Dict[str, bool] = {}
            vertex_consensus_ok = False
            if len(vertex_participants) >= 3:
                vertex_engine = VertexConsensus(vertex_participants)
                creator_last_event: Dict[str, str] = {}
                event_ids: list[str] = []
                for index, step in enumerate(chain, start=1):
                    creator = str(step.get("selected_agent", "")).strip()
                    self_parent = creator_last_event.get(creator, "")
                    other_parents = [item for item in event_ids if item != self_parent]
                    transaction = {
                        "mission_id": str(step.get("mission_id", "")).strip(),
                        "role_name": str(step.get("role_name", "")).strip().lower(),
                        "task_id": str(step.get("task_id", "")).strip(),
                        "state": str(step.get("state", "")).strip().lower(),
                        "result": dict(step.get("result", {})),
                    }
                    event = make_vertex_event(
                        creator=creator,
                        logical_ts=index,
                        transactions=[transaction],
                        self_parent=self_parent,
                        other_parents=other_parents,
                        secret=_agent_secret(creator),
                    )
                    vertex_engine.add_event(event)
                    creator_last_event[creator] = event.event_id
                    event_ids.append(event.event_id)
                logical_ts = len(event_ids)
                for sync_round in range(1, 3):
                    for participant in vertex_participants:
                        logical_ts += 1
                        self_parent = creator_last_event.get(participant, "")
                        recent_other_parents = [
                            item for item in event_ids[-max(1, len(vertex_participants) * 2) :] if item != self_parent
                        ]
                        sync_event = make_vertex_event(
                            creator=participant,
                            logical_ts=logical_ts,
                            transactions=[
                                {
                                    "mission_id": mission_id,
                                    "kind": "consensus_sync",
                                    "sync_round": sync_round,
                                    "event_count_seen": len(event_ids),
                                }
                            ],
                            self_parent=self_parent,
                            other_parents=recent_other_parents,
                            secret=_agent_secret(participant),
                        )
                        vertex_engine.add_event(sync_event)
                        creator_last_event[participant] = sync_event.event_id
                        event_ids.append(sync_event.event_id)
                vertex_consensus_payload = vertex_engine.build_proof(
                    {participant: _agent_secret(participant) for participant in vertex_participants}
                )
                vertex_proof_checks = VertexConsensus.verify_proof(
                    vertex_consensus_payload,
                    {participant: _agent_secret(participant) for participant in vertex_participants},
                )
                vertex_consensus_ok = (
                    bool(vertex_proof_checks)
                    and all(bool(item) for item in vertex_proof_checks.values())
                )
            coordination_proof = dict(vertex_consensus_payload)
            proof_signatures = dict(coordination_proof.get("signatures", {}))
            multisig_summary = dict(coordination_proof.get("multisig_summary", {}))
            if not proof_signatures and multisig_summary:
                coordination_proof["signatures"] = dict(multisig_summary)
            if not multisig_summary and proof_signatures:
                coordination_proof["multisig_summary"] = dict(proof_signatures)
            proof_checks = dict(vertex_proof_checks)
            stage_signatures_all_ok = bool(chain) and all(bool(item) for item in step_signature_checks.values())
            consensus_finalized = bool(all_success and stage_signatures_all_ok and vertex_consensus_ok)
            selected_agents = [str(step.get("selected_agent", "")).strip() for step in chain if str(step.get("selected_agent", "")).strip()]
            unique_selected_agents = set(selected_agents)
            participant_ids = [
                str(item).strip()
                for item in dict(coordination_proof.get("proof_payload", {})).get("participants", [])
                if str(item).strip()
            ]
            participant_set = set(participant_ids)
            committee_set = set(vertex_participants)
            quorum = threshold_for(len(vertex_participants)) if len(vertex_participants) >= 3 else 0
            independent_validator_quorum = max(1, quorum - 1) if quorum > 0 else 0
            readiness_agents = sorted(str(agent_key).strip() for agent_key in readiness.keys() if str(agent_key).strip())
            peer_snapshots = []
            for agent_id_key, announcement in sorted(agent_announcements.items()):
                normalized_agent_id = str(agent_id_key).strip()
                active_peers = [
                    str(item).strip() for item in dict(announcement).get("active_peers", []) if str(item).strip()
                ]
                if not active_peers and readiness_agents:
                    active_peers = [item for item in readiness_agents if item != normalized_agent_id]
                peer_snapshots.append(
                    {
                        "agent_id": normalized_agent_id,
                        "active_peers": active_peers,
                        "active_peer_count": len(active_peers),
                        "timestamp": str(dict(announcement).get("timestamp", "")),
                    }
                )
            max_peer_count = max(
                (len(cast(list[Any], item.get("active_peers", []))) for item in peer_snapshots),
                default=0,
            )
            lattice_discovery_ok = bool(readiness) and max_peer_count >= 2
            lattice_authorization_ok = bool(participant_set) and participant_set == committee_set and len(participant_set) >= 3
            lattice_independent_validation_ok = (
                bool(proof_checks)
                and all(bool(item) for item in proof_checks.values())
                and len(unique_selected_agents) >= independent_validator_quorum
            )
            lattice_reputation_scores = {
                agent: round(1.0 + (0.1 if agent in unique_selected_agents else 0.0), 3)
                for agent in sorted(committee_set)
            }
            lattice_reputation_routing_ok = bool(unique_selected_agents) and all(
                lattice_reputation_scores.get(agent, 0.0) >= 1.0 for agent in unique_selected_agents
            )
            lattice_failover_ok = bool(all_success and consensus_finalized)
            coordination_correctness = (
                len(chain) == len(stage_roles)
                and len(selected_agents) == len(set(selected_agents))
                and all(str(item.get("state", "")).strip().lower() == "success" for item in chain)
                and bool(consensus_finalized)
            )
            resilience = bool(all_success and consensus_finalized and readiness_ok and lattice_failover_ok)
            auditability = bool(vertex_consensus_ok and stage_signatures_all_ok and lattice_independent_validation_ok)
            security_posture = bool(stage_signatures_all_ok and proof_checks and all(bool(item) for item in proof_checks.values()))
            developer_clarity = bool(readiness and step_metrics and peer_snapshots)
            tashi_alignment = {
                "peer_discovery_observed": lattice_discovery_ok,
                "proof_of_coordination_verifiable": bool(proof_checks) and all(bool(item) for item in proof_checks.values()),
            }
            lattice = {
                "discovery_ok": lattice_discovery_ok,
                "authorized_participants_ok": lattice_authorization_ok,
                "independent_validation_ok": lattice_independent_validation_ok,
                "validator_quorum_required": independent_validator_quorum,
                "validator_quorum_observed": len(unique_selected_agents),
                "reputation_scores": lattice_reputation_scores,
                "reputation_routing_ok": lattice_reputation_routing_ok,
                "failover_ok": lattice_failover_ok,
            }
            competition_alignment = {
                "Coordination Correctness": coordination_correctness,
                "Resilience": resilience,
                "Auditability": auditability,
                "Security Posture": security_posture,
                "Developer clarity": developer_clarity,
            }
            finished_at = datetime.now(timezone.utc)
            os.makedirs(output_dir, exist_ok=True)
            report_path = os.path.join(output_dir, "multiprocess_mission_record.json")
            report_items_for_metrics = list(readiness.values()) + chain
            state = get_mission_state(mission_id)
            with mission_states_lock:
                role_assignments = dict(state.get("role_assignments", {}))
            selected_agent_by_role = {
                str(step.get("role_name", "")).strip().lower(): str(step.get("selected_agent", "")).strip()
                for step in chain
                if str(step.get("role_name", "")).strip() and str(step.get("selected_agent", "")).strip()
            }
            role_identity_assignments = {
                item: {
                    "role_name": item,
                    "assigned_agent": _extract_assigned_agent(role_assignments.get(item, {}))
                    or selected_agent_by_role.get(item, ""),
                }
                for item in stage_roles
            }
            report = {
                "run_id": run_id,
                "topic_namespace": topic_namespace,
                "mission_id": mission_id,
                "transport_backend": foxmq_backend,
                "mqtt_addr": foxmq_mqtt_addr,
                "started_at": bootstrap_started_at.isoformat(),
                "finished_at": finished_at.isoformat(),
                "duration_ms": round((finished_at - bootstrap_started_at).total_seconds() * 1000.0, 3),
                "readiness": readiness,
                "steps": chain,
                "step_metrics": step_metrics,
                "standard_metrics": _compute_standard_metrics(report_items_for_metrics, bootstrap_started_at, finished_at),
                "all_success": all_success and readiness_ok and consensus_finalized,
                "failure_reason": failure_reason,
                "role_identity_negotiation": True,
                "role_identity_assignments": role_identity_assignments,
                "agent_announcements": list(readiness.values()),
                "transport_info": kernel.transport_info(),
                "coordination_proof": coordination_proof,
                "app_coordination_proof": coordination_proof,
                "consensus_proof": {
                    "committee_agents": sorted(committee_agents),
                    "step_signature_checks": step_signature_checks,
                    "stage_signatures_all_ok": stage_signatures_all_ok,
                    "stage_signature_agents": sorted(valid_signature_agents),
                    "stage_signature_count": int(len(valid_signature_agents)),
                    "consensus_finalized": consensus_finalized,
                    "vertex_consensus": vertex_consensus_payload,
                    "vertex_proof_checks": vertex_proof_checks,
                },
                "proof_checks": proof_checks,
                "consensus_checks": {
                    "stage_signatures_all_ok": stage_signatures_all_ok,
                    "vertex_consensus_ok": vertex_consensus_ok,
                    "step_signature_checks": step_signature_checks,
                    "consensus_finalized": consensus_finalized,
                },
                "peer_snapshots": peer_snapshots,
                "tashi_alignment": tashi_alignment,
                "lattice": lattice,
                "competition_alignment": competition_alignment,
            }
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            bootstrap_report_written = True
            print(f"MISSION RECORD WRITTEN: {report_path}")

    def on_mission_complete(message: Dict[str, Any]) -> None:
        mission_id = str(message.get("mission_id", "")).strip()
        if not mission_id:
            return
        mission_complete_events[mission_id] = dict(message)
        if bootstrap_mission and mission_id == bootstrap_mission_id:
            write_bootstrap_report(mission_id, dict(message))
            bootstrap_completion_event.set()

    kernel.subscribe(kernel.result_stream_topic(), on_result)
    kernel.subscribe(kernel.response_topic(agent_id), on_response)
    kernel.subscribe(kernel.agent_announcement_topic(), on_announcement)
    kernel.subscribe(kernel.agent_heartbeat_topic(), on_announcement)
    kernel.subscribe(kernel.mission_complete_topic(), on_mission_complete)

    def execute_local_task(
        mission_id: str,
        role_name: str,
        task_type: str,
        task_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        started = time.perf_counter()
        correlation_id = uuid4().hex
        routed = kernel.submit_task(
            task_type=task_type,
            payload=task_payload,
            source_agent=agent_id,
            target_agent=agent_id,
            metadata={
                "origin": "decentralized_mission",
                "run_id": run_id,
                "namespace": topic_namespace,
                "mission_id": mission_id,
                "role_name": role_name,
                "__response_topic": kernel.response_topic(agent_id),
                "__correlation_data": correlation_id,
            },
        )
        task_id = str(routed.get("task_id", "")).strip()
        deadline = time.time() + 12.0
        while time.time() < deadline:
            event = (
                response_events_by_correlation.get(correlation_id)
                or response_events.get(task_id)
                or result_events.get(task_id)
            )
            if event is not None:
                enriched = dict(event)
                enriched["wait_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
                enriched["selected_agent"] = agent_id
                enriched["role_name"] = role_name
                return enriched
            time.sleep(0.05)
        return {
            "task_id": task_id,
            "state": "failed",
            "result": {"status": "failed", "reason": "result_timeout"},
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "wait_latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "selected_agent": agent_id,
            "role_name": role_name,
        }

    def publish_mission_complete(mission_id: str) -> None:
        state = get_mission_state(mission_id)
        with mission_states_lock:
            if bool(state.get("reported")):
                return
            steps_map = cast(Dict[str, Dict[str, Any]], state.get("steps", {}))
            ordered_steps = [dict(steps_map[role]) for role in stage_roles if role in steps_map]
            all_success = len(ordered_steps) == len(stage_roles) and all(
                str(item.get("state", "")).lower() == "success" for item in ordered_steps
            )
            failure_reason = ""
            if not all_success:
                for item in ordered_steps:
                    if str(item.get("state", "")).lower() != "success":
                        failure_reason = str(item.get("result", {}).get("reason", "unknown_failure"))
                        break
            state["reported"] = True
            state["completed"] = True
        kernel.publish(
            kernel.mission_complete_topic(),
            {
                "mission_id": mission_id,
                "run_id": run_id,
                "namespace": topic_namespace,
                "steps": ordered_steps,
                "all_success": all_success,
                "failure_reason": failure_reason,
                "reporter_agent": agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def request_role_intent(
        mission_id: str,
        role_name: str,
        task_type: str,
        task_payload: Dict[str, Any],
        attempt: int = 1,
        preferred_role_owner: str = "",
    ) -> None:
        if role_name not in stage_roles:
            return
        intent_id = f"{mission_id}:{role_name}:{attempt}"
        with mission_states_lock:
            if intent_id in requested_intents:
                return
            requested_intents.add(intent_id)
        expires_at = datetime.fromtimestamp(time.time() + 2.5, tz=timezone.utc)
        kernel.publish(
            kernel.role_intent_topic(role_name),
            {
                "intent_id": intent_id,
                "mission_id": mission_id,
                "role": role_name,
                "task_type": task_type,
                "task_payload": dict(task_payload),
                "run_id": run_id,
                "namespace": topic_namespace,
                "issued_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": expires_at.isoformat(),
                "attempt": int(attempt),
                "preferred_role_owner": str(preferred_role_owner).strip(),
            },
        )

    def on_mission_stage(message: Dict[str, Any]) -> None:
        mission_id = str(message.get("mission_id", "")).strip()
        role_name = str(message.get("role_name", "")).strip().lower()
        if not mission_id or role_name not in stage_roles:
            return
        state = get_mission_state(mission_id)
        with mission_states_lock:
            steps_map = cast(Dict[str, Dict[str, Any]], state.get("steps", {}))
            if role_name not in steps_map:
                steps_map[role_name] = dict(message)
            state["steps"] = steps_map
        if str(message.get("state", "")).lower() != "success":
            publish_mission_complete(mission_id)
            return
        mission_payload = cast(Dict[str, Any], state.get("payload", {}))
        if role_name == "scout":
            delay_seconds = max(0.0, float(state.get("pre_guardian_delay_seconds", 0.0)))
            guardian_payload = {
                "signal": "risk_high",
                "mission_id": mission_id,
                "scout_agent": str(message.get("selected_agent", "")),
            }
            preferred_guardian = _extract_assigned_agent(dict(state.get("role_assignments", {})).get("guardian", {}))

            def _trigger_guardian() -> None:
                if delay_seconds > 0.0:
                    time.sleep(delay_seconds)
                request_role_intent(
                    mission_id=mission_id,
                    role_name="guardian",
                    task_type="risk_mitigation",
                    task_payload=guardian_payload,
                    attempt=1,
                    preferred_role_owner=preferred_guardian,
                )

            threading.Thread(target=_trigger_guardian, daemon=True).start()
            return
        if role_name == "guardian":
            verifier_payload = {
                "mission_id": mission_id,
                "evidence_hash": str(mission_payload.get("evidence_hash", "proof-chain-placeholder")),
                "guardian_agent": str(message.get("selected_agent", "")),
            }
            preferred_verifier = _extract_assigned_agent(dict(state.get("role_assignments", {})).get("verifier", {}))
            request_role_intent(
                mission_id=mission_id,
                role_name="verifier",
                task_type="verification",
                task_payload=verifier_payload,
                attempt=1,
                preferred_role_owner=preferred_verifier,
            )
            return
        if role_name == "verifier":
            publish_mission_complete(mission_id)

    def publish_role_identity_claim(
        mission_id: str,
        role_name: str,
        attempt: int = 1,
    ) -> None:
        if role_name not in normalized_roles:
            return
        claim_id = f"{mission_id}:{role_name}:{attempt}"
        metrics = runtime.get_metrics()
        task_load = max(
            0.0,
            float(metrics.get("total_tasks", 0.0))
            - float(metrics.get("successful_tasks", 0.0))
            - float(metrics.get("failed_tasks", 0.0)),
        )
        salt = f"identity:{agent_id}:{claim_id}:{role_name}".encode("utf-8")
        tie_break = int(hashlib.sha1(salt).hexdigest()[:6], 16) / float(0xFFFFFF)
        score = round(1000.0 - task_load * 100.0 + tie_break, 6)
        kernel.publish(
            _role_identity_claim_topic(kernel, role_name),
            {
                "claim_id": claim_id,
                "mission_id": mission_id,
                "role_name": role_name,
                "agent_id": agent_id,
                "score": score,
                "load": task_load,
                "metrics": metrics,
                "attempt": int(attempt),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def on_role_identity_claim(message: Dict[str, Any]) -> None:
        claim_id = str(message.get("claim_id", "")).strip()
        role_name = str(message.get("role_name", "")).strip().lower()
        if not claim_id or role_name not in normalized_roles:
            return
        role_identity_claims.setdefault(claim_id, []).append(dict(message))
        with mission_states_lock:
            should_start = claim_id not in started_role_identity_evaluations
            if should_start:
                started_role_identity_evaluations.add(claim_id)
        if should_start:
            threading.Thread(target=evaluate_role_identity_claim, args=(dict(message),), daemon=True).start()

    def evaluate_role_identity_claim(claim_message: Dict[str, Any]) -> None:
        claim_id = str(claim_message.get("claim_id", "")).strip()
        mission_id = str(claim_message.get("mission_id", "")).strip()
        role_name = str(claim_message.get("role_name", "")).strip().lower()
        attempt = int(claim_message.get("attempt", 1) or 1)
        if not claim_id or not mission_id or role_name not in normalized_roles:
            return
        expected_agents = _known_role_agents(role_name)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            snapshot = list(role_identity_claims.get(claim_id, []))
            unique_claim_agents = {
                str(item.get("agent_id", "")).strip() for item in snapshot if str(item.get("agent_id", "")).strip()
            }
            if expected_agents and len(unique_claim_agents) >= len(expected_agents):
                break
            if len(unique_claim_agents) >= 3:
                break
            time.sleep(0.05)
        claims = list(role_identity_claims.get(claim_id, []))
        by_agent = _dedupe_claims_by_agent(claims)
        if not by_agent:
            return
        winner_agent, winner_claim = _vertex_pick_winner(
            mission_id=mission_id,
            role_name=role_name,
            claim_kind="role_identity_claim",
            by_agent=by_agent,
        )
        if not winner_agent:
            return
        if winner_agent != agent_id:
            return
        kernel.publish(
            _role_identity_assigned_topic(kernel, role_name),
            {
                "claim_id": claim_id,
                "mission_id": mission_id,
                "role_name": role_name,
                "assigned_agent": winner_agent,
                "score": float(winner_claim.get("score", 0.0)),
                "load": float(winner_claim.get("load", 0.0)),
                "attempt": attempt,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def on_role_identity_assigned(message: Dict[str, Any]) -> None:
        mission_id = str(message.get("mission_id", "")).strip()
        role_name = str(message.get("role_name", "")).strip().lower()
        assigned_agent = str(message.get("assigned_agent", "")).strip()
        if not mission_id or role_name not in stage_roles or not assigned_agent:
            return
        state = get_mission_state(mission_id)
        with mission_states_lock:
            role_assignments = dict(state.get("role_assignments", {}))
            role_assignments[role_name] = {
                "role_name": role_name,
                "assigned_agent": assigned_agent,
                "claim_id": str(message.get("claim_id", "")).strip(),
                "attempt": int(message.get("attempt", 1) or 1),
                "timestamp": str(message.get("timestamp", "")).strip(),
            }
            state["role_assignments"] = role_assignments
            scout_requested = bool(state.get("scout_intent_requested", False))
            completed = bool(state.get("completed"))
        if role_name == "scout" and not scout_requested and not completed and assigned_agent == agent_id:
            scout_payload = {
                "signal": str(state.get("payload", {}).get("scout_signal", "abnormal_withdraw")),
                "mission_id": mission_id,
            }
            request_role_intent(
                mission_id=mission_id,
                role_name="scout",
                task_type="risk_assessment",
                task_payload=scout_payload,
                attempt=1,
                preferred_role_owner=assigned_agent,
            )
            with mission_states_lock:
                state["scout_intent_requested"] = True

    def on_mission_start(message: Dict[str, Any]) -> None:
        mission_id = str(message.get("mission_id", "")).strip()
        if not mission_id:
            return
        state = get_mission_state(mission_id, base_payload=dict(message))
        with mission_states_lock:
            if bool(state.get("completed")):
                return
        for role_name in stage_roles:
            publish_role_identity_claim(
                mission_id=mission_id,
                role_name=role_name,
                attempt=1,
            )
        if "scout" in normalized_roles:
            state = get_mission_state(mission_id)

            def _fallback_scout_intent() -> None:
                time.sleep(0.6)
                with mission_states_lock:
                    local_assignments = dict(state.get("role_assignments", {}))
                    local_steps = cast(Dict[str, Dict[str, Any]], state.get("steps", {}))
                    scout_requested = bool(state.get("scout_intent_requested", False))
                    completed = bool(state.get("completed"))
                if completed or scout_requested or "scout" in local_steps:
                    return
                preferred_owner = _extract_assigned_agent(local_assignments.get("scout", {}))
                request_role_intent(
                    mission_id=mission_id,
                    role_name="scout",
                    task_type="risk_assessment",
                    task_payload={
                        "signal": str(state.get("payload", {}).get("scout_signal", "abnormal_withdraw")),
                        "mission_id": mission_id,
                    },
                    attempt=1,
                    preferred_role_owner=preferred_owner,
                )
                with mission_states_lock:
                    state["scout_intent_requested"] = True

            threading.Thread(target=_fallback_scout_intent, daemon=True).start()

    def on_role_claim(message: Dict[str, Any]) -> None:
        intent_id = str(message.get("intent_id", "")).strip()
        if not intent_id:
            return
        intent_claims.setdefault(intent_id, []).append(dict(message))

    def evaluate_role_intent(intent_message: Dict[str, Any]) -> None:
        intent_id = str(intent_message.get("intent_id", "")).strip()
        role_name = str(intent_message.get("role", "")).strip().lower()
        mission_id = str(intent_message.get("mission_id", "")).strip()
        task_type = str(intent_message.get("task_type", "")).strip()
        task_payload = dict(intent_message.get("task_payload", {}))
        if not intent_id or not mission_id or role_name not in normalized_roles:
            return
        expires_raw = str(intent_message.get("expires_at", "")).strip()
        expires_ts = _parse_iso_timestamp(expires_raw)
        deadline = min(time.time() + 2.0, expires_ts) if expires_ts > 0.0 else time.time() + 2.0
        expected_agents = _known_role_agents(role_name)
        while time.time() < deadline:
            snapshot = list(intent_claims.get(intent_id, []))
            unique_claim_agents = {
                str(item.get("agent_id", "")).strip() for item in snapshot if str(item.get("agent_id", "")).strip()
            }
            if expected_agents and len(unique_claim_agents) >= len(expected_agents):
                break
            if len(unique_claim_agents) >= 3:
                break
            time.sleep(0.05)
        claims = list(intent_claims.get(intent_id, []))
        by_agent = _dedupe_claims_by_agent(claims)
        if not by_agent:
            return
        winner_agent, _ = _vertex_pick_winner(
            mission_id=mission_id,
            role_name=role_name,
            claim_kind="role_intent_claim",
            by_agent=by_agent,
        )
        if not winner_agent:
            return
        if winner_agent != agent_id:
            return
        state = get_mission_state(mission_id)
        with mission_states_lock:
            if bool(state.get("completed")):
                return
            steps_map = cast(Dict[str, Dict[str, Any]], state.get("steps", {}))
            if role_name in steps_map:
                return
        execution = execute_local_task(
            mission_id=mission_id,
            role_name=role_name,
            task_type=task_type,
            task_payload=task_payload,
        )
        stage_payload = {
            "mission_id": mission_id,
            "role_name": role_name,
            "intent_id": intent_id,
            "state": str(execution.get("state", "")),
            "task_id": str(execution.get("task_id", "")),
            "result": dict(execution.get("result", {})),
            "completed_at": str(execution.get("completed_at", "")),
            "wait_latency_ms": float(execution.get("wait_latency_ms", 0.0)),
            "selected_agent": agent_id,
            "run_id": run_id,
            "namespace": topic_namespace,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        signature_payload = _stage_signature_payload(stage_payload)
        stage_payload["consensus_signature"] = sign_payload(_agent_secret(agent_id), signature_payload)
        kernel.publish(kernel.mission_stage_topic(), stage_payload)

    def on_role_intent(message: Dict[str, Any]) -> None:
        intent_id = str(message.get("intent_id", "")).strip()
        role_name = str(message.get("role", "")).strip().lower()
        if not intent_id or role_name not in normalized_roles:
            return
        expires_at_raw = str(message.get("expires_at", "")).strip()
        if expires_at_raw:
            try:
                expires_at = datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > expires_at:
                    return
            except ValueError:
                return
        metrics = runtime.get_metrics()
        preferred_role_owner = str(message.get("preferred_role_owner", "")).strip()
        task_load = max(
            0.0,
            float(metrics.get("total_tasks", 0.0))
            - float(metrics.get("successful_tasks", 0.0))
            - float(metrics.get("failed_tasks", 0.0)),
        )
        salt = f"{agent_id}:{intent_id}:{role_name}".encode("utf-8")
        tie_break = int(hashlib.sha1(salt).hexdigest()[:6], 16) / float(0xFFFFFF)
        preferred_bonus = 150.0 if preferred_role_owner and preferred_role_owner == agent_id else 0.0
        score = round(1000.0 - task_load * 100.0 + tie_break + preferred_bonus, 6)
        kernel.publish(
            kernel.role_claim_topic(role_name),
            {
                "intent_id": intent_id,
                "mission_id": str(message.get("mission_id", "")).strip(),
                "role": role_name,
                "agent_id": agent_id,
                "score": score,
                "load": task_load,
                "metrics": metrics,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
        with mission_states_lock:
            should_start = intent_id not in started_intent_evaluations
            if should_start:
                started_intent_evaluations.add(intent_id)
        if should_start:
            threading.Thread(target=evaluate_role_intent, args=(dict(message),), daemon=True).start()

    for item in normalized_roles:
        kernel.subscribe(kernel.role_intent_topic(item), on_role_intent)
        kernel.subscribe(kernel.role_claim_topic(item), on_role_claim)
        kernel.subscribe(_role_identity_claim_topic(kernel, item), on_role_identity_claim)
        kernel.subscribe(_role_identity_assigned_topic(kernel, item), on_role_identity_assigned)
    kernel.subscribe(kernel.mission_start_topic(), on_mission_start)
    kernel.subscribe(kernel.mission_stage_topic(), on_mission_stage)
    publish_agent_signal("announce")

    def bootstrap_mission_loop() -> None:
        if not bootstrap_mission:
            return
        ready_deadline = time.time() + max(2.0, float(bootstrap_ready_timeout_seconds))
        while time.time() < ready_deadline:
            readiness = readiness_snapshot()
            if bool(readiness) and set(stage_roles).issubset(discovered_roles(readiness)):
                break
            time.sleep(0.1)
        readiness = readiness_snapshot()
        readiness_ok = bool(readiness) and set(stage_roles).issubset(discovered_roles(readiness))
        if not readiness_ok:
            write_bootstrap_report(bootstrap_mission_id, {})
            if exit_on_mission_complete:
                lifecycle["exit_code"] = 1
                stop_event.set()
            return
        mission_start_payload = {
            "mission_id": bootstrap_mission_id,
            "run_id": run_id,
            "namespace": topic_namespace,
            "scout_signal": "abnormal_withdraw",
            "evidence_hash": "proof-chain-placeholder",
            "pre_guardian_delay_seconds": float(bootstrap_pre_guardian_delay_seconds),
            "role_identity_negotiation": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        on_mission_start(dict(mission_start_payload))
        kernel.publish(kernel.mission_start_topic(), mission_start_payload)
        wait_timeout = max(8.0, float(bootstrap_wait_timeout_seconds))
        wait_deadline = time.time() + wait_timeout
        completion: Dict[str, Any] = {}
        while time.time() < wait_deadline:
            completion = dict(mission_complete_events.get(bootstrap_mission_id, {}))
            if completion and bool(completion.get("all_success", False)):
                break
            time.sleep(0.1)
        finished = bool(completion) and bool(completion.get("all_success", False))
        if not completion:
            write_bootstrap_report(bootstrap_mission_id, {})
        else:
            write_bootstrap_report(bootstrap_mission_id, completion)
        if exit_on_mission_complete:
            lifecycle["exit_code"] = 0 if (finished and bool(completion.get("all_success", False))) else 1
            stop_event.set()

    def heartbeat_loop() -> None:
        while not stop_event.wait(1.0):
            try:
                publish_agent_signal("heartbeat")
            except Exception:
                continue

    heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()
    if bootstrap_mission:
        threading.Thread(target=bootstrap_mission_loop, daemon=True).start()
    print(
        f"AGENT PROCESS READY: id={agent_id} roles={','.join(normalized_roles)} run_id={run_id} "
        f"namespace={topic_namespace} backend={foxmq_backend} mqtt={foxmq_mqtt_addr}"
    )
    try:
        while not stop_event.wait(1.0):
            continue
    except KeyboardInterrupt:
        stop_event.set()
    runtime.stop()
    kernel.stop()
    return int(lifecycle.get("exit_code", 0))


def main() -> int:
    parser = argparse.ArgumentParser(description="Track3 coordination entrypoint")
    parser.add_argument(
        "--mode",
        choices=["internal-single", "internal-acceptance", "agent-process"],
        default="internal-single",
        help="internal-* modes are internal checks; external demo uses agent-process with agent bootstrap mission",
    )
    parser.add_argument(
        "--output-dir",
        default=os.path.join(os.getcwd(), "artifacts", "track3"),
        help="Directory for structured logs and proof files",
    )
    parser.add_argument(
        "--fault",
        choices=["none", "delay", "drop"],
        default="delay",
        help="Fault mode for internal single-process check",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
        help="Number of worker agents for internal checks",
    )
    parser.add_argument(
        "--foxmq-backend",
        choices=["mqtt"],
        default=os.getenv("FOXMQ_BACKEND", "mqtt"),
        help="FoxMQ transport backend",
    )
    parser.add_argument(
        "--foxmq-mqtt-addr",
        default=os.getenv("FOXMQ_MQTT_ADDR", "127.0.0.1:1883"),
        help="MQTT broker address used by mqtt backend, format host:port",
    )
    parser.add_argument("--agent-id", default="", help="Agent id for --mode agent-process")
    parser.add_argument(
        "--agent-capabilities",
        default="scout,guardian,verifier",
        help="Comma-separated role capabilities for agent process, example: scout,guardian,verifier",
    )
    parser.add_argument("--run-id", default="", help="Run identifier used for mission tracking and topic isolation")
    parser.add_argument(
        "--topic-namespace",
        default="",
        help="Topic namespace suffix under coordination/, example: run-20260330",
    )
    parser.add_argument(
        "--bootstrap-mission",
        action="store_true",
        help="In agent-process mode, publish mission_start from this agent without external requester",
    )
    parser.add_argument(
        "--bootstrap-ready-timeout-seconds",
        type=float,
        default=20.0,
        help="In agent-process mode, timeout for observing required role announcements before bootstrap",
    )
    parser.add_argument(
        "--bootstrap-pre-guardian-delay-seconds",
        type=float,
        default=0.0,
        help="In agent-process mode, delay before guardian stage dispatch for bootstrap mission",
    )
    parser.add_argument(
        "--bootstrap-wait-timeout-seconds",
        type=float,
        default=40.0,
        help="In agent-process mode, timeout waiting mission_complete after bootstrap start",
    )
    parser.add_argument(
        "--exit-on-mission-complete",
        action="store_true",
        help="In agent-process mode, exit after bootstrap mission completes or times out",
    )
    args = parser.parse_args()
    run_id = str(args.run_id).strip() or uuid4().hex[:12]
    topic_namespace = _normalize_topic_namespace(str(args.topic_namespace).strip() or f"run-{run_id}")

    if args.mode == "agent-process":
        if not str(args.agent_id).strip():
            raise ValueError("--agent-id is required in --mode agent-process")
        parsed_capabilities = [
            str(item).strip().lower()
            for item in str(args.agent_capabilities).split(",")
            if str(item).strip()
        ]
        return _run_agent_process(
            agent_id=str(args.agent_id),
            role_capabilities=parsed_capabilities,
            foxmq_backend=str(args.foxmq_backend),
            foxmq_mqtt_addr=str(args.foxmq_mqtt_addr),
            run_id=run_id,
            topic_namespace=topic_namespace,
            output_dir=str(args.output_dir),
            bootstrap_mission=bool(args.bootstrap_mission),
            bootstrap_ready_timeout_seconds=float(args.bootstrap_ready_timeout_seconds),
            bootstrap_pre_guardian_delay_seconds=float(args.bootstrap_pre_guardian_delay_seconds),
            bootstrap_wait_timeout_seconds=float(args.bootstrap_wait_timeout_seconds),
            exit_on_mission_complete=bool(args.exit_on_mission_complete),
        )

    if args.mode == "internal-acceptance":
        acceptance = run_acceptance(
            output_dir=args.output_dir,
            worker_count=args.workers,
            foxmq_backend=args.foxmq_backend,
            foxmq_mqtt_addr=args.foxmq_mqtt_addr or None,
        )
        print("\nTRACK3 ACCEPTANCE SUMMARY")
        print(f"Report: {acceptance['report_path']}")
        print(f"Transport: {args.foxmq_backend}")
        for name, passed in acceptance["criteria"].items():
            print(f"{name}: {'PASS' if passed else 'FAIL'}")
        return 0

    selected_fault = cast(Literal["none", "delay", "drop"], args.fault)
    summary = run_demo(
        output_dir=args.output_dir,
        fault_mode=selected_fault,
        worker_count=args.workers,
        foxmq_backend=args.foxmq_backend,
        foxmq_mqtt_addr=args.foxmq_mqtt_addr or None,
    )
    print("\nTRACK3 DEMO SUMMARY")
    print(f"Task ID:      {summary['task_id']}")
    print(f"Winner:       {summary['winner']}")
    print(f"Fault Mode:   {summary['fault_mode']}")
    print(f"Active Nodes: {', '.join(summary['active_nodes'])}")
    print(f"Events:       {summary['event_count']}")
    print(f"Proof Hash:   {summary['proof_hash']}")
    print(f"Signers:      {summary['signer_count']}")
    print(f"Event Log:    {summary['event_log_path']}")
    print(f"Commit Log:   {summary['commit_log_path']}")
    print(f"Proof File:   {summary['proof_path']}")
    print(f"Settlement:   {summary['settlement_tx_hash']}")
    print(f"Transport:    {summary['transport_backend']}")
    print(f"Checks:       {summary['checks']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
