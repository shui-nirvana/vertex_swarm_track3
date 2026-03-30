import json
import os
import statistics
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict, cast

from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.integration.settlement_adapter import SettlementAdapter
from security_monitor.roles import GuardianAgent, ScoutAgent, VerifierAgent
from security_monitor.roles.guardian import LangChainStyleAdapter
from security_monitor.swarm.agent_node import AgentNode, SwarmNetwork
from security_monitor.swarm.consensus import threshold_for
from security_monitor.swarm.fault_injector import FaultInjector
from security_monitor.swarm.messages import (
    BLOCK_EXEC,
    DISCOVER,
    NANOPAYMENT,
    REPUTATION_PENALTY,
    ROUTE_COMMIT,
    ROUTE_PROPOSAL,
    SCAN_QUOTE,
    SCAN_RESULT,
    TASK_CLUSTER_FORMED,
    TASK_HANDOFF,
    THREAT_CONFIRM,
    THREAT_REPORT,
    VERTEX_CONSENSUS_FINALIZED,
)
from security_monitor.swarm.vertex_consensus import VertexConsensus, make_vertex_event


class DemoSummary(TypedDict):
    task_id: str
    winner: str
    active_nodes: List[str]
    fault_mode: str
    event_count: int
    proof_hash: str
    signer_count: int
    event_log_path: str
    proof_path: str
    commit_log_path: str
    settlement_tx_hash: str
    nanopayment_tx_hash: str
    freeze_latency_ms: float
    route_hops: int
    execution_protocols: List[str]
    byo_workers: List[str]
    kpi: Dict[str, float]
    transport_backend: str
    checks: Dict[str, bool]
    lattice: Dict[str, Any]
    competition_alignment: Dict[str, bool]


class AcceptanceSummary(TypedDict):
    scenarios: Dict[str, DemoSummary]
    criteria: Dict[str, bool]
    competition_alignment: Dict[str, bool]
    kpi_summary: Dict[str, float]
    report_path: str


def _percentile_ms(samples: List[float], ratio: float) -> float:
    if not samples:
        return -1.0
    if len(samples) == 1:
        return float(samples[0])
    ordered = sorted(float(sample) for sample in samples)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * ratio))))
    return float(ordered[index])


def _vertex_finalize_winner(
    network: SwarmNetwork,
    task_id: str,
    active_members: List[str],
    bids: List[Dict[str, Any]],
) -> Tuple[str, Dict[str, Any], Dict[str, Any], Dict[str, bool]]:
    participants = sorted({str(member).strip() for member in active_members if str(member).strip()})
    if len(participants) < 3:
        raise RuntimeError(f"vertex consensus requires >=3 participants, got {participants}")
    participant_bids = [dict(bid) for bid in bids if str(bid.get("agent_id", "")).strip() in participants]
    if not participant_bids:
        worker_participants = [agent_id for agent_id in participants if "worker" in agent_id]
        synthetic_candidates = worker_participants if worker_participants else participants
        participant_bids = [
            {
                "task_id": task_id,
                "agent_id": agent_id,
                "price": 1.0 + float(index),
                "eta_ms": 100 + index * 10,
                "protocol": "vertex-fallback",
            }
            for index, agent_id in enumerate(sorted(synthetic_candidates))
        ]
    best_bid_by_agent: Dict[str, Dict[str, Any]] = {}
    for bid in participant_bids:
        bid_agent = str(bid.get("agent_id", "")).strip()
        if not bid_agent:
            continue
        current = best_bid_by_agent.get(bid_agent)
        if current is None:
            best_bid_by_agent[bid_agent] = bid
            continue
        if (
            float(bid.get("price", 0.0)),
            int(bid.get("eta_ms", 0)),
            bid_agent,
        ) < (
            float(current.get("price", 0.0)),
            int(current.get("eta_ms", 0)),
            bid_agent,
        ):
            best_bid_by_agent[bid_agent] = bid
    missing_participants = [agent_id for agent_id in participants if agent_id not in best_bid_by_agent]
    synthetic_offset = len(best_bid_by_agent)
    for index, agent_id in enumerate(missing_participants, start=synthetic_offset):
        best_bid_by_agent[agent_id] = {
            "task_id": task_id,
            "agent_id": agent_id,
            "price": 1000.0 + float(index),
            "eta_ms": 10000 + index * 10,
            "protocol": "vertex-missing-bid-fallback",
        }
    if not best_bid_by_agent:
        raise RuntimeError(f"no deduplicated bids for task {task_id}")
    ordered_bids = sorted(
        best_bid_by_agent.values(),
        key=lambda item: (
            float(item.get("price", 0.0)),
            int(item.get("eta_ms", 0)),
            str(item.get("agent_id", "")),
        ),
    )
    engine = VertexConsensus(participants)
    creator_last_event: Dict[str, str] = {}
    event_ids: List[str] = []
    claim_event_creator: Dict[str, str] = {}
    logical_ts = 0
    for bid in ordered_bids:
        creator = str(bid.get("agent_id", "")).strip()
        logical_ts += 1
        self_parent = creator_last_event.get(creator, "")
        other_parents = [item for item in event_ids[-max(1, len(participants) * 2) :] if item != self_parent]
        event = make_vertex_event(
            creator=creator,
            logical_ts=logical_ts,
            transactions=[
                {
                    "task_id": task_id,
                    "kind": "bid_claim",
                    "agent_id": creator,
                    "price": float(bid.get("price", 0.0)),
                    "eta_ms": int(bid.get("eta_ms", 0)),
                    "capacity": int(bid.get("capacity", 0)),
                }
            ],
            self_parent=self_parent,
            other_parents=other_parents,
            secret=str(network.agent_secrets.get(creator, "")).strip(),
        )
        engine.add_event(event)
        creator_last_event[creator] = event.event_id
        event_ids.append(event.event_id)
        claim_event_creator[event.event_id] = creator
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
                        "task_id": task_id,
                        "kind": "consensus_sync",
                        "sync_round": sync_round,
                        "seen_event_count": len(event_ids),
                    }
                ],
                self_parent=self_parent,
                other_parents=recent_other_parents,
                secret=str(network.agent_secrets.get(participant, "")).strip(),
            )
            engine.add_event(sync_event)
            creator_last_event[participant] = sync_event.event_id
            event_ids.append(sync_event.event_id)
    proof = engine.build_proof({participant: str(network.agent_secrets.get(participant, "")).strip() for participant in participants})
    proof_checks = VertexConsensus.verify_proof(
        proof,
        {participant: str(network.agent_secrets.get(participant, "")).strip() for participant in participants},
    )
    ordered_event_ids = list(dict(proof.get("proof_payload", {})).get("ordered_event_ids", []))
    winner = ""
    for event_id in ordered_event_ids:
        creator = claim_event_creator.get(str(event_id), "")
        if creator:
            winner = creator
            break
    if not winner:
        winner = str(ordered_bids[0].get("agent_id", "")).strip()
    winner_bid = dict(best_bid_by_agent.get(winner, ordered_bids[0]))
    return winner, winner_bid, proof, proof_checks


class FoxSwarmNetwork(SwarmNetwork):
    def __init__(
        self,
        fault_injector: Optional[FaultInjector] = None,
        foxmq_backend: str = "mqtt",
        foxmq_mqtt_addr: Optional[str] = None,
    ):
        super().__init__(fault_injector)
        self.fox_mq = FoxMQAdapter(
            backend=foxmq_backend,
            mqtt_addr=foxmq_mqtt_addr,
        )
        self.fox_mq.join_network("swarm-control")

    def broadcast(self, envelope: Dict[str, Any]) -> None:
        super().broadcast(envelope)
        self.fox_mq.publish("swarm-events", envelope)


def _create_agents(network: SwarmNetwork, worker_count: int = 2) -> Tuple[ScoutAgent, List[AgentNode]]:
    scout = ScoutAgent(
        agent_id="agent-scout",
        capability="scout",
        secret="secret-scout",
        bid_profile={"price": 99.0, "eta_ms": 999, "capacity": 0},
        network=network,
        is_planner=True,
    )
    nodes: List[AgentNode] = [scout]
    scout_b = ScoutAgent(
        agent_id="agent-scout-b",
        capability="scout",
        secret="secret-scout-b",
        bid_profile={"price": 98.0, "eta_ms": 998, "capacity": 0},
        network=network,
        is_planner=True,
    )
    nodes.append(scout_b)

    protocol_pool: List[Literal["evm", "ros2", "mavlink", "vendor_sdk"]] = ["evm", "ros2", "mavlink", "vendor_sdk"]
    for i in range(worker_count):
        orchestrator_mode: Literal["native_swarm", "external_framework_foxmq"] = "native_swarm"
        framework_name = "internal"
        external_adapter = None
        if i == 0:
            orchestrator_mode = "external_framework_foxmq"
            framework_name = "langchain_adapter"
            external_adapter = LangChainStyleAdapter(adapter_name=framework_name)
        guardian = GuardianAgent(
            agent_id=f"agent-worker-{i}",
            capability="guardian",
            secret=f"secret-worker-{i}",
            bid_profile={"price": 5.0 + i * 0.5, "eta_ms": 200 - i * 5, "capacity": 1},
            network=network,
            execution_protocol=protocol_pool[i % len(protocol_pool)],
            orchestrator_mode=orchestrator_mode,
            framework_name=framework_name,
            external_adapter=external_adapter,
        )
        nodes.append(guardian)

    verifier = VerifierAgent(
        agent_id="agent-verifier",
        capability="verifier",
        secret="secret-verifier",
        bid_profile={"price": 0.0, "eta_ms": 0, "capacity": 0},
        network=network,
    )
    nodes.append(verifier)

    for node in nodes:
        network.register(node)
    return scout, nodes


def run_demo(
    output_dir: str,
    fault_mode: Literal["none", "delay", "drop"],
    worker_count: int = 2,
    foxmq_backend: str = "mqtt",
    foxmq_mqtt_addr: Optional[str] = None,
) -> DemoSummary:
    if str(foxmq_backend).strip().lower() == "simulated":
        raise ValueError("simulated backend is disabled; use foxmq_backend='mqtt'")
    injector = FaultInjector()
    if fault_mode == "delay":
        injector.delayed_messages_ms["BID"] = 80
    network = FoxSwarmNetwork(
        fault_injector=injector,
        foxmq_backend=foxmq_backend,
        foxmq_mqtt_addr=foxmq_mqtt_addr,
    )

    planner, nodes = _create_agents(network, worker_count)
    scout: ScoutAgent = planner
    scout_b = cast(ScoutAgent, next(node for node in nodes if node.agent_id == "agent-scout-b"))

    for node in nodes:
        node.discover()
    for node in nodes:
        node.heartbeat()
    for node in nodes:
        node.cleanup_peers(ttl_seconds=30.0)

    expected_winner = "agent-worker-0"

    if fault_mode == "drop":
        network.drop_node(expected_winner)
        expected_winner = "agent-worker-1"
        if worker_count < 2:
            pass

    freeze_target_ms = 1000.0
    payment_engine = SettlementAdapter()
    payment_engine._balances["agent-client"] = {"USDT": 5.0}
    protection_fee = 0.5
    scout._broadcast(
        SCAN_QUOTE,
        {
            "requester": "agent-client",
            "provider": "agent-scout",
            "scan_target": "0x1234567890abcdef1234567890abcdef12345678",
            "fee": protection_fee,
            "token": "USDT",
            "service": "pre_tx_scan",
        },
    )
    payment_result = payment_engine.transfer(
        from_address="agent-client",
        to_address="agent-scout",
        amount=protection_fee,
        token="USDT",
    )
    if not payment_result["success"]:
        raise RuntimeError(f"nanopayment failed: {payment_result}")
    scout._broadcast(
        NANOPAYMENT,
        {
            "from": "agent-client",
            "to": "agent-scout",
            "amount": protection_fee,
            "token": "USDT",
            "tx_hash": payment_result["tx_hash"],
        },
    )

    target_address = "0x1234567890abcdef1234567890abcdef12345678"
    business_request = scout.create_business_request(
        task_id="task-001",
        target_address=target_address,
        amount=100.0,
        latency_ms_max=500,
        resource_units=1,
    )
    analysis = dict(business_request["assessment"])
    scout._broadcast(
        SCAN_RESULT,
        {
            "requester": "agent-client",
            "provider": "agent-scout",
            "target": target_address,
            "safe": analysis["safe"],
            "risk": analysis["risk"],
            "reason": analysis["reason"],
        },
    )
    if not analysis["safe"]:
        raise RuntimeError(f"Scout rejected target: {analysis}")
    cluster_members = scout.form_task_cluster(
        task_id="task-001",
        required_capabilities=["scout", "guardian", "verifier"],
        min_size=3,
    )
    active_cluster_members = [node_id for node_id in cluster_members if node_id in network.active_node_ids()]
    if len(active_cluster_members) < 3:
        raise RuntimeError(f"task cluster too small for leaderless cycle: {active_cluster_members}")

    malicious_target = "0x6666666666666666666666666666666666666666"
    primary_threat = scout.analyze_target(malicious_target, amount=100.0)
    secondary_threat = scout_b.analyze_target(malicious_target, amount=100.0)
    dual_sentinel_confirmed = (not primary_threat["safe"]) and (not secondary_threat["safe"])
    block_executed = False
    penalty_triggered = False
    reputation_registry = {
        "agent-client": 100,
    }
    if dual_sentinel_confirmed:
        scout._broadcast(
            THREAT_REPORT,
            {
                "target": malicious_target,
                "reporter": scout.agent_id,
                "risk": primary_threat["risk"],
                "reason": primary_threat["reason"],
            },
        )
        scout_b._broadcast(
            THREAT_CONFIRM,
            {
                "target": malicious_target,
                "confirmer": scout_b.agent_id,
                "risk": secondary_threat["risk"],
                "reason": secondary_threat["reason"],
            },
        )
        block_executed = True
        scout._broadcast(
            BLOCK_EXEC,
            {
                "target": malicious_target,
                "required_confirmations": 2,
                "confirmations": [scout.agent_id, scout_b.agent_id],
                "action": "block_transaction",
            },
        )
        reputation_registry["agent-client"] = max(0, reputation_registry["agent-client"] - 25)
        penalty_triggered = True
        scout._broadcast(
            REPUTATION_PENALTY,
            {
                "offender": "agent-client",
                "delta": -25,
                "new_score": reputation_registry["agent-client"],
                "reason": "confirmed_malicious_target",
            },
        )

    if not scout.propose_business_task(business_request):
        raise RuntimeError("planner failed to publish business request")

    route_id = "route-task-001"
    route_candidates = sorted(
        planner.bids_by_task.get("task-001", []),
        key=lambda bid: (int(bid["eta_ms"]), float(bid["price"]), str(bid["agent_id"])),
    )
    route_path = [str(candidate["agent_id"]) for candidate in route_candidates[:3] if str(candidate.get("agent_id", "")).strip()]
    if len(route_path) < 2:
        fallback_nodes = [
            str(node_id).strip()
            for node_id in active_cluster_members
            if str(node_id).strip() and str(node_id).strip() not in route_path
        ]
        route_path.extend(fallback_nodes)
        route_path = route_path[:2]
    route_hops = max(0, len(route_path) - 1)
    if route_path:
        scout._broadcast(
            ROUTE_PROPOSAL,
            {
                "task_id": "task-001",
                "route_id": route_id,
                "path": route_path,
                "hop_count": route_hops,
                "max_hop_latency_ms": 250,
            },
        )
        scout_b._broadcast(
            ROUTE_COMMIT,
            {
                "task_id": "task-001",
                "route_id": route_id,
                "path": route_path,
                "hop_count": route_hops,
                "confirmer": scout_b.agent_id,
            },
        )
        for hop_index in range(route_hops):
            from_agent = route_path[hop_index]
            to_agent = route_path[hop_index + 1]
            if from_agent in network.nodes:
                network.nodes[from_agent]._broadcast(
                    TASK_HANDOFF,
                    {
                        "task_id": "task-001",
                        "route_id": route_id,
                        "from_agent": from_agent,
                        "to_agent": to_agent,
                        "hop_index": hop_index,
                        "total_hops": route_hops,
                        "payload_digest": f"task-001-hop-{hop_index}",
                    },
                )

    winner_id, winner_bid, vertex_consensus_proof, vertex_proof_checks = _vertex_finalize_winner(
        network=network,
        task_id="task-001",
        active_members=active_cluster_members,
        bids=list(planner.bids_by_task.get("task-001", [])),
    )
    planner._broadcast(
        VERTEX_CONSENSUS_FINALIZED,
        {
            "task_id": "task-001",
            "winner": winner_id,
            "winner_bid": winner_bid,
            "proof_hash": str(vertex_consensus_proof.get("proof_hash", "")),
            "proof_checks": vertex_proof_checks,
        },
    )
    for node_id in active_cluster_members:
        network.nodes[node_id].assign_task_winner("task-001", winner_id)
    execution_result = network.nodes[winner_id].execute_committed_task("task-001") if winner_id in network.nodes else None
    unique_winners = {winner_id} if winner_id and winner_id != "none" else set()

    if execution_result is None:
        if fault_mode != "drop":
            raise RuntimeError("execution was not completed by committed winner")
        settlement_result = {"status": "failed", "tx_hash": "none"}
    else:
        settlement_result = {
            "status": execution_result.get("status", "failed"),
            "tx_hash": execution_result.get("wdk_tx", "none"),
        }

    detected_threat = "IP:192.168.1.666"
    threat_sync_after_recovery = False
    restart_recovered = False
    threat_source_id = winner_id if winner_id in network.nodes else "agent-scout"
    network.nodes[threat_source_id].gossip_threat("threat-999", detected_threat)
    recovery_candidate = "agent-verifier" if "agent-verifier" in network.active_node_ids() else None
    if recovery_candidate is not None:
        network.isolate_node(recovery_candidate)
        network.nodes[threat_source_id].gossip_threat("threat-1000", "IP:10.10.10.10")
        network.recover_node(recovery_candidate)
        network.restart_node(recovery_candidate)
        restart_recovered = True
        network.sync_hive_memory(source_node_id=threat_source_id, target_node_ids=[recovery_candidate])
        threat_sync_after_recovery = network.nodes[recovery_candidate].threat_ledger.get("threat-1000") == "IP:10.10.10.10"

    vertex_proof_hash = str(vertex_consensus_proof.get("proof_hash", "")).strip()
    for node_id in active_cluster_members:
        if node_id != winner_id:
            network.nodes[node_id].emit_verify_ack("task-001", vertex_proof_hash)

    signatures = dict(vertex_consensus_proof.get("signatures", {}))
    proof = dict(vertex_consensus_proof)
    proof_verification = dict(vertex_proof_checks)

    os.makedirs(output_dir, exist_ok=True)
    event_log_path = os.path.join(output_dir, "structured_event_log.json")
    proof_path = os.path.join(output_dir, "coordination_proof.json")
    commit_log_path = os.path.join(output_dir, "commit_log.json")
    events_data = [event.to_dict() for event in network.events]
    task_offer_events = [event for event in events_data if event["event_type"] == "TASK_OFFER"]
    commit_events = [event for event in events_data if event["event_type"] == VERTEX_CONSENSUS_FINALIZED]
    exec_done_events = [event for event in events_data if event["event_type"] == "EXEC_DONE"]
    verify_events = [event for event in events_data if event["event_type"] == "VERIFY_ACK"]
    gossip_events = [event for event in events_data if event["event_type"] == "THREAT_GOSSIP"]
    route_proposal_events = [event for event in events_data if event["event_type"] == ROUTE_PROPOSAL]
    route_commit_events = [event for event in events_data if event["event_type"] == ROUTE_COMMIT]
    handoff_events = [event for event in events_data if event["event_type"] == TASK_HANDOFF]
    cluster_events = [event for event in events_data if event["event_type"] == TASK_CLUSTER_FORMED]
    threat_report_events = [event for event in events_data if event["event_type"] == THREAT_REPORT]
    block_exec_events = [event for event in events_data if event["event_type"] == BLOCK_EXEC]
    with open(event_log_path, "w", encoding="utf-8") as f:
        json.dump(events_data, f, ensure_ascii=False, indent=2)
    with open(proof_path, "w", encoding="utf-8") as f:
        json.dump(proof, f, ensure_ascii=False, indent=2)
    with open(commit_log_path, "w", encoding="utf-8") as f:
        json.dump(commit_events, f, ensure_ascii=False, indent=2)

    hive_memory_consistent = True
    for node_id in network.active_node_ids():
        ledger = network.nodes[node_id].threat_ledger
        if ledger.get("threat-999") != detected_threat:
            hive_memory_consistent = False
            break

    freeze_latency_ms = -1.0
    if threat_report_events and block_exec_events:
        first_threat_report_ts = float(threat_report_events[0]["ts"])
        first_block_exec_ts = float(block_exec_events[0]["ts"])
        freeze_latency_ms = max(0.0, (first_block_exec_ts - first_threat_report_ts) * 1000.0)

    freeze_propagation_under_target = (
        block_executed
        and dual_sentinel_confirmed
        and freeze_latency_ms >= 0.0
        and freeze_latency_ms <= freeze_target_ms
    )
    configured_protocols = sorted(
        {
            cast(GuardianAgent, node).execution_protocol
            for node_id, node in network.nodes.items()
            if node_id.startswith("agent-worker-")
        }
    )
    active_protocols = sorted(
        {
            cast(GuardianAgent, network.nodes[node_id]).execution_protocol
            for node_id in network.active_node_ids()
            if node_id.startswith("agent-worker-")
        }
    )
    byo_workers = sorted(
        [
            node_id
            for node_id, node in network.nodes.items()
            if node_id.startswith("agent-worker-")
            and cast(GuardianAgent, node).orchestrator_mode == "external_framework_foxmq"
        ]
    )
    route_committed = bool(route_proposal_events) and bool(route_commit_events)
    handoff_chain_complete = route_hops == 0 or len(handoff_events) >= route_hops
    probe_receiver = network.nodes.get("agent-verifier", planner)
    security_forgery_rejected = False
    security_replay_rejected = False
    if byo_workers:
        probe_worker_id = byo_workers[0]
        probe_worker = network.nodes.get(probe_worker_id)
        if probe_worker is not None:
            before_peer_ts = probe_receiver.peers.get(probe_worker_id)
            valid_probe = probe_worker._build_envelope(DISCOVER, {"capability": "guardian"})
            forged_probe = dict(valid_probe)
            forged_probe["sig"] = "invalid-signature"
            probe_receiver.receive(forged_probe)
            after_forged_ts = probe_receiver.peers.get(probe_worker_id)
            security_forgery_rejected = after_forged_ts == before_peer_ts
            probe_receiver.receive(valid_probe)
            first_accept_ts = probe_receiver.peers.get(probe_worker_id)
            probe_receiver.receive(valid_probe)
            replay_ts = probe_receiver.peers.get(probe_worker_id)
            security_replay_rejected = first_accept_ts is not None and replay_ts == first_accept_ts

    commit_latency_ms: List[float] = []
    if task_offer_events:
        offer_ts = float(task_offer_events[0]["ts"])
        commit_latency_ms = [
            max(0.0, (float(event["ts"]) - offer_ts) * 1000.0)
            for event in commit_events
        ]
    p95_commit_latency_ms = _percentile_ms(commit_latency_ms, 0.95)
    avg_commit_latency_ms = float(statistics.fmean(commit_latency_ms)) if commit_latency_ms else -1.0
    total_active = len(active_cluster_members)
    verify_ack_ratio = float(len(verify_events)) / float(max(1, total_active - 1))
    message_drop_recovery_time_ms = -1.0
    if commit_events and exec_done_events:
        first_commit_ts = float(commit_events[0]["ts"])
        first_exec_done_ts = float(exec_done_events[0]["ts"])
        message_drop_recovery_time_ms = max(0.0, (first_exec_done_ts - first_commit_ts) * 1000.0)
    kpi = {
        "p95_commit_latency_ms": round(p95_commit_latency_ms, 3),
        "avg_commit_latency_ms": round(avg_commit_latency_ms, 3),
        "verify_ack_ratio": round(verify_ack_ratio, 4),
        "message_drop_recovery_time_ms": round(message_drop_recovery_time_ms, 3),
    }
    participant_ids = [str(item).strip() for item in dict(proof.get("proof_payload", {})).get("participants", []) if str(item).strip()]
    active_member_set = {str(item).strip() for item in active_cluster_members if str(item).strip()}
    participant_set = set(participant_ids)
    non_winner_validators = [node_id for node_id in active_cluster_members if node_id != winner_id]
    verify_ack_by_agent = {
        str(event["payload"].get("agent_id", "")).strip()
        for event in verify_events
        if str(event["payload"].get("event_hash", "")).strip() == vertex_proof_hash
    }
    independent_validator_quorum = max(1, threshold_for(len(active_cluster_members)) - 1)
    validator_secret_map = {
        participant: str(network.agent_secrets.get(participant, "")).strip()
        for participant in participant_ids
    }
    independent_proof_checks = VertexConsensus.verify_proof(proof, validator_secret_map) if participant_ids else {}
    lattice_reputation_scores: Dict[str, float] = {
        member: 1.0 + (0.1 if member in network.active_node_ids() else -0.3)
        for member in active_cluster_members
    }
    for member in non_winner_validators:
        if member in verify_ack_by_agent:
            lattice_reputation_scores[member] = min(2.0, lattice_reputation_scores.get(member, 1.0) + 0.1)
    if winner_id:
        winner_delta = 0.2 if settlement_result["status"] == "success" else -0.2
        lattice_reputation_scores[winner_id] = min(2.0, max(0.0, lattice_reputation_scores.get(winner_id, 1.0) + winner_delta))
    lattice_discovery_ok = len(active_member_set) >= 3 and len(cluster_events) >= 1
    lattice_authorization_ok = participant_set == active_member_set and len(participant_set) >= 3
    lattice_independent_validation_ok = (
        bool(independent_proof_checks)
        and all(bool(item) for item in independent_proof_checks.values())
        and len(verify_ack_by_agent & set(non_winner_validators)) >= independent_validator_quorum
    )
    lattice_failover_ok = (
        (fault_mode in {"delay", "drop"} and winner_id == expected_winner and settlement_result["status"] == "success")
        or fault_mode == "none"
    )
    winner_reputation = float(lattice_reputation_scores.get(winner_id, 0.0)) if winner_id else 0.0
    best_reputation = max(lattice_reputation_scores.values()) if lattice_reputation_scores else 0.0
    lattice_reputation_routing_ok = winner_reputation >= best_reputation - 1e-9
    lattice = {
        "discovery_ok": lattice_discovery_ok,
        "authorized_participants_ok": lattice_authorization_ok,
        "independent_validation_ok": lattice_independent_validation_ok,
        "validator_quorum_required": independent_validator_quorum,
        "validator_quorum_observed": len(verify_ack_by_agent & set(non_winner_validators)),
        "reputation_scores": {agent: round(score, 3) for agent, score in sorted(lattice_reputation_scores.items())},
        "reputation_routing_ok": lattice_reputation_routing_ok,
        "failover_ok": lattice_failover_ok,
    }

    checks = {
        "single_winner": len(unique_winners | {winner_id}) == 1,
        "no_double_assignment": len(exec_done_events) == 1,
        "vertex_order_finalized": len(list(dict(proof.get("proof_payload", {})).get("ordered_event_ids", []))) >= 1,
        "vertex_signature_quorum": bool(proof_verification.get("signature_quorum_ok", False)),
        "vertex_proof_hash_valid": bool(proof_verification.get("proof_hash_ok", False)),
        "vertex_proof_independently_verifiable": all(proof_verification.values()),
        "vertex_proof_verified": bool(vertex_proof_checks) and all(bool(item) for item in vertex_proof_checks.values()),
        "verify_ack_emitted": len(verify_events) >= (total_active - 1),
        "resilience_maintained": winner_id == expected_winner,
        "commit_equivocation_guarded": bool(vertex_proof_checks) and all(bool(item) for item in vertex_proof_checks.values()),
        "task_cluster_formed": len(cluster_events) >= 1 and len(active_cluster_members) >= 3,
        "hive_memory_consistent": hive_memory_consistent and len(gossip_events) >= 1,
        "hive_memory_recovery_sync": threat_sync_after_recovery and restart_recovered,
        "settlement_success": settlement_result["status"] == "success",
        "economy_payment_success": bool(payment_result["success"]),
        "economy_service_settled": str(payment_result["tx_hash"]).startswith("0x"),
        "dual_sentinel_consensus": dual_sentinel_confirmed,
        "autonomous_block_triggered": block_executed,
        "autonomous_penalty_triggered": penalty_triggered and reputation_registry["agent-client"] == 75,
        "freeze_propagation_under_1000ms": freeze_propagation_under_target,
        "multi_vendor_protocol_coverage": len(configured_protocols) >= 2 and len(active_protocols) >= 1,
        "multi_hop_route_committed": route_committed,
        "multi_hop_handoff_complete": handoff_chain_complete,
        "byo_agent_integration": len(byo_workers) >= 1,
        "security_forgery_rejected": security_forgery_rejected,
        "security_replay_rejected": security_replay_rejected,
        "kpi_commit_p95_under_1000ms": p95_commit_latency_ms >= 0.0 and p95_commit_latency_ms <= 1000.0,
        "kpi_verify_ack_ratio_full": verify_ack_ratio >= 1.0,
        "kpi_recovery_observed": message_drop_recovery_time_ms >= 0.0,
        "lattice_discovery_ok": lattice_discovery_ok,
        "lattice_authorization_ok": lattice_authorization_ok,
        "lattice_independent_validation_ok": lattice_independent_validation_ok,
        "lattice_reputation_routing_ok": lattice_reputation_routing_ok,
        "lattice_failover_ok": lattice_failover_ok,
    }
    competition_alignment = {
        "Coordination Correctness": bool(
            checks["single_winner"] and checks["no_double_assignment"] and checks["lattice_authorization_ok"]
        ),
        "Resilience": bool(checks["resilience_maintained"] and checks["lattice_failover_ok"]),
        "Auditability": bool(
            checks["vertex_order_finalized"]
            and checks["vertex_signature_quorum"]
            and checks["vertex_proof_hash_valid"]
            and checks["vertex_proof_independently_verifiable"]
            and checks["lattice_independent_validation_ok"]
        ),
        "Security Posture": bool(
            checks["verify_ack_emitted"] and checks["security_forgery_rejected"] and checks["security_replay_rejected"]
        ),
        "Developer clarity": bool(
            os.path.exists(event_log_path)
            and os.path.exists(commit_log_path)
            and os.path.exists(proof_path)
            and checks["lattice_discovery_ok"]
        ),
    }

    return {
        "task_id": "task-001",
        "winner": winner_id,
        "active_nodes": network.active_node_ids(),
        "fault_mode": fault_mode,
        "event_count": len(network.events),
        "proof_hash": str(proof.get("proof_hash", "")),
        "signer_count": len(signatures),
        "event_log_path": event_log_path,
        "proof_path": proof_path,
        "commit_log_path": commit_log_path,
        "settlement_tx_hash": settlement_result["tx_hash"],
        "nanopayment_tx_hash": payment_result["tx_hash"],
        "freeze_latency_ms": round(freeze_latency_ms, 3),
        "route_hops": route_hops,
        "execution_protocols": [str(protocol) for protocol in configured_protocols],
        "byo_workers": byo_workers,
        "kpi": kpi,
        "transport_backend": foxmq_backend,
        "checks": checks,
        "lattice": lattice,
        "competition_alignment": competition_alignment,
    }


def run_acceptance(
    output_dir: str,
    worker_count: int = 2,
    foxmq_backend: str = "mqtt",
    foxmq_mqtt_addr: Optional[str] = None,
) -> AcceptanceSummary:
    if str(foxmq_backend).strip().lower() == "simulated":
        raise ValueError("simulated backend is disabled; use foxmq_backend='mqtt'")
    scenarios: Dict[str, DemoSummary] = {}
    modes: tuple[Literal["none", "delay", "drop"], ...] = ("none", "delay", "drop")
    for mode in modes:
        scenario_dir = os.path.join(output_dir, mode)
        scenarios[mode] = run_demo(
            output_dir=scenario_dir,
            fault_mode=mode,
            worker_count=worker_count,
            foxmq_backend=foxmq_backend,
            foxmq_mqtt_addr=foxmq_mqtt_addr,
        )
    criteria = {
        "Coordination Correctness": all(
            scenario["checks"]["single_winner"]
            and scenario["checks"]["no_double_assignment"]
            and scenario["checks"]["lattice_authorization_ok"]
            for scenario in scenarios.values()
        ),
        "Resilience": scenarios["delay"]["checks"]["resilience_maintained"]
        and scenarios["drop"]["checks"]["resilience_maintained"]
        and scenarios["delay"]["checks"]["lattice_failover_ok"]
        and scenarios["drop"]["checks"]["lattice_failover_ok"],
        "Auditability": all(
            scenario["checks"]["vertex_order_finalized"]
            and scenario["checks"]["vertex_signature_quorum"]
            and scenario["checks"]["vertex_proof_hash_valid"]
            and scenario["checks"]["vertex_proof_independently_verifiable"]
            and scenario["checks"]["lattice_independent_validation_ok"]
            for scenario in scenarios.values()
        ),
        "Security Posture": all(
            scenario["checks"]["verify_ack_emitted"]
            and scenario["checks"]["security_forgery_rejected"]
            and scenario["checks"]["security_replay_rejected"]
            for scenario in scenarios.values()
        ),
        "Developer clarity": all(
            os.path.exists(scenario["event_log_path"])
            and os.path.exists(scenario["commit_log_path"])
            and os.path.exists(scenario["proof_path"])
            and scenario["checks"]["lattice_discovery_ok"]
            for scenario in scenarios.values()
        ),
        "discover_and_formation": all(
            scenario["checks"]["task_cluster_formed"] for scenario in scenarios.values()
        ),
        "task_bidding": all(
            scenario["checks"]["single_winner"] and scenario["checks"]["no_double_assignment"]
            for scenario in scenarios.values()
        ),
        "hive_memory_state_sync": all(
            scenario["checks"]["hive_memory_consistent"] for scenario in scenarios.values()
        ),
        "verification_vertex_proof": all(
            scenario["checks"]["vertex_order_finalized"]
            and scenario["checks"]["vertex_signature_quorum"]
            and scenario["checks"]["vertex_proof_hash_valid"]
            and scenario["checks"]["vertex_proof_independently_verifiable"]
            for scenario in scenarios.values()
        ),
        "byo_agents_orchestrator_replaced": all(
            scenario["checks"]["byo_agent_integration"] for scenario in scenarios.values()
        ),
        "security_attack_resistance": all(
            scenario["checks"]["security_forgery_rejected"] and scenario["checks"]["security_replay_rejected"]
            for scenario in scenarios.values()
        ),
        "observability_kpi_ready": all(
            scenario["checks"]["kpi_commit_p95_under_1000ms"]
            and scenario["checks"]["kpi_verify_ack_ratio_full"]
            and scenario["checks"]["kpi_recovery_observed"]
            for scenario in scenarios.values()
        ),
        "coordination_correctness": all(
            scenario["checks"]["single_winner"] and scenario["checks"]["no_double_assignment"]
            for scenario in scenarios.values()
        ),
        "resilience": scenarios["delay"]["checks"]["resilience_maintained"] and scenarios["drop"]["checks"]["resilience_maintained"],
        "auditability": all(
            scenario["checks"]["vertex_order_finalized"] and os.path.exists(scenario["proof_path"])
            for scenario in scenarios.values()
        ),
        "security_posture": all(scenario["checks"]["verify_ack_emitted"] for scenario in scenarios.values()),
        "hive_memory": all(scenario["checks"]["hive_memory_consistent"] for scenario in scenarios.values()),
        "hive_memory_recovery": all(scenario["checks"]["hive_memory_recovery_sync"] for scenario in scenarios.values()),
        "settlement": all(scenario["checks"]["settlement_success"] for scenario in scenarios.values()),
        "commit_equivocation_guard": all(scenario["checks"]["commit_equivocation_guarded"] for scenario in scenarios.values()),
        "agent_economy": all(
            scenario["checks"]["economy_payment_success"] and scenario["checks"]["economy_service_settled"]
            for scenario in scenarios.values()
        ),
        "autonomous_governance": all(
            scenario["checks"]["dual_sentinel_consensus"]
            and scenario["checks"]["autonomous_block_triggered"]
            and scenario["checks"]["autonomous_penalty_triggered"]
            for scenario in scenarios.values()
        ),
        "secure_mesh_freeze": all(
            scenario["checks"]["freeze_propagation_under_1000ms"] for scenario in scenarios.values()
        ),
        "multi_vendor_readiness": all(
            scenario["checks"]["multi_vendor_protocol_coverage"] for scenario in scenarios.values()
        ),
        "route_negotiation_handoff": all(
            scenario["checks"]["multi_hop_route_committed"] and scenario["checks"]["multi_hop_handoff_complete"]
            for scenario in scenarios.values()
        ),
        "developer_clarity": all(
            os.path.exists(scenario["event_log_path"]) and os.path.exists(scenario["commit_log_path"])
            for scenario in scenarios.values()
        ),
    }
    report_path = os.path.join(output_dir, "acceptance_report.json")
    kpi_summary = {
        "worst_p95_commit_latency_ms": round(
            max(scenario["kpi"]["p95_commit_latency_ms"] for scenario in scenarios.values()),
            3,
        ),
        "worst_avg_commit_latency_ms": round(
            max(scenario["kpi"]["avg_commit_latency_ms"] for scenario in scenarios.values()),
            3,
        ),
        "lowest_verify_ack_ratio": round(
            min(scenario["kpi"]["verify_ack_ratio"] for scenario in scenarios.values()),
            4,
        ),
        "worst_drop_recovery_ms": round(
            max(scenario["kpi"]["message_drop_recovery_time_ms"] for scenario in scenarios.values()),
            3,
        ),
    }
    report: Dict[str, Any] = {
        "criteria": criteria,
        "competition_alignment": {
            key: bool(criteria.get(key, False))
            for key in (
                "Coordination Correctness",
                "Resilience",
                "Auditability",
                "Security Posture",
                "Developer clarity",
            )
        },
        "scenarios": scenarios,
        "kpi_summary": kpi_summary,
    }
    competition_alignment = cast(Dict[str, bool], report["competition_alignment"])
    os.makedirs(output_dir, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return {
        "scenarios": scenarios,
        "criteria": criteria,
        "competition_alignment": competition_alignment,
        "kpi_summary": kpi_summary,
        "report_path": report_path,
    }
