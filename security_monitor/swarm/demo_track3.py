import argparse
import json
import os
import statistics
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict, cast

from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.integration.settlement_adapter import SettlementAdapter
from security_monitor.swarm.agent_node import AgentNode, SwarmNetwork
from security_monitor.swarm.fault_injector import FaultInjector
from security_monitor.swarm.messages import (
    BLOCK_EXEC,
    COMMIT_EQUIVOCATION,
    DISCOVER,
    NANOPAYMENT,
    REPUTATION_PENALTY,
    ROUTE_COMMIT,
    ROUTE_PROPOSAL,
    SCAN_QUOTE,
    SCAN_RESULT,
    TASK_HANDOFF,
    THREAT_CONFIRM,
    THREAT_REPORT,
)
from security_monitor.swarm.proof import build_hash_chain, build_proof, verify_proof_document
from security_monitor.roles import ScoutAgent, GuardianAgent, VerifierAgent
from security_monitor.roles.guardian import LangChainStyleAdapter


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


class AcceptanceSummary(TypedDict):
    scenarios: Dict[str, DemoSummary]
    criteria: Dict[str, bool]
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


class FoxSwarmNetwork(SwarmNetwork):
    """
    SwarmNetwork extended with FoxMQ integration for P2P simulation.
    """
    def __init__(
        self,
        fault_injector: Optional[FaultInjector] = None,
        foxmq_backend: str = "mqtt",
        vertex_rs_bridge_cmd: Optional[str] = None,
        foxmq_mqtt_addr: Optional[str] = None,
    ):
        super().__init__(fault_injector)
        self.fox_mq = FoxMQAdapter(
            backend=foxmq_backend,
            bridge_cmd=vertex_rs_bridge_cmd,
            mqtt_addr=foxmq_mqtt_addr,
        )
        self.fox_mq.join_network("swarm-control")

    def broadcast(self, envelope: Dict[str, Any]) -> None:
        super().broadcast(envelope)
        # Simulate P2P broadcast
        self.fox_mq.publish("swarm-events", envelope)


def _create_agents(network: SwarmNetwork, worker_count: int = 2) -> Tuple[ScoutAgent, List[AgentNode]]:
    # Scout (Planner)
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

    # Guardian (Worker)
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
    
    # Verifier (Observer/Validator)
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
    vertex_rs_bridge_cmd: Optional[str] = None,
    foxmq_mqtt_addr: Optional[str] = None,
) -> DemoSummary:
    # Use FoxSwarmNetwork for P2P simulation
    injector = FaultInjector()
    if fault_mode == "delay":
        injector.delayed_messages_ms["BID"] = 80
    network = FoxSwarmNetwork(
        fault_injector=injector,
        foxmq_backend=foxmq_backend,
        vertex_rs_bridge_cmd=vertex_rs_bridge_cmd,
        foxmq_mqtt_addr=foxmq_mqtt_addr,
    )
    
    planner, nodes = _create_agents(network, worker_count)
    scout = cast(ScoutAgent, planner)
    scout_b = cast(ScoutAgent, next(node for node in nodes if node.agent_id == "agent-scout-b"))

    for node in nodes:
        node.discover()
    for node in nodes:
        node.heartbeat()
    for node in nodes:
        node.cleanup_peers(ttl_seconds=30.0)

    # Determine expected winner based on logic in _create_agents
    # Default winner is worker-0 (lowest price)
    expected_winner = "agent-worker-0"

    if fault_mode == "drop":
        # In drop mode, we drop the expected winner to test resilience
        # We must drop BEFORE offer_task so the node doesn't bid
        network.drop_node(expected_winner)
        # The next best is worker-1
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
    analysis = scout.analyze_target(target_address, amount=100.0)
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

    scout.offer_task(
        task_id="task-001",
        mission=target_address,
        budget_ceiling=float(analysis["suggested_price"]) * 10,
        constraints={"latency_ms_max": 500},
    )

    route_id = "route-task-001"
    route_candidates = sorted(
        planner.bids_by_task.get("task-001", []),
        key=lambda bid: (int(bid["eta_ms"]), float(bid["price"]), str(bid["agent_id"])),
    )
    route_path = [str(candidate["agent_id"]) for candidate in route_candidates[:3]]
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

    for node_id in network.active_node_ids():
        network.nodes[node_id].emit_commit_vote("task-001")

    total_active = len(network.active_node_ids())
    winners = []
    for node_id in network.active_node_ids():
        winner = network.nodes[node_id].resolve_commit("task-001", total_nodes=total_active)
        winners.append(winner)
    unique_winners = {winner for winner in winners if winner}
    if len(unique_winners) != 1:
        # It's possible to have no winner if everyone dropped?
        # But here we expect resilience
        if fault_mode == "drop" and expected_winner == "agent-worker-1" and len(unique_winners) == 0:
             # Case where maybe consensus failed due to drop?
             pass
        else:
             raise RuntimeError(f"commit failed, inconsistent winners: {unique_winners}")
    
    if unique_winners:
        winner_id = unique_winners.pop()
        execution_result = network.nodes[winner_id].execute_committed_task("task-001")
    else:
        winner_id = "none"
        execution_result = None

    if execution_result is None:
        # If we expected a winner but got none, that's an error unless fault injection explains it
        if fault_mode != "drop":
             raise RuntimeError("execution was not completed by committed winner")
        settlement_result = {"status": "failed", "tx_hash": "none"}
    else:
        # Extract settlement info from execution result
        settlement_result = {
            "status": execution_result.get("status", "failed"),
            "tx_hash": execution_result.get("wdk_tx", "none")
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

    pre_verify_chain = build_hash_chain(network.events)
    pre_verify_hash = pre_verify_chain[-1]["chain_hash"] if pre_verify_chain else "GENESIS"
    for node_id in network.active_node_ids():
        network.nodes[node_id].emit_verify_ack("task-001", pre_verify_hash)

    signatures = planner.verify_acks_by_task.get("task-001", {})
    proof = build_proof(events=network.events, signatures=signatures)
    proof_verification = verify_proof_document(proof)

    os.makedirs(output_dir, exist_ok=True)
    event_log_path = os.path.join(output_dir, "structured_event_log.json")
    proof_path = os.path.join(output_dir, "coordination_proof.json")
    commit_log_path = os.path.join(output_dir, "commit_log.json")
    events_data = [event.to_dict() for event in network.events]
    task_offer_events = [event for event in events_data if event["event_type"] == "TASK_OFFER"]
    commit_events = [event for event in events_data if event["event_type"] == "COMMIT_VOTE"]
    exec_done_events = [event for event in events_data if event["event_type"] == "EXEC_DONE"]
    verify_events = [event for event in events_data if event["event_type"] == "VERIFY_ACK"]
    gossip_events = [event for event in events_data if event["event_type"] == "THREAT_GOSSIP"]
    equivocation_events = [event for event in events_data if event["event_type"] == COMMIT_EQUIVOCATION]
    route_proposal_events = [event for event in events_data if event["event_type"] == ROUTE_PROPOSAL]
    route_commit_events = [event for event in events_data if event["event_type"] == ROUTE_COMMIT]
    handoff_events = [event for event in events_data if event["event_type"] == TASK_HANDOFF]
    threat_report_events = [event for event in events_data if event["event_type"] == THREAT_REPORT]
    block_exec_events = [event for event in events_data if event["event_type"] == BLOCK_EXEC]
    with open(event_log_path, "w", encoding="utf-8") as f:
        json.dump(events_data, f, ensure_ascii=False, indent=2)
    with open(proof_path, "w", encoding="utf-8") as f:
        json.dump(proof, f, ensure_ascii=False, indent=2)
    with open(commit_log_path, "w", encoding="utf-8") as f:
        json.dump(commit_events, f, ensure_ascii=False, indent=2)

    # Check Hive Memory Consistency
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

    checks = {
        "single_winner": len(unique_winners | {winner_id}) == 1,
        "no_double_assignment": len(exec_done_events) == 1,
        "proof_chain_complete": int(proof["event_count"]) == len(proof["chain"]),
        "proof_multisig_quorum": len(signatures) >= 3,
        "proof_anchor_valid": proof_verification["anchor_payload_ok"] and proof_verification["anchor_id_ok"],
        "proof_independently_verifiable": all(proof_verification.values()),
        "verify_ack_emitted": len(verify_events) >= (total_active - 1), # At least most nodes ack
        "resilience_maintained": winner_id == expected_winner,
        "commit_equivocation_guarded": len(equivocation_events) == 0,
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
    }

    return {
        "task_id": "task-001",
        "winner": winner_id,
        "active_nodes": network.active_node_ids(),
        "fault_mode": fault_mode,
        "event_count": len(network.events),
        "proof_hash": proof["final_chain_hash"],
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
    }


def run_acceptance(
    output_dir: str,
    worker_count: int = 2,
    foxmq_backend: str = "mqtt",
    vertex_rs_bridge_cmd: Optional[str] = None,
    foxmq_mqtt_addr: Optional[str] = None,
) -> AcceptanceSummary:
    scenarios: Dict[str, DemoSummary] = {}
    for mode in ("none", "delay", "drop"):
        scenario_dir = os.path.join(output_dir, mode)
        scenarios[mode] = run_demo(
            output_dir=scenario_dir,
            fault_mode=cast(Literal["none", "delay", "drop"], mode),
            worker_count=worker_count,
            foxmq_backend=foxmq_backend,
            vertex_rs_bridge_cmd=vertex_rs_bridge_cmd,
            foxmq_mqtt_addr=foxmq_mqtt_addr,
        )
    criteria = {
        "task_bidding": all(
            scenario["checks"]["single_winner"] and scenario["checks"]["no_double_assignment"]
            for scenario in scenarios.values()
        ),
        "hive_memory_state_sync": all(
            scenario["checks"]["hive_memory_consistent"] for scenario in scenarios.values()
        ),
        "verification_multisig_proof": all(
            scenario["checks"]["proof_chain_complete"]
            and scenario["checks"]["proof_multisig_quorum"]
            and scenario["checks"]["proof_anchor_valid"]
            and scenario["checks"]["proof_independently_verifiable"]
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
            scenario["checks"]["proof_chain_complete"] and os.path.exists(scenario["proof_path"])
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
        "scenarios": scenarios,
        "kpi_summary": kpi_summary,
    }
    os.makedirs(output_dir, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return {
        "scenarios": scenarios,
        "criteria": criteria,
        "kpi_summary": kpi_summary,
        "report_path": report_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Track3 leaderless swarm demo")
    parser.add_argument(
        "--mode",
        choices=["single", "acceptance"],
        default="single",
        help="single: run one scenario, acceptance: run none/delay/drop",
    )
    parser.add_argument(
        "--output-dir",
        default=os.path.join(os.getcwd(), "artifacts"),
        help="Directory for structured logs and proof files",
    )
    parser.add_argument(
        "--fault",
        choices=["none", "delay", "drop"],
        default="delay",
        help="Fault mode to inject during demo",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
        help="Number of worker agents (default: 2)",
    )
    parser.add_argument(
        "--foxmq-backend",
        choices=["simulated", "official", "mqtt"],
        default=os.getenv("FOXMQ_BACKEND", "mqtt"),
        help="FoxMQ transport backend",
    )
    parser.add_argument(
        "--vertex-rs-bridge-cmd",
        default=os.getenv("VERTEX_RS_BRIDGE_CMD", ""),
        help="Rust bridge command used by official backend, example: vertex-rs-bridge --host 127.0.0.1 --port 1883 --stdio",
    )
    parser.add_argument(
        "--foxmq-mqtt-addr",
        default=os.getenv("FOXMQ_MQTT_ADDR", "127.0.0.1:1883"),
        help="MQTT broker address used by mqtt backend, format host:port",
    )
    args = parser.parse_args()

    if args.mode == "acceptance":
        acceptance = run_acceptance(
            output_dir=args.output_dir,
            worker_count=args.workers,
            foxmq_backend=args.foxmq_backend,
            vertex_rs_bridge_cmd=args.vertex_rs_bridge_cmd or None,
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
        vertex_rs_bridge_cmd=args.vertex_rs_bridge_cmd or None,
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
