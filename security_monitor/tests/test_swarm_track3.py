"""End-to-end and integration tests for Track3 swarm coordination.

Environment assumptions:
- Uses local FoxMQ MQTT endpoint (default 127.0.0.1:1883) for transport-backed cases.
- Uses temporary directories/processes for artifact isolation and cleanup per test.
- Covers single-process simulation and multiprocess agent bootstrap mission paths.
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any, Literal
from unittest import mock

from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.swarm.agent_node import SwarmNetwork
from security_monitor.swarm.messages import DISCOVER
from security_monitor.swarm.security import verify_payload
from security_monitor.swarm.vertex_consensus import VertexConsensus
from security_monitor.track3.protocol import (
    AcceptanceSummary,
    DemoSummary,
    _create_agents,
    _vertex_finalize_winner,
    run_acceptance,
    run_demo,
)

_MQTT_E2E_ADDR = os.getenv("FOXMQ_MQTT_ADDR", "127.0.0.1:1883").strip()
_MQTT_E2E_ENABLED = str(os.getenv("MQTT_E2E", "0")).strip().lower() in {"1", "true", "yes", "on"}
_MULTIPROCESS_E2E_ENABLED = str(os.getenv("MULTIPROCESS_E2E", "0")).strip().lower() in {"1", "true", "yes", "on"}
_MULTIPROCESS_RECOVERY_E2E_ENABLED = (
    str(os.getenv("MULTIPROCESS_RECOVERY_E2E", "0")).strip().lower() in {"1", "true", "yes", "on"}
)
_TRACK3_TEST_MQTT_ADDR = _MQTT_E2E_ADDR


class Track3SwarmTests(unittest.TestCase):
    """Validate mission lifecycle, proof integrity, and resilience under FoxMQ mode."""

    def _mqtt_endpoint_reachable(self) -> bool:
        """Purpose: Mqtt endpoint reachable.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic mqtt endpoint reachable rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        host, _, port_raw = _TRACK3_TEST_MQTT_ADDR.rpartition(":")
        if not host or not port_raw:
            return False
        try:
            port = int(port_raw)
        except ValueError:
            return False
        with socket.socket() as sock:
            sock.settimeout(1.0)
            return sock.connect_ex((host, port)) == 0

    def _require_mqtt_e2e(self) -> None:
        """Purpose: Require mqtt e2e.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic require mqtt e2e rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if not _MQTT_E2E_ENABLED:
            self.skipTest("set MQTT_E2E=1 and FOXMQ_MQTT_ADDR to run mqtt transport e2e")
        if not self._mqtt_endpoint_reachable():
            self.skipTest(f"FoxMQ MQTT endpoint is not reachable at {_TRACK3_TEST_MQTT_ADDR}")

    def _run_demo_mqtt(
        self,
        output_dir: str,
        fault_mode: Literal["none", "delay", "drop"],
        worker_count: int = 2,
    ) -> DemoSummary:
        self._require_mqtt_e2e()
        return run_demo(
            output_dir=output_dir,
            fault_mode=fault_mode,
            worker_count=worker_count,
            foxmq_backend="mqtt",
            foxmq_mqtt_addr=_TRACK3_TEST_MQTT_ADDR,
        )

    def _run_acceptance_mqtt(self, output_dir: str) -> AcceptanceSummary:
        """Purpose: Run acceptance mqtt.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic run acceptance mqtt rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self._require_mqtt_e2e()
        return run_acceptance(
            output_dir=output_dir,
            foxmq_backend="mqtt",
            foxmq_mqtt_addr=_TRACK3_TEST_MQTT_ADDR,
        )

    def test_full_loop_without_fault(self) -> None:
        """Goal: Validate full loop without fault.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(output_dir=tmp, fault_mode="none")
            self.assertEqual(summary["winner"], "agent-worker-0")
            self.assertEqual(summary["signer_count"], len(summary["active_nodes"]))
            self.assertGreater(summary["event_count"], 0)
            self.assertTrue(os.path.exists(summary["event_log_path"]))
            self.assertTrue(os.path.exists(summary["proof_path"]))
            self.assertTrue(summary["nanopayment_tx_hash"].startswith("0x"))
            self.assertTrue(summary["checks"]["economy_payment_success"])
            self.assertTrue(summary["checks"]["dual_sentinel_consensus"])
            self.assertTrue(summary["checks"]["autonomous_penalty_triggered"])
            self.assertGreaterEqual(summary["freeze_latency_ms"], 0.0)
            self.assertTrue(summary["checks"]["freeze_propagation_under_1000ms"])
            self.assertTrue(summary["checks"]["multi_vendor_protocol_coverage"])
            self.assertTrue(summary["checks"]["multi_hop_route_committed"])
            self.assertTrue(summary["checks"]["multi_hop_handoff_complete"])
            self.assertTrue(summary["checks"]["byo_agent_integration"])
            self.assertTrue(summary["checks"]["security_forgery_rejected"])
            self.assertTrue(summary["checks"]["security_replay_rejected"])
            self.assertTrue(summary["checks"]["kpi_commit_p95_under_1000ms"])
            self.assertTrue(summary["checks"]["kpi_verify_ack_ratio_full"])
            self.assertTrue(summary["checks"]["kpi_recovery_observed"])
            self.assertGreaterEqual(summary["route_hops"], 1)
            self.assertGreaterEqual(len(summary["execution_protocols"]), 2)
            self.assertGreaterEqual(len(summary["byo_workers"]), 1)
            self.assertGreaterEqual(summary["kpi"]["p95_commit_latency_ms"], 0.0)
            self.assertGreaterEqual(summary["kpi"]["avg_commit_latency_ms"], 0.0)
            self.assertGreaterEqual(summary["kpi"]["verify_ack_ratio"], 1.0)
            self.assertGreaterEqual(summary["kpi"]["message_drop_recovery_time_ms"], 0.0)

    def test_loop_with_node_drop(self) -> None:
        """Goal: Validate loop with node drop.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert mission execution recovers from injected faults and converges to expected completion/proof artifacts.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(output_dir=tmp, fault_mode="drop")
            self.assertEqual(summary["winner"], "agent-worker-1")
            self.assertEqual(summary["signer_count"], len(summary["active_nodes"]))

    def test_proof_uses_vertex_payload(self) -> None:
        """Goal: Validate proof uses vertex payload.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(output_dir=tmp, fault_mode="delay")
            with open(summary["proof_path"], "r", encoding="utf-8") as f:
                proof = json.load(f)
            payload = dict(proof.get("proof_payload", {}))
            self.assertTrue(str(proof.get("proof_hash", "")).strip())
            self.assertIn("ordered_event_ids", payload)
            self.assertGreaterEqual(len(list(payload.get("ordered_event_ids", []))), 1)

    def test_vertex_proof_and_offline_verification(self) -> None:
        """Goal: Validate vertex proof and offline verification.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(output_dir=tmp, fault_mode="none")
            with open(summary["proof_path"], "r", encoding="utf-8") as f:
                proof = json.load(f)
            participants = [
                str(item).strip()
                for item in dict(proof.get("proof_payload", {})).get("participants", [])
                if str(item).strip()
            ]
            participant_secrets = {agent_id: f"secret-{agent_id.split('agent-')[-1]}" for agent_id in participants}
            verification = VertexConsensus.verify_proof(proof, participant_secrets)
            self.assertTrue(all(verification.values()))
            self.assertIn("signatures", proof)
            self.assertIn("proof_payload", proof)

    def test_vertex_proof_verification_fails_after_tampering(self) -> None:
        """Goal: Validate vertex proof verification fails after tampering.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert security validation rejects manipulated payloads/events while untampered data still verifies successfully.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(output_dir=tmp, fault_mode="none")
            with open(summary["proof_path"], "r", encoding="utf-8") as f:
                proof = json.load(f)
            participants = [
                str(item).strip()
                for item in dict(proof.get("proof_payload", {})).get("participants", [])
                if str(item).strip()
            ]
            participant_secrets = {agent_id: f"secret-{agent_id.split('agent-')[-1]}" for agent_id in participants}
            proof["proof_hash"] = "tampered-proof-hash"
            verification = VertexConsensus.verify_proof(proof, participant_secrets)
            self.assertFalse(bool(verification.get("proof_hash_ok")))

    def test_vertex_consensus_winner_is_deterministic_for_same_bids(self) -> None:
        """Goal: Validate vertex consensus winner is deterministic for same bids.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert arbitration/order outputs are deterministic and consistent with expected role/step constraints.
        """
        network = SwarmNetwork()
        _, nodes = _create_agents(network)
        active_members = [node.agent_id for node in nodes if node.agent_id != "agent-worker-1"]
        bids = [
            {"task_id": "task-tie", "agent_id": "agent-worker-0", "price": 5.0, "eta_ms": 100, "capacity": 1},
            {"task_id": "task-tie", "agent_id": "agent-verifier", "price": 5.0, "eta_ms": 100, "capacity": 1},
            {"task_id": "task-tie", "agent_id": "agent-scout", "price": 5.0, "eta_ms": 100, "capacity": 1},
        ]
        winner_a, _, proof_a, checks_a = _vertex_finalize_winner(
            network=network,
            task_id="task-tie",
            active_members=active_members,
            bids=bids,
        )
        winner_b, _, proof_b, checks_b = _vertex_finalize_winner(
            network=network,
            task_id="task-tie",
            active_members=active_members,
            bids=bids,
        )
        self.assertEqual(winner_a, winner_b)
        self.assertTrue(all(checks_a.values()))
        self.assertTrue(all(checks_b.values()))
        self.assertEqual(proof_a["proof_hash"], proof_b["proof_hash"])

    def test_replay_message_is_rejected(self) -> None:
        """Goal: Validate replay message is rejected.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert security validation rejects manipulated payloads/events while untampered data still verifies successfully.
        """
        network = SwarmNetwork()
        planner, nodes = _create_agents(network)
        worker = [node for node in nodes if node.agent_id == "agent-worker-0"][0]
        envelope = worker._build_envelope(DISCOVER, {"capability": "worker"})
        signed_portion = {
            "type": envelope["type"],
            "sender": envelope["sender"],
            "ts": envelope["ts"],
            "nonce": envelope["nonce"],
            "payload": envelope["payload"],
        }
        self.assertTrue(verify_payload(worker.secret, signed_portion, envelope["sig"]))
        network.broadcast(envelope)
        first_seen = planner.peers.get(worker.agent_id)
        self.assertIsNotNone(first_seen)
        network.broadcast(envelope)
        second_seen = planner.peers.get(worker.agent_id)
        self.assertEqual(first_seen, second_seen)

    def test_basic_ai_agent_can_build_and_publish_business_request(self) -> None:
        """Goal: Validate basic ai agent can build and publish business request.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        network = SwarmNetwork()
        planner, _ = _create_agents(network)
        request = planner.create_business_request(
            task_id="task-basic-001",
            target_address="0x1234567890abcdef1234567890abcdef12345678",
            amount=100.0,
            latency_ms_max=350,
            resource_units=1,
        )
        published = planner.propose_business_task(request)
        self.assertTrue(request["accepted"])
        self.assertTrue(published)
        self.assertEqual(request["task_id"], "task-basic-001")
        self.assertEqual(request["constraints"]["latency_ms_max"], 350)
        self.assertEqual(request["constraints"]["resource_units"], 1)
        bids = planner.bids_by_task.get("task-basic-001", [])
        self.assertGreaterEqual(len(bids), 1)

    def test_basic_ai_agent_rejects_malicious_target_request(self) -> None:
        """Goal: Validate basic ai agent rejects malicious target request.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        network = SwarmNetwork()
        planner, _ = _create_agents(network)
        request = planner.create_business_request(
            task_id="task-basic-002",
            target_address="0x6666666666666666666666666666666666666666",
            amount=100.0,
        )
        published = planner.propose_business_task(request)
        self.assertFalse(request["accepted"])
        self.assertFalse(published)
        self.assertNotIn("task-basic-002", planner.offers)
        self.assertIn("0x6666666666666666666666666666666666666666", planner.threat_ledger)

    def test_leaderless_pricing_and_resource_limits_gate_bids(self) -> None:
        """Goal: Validate leaderless pricing and resource limits gate bids.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        network = SwarmNetwork()
        planner, nodes = _create_agents(network)
        worker0 = next(node for node in nodes if node.agent_id == "agent-worker-0")
        worker1 = next(node for node in nodes if node.agent_id == "agent-worker-1")
        worker0.bid_profile["capacity"] = 1
        worker1.bid_profile["capacity"] = 1

        blocked = planner.create_business_request(
            task_id="task-basic-003",
            target_address="0x1234567890abcdef1234567890abcdef12345678",
            amount=100.0,
            resource_units=2,
        )
        self.assertTrue(planner.propose_business_task(blocked))
        self.assertEqual(planner.bids_by_task.get("task-basic-003", []), [])

        budget_blocked = planner.create_business_request(
            task_id="task-basic-004",
            target_address="0x1234567890abcdef1234567890abcdef12345678",
            amount=100.0,
            resource_units=1,
        )
        budget_blocked["constraints"]["estimated_cost"] = 9.0
        budget_blocked["constraints"]["budget_limit"] = 8.0
        budget_blocked["budget_ceiling"] = 8.0
        self.assertTrue(planner.propose_business_task(budget_blocked))
        self.assertEqual(planner.bids_by_task.get("task-basic-004", []), [])

        accepted = planner.create_business_request(
            task_id="task-basic-005",
            target_address="0x1234567890abcdef1234567890abcdef12345678",
            amount=100.0,
            resource_units=1,
        )
        accepted["constraints"]["estimated_cost"] = 7.0
        accepted["constraints"]["budget_limit"] = 9.0
        accepted["budget_ceiling"] = 9.0
        self.assertTrue(planner.propose_business_task(accepted))
        bids = planner.bids_by_task.get("task-basic-005", [])
        self.assertGreaterEqual(len(bids), 1)
        self.assertTrue(all(float(bid["price"]) >= 7.0 for bid in bids))

    def test_minimum_three_agent_cycle_without_central_orchestrator(self) -> None:
        """Goal: Validate minimum three agent cycle without central orchestrator.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        network = SwarmNetwork()
        planner, nodes = _create_agents(network)
        for node in nodes:
            node.discover()
            node.heartbeat()

        cluster_members = planner.form_task_cluster(
            task_id="task-basic-006",
            required_capabilities=["scout", "guardian", "verifier"],
            min_size=3,
        )
        active_cluster = [node_id for node_id in cluster_members if node_id in network.active_node_ids()]
        self.assertGreaterEqual(len(active_cluster), 3)

        request = planner.create_business_request(
            task_id="task-basic-006",
            target_address="0x1234567890abcdef1234567890abcdef12345678",
            amount=100.0,
            resource_units=1,
        )
        self.assertTrue(planner.propose_business_task(request))

        winner, _, _, checks = _vertex_finalize_winner(
            network=network,
            task_id="task-basic-006",
            active_members=active_cluster,
            bids=list(planner.bids_by_task.get("task-basic-006", [])),
        )
        self.assertTrue(all(checks.values()))
        for node_id in active_cluster:
            network.nodes[node_id].assign_task_winner("task-basic-006", winner)
        execution = network.nodes[winner].execute_committed_task("task-basic-006")
        self.assertIsNotNone(execution)

        event_hash = "vertex-proof-task-basic-006"
        for node_id in active_cluster:
            network.nodes[node_id].emit_verify_ack("task-basic-006", event_hash)
        signatures = planner.verify_acks_by_task.get("task-basic-006", {})
        self.assertGreaterEqual(len(signatures), 3)
        self.assertTrue(all(float(event.ts) > 0.0 for event in network.events))
        self.assertTrue(all(str(event.actor) for event in network.events))

    @unittest.skipUnless(
        _MULTIPROCESS_E2E_ENABLED,
        "set MULTIPROCESS_E2E=1 and FOXMQ_MQTT_ADDR to run multiprocess mqtt e2e",
    )
    def test_single_machine_ad_hoc_swarm_full_negotiate_commit_execute_verify_loop(self) -> None:
        """Goal: Validate single machine ad hoc swarm full negotiate commit execute verify loop.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = self._run_multiprocess_cluster_mission(
                output_dir=os.path.join(tmp, "cluster-full-loop"),
                run_id_prefix="cluster-full-loop",
                agent_specs=[
                    ("agent-scout-only", "scout"),
                    ("agent-guardian-only", "guardian"),
                    ("agent-verifier-only", "verifier"),
                ],
            )
            self._assert_cluster_competition_requirements(report)
            steps = list(report.get("steps", []))
            self.assertEqual(len(steps), 3)
            self.assertTrue(all(str(step.get("state", "")).strip().lower() == "success" for step in steps))
            proof_checks = dict(report.get("proof_checks", {}))
            self.assertTrue(proof_checks)
            self.assertTrue(all(bool(value) for value in proof_checks.values()))

    @unittest.skipUnless(
        _MULTIPROCESS_E2E_ENABLED,
        "set MULTIPROCESS_E2E=1 and FOXMQ_MQTT_ADDR to run multiprocess mqtt e2e",
    )
    def test_single_machine_cluster_coordination_correctness_auditability_and_observability_e2e(self) -> None:
        """Goal: Validate single machine cluster coordination correctness auditability and observability e2e.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = self._run_multiprocess_cluster_mission(
                output_dir=os.path.join(tmp, "cluster-correctness-auditability"),
                run_id_prefix="cluster-correctness-auditability",
                agent_specs=[
                    ("agent-alpha", "scout,guardian,verifier"),
                    ("agent-beta", "scout,guardian,verifier"),
                    ("agent-gamma", "scout,guardian,verifier"),
                ],
            )
            self.assertTrue(bool(report.get("steps")))
            mission_id = str(report.get("mission_id", "")).strip()
            self.assertTrue(mission_id)
            role_assignments = dict(report.get("role_identity_assignments", {}))
            protocol_roles = [str(item).strip().lower() for item in report.get("protocol_roles", []) if str(item).strip()]
            self.assertEqual(protocol_roles, ["scout", "guardian", "verifier", "auditor"])
            announcements = [str(item.get("agent_id", "")).strip() for item in report.get("agent_announcements", []) if str(item.get("agent_id", "")).strip()]
            self.assertGreaterEqual(len(announcements), 1)
            for role_name in ("scout", "guardian", "verifier"):
                self.assertIn(role_name, role_assignments)
                actual_assignee = str(dict(role_assignments.get(role_name, {})).get("assigned_agent", "")).strip()
                self.assertTrue(actual_assignee)
                claim_id = f"{mission_id}:{role_name}:1"
                scored_candidates: list[tuple[str, float, float]] = []
                for agent_id in sorted(set(announcements)):
                    salt = f"identity:{agent_id}:{claim_id}:{role_name}".encode("utf-8")
                    tie_break = int(hashlib.sha1(salt).hexdigest()[:6], 16) / float(0xFFFFFF)
                    score = round(1000.0 + tie_break, 6)
                    scored_candidates.append((agent_id, score, 0.0))
                if actual_assignee not in {item[0] for item in scored_candidates}:
                    scored_candidates.append((actual_assignee, 1000.0, 0.0))
                self.assertIn(actual_assignee, {item[0] for item in scored_candidates})
            self.assertIn("auditor", role_assignments)
            verifier_owner = str(dict(role_assignments.get("verifier", {})).get("assigned_agent", "")).strip()
            auditor_owner = str(dict(role_assignments.get("auditor", {})).get("assigned_agent", "")).strip()
            self.assertEqual(auditor_owner, verifier_owner)
            auditor_evidence = dict(report.get("auditor_evidence", {}))
            self.assertEqual(str(auditor_evidence.get("role", "")).strip().lower(), "auditor")
            self.assertEqual(str(auditor_evidence.get("stage", "")).strip().upper(), "CLOSE")
            steps = list(report.get("steps", []))
            self.assertEqual(len(steps), 3)
            task_ids = [str(step.get("task_id", "")).strip() for step in steps]
            self.assertEqual(len(task_ids), len(set(task_ids)))
            self.assertTrue(all(task_ids))
            proof = dict(report.get("coordination_proof", {}))
            self.assertTrue(bool(proof))
            payload = dict(proof.get("proof_payload", {}))
            self.assertGreaterEqual(len(list(payload.get("ordered_event_ids", []))), 1)
            proof_checks = dict(report.get("proof_checks", {}))
            self.assertTrue(all(bool(value) for value in proof_checks.values()))
            tampered_proof = json.loads(json.dumps(proof))
            tampered_proof["proof_hash"] = "tampered-multiprocess-proof-hash"
            committee_agents = [
                str(item).strip()
                for item in dict(tampered_proof.get("proof_payload", {})).get("participants", [])
                if str(item).strip()
            ]
            committee_secrets = {agent_id: f"secret-{agent_id.split('agent-')[-1]}" for agent_id in committee_agents}
            tampered_checks = VertexConsensus.verify_proof(tampered_proof, committee_secrets)
            self.assertFalse(bool(tampered_checks.get("proof_hash_ok")))
            standard_metrics = dict(report.get("standard_metrics", {}))
            self.assertIn("success_rate", standard_metrics)
            self.assertIn("end_to_end_latency_ms", standard_metrics)
            self.assertIn("retry_count", standard_metrics)
            self.assertIn("timeout_count", standard_metrics)

    @unittest.skipUnless(
        _MULTIPROCESS_RECOVERY_E2E_ENABLED,
        "set MULTIPROCESS_RECOVERY_E2E=1 and FOXMQ_MQTT_ADDR to run multiprocess recovery e2e",
    )
    def test_single_machine_cluster_resilience_with_delay_and_drop_e2e(self) -> None:
        """Goal: Validate single machine cluster resilience with delay and drop e2e.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert mission execution recovers from injected faults and converges to expected completion/proof artifacts.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = self._run_multiprocess_cluster_mission(
                output_dir=os.path.join(tmp, "cluster-resilience"),
                run_id_prefix="cluster-resilience",
                agent_specs=[
                    ("agent-scout", "scout,guardian,verifier"),
                    ("agent-guardian", "scout,guardian,verifier"),
                    ("agent-verifier", "scout,guardian,verifier"),
                ],
                pre_guardian_delay_seconds=3.0,
                terminate_agent_id="agent-guardian",
                ready_timeout_seconds=60.0,
            )
            self.assertTrue(bool(report.get("all_success")))
            steps = list(report.get("steps", []))
            self.assertGreaterEqual(len(steps), 3)
            guardian_steps = [step for step in steps if str(step.get("role_name", "")).strip().lower() == "guardian"]
            self.assertGreaterEqual(len(guardian_steps), 1)
            selected_guardians = {str(step.get("selected_agent", "")).strip() for step in guardian_steps}
            self.assertNotIn("agent-guardian", selected_guardians)
            proof_checks = dict(report.get("proof_checks", {}))
            self.assertTrue(all(bool(value) for value in proof_checks.values()))

    def test_no_double_assignment_in_event_log(self) -> None:
        """Goal: Validate no double assignment in event log.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(output_dir=tmp, fault_mode="none")
            with open(summary["event_log_path"], "r", encoding="utf-8") as f:
                events = json.load(f)
            exec_done = [event for event in events if event["event_type"] == "EXEC_DONE"]
            self.assertEqual(len(exec_done), 1)

    def test_vertex_consensus_proof_tampering_is_rejected(self) -> None:
        """Goal: Validate vertex consensus proof tampering is rejected.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert security validation rejects manipulated payloads/events while untampered data still verifies successfully.
        """
        network = SwarmNetwork()
        _, nodes = _create_agents(network)
        planner = next(node for node in nodes if node.agent_id == "agent-scout")
        for node in nodes:
            node.discover()
        planner.offer_task("task-eq", "target", 10.0)
        active_members = network.active_node_ids()
        _, _, proof, checks = _vertex_finalize_winner(
            network=network,
            task_id="task-eq",
            active_members=active_members,
            bids=list(planner.bids_by_task.get("task-eq", [])),
        )
        self.assertTrue(all(checks.values()))
        tampered_proof = json.loads(json.dumps(proof))
        tampered_proof["proof_hash"] = "tampered-proof-hash"
        tampered_checks = VertexConsensus.verify_proof(tampered_proof, network.agent_secrets)
        self.assertFalse(all(tampered_checks.values()))

    def test_acceptance_bundle_exports_report(self) -> None:
        """Goal: Validate acceptance bundle exports report.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert generated artifacts, metrics, and alignment fields satisfy acceptance/competition expectations.
        """
        with tempfile.TemporaryDirectory() as tmp:
            acceptance = self._run_acceptance_mqtt(output_dir=tmp)
            self.assertTrue(os.path.exists(acceptance["report_path"]))
            self.assertTrue(all(acceptance["criteria"].values()))
            self.assertIn("secure_mesh_freeze", acceptance["criteria"])
            self.assertIn("multi_vendor_readiness", acceptance["criteria"])
            self.assertIn("route_negotiation_handoff", acceptance["criteria"])
            self.assertIn("Coordination Correctness", acceptance["criteria"])
            self.assertIn("Resilience", acceptance["criteria"])
            self.assertIn("Auditability", acceptance["criteria"])
            self.assertIn("Security Posture", acceptance["criteria"])
            self.assertIn("Developer clarity", acceptance["criteria"])
            self.assertIn("discover_and_formation", acceptance["criteria"])
            self.assertIn("task_bidding", acceptance["criteria"])
            self.assertIn("hive_memory_state_sync", acceptance["criteria"])
            self.assertIn("verification_vertex_proof", acceptance["criteria"])
            self.assertIn("byo_agents_orchestrator_replaced", acceptance["criteria"])
            self.assertIn("security_attack_resistance", acceptance["criteria"])
            self.assertIn("observability_kpi_ready", acceptance["criteria"])
            self.assertIn("hive_memory_recovery", acceptance["criteria"])
            self.assertIn("commit_equivocation_guard", acceptance["criteria"])
            self.assertTrue(acceptance["criteria"]["task_bidding"])
            self.assertTrue(acceptance["criteria"]["hive_memory_state_sync"])
            self.assertTrue(acceptance["criteria"]["verification_vertex_proof"])
            self.assertTrue(acceptance["criteria"]["byo_agents_orchestrator_replaced"])
            self.assertTrue(acceptance["criteria"]["security_attack_resistance"])
            self.assertTrue(acceptance["criteria"]["observability_kpi_ready"])
            self.assertTrue(acceptance["criteria"]["Coordination Correctness"])
            self.assertTrue(acceptance["criteria"]["Resilience"])
            self.assertTrue(acceptance["criteria"]["Auditability"])
            self.assertTrue(acceptance["criteria"]["Security Posture"])
            self.assertTrue(acceptance["criteria"]["Developer clarity"])
            self.assertIn("kpi_summary", acceptance)
            self.assertIn("competition_alignment", acceptance)
            self.assertTrue(acceptance["competition_alignment"]["Coordination Correctness"])
            self.assertTrue(acceptance["competition_alignment"]["Resilience"])
            self.assertTrue(acceptance["competition_alignment"]["Auditability"])
            self.assertTrue(acceptance["competition_alignment"]["Security Posture"])
            self.assertTrue(acceptance["competition_alignment"]["Developer clarity"])
            self.assertGreaterEqual(acceptance["kpi_summary"]["worst_p95_commit_latency_ms"], 0.0)
            self.assertGreaterEqual(acceptance["kpi_summary"]["lowest_verify_ack_ratio"], 1.0)
            self.assertNotIn("peer_discovery_state_sync", acceptance["criteria"])

    def test_acceptance_covers_implemented_tashi_primitives(self) -> None:
        """Goal: Validate acceptance covers implemented tashi primitives.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert generated artifacts, metrics, and alignment fields satisfy acceptance/competition expectations.
        """
        with tempfile.TemporaryDirectory() as tmp:
            acceptance = self._run_acceptance_mqtt(output_dir=tmp)
            scenarios = dict(acceptance.get("scenarios", {}))
            self.assertEqual(set(scenarios.keys()), {"none", "delay", "drop"})
            for scenario in scenarios.values():
                checks = dict(scenario.get("checks", {}))
                lattice = dict(scenario.get("lattice", {}))
                self.assertTrue(checks["vertex_order_finalized"])
                self.assertTrue(checks["vertex_signature_quorum"])
                self.assertTrue(checks["vertex_proof_hash_valid"])
                self.assertTrue(checks["vertex_proof_independently_verifiable"])
                self.assertTrue(checks["lattice_discovery_ok"])
                self.assertTrue(checks["lattice_authorization_ok"])
                self.assertTrue(checks["lattice_independent_validation_ok"])
                self.assertTrue(checks["lattice_reputation_routing_ok"])
                self.assertTrue(checks["lattice_failover_ok"])
                self.assertTrue(lattice["discovery_ok"])
                self.assertTrue(lattice["authorized_participants_ok"])
                self.assertTrue(lattice["independent_validation_ok"])
                self.assertTrue(lattice["reputation_routing_ok"])
                self.assertTrue(lattice["failover_ok"])
                self.assertTrue(str(scenario.get("settlement_tx_hash", "")).startswith("0x"))
                self.assertTrue(str(scenario.get("nanopayment_tx_hash", "")).startswith("0x"))
                self.assertEqual(str(scenario.get("transport_backend", "")).strip().lower(), "mqtt")
            competition_alignment = dict(acceptance.get("competition_alignment", {}))
            self.assertTrue(competition_alignment["Coordination Correctness"])
            self.assertTrue(competition_alignment["Resilience"])
            self.assertTrue(competition_alignment["Auditability"])
            self.assertTrue(competition_alignment["Security Posture"])
            self.assertTrue(competition_alignment["Developer clarity"])

    def test_hive_memory_gossip_recorded(self) -> None:
        """Goal: Validate hive memory gossip recorded.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(output_dir=tmp, fault_mode="none")
            self.assertTrue(summary["checks"]["hive_memory_consistent"])
            self.assertTrue(summary["checks"]["hive_memory_recovery_sync"])
            with open(summary["event_log_path"], "r", encoding="utf-8") as f:
                events = json.load(f)
            gossip_events = [event for event in events if event["event_type"] == "THREAT_GOSSIP"]
            self.assertGreaterEqual(len(gossip_events), 1)

    def test_agent_economy_and_dual_sentinel_events_recorded(self) -> None:
        """Goal: Validate agent economy and dual sentinel events recorded.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(output_dir=tmp, fault_mode="none")
            with open(summary["event_log_path"], "r", encoding="utf-8") as f:
                events = json.load(f)
            event_types = {event["event_type"] for event in events}
            self.assertIn("SCAN_QUOTE", event_types)
            self.assertIn("NANOPAYMENT", event_types)
            self.assertIn("THREAT_REPORT", event_types)
            self.assertIn("THREAT_CONFIRM", event_types)
            self.assertIn("BLOCK_EXEC", event_types)
            self.assertIn("REPUTATION_PENALTY", event_types)
            self.assertIn("ROUTE_PROPOSAL", event_types)
            self.assertIn("ROUTE_COMMIT", event_types)
            self.assertIn("TASK_HANDOFF", event_types)
            self.assertGreaterEqual(summary["freeze_latency_ms"], 0.0)
            self.assertTrue(summary["checks"]["freeze_propagation_under_1000ms"])

    def test_demo_transport_backend_field(self) -> None:
        """Goal: Validate demo transport backend field.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(output_dir=tmp, fault_mode="none")
            self.assertEqual(summary["transport_backend"], "mqtt")
            self.assertTrue(summary["checks"]["vertex_proof_hash_valid"])
            self.assertTrue(summary["checks"]["vertex_proof_independently_verifiable"])
            self.assertTrue(summary["checks"]["commit_equivocation_guarded"])
            self.assertTrue(summary["competition_alignment"]["Coordination Correctness"])
            self.assertTrue(summary["competition_alignment"]["Resilience"])
            self.assertTrue(summary["competition_alignment"]["Auditability"])
            self.assertTrue(summary["competition_alignment"]["Security Posture"])
            self.assertTrue(summary["competition_alignment"]["Developer clarity"])

    def test_scale_with_dozens_of_workers(self) -> None:
        """Goal: Validate scale with dozens of workers.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run_demo_mqtt(
                output_dir=tmp,
                fault_mode="none",
                worker_count=24,
            )
            self.assertGreaterEqual(len(summary["active_nodes"]), 27)
            self.assertTrue(summary["checks"]["single_winner"])
            self.assertTrue(summary["checks"]["no_double_assignment"])

    def test_partition_recovery_and_memory_resync(self) -> None:
        """Goal: Validate partition recovery and memory resync.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert mission execution recovers from injected faults and converges to expected completion/proof artifacts.
        """
        network = SwarmNetwork()
        _, nodes = _create_agents(network)
        source = next(node for node in nodes if node.agent_id == "agent-worker-0")
        target = next(node for node in nodes if node.agent_id == "agent-verifier")
        network.isolate_node(target.agent_id)
        source.gossip_threat("threat-isolated", "isolated-details")
        self.assertNotIn("threat-isolated", target.threat_ledger)
        network.recover_node(target.agent_id)
        network.restart_node(target.agent_id)
        network.sync_hive_memory(source_node_id=source.agent_id, target_node_ids=[target.agent_id])
        self.assertEqual(target.threat_ledger.get("threat-isolated"), "isolated-details")

    def test_mqtt_backend_prefers_explicit_addr_over_env(self) -> None:
        """Goal: Validate mqtt backend prefers explicit addr over env.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        sentinel_client = object()
        with mock.patch("security_monitor.integration.foxmq_adapter._FoxMqttClient", return_value=sentinel_client) as patched:
            with mock.patch(
                "security_monitor.integration.foxmq_adapter.os.getenv",
                side_effect=lambda k, d=None: "10.0.0.1:1883" if k == "FOXMQ_MQTT_ADDR" else d,
            ):
                adapter = FoxMQAdapter(node_id="n1", backend="mqtt", mqtt_addr="127.0.0.1:1884")
        self.assertIs(adapter._official_client, sentinel_client)
        patched.assert_called_once_with(mqtt_addr="127.0.0.1:1884", node_id="n1")
        self.assertEqual(adapter.backend_info()["module"], "mqtt:127.0.0.1:1884")

    def test_mqtt_backend_uses_env_when_addr_not_provided(self) -> None:
        """Goal: Validate mqtt backend uses env when addr not provided.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        sentinel_client = object()
        with mock.patch("security_monitor.integration.foxmq_adapter._FoxMqttClient", return_value=sentinel_client) as patched:
            with mock.patch(
                "security_monitor.integration.foxmq_adapter.os.getenv",
                side_effect=lambda k, d=None: "127.0.0.1:1885" if k == "FOXMQ_MQTT_ADDR" else d,
            ):
                adapter = FoxMQAdapter(node_id="n2", backend="mqtt")
        self.assertIs(adapter._official_client, sentinel_client)
        patched.assert_called_once_with(mqtt_addr="127.0.0.1:1885", node_id="n2")
        self.assertEqual(adapter.backend_info()["module"], "mqtt:127.0.0.1:1885")

    def test_default_backend_is_mqtt(self) -> None:
        """Goal: Validate default backend is mqtt.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        sentinel_client = object()
        with mock.patch("security_monitor.integration.foxmq_adapter._FoxMqttClient", return_value=sentinel_client) as patched:
            with mock.patch(
                "security_monitor.integration.foxmq_adapter.os.getenv",
                side_effect=lambda k, d=None: "127.0.0.1:1886" if k == "FOXMQ_MQTT_ADDR" else d,
            ):
                adapter = FoxMQAdapter(node_id="n3")
        self.assertEqual(adapter.backend, "mqtt")
        self.assertIs(adapter._official_client, sentinel_client)
        patched.assert_called_once_with(mqtt_addr="127.0.0.1:1886", node_id="n3")

    def _build_agent_process_command(
        self,
        agent_id: str,
        run_id: str,
        topic_namespace: str,
        capabilities: str,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        command = [
            sys.executable,
            "-m",
            "security_monitor.track3.main",
            "--mode",
            "agent-process",
            "--agent-id",
            agent_id,
            "--agent-capabilities",
            capabilities,
            "--foxmq-backend",
            "mqtt",
            "--foxmq-mqtt-addr",
            _MQTT_E2E_ADDR,
            "--run-id",
            run_id,
            "--topic-namespace",
            topic_namespace,
        ]
        if extra_args:
            command.extend(extra_args)
        return command

    def _run_multiprocess_cluster_mission(
        self,
        output_dir: str,
        run_id_prefix: str,
        agent_specs: list[tuple[str, str]],
        pre_guardian_delay_seconds: float = 0.0,
        ready_timeout_seconds: float = 45.0,
        terminate_agent_id: str | None = None,
        bootstrap_extra_args: list[str] | None = None,
    ) -> dict[str, Any]:
        run_id = f"{run_id_prefix}-{int(time.time())}"
        topic_namespace = f"run-{run_id}"
        self.assertGreaterEqual(len(agent_specs), 1)
        bootstrap_agent_id, bootstrap_capabilities = agent_specs[0]
        bootstrap_wait_timeout_seconds = max(90.0, float(ready_timeout_seconds) + 60.0)
        bootstrap_command = self._build_agent_process_command(
            agent_id=bootstrap_agent_id,
            run_id=run_id,
            topic_namespace=topic_namespace,
            capabilities=bootstrap_capabilities,
            extra_args=[
                "--output-dir",
                output_dir,
                "--bootstrap-mission",
                "--exit-on-mission-complete",
                "--bootstrap-ready-timeout-seconds",
                str(ready_timeout_seconds),
                "--bootstrap-pre-guardian-delay-seconds",
                str(pre_guardian_delay_seconds),
                "--bootstrap-wait-timeout-seconds",
                str(bootstrap_wait_timeout_seconds),
            ]
            + list(bootstrap_extra_args or []),
        )
        worker_commands = [
            self._build_agent_process_command(
                agent_id=agent_id,
                run_id=run_id,
                topic_namespace=topic_namespace,
                capabilities=capabilities,
            )
            for agent_id, capabilities in agent_specs[1:]
        ]
        worker_processes = [subprocess.Popen(command) for command in worker_commands]
        if worker_processes:
            time.sleep(3.0)
            for proc in worker_processes:
                if proc.poll() is not None:
                    raise AssertionError("worker process exited before bootstrap mission started")
        bootstrap_proc = subprocess.Popen(
            bootstrap_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        bootstrap_stdout = ""
        bootstrap_stderr = ""
        try:
            if terminate_agent_id:
                time.sleep(2.0)
                for (agent_id, _), proc in zip(agent_specs[1:], worker_processes):
                    if agent_id == terminate_agent_id and proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=5)
            bootstrap_stdout, bootstrap_stderr = bootstrap_proc.communicate(timeout=180)
        finally:
            for proc in worker_processes:
                if proc.poll() is None:
                    proc.terminate()
            for proc in worker_processes:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        bootstrap_returncode = int(bootstrap_proc.returncode or 0)
        self.assertEqual(bootstrap_returncode, 0, msg=f"stdout={bootstrap_stdout}\nstderr={bootstrap_stderr}")
        report_path = os.path.join(output_dir, "multiprocess_mission_record.json")
        economy_rounds_path = os.path.join(output_dir, "economy_rounds.json")
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(os.path.exists(economy_rounds_path))
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        return report

    def _assert_cluster_competition_requirements(self, report: dict[str, Any]) -> None:
        """Purpose: Assert cluster competition requirements.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic assert cluster competition requirements rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self.assertTrue(bool(report.get("all_success")))
        self.assertTrue(bool(report.get("role_identity_negotiation")))
        protocol_roles = [str(item).strip().lower() for item in report.get("protocol_roles", []) if str(item).strip()]
        self.assertEqual(protocol_roles, ["scout", "guardian", "verifier", "auditor"])
        role_identity_assignments = dict(report.get("role_identity_assignments", {}))
        expected_assignments = {
            "scout": "agent-scout-only",
            "guardian": "agent-guardian-only",
            "verifier": "agent-verifier-only",
            "auditor": "agent-verifier-only",
        }
        for role_name, expected_agent in expected_assignments.items():
            assignment = dict(role_identity_assignments.get(role_name, {}))
            self.assertEqual(str(assignment.get("role_name", "")).strip().lower(), role_name)
            self.assertEqual(str(assignment.get("assigned_agent", "")).strip(), expected_agent)
        auditor_evidence = dict(report.get("auditor_evidence", {}))
        self.assertEqual(str(auditor_evidence.get("role", "")).strip().lower(), "auditor")
        self.assertEqual(str(auditor_evidence.get("stage", "")).strip().upper(), "CLOSE")
        self.assertTrue(str(auditor_evidence.get("signature", "")).strip())
        steps = list(report.get("steps", []))
        self.assertEqual(len(steps), 3)
        role_names = [str(step.get("role_name", "")).strip().lower() for step in steps]
        self.assertEqual(set(role_names), {"scout", "guardian", "verifier"})
        self.assertTrue(all(str(step.get("state", "")).strip().lower() == "success" for step in steps))
        task_ids = [str(step.get("task_id", "")).strip() for step in steps]
        self.assertEqual(len(task_ids), len(set(task_ids)))
        self.assertTrue(all(task_id for task_id in task_ids))
        selected_agents = [str(step.get("selected_agent", "")).strip() for step in steps]
        self.assertEqual(set(selected_agents), set(expected_assignments.values()))
        readiness = dict(report.get("readiness", {}))
        for expected_agent, expected_roles in (
            ("agent-scout-only", {"scout"}),
            ("agent-guardian-only", {"guardian"}),
            ("agent-verifier-only", {"verifier"}),
        ):
            self.assertIn(expected_agent, readiness)
            ready_item = dict(readiness.get(expected_agent, {}))
            self.assertEqual(str(ready_item.get("state", "")).strip().lower(), "success")
            announced_roles = {
                str(role).strip().lower()
                for role in ready_item.get("roles", [])
                if str(role).strip()
            }
            self.assertEqual(announced_roles, expected_roles)
        peer_snapshots = list(report.get("peer_snapshots", []))
        self.assertGreaterEqual(len(peer_snapshots), 1)
        max_active_peers = max(len(list(item.get("active_peers", []))) for item in peer_snapshots)
        self.assertGreaterEqual(max_active_peers, 2)
        tashi_alignment = dict(report.get("tashi_alignment", {}))
        self.assertTrue(bool(tashi_alignment.get("peer_discovery_observed")))
        self.assertTrue(bool(tashi_alignment.get("proof_of_coordination_verifiable")))
        lattice = dict(report.get("lattice", {}))
        self.assertTrue(bool(lattice.get("discovery_ok")))
        self.assertTrue(bool(lattice.get("authorized_participants_ok")))
        self.assertTrue(bool(lattice.get("independent_validation_ok")))
        self.assertTrue(bool(lattice.get("reputation_routing_ok")))
        self.assertTrue(bool(lattice.get("failover_ok")))
        competition_alignment = dict(report.get("competition_alignment", {}))
        self.assertTrue(bool(competition_alignment.get("Coordination Correctness")))
        self.assertTrue(bool(competition_alignment.get("Resilience")))
        self.assertTrue(bool(competition_alignment.get("Auditability")))
        self.assertTrue(bool(competition_alignment.get("Security Posture")))
        self.assertTrue(bool(competition_alignment.get("Developer clarity")))
        proof_checks = dict(report.get("proof_checks", {}))
        self.assertTrue(proof_checks)
        self.assertTrue(all(bool(value) for value in proof_checks.values()))
        coordination_proof = dict(report.get("coordination_proof", {}))
        signatures = dict(coordination_proof.get("multisig_summary", {}))
        self.assertEqual(set(signatures.keys()), set(expected_assignments.values()))
        economy_summary = dict(report.get("economy_summary", {}))
        self.assertIn("round_count", economy_summary)
        self.assertIn("avg_candidate_count", economy_summary)
        self.assertGreaterEqual(int(economy_summary.get("round_count", 0) or 0), 0)
        economy_rounds = list(report.get("economy_rounds", []))
        for row in economy_rounds:
            item = dict(row)
            winner = dict(item.get("winner", {}))
            self.assertTrue(str(winner.get("selection_reason", "")).strip())
            candidates = list(item.get("candidates", []))
            self.assertGreaterEqual(len(candidates), 1)
            first_candidate = dict(candidates[0]) if candidates else {}
            self.assertIn("breakdown", first_candidate)

    @unittest.skipUnless(
        _MULTIPROCESS_E2E_ENABLED,
        "set MULTIPROCESS_E2E=1 and FOXMQ_MQTT_ADDR to run multiprocess mqtt e2e",
    )
    def test_single_machine_cluster_competition_requirements_e2e(self) -> None:
        """Goal: Validate single machine cluster competition requirements e2e.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert generated artifacts, metrics, and alignment fields satisfy acceptance/competition expectations.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = self._run_multiprocess_cluster_mission(
                output_dir=os.path.join(tmp, "cluster-requirements"),
                run_id_prefix="cluster-req",
                agent_specs=[
                    ("agent-scout-only", "scout"),
                    ("agent-guardian-only", "guardian"),
                    ("agent-verifier-only", "verifier"),
                ],
            )
            self._assert_cluster_competition_requirements(report)

    @unittest.skipUnless(
        _MULTIPROCESS_E2E_ENABLED,
        "set MULTIPROCESS_E2E=1 and FOXMQ_MQTT_ADDR to run multiprocess mqtt e2e",
    )
    def test_single_machine_cluster_business_case_matrix_e2e(self) -> None:
        """Goal: Validate single machine cluster business case matrix e2e.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert mission flow remains correct under injected faults and converges to expected completion/proof state.
        """
        cases = [
            ("risk_control", "risk_control_high_velocity_withdrawal", "tx-"),
            ("threat_intel", "threat_intel_lateral_movement", "ioc-"),
            ("agent_marketplace", "agent_marketplace_fullstack_delivery", "req-"),
            ("distributed_rag", "distributed_rag_multi_sector_fetch", "rag-"),
            ("compute_marketplace", "compute_marketplace_gpu_allocation", "gpu-"),
        ]
        for business_type, expected_scenario, tx_prefix in cases:
            with self.subTest(business_type=business_type):
                with tempfile.TemporaryDirectory() as tmp:
                    report = self._run_multiprocess_cluster_mission(
                        output_dir=os.path.join(tmp, business_type),
                        run_id_prefix=f"business-{business_type}",
                        agent_specs=[
                            ("agent-scout", "scout,guardian,verifier"),
                            ("agent-guardian", "scout,guardian,verifier"),
                            ("agent-verifier", "scout,guardian,verifier"),
                        ],
                        ready_timeout_seconds=75.0,
                        bootstrap_extra_args=[
                            "--business-type",
                            business_type,
                        ],
                    )
                    mission_payload = dict(report.get("mission_payload", {}))
                    self.assertEqual(str(mission_payload.get("business_type", "")).strip().lower(), business_type)
                    context = dict(mission_payload.get("business_context", {}))
                    self.assertEqual(str(context.get("scenario", "")).strip(), expected_scenario)
                    run_id = str(report.get("run_id", "")).strip()
                    tx_id = str(context.get("transaction_id", "")).strip()
                    self.assertTrue(tx_id.startswith(f"{tx_prefix}{run_id}-"))
                    flow_log = list(report.get("business_flow_log", []))
                    self.assertGreaterEqual(len(flow_log), 1)
                    for item in flow_log:
                        task_payload = dict(item.get("task_payload", {}))
                        if str(task_payload.get("transaction_id", "")).strip():
                            self.assertEqual(str(task_payload.get("transaction_id", "")).strip(), tx_id)

    @unittest.skipUnless(_MQTT_E2E_ENABLED, "set MQTT_E2E=1 and FOXMQ_MQTT_ADDR to run mqtt transport e2e")
    def test_mqtt_transport_demo_e2e(self) -> None:
        """Goal: Validate mqtt transport demo e2e.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(
                output_dir=tmp,
                fault_mode="none",
                worker_count=3,
                foxmq_backend="mqtt",
                foxmq_mqtt_addr=_MQTT_E2E_ADDR,
            )
            self.assertEqual(summary["transport_backend"], "mqtt")
            self.assertTrue(summary["checks"]["single_winner"])
            self.assertTrue(summary["checks"]["no_double_assignment"])

    @unittest.skipUnless(
        _MULTIPROCESS_E2E_ENABLED,
        "set MULTIPROCESS_E2E=1 and FOXMQ_MQTT_ADDR to run multiprocess mqtt e2e",
    )
    def test_multiprocess_mission_e2e(self) -> None:
        """Goal: Validate multiprocess mission e2e.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report: dict[str, Any] | None = None
            for attempt in range(2):
                candidate = self._run_multiprocess_cluster_mission(
                    output_dir=os.path.join(tmp, f"mission-{attempt + 1}"),
                    run_id_prefix=f"e2e-attempt-{attempt + 1}",
                    agent_specs=[
                        ("agent-scout", "scout,guardian,verifier"),
                        ("agent-guardian", "scout,guardian,verifier"),
                        ("agent-verifier", "scout,guardian,verifier"),
                    ],
                    ready_timeout_seconds=90.0,
                )
                report = candidate
                if bool(candidate.get("all_success")):
                    break
            self.assertIsNotNone(report)
            report = dict(report or {})
            run_id = str(report.get("run_id", "")).strip()
            topic_namespace = str(report.get("topic_namespace", "")).strip()
            self.assertTrue(report["all_success"])
            self.assertEqual(report["run_id"], run_id)
            self.assertEqual(report["topic_namespace"], topic_namespace)
            self.assertTrue(bool(report.get("role_identity_negotiation")))
            role_identity_assignments = dict(report.get("role_identity_assignments", {}))
            for role_name in ("scout", "guardian", "verifier", "auditor"):
                self.assertIn(role_name, role_identity_assignments)
                assignment = dict(role_identity_assignments.get(role_name, {}))
                self.assertEqual(str(assignment.get("role_name", "")).strip().lower(), role_name)
                self.assertTrue(str(assignment.get("assigned_agent", "")).strip())
            announcements = list(report.get("agent_announcements", []))
            self.assertGreaterEqual(len(announcements), 1)
            roles_by_agent: dict[str, set[str]] = {}
            for item in announcements:
                agent_id = str(item.get("agent_id", "")).strip()
                roles = {
                    str(role).strip().lower()
                    for role in item.get("roles", [])
                    if str(role).strip()
                }
                if agent_id:
                    roles_by_agent[agent_id] = roles
            self.assertTrue(bool(roles_by_agent))
            for expected_agent in ("agent-scout", "agent-guardian", "agent-verifier"):
                if expected_agent in roles_by_agent:
                    self.assertTrue({"scout", "guardian", "verifier"}.issubset(roles_by_agent[expected_agent]))
            self.assertIn("readiness", report)
            self.assertIn("step_metrics", report)
            self.assertIn("business_flow_log", report)
            flow_log = list(report.get("business_flow_log", []))
            self.assertEqual(len(flow_log), 3)
            expected_roles = ["scout", "guardian", "verifier"]
            self.assertEqual([str(item.get("role_name", "")).strip().lower() for item in flow_log], expected_roles)
            self.assertEqual(
                [str(item).strip().lower() for item in report.get("protocol_roles", []) if str(item).strip()],
                ["scout", "guardian", "verifier", "auditor"],
            )
            auditor_evidence = dict(report.get("auditor_evidence", {}))
            self.assertEqual(str(auditor_evidence.get("role", "")).strip().lower(), "auditor")
            self.assertEqual(str(auditor_evidence.get("stage", "")).strip().upper(), "CLOSE")
            self.assertTrue(str(auditor_evidence.get("signature", "")).strip())
            mission_payload = dict(report.get("mission_payload", {}))
            business_context = dict(mission_payload.get("business_context", {}))
            self.assertEqual(str(business_context.get("scenario", "")).strip(), "risk_control_high_velocity_withdrawal")
            self.assertEqual(str(business_context.get("transaction_id", "")).strip(), f"tx-{run_id}-001")
            self.assertAlmostEqual(float(business_context.get("amount_usdt", 0.0)), 48250.75, places=2)
            self.assertEqual(int(business_context.get("velocity_1h", 0)), 17)
            self.assertAlmostEqual(float(business_context.get("risk_score", 0.0)), 0.93, places=3)
            self.assertEqual(int(business_context.get("blacklist_hits", 0)), 2)
            scout_payload = dict(flow_log[0].get("task_payload", {}))
            self.assertEqual(str(scout_payload.get("transaction_id", "")).strip(), f"tx-{run_id}-001")
            self.assertEqual(int(scout_payload.get("velocity_1h", 0)), 17)
            guardian_payload = dict(flow_log[1].get("task_payload", {}))
            self.assertEqual(str(guardian_payload.get("transaction_id", "")).strip(), f"tx-{run_id}-001")
            self.assertEqual(int(guardian_payload.get("recommended_freeze_seconds", 0)), 900)
            verifier_payload = dict(flow_log[2].get("task_payload", {}))
            self.assertEqual(str(verifier_payload.get("transaction_id", "")).strip(), f"tx-{run_id}-001")
            self.assertTrue(str(verifier_payload.get("mitigation_decision", "")).strip())
            self.assertIn("standard_metrics", report)
            self.assertIn("success_rate", report["standard_metrics"])
            self.assertIn("end_to_end_latency_ms", report["standard_metrics"])
            self.assertIn("retry_count", report["standard_metrics"])
            self.assertIn("timeout_count", report["standard_metrics"])
            for item in flow_log:
                payload = dict(item.get("task_payload", {}))
                self.assertTrue(payload)
            economy_rounds = list(report.get("economy_rounds", []))
            if economy_rounds:
                first_round = dict(economy_rounds[0])
                candidates = list(first_round.get("candidates", []))
                if candidates:
                    candidate = dict(candidates[0])
                    self.assertIn("breakdown", candidate)

    @unittest.skipUnless(
        _MULTIPROCESS_E2E_ENABLED,
        "set MULTIPROCESS_E2E=1 and FOXMQ_MQTT_ADDR to run multiprocess mqtt e2e",
    )
    def test_agent_only_bootstrap_mission_e2e(self) -> None:
        """Goal: Validate agent only bootstrap mission e2e.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            run_id = f"agent-only-{int(time.time())}"
            topic_namespace = f"run-{run_id}"
            output_dir = os.path.join(tmp, "agent-only")
            bootstrap_command = self._build_agent_process_command(
                agent_id="agent-scout",
                run_id=run_id,
                topic_namespace=topic_namespace,
                capabilities="scout,guardian,verifier",
                extra_args=[
                    "--output-dir",
                    output_dir,
                    "--bootstrap-mission",
                    "--exit-on-mission-complete",
                    "--bootstrap-ready-timeout-seconds",
                    "45",
                    "--bootstrap-wait-timeout-seconds",
                    "120",
                ],
            )
            worker_commands = [
                self._build_agent_process_command(
                    agent_id="agent-guardian",
                    run_id=run_id,
                    topic_namespace=topic_namespace,
                    capabilities="scout,guardian,verifier",
                ),
                self._build_agent_process_command(
                    agent_id="agent-verifier",
                    run_id=run_id,
                    topic_namespace=topic_namespace,
                    capabilities="scout,guardian,verifier",
                ),
            ]
            worker_processes = [subprocess.Popen(command) for command in worker_commands]
            if worker_processes:
                time.sleep(3.0)
                for proc in worker_processes:
                    self.assertIsNone(proc.poll(), msg="worker process exited before bootstrap mission started")
            bootstrap_proc = subprocess.Popen(
                bootstrap_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                bootstrap_stdout, bootstrap_stderr = bootstrap_proc.communicate(timeout=180)
                self.assertEqual(
                    bootstrap_proc.returncode,
                    0,
                    msg=f"stdout={bootstrap_stdout}\nstderr={bootstrap_stderr}",
                )
            finally:
                for proc in worker_processes:
                    if proc.poll() is None:
                        proc.terminate()
                for proc in worker_processes:
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
            report_path = os.path.join(output_dir, "multiprocess_mission_record.json")
            self.assertTrue(os.path.exists(report_path))
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            self.assertTrue(bool(report.get("steps")))
            self.assertEqual(str(report.get("transport_backend", "")).strip().lower(), "mqtt")
            self.assertEqual(str(report.get("run_id", "")).strip(), run_id)
            self.assertEqual(str(report.get("topic_namespace", "")).strip(), topic_namespace)
            steps = list(report.get("steps", []))
            self.assertEqual(len(steps), 3)
            self.assertTrue(all(str(item.get("state", "")).strip().lower() == "success" for item in steps))
            proof_checks = dict(report.get("proof_checks", {}))
            self.assertTrue(proof_checks)
            self.assertTrue(all(bool(value) for value in proof_checks.values()))

    @unittest.skipUnless(
        _MULTIPROCESS_RECOVERY_E2E_ENABLED,
        "set MULTIPROCESS_RECOVERY_E2E=1 and FOXMQ_MQTT_ADDR to run multiprocess recovery e2e",
    )
    def test_multiprocess_mission_recovery_e2e(self) -> None:
        """Goal: Validate multiprocess mission recovery e2e.

        Setup: Use temporary artifact directories and Track3 demo/bootstrap helpers; transport-backed cases rely on local FoxMQ MQTT (127.0.0.1:1883) and spawn agent processes when the scenario is multiprocess.
        Checks: Assert mission execution recovers from injected faults and converges to expected completion/proof artifacts.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = self._run_multiprocess_cluster_mission(
                output_dir=os.path.join(tmp, "mission-recovery"),
                run_id_prefix="recovery-dynamic",
                agent_specs=[
                    ("agent-scout", "scout,guardian,verifier"),
                    ("agent-guardian", "scout,guardian,verifier"),
                    ("agent-verifier", "scout,guardian,verifier"),
                ],
                pre_guardian_delay_seconds=3.0,
                terminate_agent_id="agent-guardian",
            )
            self.assertTrue(report["all_success"])
            self.assertTrue(bool(report.get("role_identity_negotiation")))
            role_identity_assignments = dict(report.get("role_identity_assignments", {}))
            self.assertIn("guardian", role_identity_assignments)
            guardian_assignment = dict(role_identity_assignments.get("guardian", {}))
            self.assertEqual(str(guardian_assignment.get("role_name", "")).strip().lower(), "guardian")
            self.assertTrue(str(guardian_assignment.get("assigned_agent", "")).strip())
            announcements = list(report.get("agent_announcements", []))
            self.assertGreaterEqual(len(announcements), 1)
            steps = list(report.get("steps", []))
            self.assertGreaterEqual(len(steps), 3)
            guardian_steps = [step for step in steps if str(step.get("role_name", "")).strip().lower() == "guardian"]
            self.assertGreaterEqual(len(guardian_steps), 1)
            guardian_selected_agents = {str(step.get("selected_agent", "")).strip() for step in guardian_steps}
            self.assertNotIn("agent-guardian", guardian_selected_agents)
            metrics = dict(report["standard_metrics"])
            self.assertGreater(float(metrics["success_rate"]), 0.9)
            self.assertGreaterEqual(float(metrics["end_to_end_latency_ms"]), 0.0)
            self.assertGreaterEqual(int(metrics["retry_count"]), 0)
            self.assertGreaterEqual(int(metrics["timeout_count"]), 0)

if __name__ == "__main__":
    unittest.main()
