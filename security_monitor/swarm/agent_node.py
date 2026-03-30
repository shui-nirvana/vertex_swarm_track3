import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from security_monitor.swarm.execution import execute_task
from security_monitor.swarm.fault_injector import FaultInjector
from security_monitor.swarm.messages import (
    BID,
    DISCOVER,
    EXEC_DONE,
    EXEC_START,
    HEARTBEAT,
    NODE_RESTART,
    TASK_CLUSTER_FORMED,
    TASK_OFFER,
    THREAT_GOSSIP,
    VERIFY_ACK,
    EventRecord,
)
from security_monitor.swarm.security import ReplayProtector, sign_payload, verify_payload


@dataclass
class AgentNode:
    agent_id: str
    capability: str
    secret: str
    bid_profile: Dict[str, Any]
    network: "SwarmNetwork"
    is_planner: bool = False
    active: bool = True
    peers: Dict[str, float] = field(default_factory=dict)
    offers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    bids_by_task: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    committed_winner_by_task: Dict[str, str] = field(default_factory=dict)
    executions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    verify_acks_by_task: Dict[str, Dict[str, str]] = field(default_factory=dict)
    threat_ledger: Dict[str, str] = field(default_factory=dict)  # Hive Memory: threat_id -> threat_details
    task_clusters: Dict[str, List[str]] = field(default_factory=dict)
    replay: ReplayProtector = field(default_factory=ReplayProtector)
    _nonce: int = 0

    def _next_nonce(self) -> str:
        self._nonce += 1
        return f"{self.agent_id}-{self._nonce}"

    def _build_envelope(self, message_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        envelope = {
            "type": message_type,
            "sender": self.agent_id,
            "ts": time.time(),
            "nonce": self._next_nonce(),
            "payload": payload,
        }
        signing_data = {
            "type": envelope["type"],
            "sender": envelope["sender"],
            "ts": envelope["ts"],
            "nonce": envelope["nonce"],
            "payload": envelope["payload"],
        }
        envelope["sig"] = sign_payload(self.secret, signing_data)
        return envelope

    def _broadcast(self, message_type: str, payload: Dict[str, Any]) -> None:
        envelope = self._build_envelope(message_type, payload)
        self.network.broadcast(envelope)

    def discover(self) -> None:
        self._broadcast(
            DISCOVER,
            {
                "capability": self.capability,
            },
        )

    def heartbeat(self) -> None:
        self._broadcast(
            HEARTBEAT,
            {
                "capability": self.capability,
            },
        )

    def cleanup_peers(self, ttl_seconds: float = 10.0) -> None:
        now = time.time()
        stale = [peer_id for peer_id, last_seen in self.peers.items() if now - last_seen > ttl_seconds]
        for peer_id in stale:
            self.peers.pop(peer_id, None)

    def offer_task(self, task_id: str, mission: str, budget_ceiling: float, constraints: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "task_id": task_id,
            "mission": mission,
            "budget_ceiling": budget_ceiling,
            "constraints": constraints or {},
        }
        self.offers[task_id] = payload
        self._broadcast(TASK_OFFER, payload)

    def form_task_cluster(
        self,
        task_id: str,
        required_capabilities: Optional[List[str]] = None,
        min_size: int = 3,
    ) -> List[str]:
        required = {str(cap).strip().lower() for cap in (required_capabilities or []) if str(cap).strip()}
        candidates = [
            node_id
            for node_id in self.network.active_node_ids()
            if node_id in self.network.nodes
            and (not required or str(self.network.nodes[node_id].capability).strip().lower() in required)
        ]
        members = sorted(candidates)
        if self.agent_id not in members and self.agent_id in self.network.nodes:
            members = sorted(set(members) | {self.agent_id})
        if len(members) > 0 and len(members) < max(1, int(min_size)):
            extras = [node_id for node_id in sorted(self.network.active_node_ids()) if node_id not in members]
            for node_id in extras:
                members.append(node_id)
                if len(members) >= max(1, int(min_size)):
                    break
        self.task_clusters[str(task_id)] = members
        self._broadcast(
            TASK_CLUSTER_FORMED,
            {
                "task_id": str(task_id),
                "members": members,
                "required_capabilities": sorted(required),
            },
        )
        return members

    def _maybe_bid(self, offer: Dict[str, Any]) -> None:
        if self.is_planner:
            return
        constraints = dict(offer.get("constraints", {}))
        required_quota = max(1, int(constraints.get("required_quota", 1)))
        capacity = int(self.bid_profile.get("capacity", 1))
        if capacity < required_quota:
            return
        estimated_cost = float(constraints.get("estimated_cost", self.bid_profile.get("price", 1.0)))
        budget_limit = float(constraints.get("budget_limit", offer.get("budget_ceiling", 0.0)))
        bid_price = max(float(self.bid_profile.get("price", 1.0)), estimated_cost)
        if bid_price > budget_limit:
            return
        bid_payload = {
            "task_id": offer["task_id"],
            "agent_id": self.agent_id,
            "price": bid_price,
            "eta_ms": int(self.bid_profile.get("eta_ms", 100)),
            "capacity": capacity,
            "required_quota": required_quota,
            "estimated_cost": estimated_cost,
            "budget_limit": budget_limit,
        }
        self._broadcast(BID, bid_payload)

    def assign_task_winner(self, task_id: str, winner_agent_id: str) -> None:
        task_key = str(task_id).strip()
        winner = str(winner_agent_id).strip()
        if not task_key or not winner:
            return
        self.committed_winner_by_task[task_key] = winner

    def execute_committed_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        winner = self.committed_winner_by_task.get(task_id)
        if winner != self.agent_id:
            return None
        offer = self.offers.get(task_id)
        if offer is None:
            return None
        self._broadcast(
            EXEC_START,
            {
                "task_id": task_id,
                "worker_id": self.agent_id,
            },
        )
        result = execute_task(task=offer, worker_id=self.agent_id)
        self.executions[task_id] = result
        self._broadcast(
            EXEC_DONE,
            {
                "task_id": task_id,
                "worker_id": self.agent_id,
                "result_digest": result["result_digest"],
            },
        )
        return result

    def emit_verify_ack(self, task_id: str, event_hash: str) -> None:
        self._broadcast(
            VERIFY_ACK,
            {
                "task_id": task_id,
                "agent_id": self.agent_id,
                "event_hash": event_hash,
            },
        )

    def gossip_threat(self, threat_id: str, details: str) -> None:
        """
        Hive Memory: Broadcast a threat to update the swarm's shared world view.
        """
        self.threat_ledger[threat_id] = details
        self._broadcast(
            THREAT_GOSSIP,
            {
                "threat_id": threat_id,
                "details": details,
                "reporter": self.agent_id,
            },
        )

    def receive(self, envelope: Dict[str, Any]) -> None:
        if not self.active:
            return
        message_type = str(envelope["type"])
        sender = str(envelope["sender"])
        ts = float(envelope["ts"])
        nonce = str(envelope["nonce"])
        payload = dict(envelope["payload"])
        signature = str(envelope["sig"])
        sender_secret = self.network.agent_secrets.get(sender)
        if sender_secret is None:
            return
        signed_portion = {
            "type": message_type,
            "sender": sender,
            "ts": ts,
            "nonce": nonce,
            "payload": payload,
        }
        if not verify_payload(sender_secret, signed_portion, signature):
            return
        replay_ok, _ = self.replay.check_and_mark(sender=sender, nonce=nonce, ts=ts)
        if not replay_ok:
            return
        if message_type in {DISCOVER, HEARTBEAT}:
            self.peers[sender] = time.time()
            return
        if message_type == TASK_OFFER:
            task_id = str(payload["task_id"])
            self.offers[task_id] = payload
            self._maybe_bid(payload)
            return
        if message_type == BID:
            task_id = str(payload["task_id"])
            bids = self.bids_by_task.setdefault(task_id, [])
            existing = {str(item["agent_id"]) for item in bids}
            if str(payload["agent_id"]) not in existing:
                bids.append(payload)
            return
        if message_type == EXEC_DONE:
            task_id = str(payload["task_id"])
            self.executions[task_id] = payload
            return
        if message_type == VERIFY_ACK:
            task_id = str(payload["task_id"])
            acks = self.verify_acks_by_task.setdefault(task_id, {})
            acks[str(payload["agent_id"])] = signature
            return
        if message_type == THREAT_GOSSIP:
            # Hive Memory: Update local world view from peer gossip
            threat_id = str(payload["threat_id"])
            details = str(payload["details"])
            self.threat_ledger[threat_id] = details
            return
        if message_type == TASK_CLUSTER_FORMED:
            task_id = str(payload.get("task_id", ""))
            members = [str(member) for member in list(payload.get("members", []))]
            if task_id:
                self.task_clusters[task_id] = members
            return


class SwarmNetwork:
    def __init__(self, fault_injector: Optional[FaultInjector] = None):
        self.nodes: Dict[str, AgentNode] = {}
        self.agent_secrets: Dict[str, str] = {}
        self.events: List[EventRecord] = []
        self.fault_injector = fault_injector or FaultInjector()
        self.partitioned_nodes: set[str] = set()

    def register(self, node: AgentNode) -> None:
        self.nodes[node.agent_id] = node
        self.agent_secrets[node.agent_id] = node.secret

    def active_node_ids(self) -> List[str]:
        return [node_id for node_id, node in self.nodes.items() if node.active and not self.fault_injector.is_node_dropped(node_id)]

    def drop_node(self, node_id: str) -> None:
        self.fault_injector.dropped_nodes.add(node_id)

    def isolate_node(self, node_id: str) -> None:
        if node_id not in self.nodes:
            return
        self.partitioned_nodes.add(node_id)

    def recover_node(self, node_id: str) -> None:
        self.partitioned_nodes.discard(node_id)

    def restart_node(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node is None:
            return
        node.peers.clear()
        node.offers.clear()
        node.bids_by_task.clear()
        node.committed_winner_by_task.clear()
        node.executions.clear()
        node.verify_acks_by_task.clear()
        node.threat_ledger.clear()
        node.task_clusters.clear()
        node.replay = ReplayProtector()
        self.events.append(
            EventRecord(
                ts=time.time(),
                actor=node_id,
                event_type=NODE_RESTART,
                payload={"node_id": node_id},
            )
        )

    def sync_hive_memory(self, source_node_id: str, target_node_ids: Optional[List[str]] = None) -> None:
        source_node = self.nodes.get(source_node_id)
        if source_node is None:
            return
        targets = target_node_ids or list(self.nodes.keys())
        target_set = {target_id for target_id in targets if target_id in self.nodes and target_id != source_node_id}
        for threat_id, details in source_node.threat_ledger.items():
            payload = {
                "threat_id": threat_id,
                "details": details,
                "reporter": source_node_id,
            }
            envelope = source_node._build_envelope(THREAT_GOSSIP, payload)
            self.events.append(
                EventRecord(
                    ts=float(envelope["ts"]),
                    actor=source_node_id,
                    event_type=THREAT_GOSSIP,
                    payload=payload,
                )
            )
            for target_id in target_set:
                if self.fault_injector.is_node_dropped(target_id):
                    continue
                if self._is_partition_blocked(sender=source_node_id, receiver=target_id):
                    continue
                self.nodes[target_id].receive(envelope)

    def _is_partition_blocked(self, sender: str, receiver: str) -> bool:
        if sender == receiver:
            return False
        return sender in self.partitioned_nodes or receiver in self.partitioned_nodes

    def broadcast(self, envelope: Dict[str, Any]) -> None:
        sender = str(envelope["sender"])
        if self.fault_injector.is_node_dropped(sender):
            return
        self.fault_injector.apply_delay(str(envelope["type"]))
        self.events.append(
            EventRecord(
                ts=float(envelope["ts"]),
                actor=sender,
                event_type=str(envelope["type"]),
                payload=dict(envelope["payload"]),
            )
        )
        for node_id, node in self.nodes.items():
            if self.fault_injector.is_node_dropped(node_id):
                continue
            if self._is_partition_blocked(sender=sender, receiver=node_id):
                continue
            node.receive(envelope)
