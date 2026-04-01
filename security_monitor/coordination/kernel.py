"""Coordination kernel that manages tasks, policies, and transport interactions.

The kernel tracks task lifecycle state, applies policy hooks before dispatch, and
publishes/subscribes coordination messages through pluggable transports.
"""

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Tuple

from security_monitor.coordination.models import CoordinationTask, TaskState
from security_monitor.transports.base import BaseTransport

PolicyHook = Callable[[CoordinationTask], Tuple[bool, str]]


class CoordinationKernel:
    def __init__(
        self,
        transport: BaseTransport,
        policy_hooks: List[PolicyHook] | None = None,
        topic_root: str = "coordination",
    ):
        self.transport = transport
        self.policy_hooks = list(policy_hooks or [])
        self.state_store: Dict[str, Any] = {}
        self.task_states: Dict[str, Dict[str, Any]] = {}
        self.agent_capabilities: Dict[str, set[str]] = defaultdict(set)
        normalized_topic_root = str(topic_root).strip().strip("/")
        self.topic_root = normalized_topic_root or "coordination"
        self.started = False

    def start(self) -> None:
        """Purpose: Start.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic start rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if self.started:
            return
        self.transport.connect()
        self.started = True

    def stop(self) -> None:
        """Purpose: Stop.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic stop rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if not self.started:
            return
        self.transport.close()
        self.started = False

    def register_agent(self, agent_id: str, capabilities: List[str] | None = None) -> None:
        """Purpose: Register agent.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic register agent rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        normalized_agent_id = str(agent_id).strip()
        if not normalized_agent_id:
            raise ValueError("agent_id is required")
        normalized_capabilities = {str(cap).strip().lower() for cap in (capabilities or []) if str(cap).strip()}
        self.agent_capabilities[normalized_agent_id] = normalized_capabilities
        self.sync_state(f"agent:{normalized_agent_id}", {"capabilities": sorted(normalized_capabilities)})

    def add_policy_hook(self, hook: PolicyHook) -> None:
        """Purpose: Add policy hook.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic add policy hook rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self.policy_hooks.append(hook)

    def subscribe(self, topic: str, callback: Callable[[dict[str, Any]], None]) -> None:
        """Purpose: Subscribe.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic subscribe rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self.transport.subscribe(topic, callback)

    def publish(self, topic: str, payload: Dict[str, Any]) -> str:
        """Purpose: Publish.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic publish rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if not self.started:
            self.start()
        return self.transport.publish(topic, payload)

    def active_peers(self) -> list[str]:
        """Purpose: Active peers.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic active peers rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if not self.started:
            self.start()
        return list(self.transport.get_active_peers())

    def transport_info(self) -> Dict[str, Any]:
        """Purpose: Transport info.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic transport info rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if not self.started:
            self.start()
        return dict(self.transport.backend_info())

    def submit_task(
        self,
        task_type: str,
        payload: Dict[str, Any],
        source_agent: str = "",
        target_agent: str = "",
        metadata: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Create a task envelope, persist pending state, and dispatch via routing."""
        task = CoordinationTask(
            task_id=str(uuid.uuid4()),
            task_type=str(task_type),
            payload=dict(payload),
            source_agent=source_agent,
            target_agent=target_agent,
            metadata=dict(metadata or {}),
        )
        self._set_task_state(task.task_id, TaskState.PENDING, {"created_at": task.created_at.isoformat()})
        return self.route_task(task)

    def task_topic(self, agent_id: str) -> str:
        """Purpose: Task topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic task topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/tasks/{str(agent_id).strip()}"

    def result_topic(self, task_id: str) -> str:
        """Purpose: Result topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic result topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/results/{str(task_id).strip()}"

    def result_stream_topic(self) -> str:
        """Purpose: Result stream topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic result stream topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/results"

    def result_wildcard_topic(self) -> str:
        """Purpose: Result wildcard topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic result wildcard topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/results/+"

    def response_topic(self, agent_id: str) -> str:
        """Purpose: Response topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic response topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/responses/{str(agent_id).strip()}"

    def agent_announcement_topic(self) -> str:
        """Purpose: Agent announcement topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic agent announcement topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/agents/announcements"

    def agent_heartbeat_topic(self) -> str:
        """Purpose: Agent heartbeat topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic agent heartbeat topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/agents/heartbeats"

    def role_intent_topic(self, role: str) -> str:
        """Purpose: Role intent topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic role intent topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/roles/{str(role).strip().lower()}/intent"

    def role_claim_topic(self, role: str) -> str:
        """Purpose: Role claim topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic role claim topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/roles/{str(role).strip().lower()}/claim"

    def mission_start_topic(self) -> str:
        """Purpose: Mission start topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic mission start topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/missions/start"

    def mission_stage_topic(self) -> str:
        """Purpose: Mission stage topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic mission stage topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/missions/stage"

    def mission_complete_topic(self) -> str:
        """Purpose: Mission complete topic.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic mission complete topic rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return f"{self.topic_root}/missions/complete"

    def route_task(self, task: CoordinationTask) -> Dict[str, Any]:
        """Evaluate policy, resolve target agent, publish task payload, and track route metadata."""
        allowed, reason = self._evaluate_policy(task)
        if not allowed:
            self._set_task_state(task.task_id, TaskState.FAILED, {"reason": reason})
            return {"status": "blocked", "task_id": task.task_id, "reason": reason}

        target_agent = task.target_agent or self._resolve_target_agent(task.task_type)
        if not target_agent:
            self._set_task_state(task.task_id, TaskState.FAILED, {"reason": "No agent route available"})
            return {"status": "error", "task_id": task.task_id, "reason": "No agent route available"}

        topic = self.task_topic(target_agent)
        event_payload = {
            "task_id": task.task_id,
            "task_type": task.task_type,
            "payload": task.payload,
            "source_agent": task.source_agent,
            "target_agent": target_agent,
            "metadata": task.metadata,
            "created_at": task.created_at.isoformat(),
        }
        self._set_task_state(
            task.task_id,
            TaskState.ROUTED,
            {
                "task_type": task.task_type,
                "source_agent": task.source_agent,
                "target_agent": target_agent,
                "metadata": dict(task.metadata),
                "topic": topic,
                "routed_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        self.publish(topic, event_payload)
        return {"status": "routed", "task_id": task.task_id, "target_agent": target_agent, "topic": topic}

    def set_task_running(self, task_id: str, worker_agent: str) -> None:
        """Purpose: Set task running.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic set task running rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self._set_task_state(task_id, TaskState.RUNNING, {"worker_agent": worker_agent})

    def complete_task(self, task_id: str, result: Dict[str, Any], success: bool = True) -> None:
        """Purpose: Complete task.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic complete task rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        state = TaskState.SUCCESS if success else TaskState.FAILED
        self._set_task_state(
            task_id,
            state,
            {"result": dict(result), "completed_at": datetime.now(timezone.utc).isoformat()},
        )
        snapshot = self.get_task_state(task_id) or {"task_id": task_id, "state": state.value, "result": dict(result)}
        self.publish(self.result_topic(task_id), snapshot)
        self.publish(self.result_stream_topic(), snapshot)
        metadata = dict(snapshot.get("metadata", {}))
        response_topic = str(metadata.get("__response_topic", "") or metadata.get("response_topic", "")).strip()
        if response_topic:
            response_payload = dict(snapshot)
            correlation_data = metadata.get("__correlation_data")
            if correlation_data is not None:
                response_payload["__correlation_data"] = correlation_data
            self.publish(response_topic, response_payload)

    def get_task_state(self, task_id: str) -> Dict[str, Any] | None:
        """Purpose: Get task state.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic get task state rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        state = self.task_states.get(task_id)
        if state is None:
            return None
        return dict(state)

    def sync_state(self, key: str, value: Any) -> None:
        """Persist a shared key/value snapshot for coordination-level state synchronization."""
        self.state_store[str(key)] = value

    def get_state(self, key: str, default: Any = None) -> Any:
        """Purpose: Get state.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic get state rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return self.state_store.get(str(key), default)

    def _evaluate_policy(self, task: CoordinationTask) -> Tuple[bool, str]:
        """Purpose: Evaluate policy.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic evaluate policy rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        for hook in self.policy_hooks:
            allow, reason = hook(task)
            if not allow:
                return False, reason
        return True, "ok"

    def _resolve_target_agent(self, task_type: str) -> str:
        """Pick the first active agent advertising capability for the requested task type."""
        normalized_task_type = str(task_type).strip().lower()
        for agent_id, capabilities in self.agent_capabilities.items():
            if normalized_task_type in capabilities:
                return agent_id
        return ""

    def _set_task_state(self, task_id: str, state: TaskState, extras: Dict[str, Any] | None = None) -> None:
        """Upsert task lifecycle snapshot with latest state and optional attached metadata."""
        snapshot = dict(self.task_states.get(task_id, {}))
        snapshot["task_id"] = task_id
        snapshot["state"] = state.value
        if extras:
            snapshot.update(extras)
        self.task_states[task_id] = snapshot
