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
        if self.started:
            return
        self.transport.connect()
        self.started = True

    def stop(self) -> None:
        if not self.started:
            return
        self.transport.close()
        self.started = False

    def register_agent(self, agent_id: str, capabilities: List[str] | None = None) -> None:
        normalized_agent_id = str(agent_id).strip()
        if not normalized_agent_id:
            raise ValueError("agent_id is required")
        normalized_capabilities = {str(cap).strip().lower() for cap in (capabilities or []) if str(cap).strip()}
        self.agent_capabilities[normalized_agent_id] = normalized_capabilities
        self.sync_state(f"agent:{normalized_agent_id}", {"capabilities": sorted(normalized_capabilities)})

    def add_policy_hook(self, hook: PolicyHook) -> None:
        self.policy_hooks.append(hook)

    def subscribe(self, topic: str, callback: Callable[[dict[str, Any]], None]) -> None:
        self.transport.subscribe(topic, callback)

    def publish(self, topic: str, payload: Dict[str, Any]) -> str:
        if not self.started:
            self.start()
        return self.transport.publish(topic, payload)

    def active_peers(self) -> list[str]:
        if not self.started:
            self.start()
        return list(self.transport.get_active_peers())

    def transport_info(self) -> Dict[str, Any]:
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
        return f"{self.topic_root}/tasks/{str(agent_id).strip()}"

    def result_topic(self, task_id: str) -> str:
        return f"{self.topic_root}/results/{str(task_id).strip()}"

    def result_stream_topic(self) -> str:
        return f"{self.topic_root}/results"

    def result_wildcard_topic(self) -> str:
        return f"{self.topic_root}/results/+"

    def response_topic(self, agent_id: str) -> str:
        return f"{self.topic_root}/responses/{str(agent_id).strip()}"

    def agent_announcement_topic(self) -> str:
        return f"{self.topic_root}/agents/announcements"

    def agent_heartbeat_topic(self) -> str:
        return f"{self.topic_root}/agents/heartbeats"

    def role_intent_topic(self, role: str) -> str:
        return f"{self.topic_root}/roles/{str(role).strip().lower()}/intent"

    def role_claim_topic(self, role: str) -> str:
        return f"{self.topic_root}/roles/{str(role).strip().lower()}/claim"

    def mission_start_topic(self) -> str:
        return f"{self.topic_root}/missions/start"

    def mission_stage_topic(self) -> str:
        return f"{self.topic_root}/missions/stage"

    def mission_complete_topic(self) -> str:
        return f"{self.topic_root}/missions/complete"

    def route_task(self, task: CoordinationTask) -> Dict[str, Any]:
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
        self._set_task_state(task_id, TaskState.RUNNING, {"worker_agent": worker_agent})

    def complete_task(self, task_id: str, result: Dict[str, Any], success: bool = True) -> None:
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
        state = self.task_states.get(task_id)
        if state is None:
            return None
        return dict(state)

    def sync_state(self, key: str, value: Any) -> None:
        self.state_store[str(key)] = value

    def get_state(self, key: str, default: Any = None) -> Any:
        return self.state_store.get(str(key), default)

    def _evaluate_policy(self, task: CoordinationTask) -> Tuple[bool, str]:
        for hook in self.policy_hooks:
            allow, reason = hook(task)
            if not allow:
                return False, reason
        return True, "ok"

    def _resolve_target_agent(self, task_type: str) -> str:
        normalized_task_type = str(task_type).strip().lower()
        for agent_id, capabilities in self.agent_capabilities.items():
            if normalized_task_type in capabilities:
                return agent_id
        return ""

    def _set_task_state(self, task_id: str, state: TaskState, extras: Dict[str, Any] | None = None) -> None:
        snapshot = dict(self.task_states.get(task_id, {}))
        snapshot["task_id"] = task_id
        snapshot["state"] = state.value
        if extras:
            snapshot.update(extras)
        self.task_states[task_id] = snapshot
