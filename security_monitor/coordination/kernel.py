import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Tuple

from security_monitor.coordination.models import CoordinationTask, TaskState
from security_monitor.transports.base import BaseTransport

PolicyHook = Callable[[CoordinationTask], Tuple[bool, str]]


class CoordinationKernel:
    def __init__(self, transport: BaseTransport, policy_hooks: List[PolicyHook] | None = None):
        self.transport = transport
        self.policy_hooks = list(policy_hooks or [])
        self.state_store: Dict[str, Any] = {}
        self.task_states: Dict[str, Dict[str, Any]] = {}
        self.agent_capabilities: Dict[str, set[str]] = defaultdict(set)
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

    def route_task(self, task: CoordinationTask) -> Dict[str, Any]:
        allowed, reason = self._evaluate_policy(task)
        if not allowed:
            self._set_task_state(task.task_id, TaskState.FAILED, {"reason": reason})
            return {"status": "blocked", "task_id": task.task_id, "reason": reason}

        target_agent = task.target_agent or self._resolve_target_agent(task.task_type)
        if not target_agent:
            self._set_task_state(task.task_id, TaskState.FAILED, {"reason": "No agent route available"})
            return {"status": "error", "task_id": task.task_id, "reason": "No agent route available"}

        topic = f"coordination/tasks/{target_agent}"
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
            {"target_agent": target_agent, "topic": topic, "routed_at": datetime.now(timezone.utc).isoformat()},
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
