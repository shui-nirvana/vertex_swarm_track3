from typing import Any, Dict

from security_monitor.coordination.kernel import CoordinationKernel


class OrchestratorCompatibilityAdapter:
    def __init__(self, kernel: CoordinationKernel):
        self.kernel = kernel

    def publish(self, topic: str, payload: Dict[str, Any]) -> str:
        return self.kernel.publish(topic, payload)

    def subscribe(self, topic: str, callback) -> None:
        self.kernel.subscribe(topic, callback)

    def dispatch_task(
        self,
        task_type: str,
        payload: Dict[str, Any],
        source_agent: str = "legacy-orchestrator",
        target_agent: str = "",
        metadata: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        route_metadata = {"compat_entry": "centralized_orchestrator"}
        route_metadata.update(dict(metadata or {}))
        return self.kernel.submit_task(
            task_type=task_type,
            payload=payload,
            source_agent=source_agent,
            target_agent=target_agent,
            metadata=route_metadata,
        )

    def sync_state(self, key: str, value: Any) -> None:
        self.kernel.sync_state(key, value)

    def read_state(self, key: str, default: Any = None) -> Any:
        return self.kernel.get_state(key, default)
