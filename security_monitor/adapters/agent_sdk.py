from typing import Any, Dict, Iterable

from security_monitor.adapters.centralized_compat import OrchestratorCompatibilityAdapter
from security_monitor.coordination import AgentPluginRuntime, CoordinationKernel
from security_monitor.plugins import AgentBusinessPlugin
from security_monitor.transports import build_transport


class ExternalAgentSDK:
    def __init__(
        self,
        agent_id: str,
        backend: str = "mqtt",
        bridge_cmd: str | None = None,
        mqtt_addr: str | None = None,
        fallback_to_simulated: bool = True,
        max_workers: int = 4,
        max_inflight: int = 64,
        plugin_timeout_s: float = 3.0,
        max_retries: int = 1,
    ):
        transport = build_transport(
            node_id=agent_id,
            backend=backend,
            bridge_cmd=bridge_cmd,
            mqtt_addr=mqtt_addr,
            fallback_to_simulated=fallback_to_simulated,
        )
        self.kernel = CoordinationKernel(transport=transport)
        self.compat = OrchestratorCompatibilityAdapter(self.kernel)
        self.runtime = AgentPluginRuntime(
            agent_id=agent_id,
            kernel=self.kernel,
            plugins=[],
            max_workers=max_workers,
            max_inflight=max_inflight,
            plugin_timeout_s=plugin_timeout_s,
            max_retries=max_retries,
        )

    def register_plugins(self, plugins: Iterable[AgentBusinessPlugin]) -> None:
        for plugin in plugins:
            self.runtime.registry.register(plugin)

    def start_agent_runtime(self) -> None:
        self.runtime.start()

    def dispatch(
        self,
        task_type: str,
        payload: Dict[str, Any],
        source_agent: str = "external-agent",
        target_agent: str = "",
        metadata: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return self.compat.dispatch_task(
            task_type=task_type,
            payload=payload,
            source_agent=source_agent,
            target_agent=target_agent,
            metadata=metadata,
        )

    def get_task_state(self, task_id: str) -> Dict[str, Any] | None:
        return self.kernel.get_task_state(task_id)

    def get_metrics(self) -> Dict[str, float]:
        return self.runtime.get_metrics()

    def stop(self) -> None:
        self.runtime.stop()
