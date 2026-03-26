from typing import Any, Dict
from time import sleep

from security_monitor.adapters.centralized_compat import OrchestratorCompatibilityAdapter
from security_monitor.coordination import AgentPluginRuntime, CoordinationKernel
from security_monitor.plugins import CrossOrgAlertPlugin
from security_monitor.transports.factory import build_transport


def _wait_for_terminal_state(kernel: CoordinationKernel, task_id: str, rounds: int = 120) -> Dict[str, Any] | None:
    for _ in range(rounds):
        state = kernel.get_task_state(task_id)
        if state and state.get("state") in ("success", "failed", "blocked"):
            return state
        sleep(0.01)
    return kernel.get_task_state(task_id)


def run_cross_org_alert_scenario(backend: str = "simulated") -> Dict[str, Any]:
    transport = build_transport(node_id="cross-org-kernel", backend=backend, fallback_to_simulated=False)
    kernel = CoordinationKernel(transport=transport)
    kernel.register_agent("org-a-alert-node", ["alert_sync"])
    kernel.register_agent("org-b-alert-node", ["alert_sync"])
    compat = OrchestratorCompatibilityAdapter(kernel)
    first = compat.dispatch_task(
        task_type="alert_sync",
        payload={"from_org": "org-a", "to_org": "org-b", "alert_id": "alert-2026-001"},
        source_agent="central-alert-orchestrator",
    )
    second = compat.dispatch_task(
        task_type="alert_sync",
        payload={"from_org": "org-b", "to_org": "org-a", "alert_id": "alert-2026-002"},
        source_agent="central-alert-orchestrator",
    )
    return {"scenario": "cross_org_alert", "dispatches": [first, second]}


def run_cross_org_alert_agent_driven_scenario(backend: str = "simulated") -> Dict[str, Any]:
    transport = build_transport(node_id="cross-org-kernel-agent-driven", backend=backend, fallback_to_simulated=False)
    kernel = CoordinationKernel(transport=transport)
    runtime = AgentPluginRuntime(
        agent_id="org-alert-runtime",
        kernel=kernel,
        plugins=[CrossOrgAlertPlugin()],
    )
    runtime.start()
    compat = OrchestratorCompatibilityAdapter(kernel)
    first = compat.dispatch_task(
        task_type="alert_sync",
        payload={"from_org": "org-a", "to_org": "org-b", "alert_id": "alert-2026-101"},
        source_agent="legacy-orchestrator",
        metadata={"plugin": "cross_org_alert"},
    )
    second = compat.dispatch_task(
        task_type="alert_sync",
        payload={"from_org": "org-b", "to_org": "org-a", "alert_id": "alert-2026-102"},
        source_agent="legacy-orchestrator",
        metadata={"plugin": "cross_org_alert"},
    )
    return {
        "scenario": "cross_org_alert_agent_driven",
        "dispatches": [first, second],
        "task_states": [
            _wait_for_terminal_state(kernel, first["task_id"]),
            _wait_for_terminal_state(kernel, second["task_id"]),
        ],
    }
