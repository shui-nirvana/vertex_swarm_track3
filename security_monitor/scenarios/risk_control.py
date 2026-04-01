"""Risk Control module for Vertex Swarm Track3."""

from time import sleep
from typing import Any, Dict

from security_monitor.adapters.centralized_compat import OrchestratorCompatibilityAdapter
from security_monitor.coordination import AgentPluginRuntime, CoordinationKernel
from security_monitor.plugins import RiskControlPlugin
from security_monitor.transports.factory import build_transport

BUSINESS_TYPE = "risk_control"
DEFAULT_TEMPLATE_FILENAME = "risk_control.default.json"


def _wait_for_terminal_state(kernel: CoordinationKernel, task_id: str, rounds: int = 120) -> Dict[str, Any] | None:
    """Purpose: Wait for terminal state.

    Inputs:
    - Uses function parameters plus relevant in-memory runtime state.

    Behavior:
    - Validates/normalizes key fields before doing state transitions.
    - Executes deterministic wait for terminal state rules so all nodes converge on the same result.

    Outputs:
    - Returns normalized data or state updates consumed by downstream logic.
    """
    for _ in range(rounds):
        state = kernel.get_task_state(task_id)
        if state and state.get("state") in ("success", "failed", "blocked"):
            return state
        sleep(0.01)
    return kernel.get_task_state(task_id)


def run_risk_control_scenario(backend: str = "mqtt") -> Dict[str, Any]:
    """Purpose: Run risk control scenario.

    Inputs:
    - Uses function parameters plus relevant in-memory runtime state.

    Behavior:
    - Validates/normalizes key fields before doing state transitions.
    - Executes deterministic run risk control scenario rules so all nodes converge on the same result.

    Outputs:
    - Returns normalized data or state updates consumed by downstream logic.
    """
    transport = build_transport(node_id="risk-kernel", backend=backend, fallback_to_simulated=False)
    kernel = CoordinationKernel(transport=transport)
    kernel.register_agent("risk-sentinel", ["risk_assessment"])
    kernel.register_agent("risk-guardian", ["risk_mitigation"])
    compat = OrchestratorCompatibilityAdapter(kernel)
    dispatched = compat.dispatch_task(
        task_type="risk_assessment",
        payload={"org_id": "org-a", "asset": "vault-42", "signal": "abnormal-withdraw"},
        source_agent="risk-orchestrator",
    )
    compat.sync_state("risk:last_dispatch", dispatched)
    return {
        "scenario": "risk_control",
        "dispatch": dispatched,
        "state": kernel.get_state("risk:last_dispatch"),
    }


def run_risk_control_agent_driven_scenario(backend: str = "mqtt") -> Dict[str, Any]:
    """Purpose: Run risk control agent driven scenario.

    Inputs:
    - Uses function parameters plus relevant in-memory runtime state.

    Behavior:
    - Validates/normalizes key fields before doing state transitions.
    - Executes deterministic run risk control agent driven scenario rules so all nodes converge on the same result.

    Outputs:
    - Returns normalized data or state updates consumed by downstream logic.
    """
    transport = build_transport(node_id="risk-kernel-agent-driven", backend=backend, fallback_to_simulated=False)
    kernel = CoordinationKernel(transport=transport)
    runtime = AgentPluginRuntime(
        agent_id="risk-agent-runtime",
        kernel=kernel,
        plugins=[RiskControlPlugin()],
    )
    runtime.start()
    try:
        compat = OrchestratorCompatibilityAdapter(kernel)
        dispatched = compat.dispatch_task(
            task_type="risk_assessment",
            payload={"org_id": "org-a", "asset": "vault-42", "signal": "abnormal-withdraw"},
            source_agent="legacy-orchestrator",
            metadata={"plugin": "risk_control"},
        )
        task_state = _wait_for_terminal_state(kernel, dispatched["task_id"])
        return {
            "scenario": "risk_control_agent_driven",
            "dispatch": dispatched,
            "task_state": task_state,
        }
    finally:
        runtime.stop()
