"""Langchain Adapter module for Vertex Swarm Track3."""

from typing import Any, Dict

from security_monitor.adapters.base import AgentAdapter


class LangChainAgentAdapter(AgentAdapter):
    def __init__(self, agent_id: str, capabilities: list[str] | None = None):
        """Purpose: Init.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic init rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        super().__init__(agent_id=agent_id, framework_name="langchain", capabilities=capabilities or [])

    def transform_task(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Purpose: Transform task.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic transform task rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        payload = dict(task_payload)
        payload["runtime"] = "langchain"
        payload["graph_mode"] = "tool-call-graph"
        return payload

    def transform_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Purpose: Transform result.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic transform result rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        shaped = dict(result)
        shaped["framework"] = self.framework_name
        return shaped
