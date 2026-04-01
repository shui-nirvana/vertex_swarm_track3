"""Base module for Vertex Swarm Track3."""

from dataclasses import dataclass
from typing import Any, Dict, Protocol, Sequence


class AgentBusinessPlugin(Protocol):
    plugin_name: str

    @property
    def supported_task_types(self) -> Sequence[str]:
        """Purpose: Supported task types.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic supported task types rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        ...

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        """Purpose: Supports.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic supports rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        ...

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Purpose: Handle.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic handle rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        ...


@dataclass(slots=True)
class PluginSelection:
    plugin_name: str
    task_type: str
