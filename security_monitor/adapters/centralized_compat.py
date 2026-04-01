"""Centralized Compat module for Vertex Swarm Track3."""

from typing import Any, Dict

from security_monitor.coordination.kernel import CoordinationKernel


class OrchestratorCompatibilityAdapter:
    def __init__(self, kernel: CoordinationKernel):
        """Purpose: Init.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic init rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self.kernel = kernel

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
        return self.kernel.publish(topic, payload)

    def subscribe(self, topic: str, callback) -> None:
        """Purpose: Subscribe.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic subscribe rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
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
        """Purpose: Sync state.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic sync state rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self.kernel.sync_state(key, value)

    def read_state(self, key: str, default: Any = None) -> Any:
        """Purpose: Read state.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic read state rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return self.kernel.get_state(key, default)
