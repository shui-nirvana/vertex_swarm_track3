"""Base module for Vertex Swarm Track3."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict

TransportCallback = Callable[[Dict[str, Any]], None]


class BaseTransport(ABC):
    backend_name = "base"

    @abstractmethod
    def connect(self) -> None:
        """Purpose: Connect.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic connect rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        raise NotImplementedError

    @abstractmethod
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
        raise NotImplementedError

    @abstractmethod
    def subscribe(self, topic: str, callback: TransportCallback) -> None:
        """Purpose: Subscribe.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic subscribe rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        """Purpose: Close.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic close rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        raise NotImplementedError

    def get_active_peers(self) -> list[str]:
        """Purpose: Get active peers.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic get active peers rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return []

    def backend_info(self) -> Dict[str, Any]:
        """Purpose: Backend info.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic backend info rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return {"backend": self.backend_name}
