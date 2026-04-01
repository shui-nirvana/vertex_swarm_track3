"""Fault Injector module for Vertex Swarm Track3."""

import time
from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class FaultInjector:
    dropped_nodes: Set[str] = field(default_factory=set)
    delayed_messages_ms: Dict[str, int] = field(default_factory=dict)

    def is_node_dropped(self, node_id: str) -> bool:
        """Purpose: Is node dropped.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic is node dropped rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return node_id in self.dropped_nodes

    def apply_delay(self, message_type: str) -> None:
        """Purpose: Apply delay.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic apply delay rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        delay_ms = self.delayed_messages_ms.get(message_type, 0)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)
