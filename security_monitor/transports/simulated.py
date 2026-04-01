"""Simulated module for Vertex Swarm Track3."""

import threading
import uuid
from collections import defaultdict
from typing import Any, Dict, List

from security_monitor.transports.base import BaseTransport, TransportCallback


class SimulatedTransport(BaseTransport):
    backend_name = "simulated"
    _bus: Dict[str, List[TransportCallback]] = defaultdict(list)
    _lock = threading.Lock()

    def __init__(self, node_id: str):
        """Purpose: Init.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic init rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self.node_id = node_id
        self.connected = False

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
        self.connected = True

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
        if not self.connected:
            self.connect()
        message_id = str(uuid.uuid4())
        envelope = dict(payload)
        envelope["message_id"] = message_id
        envelope["_sender"] = self.node_id
        with self._lock:
            callbacks = list(self._bus.get(topic, []))
        for callback in callbacks:
            callback(envelope)
        return message_id

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
        with self._lock:
            self._bus[topic].append(callback)

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
        self.connected = False
