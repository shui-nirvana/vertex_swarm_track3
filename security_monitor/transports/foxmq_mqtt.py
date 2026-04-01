"""Foxmq Mqtt module for Vertex Swarm Track3."""

import uuid
from typing import Any, Dict

from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.transports.base import BaseTransport, TransportCallback


class FoxMQMqttTransport(BaseTransport):
    backend_name = "foxmq-mqtt"

    def __init__(self, node_id: str, backend: str = "mqtt", mqtt_addr: str | None = None):
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
        self.backend = backend
        self.mqtt_addr = mqtt_addr
        self._adapter: FoxMQAdapter | None = None
        self._network_topic = "swarm-control"

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
        if self._adapter is not None:
            return
        self._adapter = FoxMQAdapter(
            node_id=self.node_id,
            backend=self.backend,
            mqtt_addr=self.mqtt_addr,
        )
        self._adapter.join_network(self._network_topic)

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
        if self._adapter is None:
            self.connect()
        assert self._adapter is not None
        message_id = str(uuid.uuid4())
        outbound = dict(payload)
        outbound["message_id"] = message_id
        self._adapter.publish(topic, outbound)
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
        if self._adapter is None:
            self.connect()
        assert self._adapter is not None
        self._adapter.subscribe(topic, callback)

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
        if self._adapter is None:
            return
        self._adapter.close()
        self._adapter = None

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
        if self._adapter is None:
            self.connect()
        assert self._adapter is not None
        return list(self._adapter.get_active_peers())

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
        if self._adapter is None:
            self.connect()
        assert self._adapter is not None
        info = dict(self._adapter.backend_info())
        info["network_topic"] = self._network_topic
        return info
