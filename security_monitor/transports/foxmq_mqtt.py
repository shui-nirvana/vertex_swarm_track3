import uuid
from typing import Any, Dict

from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.transports.base import BaseTransport, TransportCallback


class FoxMQMqttTransport(BaseTransport):
    backend_name = "foxmq-mqtt"

    def __init__(self, node_id: str, backend: str = "mqtt", mqtt_addr: str | None = None):
        self.node_id = node_id
        self.backend = backend
        self.mqtt_addr = mqtt_addr
        self._adapter: FoxMQAdapter | None = None
        self._network_topic = "swarm-control"

    def connect(self) -> None:
        if self._adapter is not None:
            return
        self._adapter = FoxMQAdapter(
            node_id=self.node_id,
            backend=self.backend,
            mqtt_addr=self.mqtt_addr,
        )
        self._adapter.join_network(self._network_topic)

    def publish(self, topic: str, payload: Dict[str, Any]) -> str:
        if self._adapter is None:
            self.connect()
        assert self._adapter is not None
        message_id = str(uuid.uuid4())
        outbound = dict(payload)
        outbound["message_id"] = message_id
        self._adapter.publish(topic, outbound)
        return message_id

    def subscribe(self, topic: str, callback: TransportCallback) -> None:
        if self._adapter is None:
            self.connect()
        assert self._adapter is not None
        self._adapter.subscribe(topic, callback)

    def close(self) -> None:
        if self._adapter is None:
            return
        self._adapter.close()
        self._adapter = None

    def get_active_peers(self) -> list[str]:
        if self._adapter is None:
            self.connect()
        assert self._adapter is not None
        return list(self._adapter.get_active_peers())

    def backend_info(self) -> Dict[str, Any]:
        if self._adapter is None:
            self.connect()
        assert self._adapter is not None
        info = dict(self._adapter.backend_info())
        info["network_topic"] = self._network_topic
        return info
