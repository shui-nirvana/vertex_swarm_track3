import uuid
from typing import Any, Dict

from security_monitor.integration.foxmq_adapter import FoxMQAdapter
from security_monitor.transports.base import BaseTransport, TransportCallback


class FoxMQMqttTransport(BaseTransport):
    backend_name = "foxmq-mqtt"

    def __init__(self, node_id: str, backend: str = "mqtt", bridge_cmd: str | None = None, mqtt_addr: str | None = None):
        self.node_id = node_id
        self.backend = backend
        self.bridge_cmd = bridge_cmd
        self.mqtt_addr = mqtt_addr
        self._adapter: FoxMQAdapter | None = None

    def connect(self) -> None:
        if self._adapter is not None:
            return
        self._adapter = FoxMQAdapter(
            node_id=self.node_id,
            backend=self.backend,
            bridge_cmd=self.bridge_cmd,
            mqtt_addr=self.mqtt_addr,
        )

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
        close_fn = getattr(self._adapter, "close", None)
        if callable(close_fn):
            close_fn()
        self._adapter = None
