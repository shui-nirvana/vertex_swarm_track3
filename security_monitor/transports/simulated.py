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
        self.node_id = node_id
        self.connected = False

    def connect(self) -> None:
        self.connected = True

    def publish(self, topic: str, payload: Dict[str, Any]) -> str:
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
        with self._lock:
            self._bus[topic].append(callback)

    def close(self) -> None:
        self.connected = False
