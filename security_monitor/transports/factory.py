from security_monitor.transports.base import BaseTransport
from security_monitor.transports.foxmq_mqtt import FoxMQMqttTransport
from security_monitor.transports.simulated import SimulatedTransport


def build_transport(
    node_id: str,
    backend: str = "mqtt",
    bridge_cmd: str | None = None,
    mqtt_addr: str | None = None,
    fallback_to_simulated: bool = False,
) -> BaseTransport:
    normalized_backend = str(backend).strip().lower() or "mqtt"
    if normalized_backend in {"simulated", "memory"}:
        return SimulatedTransport(node_id=node_id)
    if normalized_backend in {"mqtt", "official"}:
        try:
            return FoxMQMqttTransport(
                node_id=node_id,
                backend=normalized_backend,
                bridge_cmd=bridge_cmd,
                mqtt_addr=mqtt_addr,
            )
        except Exception:
            if not fallback_to_simulated:
                raise
            return SimulatedTransport(node_id=node_id)
    if fallback_to_simulated:
        return SimulatedTransport(node_id=node_id)
    raise ValueError(f"unsupported transport backend: {backend}")
