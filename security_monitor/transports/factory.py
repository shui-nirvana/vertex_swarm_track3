from security_monitor.transports.base import BaseTransport
from security_monitor.transports.foxmq_mqtt import FoxMQMqttTransport


def build_transport(
    node_id: str,
    backend: str = "mqtt",
    mqtt_addr: str | None = None,
    fallback_to_simulated: bool = False,
) -> BaseTransport:
    normalized_backend = str(backend).strip().lower() or "mqtt"
    if normalized_backend in {"simulated", "memory"}:
        raise ValueError("simulated backend is disabled; use backend='mqtt'")
    if normalized_backend == "mqtt":
        return FoxMQMqttTransport(
            node_id=node_id,
            backend=normalized_backend,
            mqtt_addr=mqtt_addr,
        )
    if fallback_to_simulated:
        raise ValueError("fallback_to_simulated is disabled; use backend='mqtt'")
    raise ValueError(f"unsupported transport backend: {backend}")
