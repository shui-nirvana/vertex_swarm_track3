"""Foxmq Adapter module for Vertex Swarm Track3."""

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class _FoxMqttClient:
    def __init__(self, mqtt_addr: str, node_id: str, timeout_seconds: float = 3.0):
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
        self._subscriptions: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self._known_peers: Dict[str, float] = {}
        self._timeout_seconds = timeout_seconds
        self._connected = threading.Event()
        self._connect_error: Optional[str] = None
        self._mqtt_addr = mqtt_addr
        self._publish_qos = self._parse_qos(os.getenv("FOXMQ_MQTT_QOS", "1"), default=1)
        self._subscribe_qos = self._parse_qos(os.getenv("FOXMQ_MQTT_SUB_QOS", str(self._publish_qos)), default=self._publish_qos)
        self._keepalive = self._parse_keepalive(os.getenv("FOXMQ_MQTT_KEEPALIVE", "30"), default=30)
        self._clean_session = self._parse_bool(os.getenv("FOXMQ_MQTT_CLEAN_SESSION", "1"))
        self._clean_start = self._parse_bool(os.getenv("FOXMQ_MQTT_CLEAN_START", "1"))
        self._session_expiry = self._parse_int(os.getenv("FOXMQ_MQTT_SESSION_EXPIRY", "0"), default=0, minimum=0)
        self._receive_maximum = self._parse_int(os.getenv("FOXMQ_MQTT_RECEIVE_MAXIMUM", "0"), default=0, minimum=0)
        self._max_inflight = self._parse_int(os.getenv("FOXMQ_MQTT_MAX_INFLIGHT", "0"), default=0, minimum=0)
        self._max_queued = self._parse_int(os.getenv("FOXMQ_MQTT_MAX_QUEUED", "0"), default=0, minimum=0)
        self._will_topic = str(os.getenv("FOXMQ_MQTT_WILL_TOPIC", "")).strip()
        self._will_payload = str(os.getenv("FOXMQ_MQTT_WILL_PAYLOAD", "")).strip()
        self._will_qos = self._parse_qos(os.getenv("FOXMQ_MQTT_WILL_QOS", str(self._publish_qos)), default=self._publish_qos)
        self._will_retain = self._parse_bool(os.getenv("FOXMQ_MQTT_WILL_RETAIN", "0"))
        protocol_label = str(os.getenv("FOXMQ_MQTT_PROTOCOL", "3.1.1")).strip().lower()
        host, port = self._parse_mqtt_addr(mqtt_addr)
        try:
            import paho.mqtt.client as mqtt
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "mqtt FoxMQ backend requested but paho-mqtt is not installed; "
                "run `python -m pip install paho-mqtt`"
            ) from exc
        mqtt_v5 = getattr(mqtt, "MQTTv5", None)
        selected_protocol = mqtt.MQTTv311
        if protocol_label in {"5", "mqttv5", "v5"} and mqtt_v5 is not None:
            selected_protocol = mqtt_v5
        self._mqtt = mqtt
        self._is_mqtt_v5 = mqtt_v5 is not None and selected_protocol == mqtt_v5
        callback_api_version = getattr(getattr(mqtt, "CallbackAPIVersion", None), "VERSION2", None)
        client_id = self._build_client_id(node_id)
        if callback_api_version is None:
            if self._is_mqtt_v5:
                self._client = mqtt.Client(client_id=client_id, protocol=selected_protocol)
            else:
                self._client = mqtt.Client(
                    client_id=client_id,
                    protocol=selected_protocol,
                    clean_session=self._clean_session,
                )
        else:
            if self._is_mqtt_v5:
                self._client = mqtt.Client(
                    callback_api_version=callback_api_version,
                    client_id=client_id,
                    protocol=selected_protocol,
                )
            else:
                self._client = mqtt.Client(
                    callback_api_version=callback_api_version,
                    client_id=client_id,
                    protocol=selected_protocol,
                    clean_session=self._clean_session,
                )
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        if self._will_topic:
            will_payload = self._will_payload or json.dumps(
                {"kind": "will_disconnect", "agent_id": self.node_id, "timestamp": time.time()},
                ensure_ascii=False,
            )
            self._client.will_set(
                self._will_topic,
                payload=will_payload,
                qos=self._will_qos,
                retain=self._will_retain,
            )
        if self._max_inflight > 0:
            self._client.max_inflight_messages_set(self._max_inflight)
        if self._max_queued > 0:
            self._client.max_queued_messages_set(self._max_queued)
        username = str(os.getenv("FOXMQ_MQTT_USERNAME", "")).strip()
        if username:
            self._client.username_pw_set(username=username, password=os.getenv("FOXMQ_MQTT_PASSWORD", ""))
        if self._parse_bool(os.getenv("FOXMQ_MQTT_TLS", "0")):
            ca_certs = str(os.getenv("FOXMQ_MQTT_TLS_CA_CERTS", "")).strip() or None
            certfile = str(os.getenv("FOXMQ_MQTT_TLS_CERTFILE", "")).strip() or None
            keyfile = str(os.getenv("FOXMQ_MQTT_TLS_KEYFILE", "")).strip() or None
            self._client.tls_set(ca_certs=ca_certs, certfile=certfile, keyfile=keyfile)
            if self._parse_bool(os.getenv("FOXMQ_MQTT_TLS_INSECURE", "0")):
                self._client.tls_insecure_set(True)
        try:
            connect_kwargs: Dict[str, Any] = {"keepalive": self._keepalive}
            if self._is_mqtt_v5:
                connect_kwargs["clean_start"] = self._clean_start
                connect_properties = self._build_connect_properties()
                if connect_properties is not None:
                    connect_kwargs["properties"] = connect_properties
            self._client.connect(host, port, **connect_kwargs)
        except Exception as exc:
            raise RuntimeError(
                f"failed to connect to FoxMQ broker at {mqtt_addr}; "
                "ensure broker is running and mqtt address is reachable"
            ) from exc
        self._client.loop_start()
        if not self._connected.wait(timeout=self._timeout_seconds):
            self._client.loop_stop()
            self._client.disconnect()
            raise RuntimeError(f"timeout waiting for mqtt connection to {mqtt_addr}")
        if self._connect_error:
            self._client.loop_stop()
            self._client.disconnect()
            raise RuntimeError(self._connect_error)

    @staticmethod
    def _build_client_id(node_id: str) -> str:
        """Purpose: Build client id.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic build client id rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        raw = f"foxmq-{node_id}"
        compact = "".join(ch for ch in raw if ch.isalnum() or ch in {"-", "_"})
        if not compact:
            compact = f"foxmq-{uuid.uuid4().hex[:8]}"
        if len(compact) <= 23:
            return compact
        digest = hashlib.sha1(compact.encode("utf-8")).hexdigest()[:8]
        keep = max(1, 23 - len(digest) - 1)
        return f"{compact[:keep]}-{digest}"

    @staticmethod
    def _parse_mqtt_addr(mqtt_addr: str) -> Tuple[str, int]:
        """Purpose: Parse mqtt addr.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic parse mqtt addr rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        value = mqtt_addr.strip()
        if not value:
            raise RuntimeError("FOXMQ_MQTT_ADDR is empty")
        if ":" not in value:
            raise RuntimeError(
                f"invalid FOXMQ_MQTT_ADDR value: {mqtt_addr}; expected host:port, for example 127.0.0.1:1883"
            )
        host, port_str = value.rsplit(":", 1)
        host = host.strip()
        if not host:
            raise RuntimeError(f"invalid FOXMQ_MQTT_ADDR value: {mqtt_addr}; host is empty")
        try:
            port = int(port_str)
        except ValueError as exc:
            raise RuntimeError(f"invalid FOXMQ_MQTT_ADDR value: {mqtt_addr}; port must be integer") from exc
        if port <= 0 or port > 65535:
            raise RuntimeError(f"invalid FOXMQ_MQTT_ADDR value: {mqtt_addr}; port must be in 1..65535")
        return host, port

    @staticmethod
    def _reason_code_to_int(reason_code: Any) -> int:
        """Purpose: Reason code to int.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic reason code to int rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if isinstance(reason_code, int):
            return reason_code
        value = getattr(reason_code, "value", None)
        if isinstance(value, int):
            return value
        try:
            return int(reason_code)
        except Exception:
            return -1

    @staticmethod
    def _parse_bool(raw: Any) -> bool:
        """Purpose: Parse bool.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic parse bool rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        value = str(raw).strip().lower()
        return value in {"1", "true", "yes", "on"}

    @staticmethod
    def _parse_qos(raw: Any, default: int) -> int:
        """Purpose: Parse qos.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic parse qos rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        try:
            parsed = int(str(raw).strip())
        except Exception:
            return int(default)
        if parsed < 0:
            return 0
        if parsed > 2:
            return 2
        return parsed

    @staticmethod
    def _parse_keepalive(raw: Any, default: int) -> int:
        """Purpose: Parse keepalive.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic parse keepalive rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        try:
            parsed = int(str(raw).strip())
        except Exception:
            return int(default)
        if parsed <= 0:
            return int(default)
        return parsed

    @staticmethod
    def _parse_int(raw: Any, default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
        """Purpose: Parse int.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic parse int rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        try:
            parsed = int(str(raw).strip())
        except Exception:
            return int(default)
        if minimum is not None and parsed < minimum:
            return int(minimum)
        if maximum is not None and parsed > maximum:
            return int(maximum)
        return parsed

    def _build_connect_properties(self) -> Optional[Any]:
        """Purpose: Build connect properties.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic build connect properties rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if not self._is_mqtt_v5:
            return None
        properties_cls = getattr(self._mqtt, "Properties", None)
        packet_types = getattr(self._mqtt, "PacketTypes", None)
        if properties_cls is None or packet_types is None:
            return None
        properties = properties_cls(packet_types.CONNECT)
        changed = False
        if self._session_expiry > 0:
            properties.SessionExpiryInterval = int(self._session_expiry)
            changed = True
        if self._receive_maximum > 0:
            properties.ReceiveMaximum = int(self._receive_maximum)
            changed = True
        if changed:
            return properties
        return None

    def _build_publish_properties(self, message: Dict[str, Any]) -> Optional[Any]:
        """Purpose: Build publish properties.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic build publish properties rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if not self._is_mqtt_v5:
            return None
        properties_cls = getattr(self._mqtt, "Properties", None)
        packet_types = getattr(self._mqtt, "PacketTypes", None)
        if properties_cls is None or packet_types is None:
            return None
        properties = properties_cls(packet_types.PUBLISH)
        changed = False
        response_topic = message.pop("__response_topic", None)
        if response_topic is not None:
            properties.ResponseTopic = str(response_topic)
            changed = True
        correlation_data = message.pop("__correlation_data", None)
        if correlation_data is not None:
            if isinstance(correlation_data, bytes):
                properties.CorrelationData = correlation_data
            else:
                properties.CorrelationData = str(correlation_data).encode("utf-8")
            changed = True
        topic_alias = message.pop("__topic_alias", None)
        if topic_alias is not None:
            properties.TopicAlias = self._parse_int(topic_alias, default=0, minimum=0, maximum=65535)
            changed = True
        user_properties = message.pop("__user_properties", None)
        if isinstance(user_properties, dict):
            properties.UserProperty = [(str(k), str(v)) for k, v in user_properties.items()]
            changed = True
        elif isinstance(user_properties, list):
            pairs: list[tuple[str, str]] = []
            for item in user_properties:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    pairs.append((str(item[0]), str(item[1])))
            if pairs:
                properties.UserProperty = pairs
                changed = True
        if changed:
            return properties
        return None

    def _on_connect(self, _client: Any, _userdata: Any, _flags: Any, reason_code: Any, _properties: Any = None) -> None:
        """Purpose: On connect.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic on connect rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        code = self._reason_code_to_int(reason_code)
        if code == 0:
            self._connected.set()
            return
        self._connect_error = f"mqtt connection rejected by broker {self._mqtt_addr} with reason code {code}"
        self._connected.set()

    def _on_message(self, _client: Any, _userdata: Any, message: Any) -> None:
        """Purpose: On message.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic on message rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        try:
            payload = json.loads(message.payload.decode("utf-8"))
        except Exception:
            logger.warning(f"mqtt backend received non-json payload on {message.topic}")
            return
        if not isinstance(payload, dict):
            return
        properties = getattr(message, "properties", None)
        if properties is not None:
            correlation_data = getattr(properties, "CorrelationData", None)
            if isinstance(correlation_data, bytes):
                payload["__correlation_data"] = correlation_data.decode("utf-8", errors="replace")
            elif correlation_data is not None:
                payload["__correlation_data"] = str(correlation_data)
            response_topic = getattr(properties, "ResponseTopic", None)
            if response_topic is not None:
                payload["__response_topic"] = str(response_topic)
            user_property = getattr(properties, "UserProperty", None)
            if isinstance(user_property, list):
                payload["__user_properties"] = [
                    [str(item[0]), str(item[1])]
                    for item in user_property
                    if isinstance(item, (list, tuple)) and len(item) >= 2
                ]
        sender = str(payload.get("_sender", ""))
        if sender and sender != self.node_id:
            self._known_peers[sender] = time.time()
        callbacks = list(self._subscriptions.get(str(message.topic), []))
        for callback in callbacks:
            try:
                callback(dict(payload))
            except Exception as exc:
                logger.error(f"mqtt callback failed on {message.topic}: {exc}")

    def join_network(self, topic: str) -> None:
        """Purpose: Join network.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic join network rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        _ = topic

    def leave_network(self) -> None:
        """Purpose: Leave network.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic leave network rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self._client.loop_stop()
        self._client.disconnect()

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Purpose: Subscribe.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic subscribe rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self._subscriptions.setdefault(topic, []).append(callback)
        result = self._client.subscribe(topic, qos=self._subscribe_qos)
        if isinstance(result, tuple) and result:
            code = int(result[0])
            if code != 0:
                raise RuntimeError(f"mqtt subscribe failed on topic {topic}, code={code}")

    def publish(self, topic: str, message: Dict[str, Any]) -> None:
        """Purpose: Publish.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic publish rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        payload_body = dict(message)
        publish_kwargs: Dict[str, Any] = {}
        publish_properties = self._build_publish_properties(payload_body)
        if publish_properties is not None:
            publish_kwargs["properties"] = publish_properties
        payload = json.dumps(payload_body, ensure_ascii=False)
        info = self._client.publish(topic, payload, qos=self._publish_qos, **publish_kwargs)
        code = getattr(info, "rc", 0)
        if isinstance(code, int) and code != 0:
            raise RuntimeError(f"mqtt publish failed on topic {topic}, code={code}")

    def get_active_peers(self) -> List[str]:
        """Purpose: Get active peers.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic get active peers rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return sorted(self._known_peers.keys())

    def backend_profile(self) -> Dict[str, str]:
        """Purpose: Backend profile.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic backend profile rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return {
            "mqtt_protocol": "5" if self._is_mqtt_v5 else "3.1.1",
            "publish_qos": str(self._publish_qos),
            "subscribe_qos": str(self._subscribe_qos),
            "keepalive_seconds": str(self._keepalive),
            "tls_enabled": "true" if self._parse_bool(os.getenv("FOXMQ_MQTT_TLS", "0")) else "false",
        }


class FoxMQAdapter:
    def __init__(
        self,
        node_id: Optional[str] = None,
        backend: Optional[str] = None,
        mqtt_addr: Optional[str] = None,
    ):
        self.node_id = node_id or f"node-{uuid.uuid4().hex[:8]}"
        self.peers: List[str] = []
        self._subscriptions: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self._mqtt_addr = (mqtt_addr or "").strip()
        env_backend = os.getenv("FOXMQ_BACKEND", "mqtt")
        backend_value = backend if backend is not None else (env_backend if env_backend is not None else "mqtt")
        self.backend = backend_value.strip().lower()
        if self.backend not in {"simulated", "mqtt"}:
            raise ValueError(f"unsupported FoxMQ backend: {self.backend}")
        self._official_client: Optional[Any] = None
        self._official_module_name: Optional[str] = None
        if self.backend == "mqtt":
            self._official_client, self._official_module_name = self._create_mqtt_client()

    _shared_bus: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
    _shared_peers: List[str] = []

    def _create_mqtt_client(self) -> Tuple[Any, str]:
        """Purpose: Create mqtt client.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic create mqtt client rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        mqtt_addr = self._mqtt_addr or os.getenv("FOXMQ_MQTT_ADDR", "127.0.0.1:1883").strip()
        return _FoxMqttClient(mqtt_addr=mqtt_addr, node_id=self.node_id), f"mqtt:{mqtt_addr}"

    @staticmethod
    def _call_first(target: Any, method_names: Tuple[str, ...], *args: Any, **kwargs: Any) -> bool:
        """Purpose: Call first.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic call first rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        for method_name in method_names:
            method = getattr(target, method_name, None)
            if callable(method):
                method(*args, **kwargs)
                return True
        return False

    def join_network(self, topic: str = "default") -> None:
        """Purpose: Join network.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic join network rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if self.backend == "mqtt":
            if self._official_client is None:
                raise RuntimeError(f"{self.backend} FoxMQ client not initialized")
            joined = self._call_first(self._official_client, ("join_network", "join", "connect"), topic)
            if not joined:
                raise RuntimeError(f"{self.backend} FoxMQ client does not expose join/connect method")
            logger.info(f"Node {self.node_id} joined {self.backend} FoxMQ topic '{topic}'")
            return
        if self.node_id not in FoxMQAdapter._shared_peers:
            FoxMQAdapter._shared_peers.append(self.node_id)
        logger.info(f"Node {self.node_id} joined network topic '{topic}'")

    def leave_network(self) -> None:
        """Purpose: Leave network.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic leave network rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if self.backend == "mqtt":
            if self._official_client is None:
                return
            self._call_first(self._official_client, ("leave_network", "leave", "disconnect"))
            logger.info(f"Node {self.node_id} left {self.backend} FoxMQ network")
            return
        if self.node_id in FoxMQAdapter._shared_peers:
            FoxMQAdapter._shared_peers.remove(self.node_id)
        logger.info(f"Node {self.node_id} left network")

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
        self.leave_network()

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Purpose: Subscribe.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic subscribe rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if self.backend == "mqtt":
            if self._official_client is None:
                raise RuntimeError(f"{self.backend} FoxMQ client not initialized")
            subscribed = self._call_first(self._official_client, ("subscribe",), topic, callback)
            if not subscribed:
                raise RuntimeError(f"{self.backend} FoxMQ client does not expose subscribe(topic, callback)")
            logger.debug(f"Node {self.node_id} subscribed to {self.backend} topic {topic}")
            return
        if topic not in FoxMQAdapter._shared_bus:
            FoxMQAdapter._shared_bus[topic] = []
        FoxMQAdapter._shared_bus[topic].append(callback)
        logger.debug(f"Node {self.node_id} subscribed to {topic}")

    def publish(self, topic: str, message: Dict[str, Any]) -> None:
        """Purpose: Publish.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic publish rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        msg_with_meta = message.copy()
        msg_with_meta["_sender"] = self.node_id
        msg_with_meta["_timestamp"] = time.time()

        if self.backend == "mqtt":
            if self._official_client is None:
                raise RuntimeError(f"{self.backend} FoxMQ client not initialized")
            published = self._call_first(self._official_client, ("publish", "send", "broadcast"), topic, msg_with_meta)
            if not published:
                raise RuntimeError(f"{self.backend} FoxMQ client does not expose publish/send/broadcast")
            return

        if topic in FoxMQAdapter._shared_bus:
            for callback in FoxMQAdapter._shared_bus[topic]:
                try:
                    callback(msg_with_meta)
                except Exception as e:
                    logger.error(f"Error processing message on topic {topic}: {e}")

    def broadcast(self, message: Dict[str, Any]) -> None:
        """Purpose: Broadcast.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic broadcast rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self.publish("global", message)

    def get_active_peers(self) -> List[str]:
        """Purpose: Get active peers.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic get active peers rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if self.backend == "mqtt":
            if self._official_client is None:
                return []
            getter = getattr(self._official_client, "get_active_peers", None)
            if callable(getter):
                return list(getter())
            peers = getattr(self._official_client, "peers", None)
            if isinstance(peers, list):
                return [str(peer) for peer in peers if str(peer) != self.node_id]
            return []
        return [p for p in FoxMQAdapter._shared_peers if p != self.node_id]

    def backend_info(self) -> Dict[str, str]:
        """Purpose: Backend info.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic backend info rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        info = {
            "backend": self.backend,
            "module": self._official_module_name or "simulated",
            "node_id": self.node_id,
        }
        profile_getter = getattr(self._official_client, "backend_profile", None)
        if callable(profile_getter):
            for key, value in dict(profile_getter()).items():
                info[str(key)] = str(value)
        return info

    @classmethod
    def reset_simulation(cls) -> None:
        """Purpose: Reset simulation.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic reset simulation rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        cls._shared_bus = {}
        cls._shared_peers = []
