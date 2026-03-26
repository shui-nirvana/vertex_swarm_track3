from abc import ABC, abstractmethod
from typing import Any, Callable, Dict

TransportCallback = Callable[[Dict[str, Any]], None]


class BaseTransport(ABC):
    backend_name = "base"

    @abstractmethod
    def connect(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def publish(self, topic: str, payload: Dict[str, Any]) -> str:
        raise NotImplementedError

    @abstractmethod
    def subscribe(self, topic: str, callback: TransportCallback) -> None:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError
