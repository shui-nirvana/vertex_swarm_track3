from dataclasses import dataclass
from typing import Any, Dict, Iterable, Protocol


class AgentBusinessPlugin(Protocol):
    plugin_name: str
    supported_task_types: Iterable[str]

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        ...

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        ...


@dataclass(slots=True)
class PluginSelection:
    plugin_name: str
    task_type: str
