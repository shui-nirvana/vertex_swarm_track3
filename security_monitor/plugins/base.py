from dataclasses import dataclass
from typing import Any, Dict, Protocol, Sequence


class AgentBusinessPlugin(Protocol):
    plugin_name: str

    @property
    def supported_task_types(self) -> Sequence[str]:
        ...

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        ...

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        ...


@dataclass(slots=True)
class PluginSelection:
    plugin_name: str
    task_type: str
