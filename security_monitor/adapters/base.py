from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass(slots=True)
class AgentAdapter:
    agent_id: str
    framework_name: str
    capabilities: list[str] = field(default_factory=list)

    def supports(self, task_type: str) -> bool:
        return str(task_type).strip().lower() in {cap.lower() for cap in self.capabilities}

    def transform_task(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        return dict(task_payload)

    def transform_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        return dict(result)
