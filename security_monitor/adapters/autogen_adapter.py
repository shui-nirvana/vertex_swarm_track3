from typing import Any, Dict

from security_monitor.adapters.base import AgentAdapter


class AutoGenAgentAdapter(AgentAdapter):
    def __init__(self, agent_id: str, capabilities: list[str] | None = None):
        super().__init__(agent_id=agent_id, framework_name="autogen", capabilities=capabilities or [])

    def transform_task(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(task_payload)
        payload["runtime"] = "autogen"
        payload["chat_mesh"] = "group-chat"
        return payload

    def transform_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        shaped = dict(result)
        shaped["framework"] = self.framework_name
        return shaped
