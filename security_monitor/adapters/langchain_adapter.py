from typing import Any, Dict

from security_monitor.adapters.base import AgentAdapter


class LangChainAgentAdapter(AgentAdapter):
    def __init__(self, agent_id: str, capabilities: list[str] | None = None):
        super().__init__(agent_id=agent_id, framework_name="langchain", capabilities=capabilities or [])

    def transform_task(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(task_payload)
        payload["runtime"] = "langchain"
        payload["graph_mode"] = "tool-call-graph"
        return payload

    def transform_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        shaped = dict(result)
        shaped["framework"] = self.framework_name
        return shaped
