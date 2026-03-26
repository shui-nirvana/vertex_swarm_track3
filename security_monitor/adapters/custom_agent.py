from typing import Any, Callable, Dict

from security_monitor.adapters.base import AgentAdapter


class CustomAgentAdapter(AgentAdapter):
    def __init__(
        self,
        agent_id: str,
        capabilities: list[str] | None = None,
        task_transform: Callable[[Dict[str, Any]], Dict[str, Any]] | None = None,
        result_transform: Callable[[Dict[str, Any]], Dict[str, Any]] | None = None,
    ):
        super().__init__(agent_id=agent_id, framework_name="custom", capabilities=capabilities or [])
        self.task_transform = task_transform
        self.result_transform = result_transform

    def transform_task(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        if self.task_transform is None:
            return dict(task_payload)
        return dict(self.task_transform(dict(task_payload)))

    def transform_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        if self.result_transform is None:
            return dict(result)
        return dict(self.result_transform(dict(result)))
