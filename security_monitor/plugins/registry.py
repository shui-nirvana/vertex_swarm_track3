"""Registry module for Vertex Swarm Track3."""

from typing import Any, Dict, List

from security_monitor.plugins.base import AgentBusinessPlugin


class PluginRegistry:
    def __init__(self):
        """Purpose: Init.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic init rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self._plugins: Dict[str, AgentBusinessPlugin] = {}

    def register(self, plugin: AgentBusinessPlugin) -> None:
        """Purpose: Register.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic register rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self._plugins[str(plugin.plugin_name)] = plugin

    def list_plugin_names(self) -> List[str]:
        """Purpose: List plugin names.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic list plugin names rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return sorted(self._plugins.keys())

    def list_plugins(self) -> List[AgentBusinessPlugin]:
        """Purpose: List plugins.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic list plugins rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return [self._plugins[name] for name in self.list_plugin_names()]

    def get(self, plugin_name: str) -> AgentBusinessPlugin | None:
        """Purpose: Get.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic get rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return self._plugins.get(str(plugin_name))

    def select(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> AgentBusinessPlugin | None:
        """Purpose: Select.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic select rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        preferred = str(metadata.get("plugin", "")).strip()
        if preferred:
            plugin = self.get(preferred)
            if plugin is not None and plugin.supports(task_type, payload, metadata):
                return plugin
        for plugin in self._plugins.values():
            if plugin.supports(task_type, payload, metadata):
                return plugin
        return None
