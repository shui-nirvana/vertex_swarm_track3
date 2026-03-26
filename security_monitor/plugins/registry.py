from typing import Any, Dict, List

from security_monitor.plugins.base import AgentBusinessPlugin


class PluginRegistry:
    def __init__(self):
        self._plugins: Dict[str, AgentBusinessPlugin] = {}

    def register(self, plugin: AgentBusinessPlugin) -> None:
        self._plugins[str(plugin.plugin_name)] = plugin

    def list_plugin_names(self) -> List[str]:
        return sorted(self._plugins.keys())

    def list_plugins(self) -> List[AgentBusinessPlugin]:
        return [self._plugins[name] for name in self.list_plugin_names()]

    def get(self, plugin_name: str) -> AgentBusinessPlugin | None:
        return self._plugins.get(str(plugin_name))

    def select(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> AgentBusinessPlugin | None:
        preferred = str(metadata.get("plugin", "")).strip()
        if preferred:
            plugin = self.get(preferred)
            if plugin is not None and plugin.supports(task_type, payload, metadata):
                return plugin
        for plugin in self._plugins.values():
            if plugin.supports(task_type, payload, metadata):
                return plugin
        return None
