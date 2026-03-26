from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from threading import Lock, Semaphore
from time import perf_counter
from typing import Any, Dict, Iterable

from security_monitor.coordination.kernel import CoordinationKernel
from security_monitor.plugins import AgentBusinessPlugin, PluginRegistry


class AgentPluginRuntime:
    def __init__(
        self,
        agent_id: str,
        kernel: CoordinationKernel,
        plugins: Iterable[AgentBusinessPlugin],
        max_workers: int = 4,
        max_inflight: int = 64,
        plugin_timeout_s: float = 3.0,
        max_retries: int = 1,
    ):
        self.agent_id = str(agent_id)
        self.kernel = kernel
        self.registry = PluginRegistry()
        for plugin in plugins:
            self.registry.register(plugin)
        self.executor = ThreadPoolExecutor(max_workers=max(1, int(max_workers)))
        self.inflight_semaphore = Semaphore(max(1, int(max_inflight)))
        self.plugin_timeout_s = float(plugin_timeout_s)
        self.max_retries = max(0, int(max_retries))
        self.metrics_lock = Lock()
        self.metrics: Dict[str, float] = {
            "total_tasks": 0,
            "successful_tasks": 0,
            "failed_tasks": 0,
            "timeout_failures": 0,
            "queue_rejections": 0,
            "retried_tasks": 0,
            "total_latency_ms": 0.0,
        }

    def start(self) -> None:
        capabilities = sorted(
            {
                str(task_type)
                for plugin in self.registry.list_plugins()
                for task_type in plugin.supported_task_types
            }
        )
        self.kernel.register_agent(self.agent_id, capabilities)
        self.kernel.subscribe(f"coordination/tasks/{self.agent_id}", self._handle_task)

    def _handle_task(self, message: Dict[str, Any]) -> None:
        if not self.inflight_semaphore.acquire(blocking=False):
            task_id = str(message.get("task_id", ""))
            self._increment_metric("queue_rejections")
            self._increment_metric("failed_tasks")
            self.kernel.complete_task(
                task_id=task_id,
                result={"status": "failed", "reason": "queue_full"},
                success=False,
            )
            return
        task_start = perf_counter()
        future = self.executor.submit(self._process_task, message, task_start)
        future.add_done_callback(lambda _: self.inflight_semaphore.release())

    def _process_task(self, message: Dict[str, Any], task_start: float) -> None:
        task_id = str(message.get("task_id", ""))
        task_type = str(message.get("task_type", ""))
        payload = dict(message.get("payload", {}))
        metadata = dict(message.get("metadata", {}))
        self._increment_metric("total_tasks")
        plugin = self.registry.select(task_type=task_type, payload=payload, metadata=metadata)
        if plugin is None:
            self._increment_metric("failed_tasks")
            self.kernel.complete_task(
                task_id=task_id,
                result={"status": "failed", "reason": "plugin_not_found"},
                success=False,
            )
            return
        self.kernel.set_task_running(task_id=task_id, worker_agent=self.agent_id)
        result: Dict[str, Any] | None = None
        failure_reason = ""
        attempts = self.max_retries + 1
        used_attempts = 0
        for attempt in range(attempts):
            used_attempts = attempt + 1
            try:
                result = self._invoke_with_timeout(plugin, payload, self.plugin_timeout_s)
                if attempt > 0:
                    self._increment_metric("retried_tasks")
                break
            except FuturesTimeoutError:
                failure_reason = "plugin_timeout"
                if attempt == attempts - 1:
                    self._increment_metric("timeout_failures")
            except Exception as exc:
                failure_reason = f"plugin_error:{type(exc).__name__}"
            if attempt == attempts - 1:
                self._increment_metric("failed_tasks")
                self.kernel.complete_task(
                    task_id=task_id,
                    result={
                        "status": "failed",
                        "reason": failure_reason or "plugin_execution_failed",
                        "plugin": plugin.plugin_name,
                        "agent_id": self.agent_id,
                        "task_type": task_type,
                        "metadata": metadata,
                        "attempts": used_attempts,
                    },
                    success=False,
                )
                return
        if result is None:
            self._increment_metric("failed_tasks")
            self.kernel.complete_task(
                task_id=task_id,
                result={"status": "failed", "reason": "plugin_execution_failed"},
                success=False,
            )
            return
        result["plugin"] = plugin.plugin_name
        result["agent_id"] = self.agent_id
        result["task_type"] = task_type
        result["metadata"] = metadata
        result["attempts"] = used_attempts
        duration_ms = (perf_counter() - task_start) * 1000.0
        result["latency_ms"] = round(duration_ms, 3)
        self._increment_metric("successful_tasks")
        self._increment_metric("total_latency_ms", duration_ms)
        self.kernel.complete_task(task_id=task_id, result=result, success=True)

    def _invoke_with_timeout(
        self,
        plugin: AgentBusinessPlugin,
        payload: Dict[str, Any],
        timeout_s: float,
    ) -> Dict[str, Any]:
        timeout_executor = ThreadPoolExecutor(max_workers=1)
        future = timeout_executor.submit(plugin.handle, payload)
        try:
            return future.result(timeout=max(0.001, float(timeout_s)))
        finally:
            timeout_executor.shutdown(wait=False, cancel_futures=True)

    def _increment_metric(self, key: str, value: float = 1.0) -> None:
        with self.metrics_lock:
            self.metrics[key] = float(self.metrics.get(key, 0.0)) + float(value)

    def get_metrics(self) -> Dict[str, float]:
        with self.metrics_lock:
            snapshot = dict(self.metrics)
        success = max(1.0, snapshot.get("successful_tasks", 0.0))
        snapshot["avg_latency_ms"] = snapshot.get("total_latency_ms", 0.0) / success
        return snapshot

    def stop(self) -> None:
        self.executor.shutdown(wait=True, cancel_futures=True)
