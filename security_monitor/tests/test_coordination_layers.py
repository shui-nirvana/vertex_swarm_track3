import unittest
from time import sleep
from typing import Any, Dict

from security_monitor.adapters import (
    AutoGenAgentAdapter,
    CustomAgentAdapter,
    ExternalAgentSDK,
    LangChainAgentAdapter,
    OrchestratorCompatibilityAdapter,
)
from security_monitor.coordination import CoordinationKernel
from security_monitor.scenarios import (
    run_cross_org_alert_agent_driven_scenario,
    run_cross_org_alert_scenario,
    run_risk_control_agent_driven_scenario,
    run_risk_control_scenario,
)
from security_monitor.transports import SimulatedTransport, build_transport
from security_monitor.plugins import CrossOrgAlertPlugin


class FlakyRetryPlugin:
    plugin_name = "flaky_retry"
    supported_task_types = ("retry_task",)

    def __init__(self):
        self.calls = 0

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        return str(task_type) == "retry_task"

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("transient")
        return {"status": "ok", "value": task_payload.get("value", 0)}


class SlowTimeoutPlugin:
    plugin_name = "slow_timeout"
    supported_task_types = ("slow_task",)

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        return str(task_type) == "slow_task"

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        sleep(float(task_payload.get("sleep", 0.05)))
        return {"status": "ok"}


class CoordinationLayerTests(unittest.TestCase):
    def _wait_for_terminal(self, kernel: CoordinationKernel, task_id: str, rounds: int = 120) -> Dict[str, Any]:
        for _ in range(rounds):
            state = kernel.get_task_state(task_id)
            if state and state.get("state") in ("success", "failed", "blocked"):
                return state
            sleep(0.01)
        return kernel.get_task_state(task_id) or {}

    def test_kernel_publish_subscribe_and_task_routing(self) -> None:
        transport = SimulatedTransport(node_id="kernel-test")
        kernel = CoordinationKernel(transport=transport)
        kernel.register_agent("risk-agent", ["risk_assessment"])
        received = []
        kernel.subscribe("coordination/tasks/risk-agent", lambda msg: received.append(msg))
        routed = kernel.submit_task(
            task_type="risk_assessment",
            payload={"signal": "high"},
            source_agent="planner",
        )
        self.assertEqual(routed["status"], "routed")
        self.assertEqual(routed["target_agent"], "risk-agent")
        self.assertEqual(len(received), 1)
        state = kernel.get_task_state(routed["task_id"])
        self.assertIsNotNone(state)
        self.assertEqual(state["state"], "routed")

    def test_policy_hook_blocks_task(self) -> None:
        transport = SimulatedTransport(node_id="policy-test")
        kernel = CoordinationKernel(transport=transport)
        kernel.register_agent("risk-agent", ["risk_assessment"])
        kernel.add_policy_hook(
            lambda task: (False, "budget_exceeded")
            if float(task.payload.get("budget", 0.0)) > 100.0
            else (True, "ok")
        )
        blocked = kernel.submit_task("risk_assessment", {"budget": 500.0})
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["reason"], "budget_exceeded")

    def test_transport_factory_fallbacks_to_simulated(self) -> None:
        transport = build_transport(node_id="n1", backend="unknown-backend", fallback_to_simulated=True)
        self.assertEqual(transport.backend_name, "simulated")

    def test_orchestrator_compat_entry(self) -> None:
        kernel = CoordinationKernel(transport=SimulatedTransport(node_id="compat-test"))
        kernel.register_agent("alert-agent", ["alert_sync"])
        compat = OrchestratorCompatibilityAdapter(kernel)
        routed = compat.dispatch_task("alert_sync", {"alert_id": "a-1"}, metadata={"plugin": "cross_org_alert"})
        self.assertEqual(routed["status"], "routed")
        state = kernel.get_task_state(routed["task_id"])
        self.assertEqual(state["state"], "routed")
        compat.sync_state("compat:last", routed["task_id"])
        self.assertEqual(compat.read_state("compat:last"), routed["task_id"])

    def test_agent_adapters_are_thin_wrappers(self) -> None:
        langchain = LangChainAgentAdapter(agent_id="a1", capabilities=["alert_sync"])
        autogen = AutoGenAgentAdapter(agent_id="a2", capabilities=["alert_sync"])
        custom = CustomAgentAdapter(
            agent_id="a3",
            capabilities=["alert_sync"],
            task_transform=lambda payload: {**payload, "runtime": "custom"},
        )
        self.assertEqual(langchain.transform_task({"x": 1})["runtime"], "langchain")
        self.assertEqual(autogen.transform_task({"x": 1})["runtime"], "autogen")
        self.assertEqual(custom.transform_task({"x": 1})["runtime"], "custom")

    def test_example_scenarios(self) -> None:
        risk = run_risk_control_scenario()
        cross_org = run_cross_org_alert_scenario()
        self.assertEqual(risk["scenario"], "risk_control")
        self.assertEqual(cross_org["scenario"], "cross_org_alert")
        self.assertEqual(len(cross_org["dispatches"]), 2)

    def test_agent_driven_plugin_scenarios(self) -> None:
        risk = run_risk_control_agent_driven_scenario()
        cross_org = run_cross_org_alert_agent_driven_scenario()
        self.assertEqual(risk["scenario"], "risk_control_agent_driven")
        self.assertEqual(risk["task_state"]["state"], "success")
        self.assertEqual(risk["task_state"]["result"]["plugin"], "risk_control")
        self.assertEqual(risk["task_state"]["result"]["metadata"]["compat_entry"], "centralized_orchestrator")
        self.assertEqual(cross_org["scenario"], "cross_org_alert_agent_driven")
        self.assertEqual(len(cross_org["dispatches"]), 2)
        self.assertTrue(all(state["state"] == "success" for state in cross_org["task_states"]))
        self.assertTrue(all(state["result"]["plugin"] == "cross_org_alert" for state in cross_org["task_states"]))
        self.assertTrue(
            all(state["result"]["metadata"]["compat_entry"] == "centralized_orchestrator" for state in cross_org["task_states"])
        )

    def test_external_agent_sdk_non_intrusive_integration(self) -> None:
        sdk = ExternalAgentSDK(agent_id="ecosystem-agent", backend="simulated")
        sdk.register_plugins([CrossOrgAlertPlugin()])
        sdk.start_agent_runtime()
        dispatched = sdk.dispatch(
            task_type="alert_sync",
            payload={"from_org": "org-a", "to_org": "org-b", "alert_id": "alert-eco-001"},
            source_agent="third-party-orchestrator",
            metadata={"plugin": "cross_org_alert"},
        )
        state = self._wait_for_terminal(sdk.kernel, dispatched["task_id"])
        self.assertEqual(dispatched["status"], "routed")
        self.assertIsNotNone(state)
        self.assertEqual(state["state"], "success")
        self.assertEqual(state["result"]["plugin"], "cross_org_alert")
        self.assertEqual(state["result"]["metadata"]["compat_entry"], "centralized_orchestrator")
        sdk.stop()

    def test_runtime_retry_timeout_and_metrics(self) -> None:
        retry_plugin = FlakyRetryPlugin()
        runtime = ExternalAgentSDK(
            agent_id="runtime-agent",
            backend="simulated",
            max_workers=2,
            max_inflight=4,
            plugin_timeout_s=0.01,
            max_retries=1,
        )
        runtime.register_plugins([retry_plugin, SlowTimeoutPlugin()])
        runtime.start_agent_runtime()
        first = runtime.dispatch("retry_task", {"value": 7}, metadata={"plugin": "flaky_retry"})
        second = runtime.dispatch("slow_task", {"sleep": 0.06}, metadata={"plugin": "slow_timeout"})
        first_state = self._wait_for_terminal(runtime.kernel, first["task_id"])
        second_state = self._wait_for_terminal(runtime.kernel, second["task_id"])
        metrics = runtime.get_metrics()
        self.assertEqual(first_state["state"], "success")
        self.assertEqual(first_state["result"]["value"], 7)
        self.assertEqual(second_state["state"], "failed")
        self.assertEqual(second_state["result"]["reason"], "plugin_timeout")
        self.assertGreaterEqual(metrics["retried_tasks"], 1.0)
        self.assertGreaterEqual(metrics["timeout_failures"], 1.0)
        runtime.stop()

    def test_runtime_queue_rejection(self) -> None:
        sdk = ExternalAgentSDK(
            agent_id="queue-agent",
            backend="simulated",
            max_workers=1,
            max_inflight=1,
            plugin_timeout_s=0.5,
            max_retries=0,
        )
        sdk.register_plugins([SlowTimeoutPlugin()])
        sdk.start_agent_runtime()
        first = sdk.dispatch("slow_task", {"sleep": 0.1}, metadata={"plugin": "slow_timeout"})
        second = sdk.dispatch("slow_task", {"sleep": 0.1}, metadata={"plugin": "slow_timeout"})
        first_state = self._wait_for_terminal(sdk.kernel, first["task_id"])
        second_state = self._wait_for_terminal(sdk.kernel, second["task_id"])
        metrics = sdk.get_metrics()
        self.assertEqual(first_state["state"], "success")
        self.assertEqual(second_state["state"], "failed")
        self.assertEqual(second_state["result"]["reason"], "queue_full")
        self.assertGreaterEqual(metrics["queue_rejections"], 1.0)
        sdk.stop()


if __name__ == "__main__":
    unittest.main()
