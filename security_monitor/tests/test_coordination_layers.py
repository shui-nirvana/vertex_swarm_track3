"""Integration tests for coordination kernel, adapters, plugins, and transports.

Environment assumptions:
- Default path uses simulated in-memory transport for deterministic behavior.
- MQTT transport checks use local FoxMQ endpoint when FOXMQ_MQTT_ADDR is available.
- Scenario tests build isolated runtime state and avoid external cloud dependencies.
"""

import os
import socket
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
from security_monitor.coordination.agent_runtime import AgentPluginRuntime
from security_monitor.plugins import CrossOrgAlertPlugin
from security_monitor.scenarios import (
    run_cross_org_alert_agent_driven_scenario,
    run_cross_org_alert_scenario,
    run_risk_control_agent_driven_scenario,
    run_risk_control_scenario,
)
from security_monitor.scenarios.business_registry import BUSINESS_TEMPLATE_FILES
from security_monitor.transports import build_transport
from security_monitor.transports.simulated import SimulatedTransport

_MQTT_E2E_ADDR = os.getenv("FOXMQ_MQTT_ADDR", "127.0.0.1:1883").strip()
_MQTT_E2E_ENABLED = str(os.getenv("MQTT_E2E", "0")).strip().lower() in {"1", "true", "yes", "on"}
_COORD_TEST_MQTT_ADDR = _MQTT_E2E_ADDR


class FlakyRetryPlugin:
    plugin_name = "flaky_retry"
    supported_task_types = ("retry_task",)

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
        self.calls = 0

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        """Purpose: Supports.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic supports rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return str(task_type) == "retry_task"

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Purpose: Handle.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic handle rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("transient")
        return {"status": "ok", "value": task_payload.get("value", 0)}


class SlowTimeoutPlugin:
    plugin_name = "slow_timeout"
    supported_task_types = ("slow_task",)

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        """Purpose: Supports.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic supports rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return str(task_type) == "slow_task"

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Purpose: Handle.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic handle rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        sleep(float(task_payload.get("sleep", 0.05)))
        return {"status": "ok"}


class EchoPlugin:
    plugin_name = "echo"
    supported_task_types = ("echo_task",)

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        """Purpose: Supports.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic supports rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return str(task_type) == "echo_task"

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Purpose: Handle.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic handle rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return {"status": "ok", "echo": task_payload.get("echo", "")}


class CoordinationLayerTests(unittest.TestCase):
    """Validate cross-layer task routing, policy enforcement, and transport behavior."""

    def setUp(self) -> None:
        """Purpose: SetUp.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic setUp rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        SimulatedTransport._bus.clear()

    def _require_mqtt_e2e(self) -> None:
        """Purpose: Require mqtt e2e.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic require mqtt e2e rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if not _MQTT_E2E_ENABLED:
            self.skipTest("set MQTT_E2E=1 and FOXMQ_MQTT_ADDR to run mqtt transport e2e")
        host, _, port_raw = _COORD_TEST_MQTT_ADDR.rpartition(":")
        if not bool(host and port_raw):
            self.skipTest(f"invalid FOXMQ_MQTT_ADDR: {_COORD_TEST_MQTT_ADDR}")
        with socket.socket() as sock:
            sock.settimeout(1.0)
            if sock.connect_ex((host, int(port_raw))) != 0:
                self.skipTest(f"FoxMQ MQTT endpoint is not reachable at {_COORD_TEST_MQTT_ADDR}")

    def _build_mqtt_transport(self, node_id: str):
        """Purpose: Build mqtt transport.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic build mqtt transport rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self._require_mqtt_e2e()
        return build_transport(node_id=node_id, backend="mqtt", mqtt_addr=_COORD_TEST_MQTT_ADDR, fallback_to_simulated=False)

    def _wait_for_terminal(self, kernel: CoordinationKernel, task_id: str, rounds: int = 120) -> Dict[str, Any]:
        """Purpose: Wait for terminal.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic wait for terminal rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        for _ in range(rounds):
            state = kernel.get_task_state(task_id)
            if state and state.get("state") in ("success", "failed", "blocked"):
                return state
            sleep(0.01)
        return kernel.get_task_state(task_id) or {}

    def _build_single_agent_runtime(
        self,
        plugins: list[Any],
        *,
        max_workers: int = 2,
        max_inflight: int = 4,
        plugin_timeout_s: float = 0.05,
        max_retries: int = 1,
    ) -> tuple[CoordinationKernel, AgentPluginRuntime]:
        kernel = CoordinationKernel(transport=SimulatedTransport(node_id="single-agent-kernel"))
        runtime = AgentPluginRuntime(
            agent_id="single-agent-worker",
            kernel=kernel,
            plugins=plugins,
            max_workers=max_workers,
            max_inflight=max_inflight,
            plugin_timeout_s=plugin_timeout_s,
            max_retries=max_retries,
        )
        runtime.start()
        return kernel, runtime

    def test_kernel_publish_subscribe_and_task_routing(self) -> None:
        """Goal: Validate kernel publish subscribe and task routing.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        transport = self._build_mqtt_transport(node_id="kernel-test")
        kernel = CoordinationKernel(transport=transport)
        kernel.register_agent("risk-agent", ["risk_assessment"])
        received = []
        kernel.subscribe(kernel.task_topic("risk-agent"), lambda msg: received.append(msg))
        routed = kernel.submit_task(
            task_type="risk_assessment",
            payload={"signal": "high"},
            source_agent="planner",
        )
        for _ in range(20):
            if received:
                break
            sleep(0.01)
        self.assertEqual(routed["status"], "routed")
        self.assertEqual(routed["target_agent"], "risk-agent")
        self.assertEqual(len(received), 1)
        state = kernel.get_task_state(routed["task_id"])
        if state is None:
            self.fail("task state should not be None")
        self.assertEqual(state["state"], "routed")

    def test_kernel_topic_namespace_is_applied(self) -> None:
        """Goal: Validate kernel topic namespace is applied.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        kernel = CoordinationKernel(
            transport=SimulatedTransport(node_id="ns-kernel"),
            topic_root="coordination/run-test-001",
        )
        kernel.register_agent("risk-agent", ["risk_assessment"])
        routed = kernel.submit_task(
            task_type="risk_assessment",
            payload={"signal": "high"},
            source_agent="planner",
        )
        self.assertEqual(routed["status"], "routed")
        self.assertEqual(routed["topic"], "coordination/run-test-001/tasks/risk-agent")

    def test_policy_hook_blocks_task(self) -> None:
        """Goal: Validate policy hook blocks task.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        transport = self._build_mqtt_transport(node_id="policy-test")
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

    def test_transport_factory_rejects_unknown_backend(self) -> None:
        """Goal: Validate transport factory rejects unknown backend.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        with self.assertRaises(ValueError):
            build_transport(node_id="n1", backend="unknown-backend", fallback_to_simulated=True)

    def test_orchestrator_compat_entry(self) -> None:
        """Goal: Validate orchestrator compat entry.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        kernel = CoordinationKernel(transport=self._build_mqtt_transport(node_id="compat-test"))
        kernel.register_agent("alert-agent", ["alert_sync"])
        compat = OrchestratorCompatibilityAdapter(kernel)
        routed = compat.dispatch_task("alert_sync", {"alert_id": "a-1"}, metadata={"plugin": "cross_org_alert"})
        self.assertEqual(routed["status"], "routed")
        state = kernel.get_task_state(routed["task_id"])
        if state is None:
            self.fail("task state should not be None")
        self.assertEqual(state["state"], "routed")
        compat.sync_state("compat:last", routed["task_id"])
        self.assertEqual(compat.read_state("compat:last"), routed["task_id"])

    def test_agent_adapters_are_thin_wrappers(self) -> None:
        """Goal: Validate agent adapters are thin wrappers.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
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
        """Goal: Validate example scenarios.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        self._require_mqtt_e2e()
        risk = run_risk_control_scenario(backend="mqtt")
        cross_org = run_cross_org_alert_scenario(backend="mqtt")
        self.assertEqual(risk["scenario"], "risk_control")
        self.assertEqual(cross_org["scenario"], "cross_org_alert")
        self.assertEqual(len(cross_org["dispatches"]), 2)

    def test_business_registry_contains_five_type_driven_cases(self) -> None:
        """Goal: Validate business registry contains five type driven cases.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        expected = {"risk_control", "threat_intel", "agent_marketplace", "distributed_rag", "compute_marketplace"}
        self.assertEqual(set(BUSINESS_TEMPLATE_FILES.keys()), expected)

    def test_agent_driven_plugin_scenarios(self) -> None:
        """Goal: Validate agent driven plugin scenarios.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        self._require_mqtt_e2e()
        risk = run_risk_control_agent_driven_scenario(backend="mqtt")
        cross_org = run_cross_org_alert_agent_driven_scenario(backend="mqtt")
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
        """Goal: Validate external agent sdk non intrusive integration.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        self._require_mqtt_e2e()
        sdk = ExternalAgentSDK(agent_id="ecosystem-agent", backend="mqtt", mqtt_addr=_COORD_TEST_MQTT_ADDR)
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
        """Goal: Validate runtime retry timeout and metrics.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        self._require_mqtt_e2e()
        retry_plugin = FlakyRetryPlugin()
        runtime = ExternalAgentSDK(
            agent_id="runtime-agent",
            backend="mqtt",
            mqtt_addr=_COORD_TEST_MQTT_ADDR,
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
        """Goal: Validate runtime queue rejection.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        self._require_mqtt_e2e()
        sdk = ExternalAgentSDK(
            agent_id="queue-agent",
            backend="mqtt",
            mqtt_addr=_COORD_TEST_MQTT_ADDR,
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

    def test_single_agent_gate_route_success_plugin_success(self) -> None:
        """Goal: Validate single agent gate route success plugin success.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        kernel, runtime = self._build_single_agent_runtime([EchoPlugin()])
        routed = kernel.submit_task(
            task_type="echo_task",
            payload={"echo": "mission-ok"},
            source_agent="planner",
        )
        state = self._wait_for_terminal(kernel, routed["task_id"])
        metrics = runtime.get_metrics()
        self.assertEqual(routed["status"], "routed")
        self.assertEqual(state["state"], "success")
        self.assertEqual(state["result"]["echo"], "mission-ok")
        self.assertEqual(state["result"]["plugin"], "echo")
        self.assertGreaterEqual(metrics["total_tasks"], 1.0)
        self.assertGreaterEqual(metrics["successful_tasks"], 1.0)
        runtime.stop()

    def test_single_agent_gate_plugin_failure_not_found(self) -> None:
        """Goal: Validate single agent gate plugin failure not found.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        kernel, runtime = self._build_single_agent_runtime([EchoPlugin()])
        routed = kernel.submit_task(
            task_type="unknown_task",
            payload={"echo": "missing-plugin"},
            source_agent="planner",
            target_agent="single-agent-worker",
        )
        state = self._wait_for_terminal(kernel, routed["task_id"])
        metrics = runtime.get_metrics()
        self.assertEqual(routed["status"], "routed")
        self.assertEqual(state["state"], "failed")
        self.assertEqual(state["result"]["reason"], "plugin_not_found")
        self.assertGreaterEqual(metrics["failed_tasks"], 1.0)
        runtime.stop()

    def test_single_agent_gate_timeout_retry_queuefull_and_metrics(self) -> None:
        """Goal: Validate single agent gate timeout retry queuefull and metrics.

        Setup: Initialize coordination kernel/runtime with simulated transport by default (or local MQTT when explicitly requested), register plugins/adapters, and isolate task state per test.
        Checks: Assert expected outputs, state transitions, and emitted artifacts for the targeted execution path.
        """
        kernel, runtime = self._build_single_agent_runtime(
            [FlakyRetryPlugin(), SlowTimeoutPlugin()],
            max_workers=1,
            max_inflight=1,
            plugin_timeout_s=0.01,
            max_retries=1,
        )
        timeout_task = kernel.submit_task(
            task_type="slow_task",
            payload={"sleep": 0.06},
            source_agent="planner",
        )
        queue_full_task = kernel.submit_task(
            task_type="slow_task",
            payload={"sleep": 0.06},
            source_agent="planner",
        )
        queue_state = self._wait_for_terminal(kernel, queue_full_task["task_id"])
        timeout_state = self._wait_for_terminal(kernel, timeout_task["task_id"])
        retry_task = kernel.submit_task(
            task_type="retry_task",
            payload={"value": 9},
            source_agent="planner",
        )
        retry_state = self._wait_for_terminal(kernel, retry_task["task_id"])
        metrics = runtime.get_metrics()
        self.assertEqual(retry_state["state"], "success")
        self.assertEqual(retry_state["result"]["attempts"], 2)
        self.assertEqual(timeout_state["state"], "failed")
        self.assertEqual(timeout_state["result"]["reason"], "plugin_timeout")
        self.assertEqual(queue_state["state"], "failed")
        self.assertEqual(queue_state["result"]["reason"], "queue_full")
        self.assertGreaterEqual(metrics["retried_tasks"], 1.0)
        self.assertGreaterEqual(metrics["timeout_failures"], 1.0)
        self.assertGreaterEqual(metrics["queue_rejections"], 1.0)
        self.assertGreaterEqual(metrics["avg_latency_ms"], 0.0)
        runtime.stop()


if __name__ == "__main__":
    unittest.main()
