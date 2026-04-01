"""Tests for local panel server record parsing and projections."""

import json
import os
import tempfile
import unittest
from typing import Any

from security_monitor.panel.server import (
    _build_agent_panels,
    _build_overview,
    _build_swarm_agent_view,
    _build_timeline,
    _business_template_payload,
    _collect_record_files,
    _load_mission_record,
    _pick_requester_agent,
)


class PanelServerTests(unittest.TestCase):
    def _write_record(self, base_dir: str, payload: dict[str, Any], name: str = "multiprocess_mission_record.json") -> str:
        path = os.path.join(base_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return path

    def test_collect_and_parse_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "mission_id": "mission-demo",
                "run_id": "run-demo",
                "topic_namespace": "run-demo",
                "mission_payload": {"business_context": {"business_type": "risk_control"}},
                "business_flow_log": [],
            }
            record_path = self._write_record(tmp, payload)
            files = _collect_record_files(tmp)
            self.assertIn(record_path, files)
            record = _load_mission_record(record_path)
            self.assertIsNotNone(record)
            assert record is not None
            self.assertEqual(record.mission_id, "mission-demo")
            self.assertEqual(record.run_id, "run-demo")

    def test_overview_timeline_and_agent_view(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "mission_id": "mission-demo",
                "run_id": "run-demo",
                "topic_namespace": "run-demo",
                "mission_payload": {
                    "business_type": "risk_control",
                    "business_context": {"scenario": "risk_control_high_velocity_withdrawal"},
                },
                "agent_announcements": [
                    {"agent_id": "agent-a", "roles": ["scout"], "active_peer_count": 2, "timestamp": "t1"},
                    {"agent_id": "agent-b", "roles": ["guardian"], "active_peer_count": 2, "timestamp": "t2"},
                ],
                "business_flow_log": [
                    {
                        "step_index": 1,
                        "role_name": "scout",
                        "task_type": "risk_assessment",
                        "selected_agent": "agent-a",
                        "state": "success",
                        "task_payload": {"transaction_id": "tx-1"},
                        "result_summary": {"status": "processed"},
                        "timestamp": "2026-01-01T00:00:00+00:00",
                    }
                ],
                "steps": [{"task_id": "task-1", "state": "success"}],
                "step_metrics": {"scout": {"state": "success"}},
                "proof_checks": {"proof_hash_ok": True},
                "standard_metrics": {"success_rate": 1.0},
            }
            record = _load_mission_record(self._write_record(tmp, payload))
            self.assertIsNotNone(record)
            assert record is not None
            overview = _build_overview(record)
            self.assertEqual(overview["business_type"], "risk_control")
            self.assertEqual(overview["current_layer"], "completed")
            self.assertEqual(overview["current_stage"], "guardian")
            self.assertEqual(int(overview["step_count"]), 1)
            self.assertEqual(int(overview["current_layer_index"]), 5)
            summary = dict(overview["stage_summary"])
            self.assertEqual(int(summary.get("total_duration_ms", 0)), 0)
            stage_failure = dict(overview["stage_failure"])
            self.assertEqual(str(stage_failure.get("failed_stage", "")), "")
            self.assertEqual(int(stage_failure.get("failed_step_index", 0)), 0)
            layer_states = {str(item.get("layer", "")): str(item.get("state", "")) for item in overview["layers"]}
            self.assertEqual(layer_states.get("business"), "done")
            self.assertEqual(layer_states.get("acceptance"), "done")
            stage_states = {str(item.get("role_name", "")): str(item.get("state", "")) for item in overview["stages"]}
            stage_durations = {str(item.get("role_name", "")): item.get("duration_ms") for item in overview["stages"]}
            self.assertEqual(stage_states.get("scout"), "done")
            self.assertEqual(stage_states.get("guardian"), "running")
            self.assertEqual(stage_states.get("verifier"), "pending")
            self.assertEqual(int(stage_durations.get("scout") or 0), 0)
            timeline = _build_timeline(record, limit=200, offset=0)
            self.assertEqual(len(timeline["timeline"]), 1)
            self.assertEqual(timeline["timeline"][0]["role_name"], "scout")
            agents = _build_swarm_agent_view(record)
            self.assertEqual(len(agents), 2)
            self.assertEqual(agents[0]["agent_id"], "agent-a")

    def test_overview_current_layer_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "mission_id": "mission-progress",
                "run_id": "run-progress",
                "topic_namespace": "run-progress",
                "mission_payload": {"business_type": "threat_intel", "business_context": {"scenario": "demo"}},
                "steps": [{"task_id": "task-1"}],
                "step_metrics": {"scout": {"state": "running"}},
                "business_flow_log": [
                    {"role_name": "scout", "state": "running", "timestamp": "2026-01-01T00:00:00+00:00"},
                    {"role_name": "scout", "state": "running", "timestamp": "2026-01-01T00:00:01+00:00"},
                ],
            }
            record = _load_mission_record(self._write_record(tmp, payload))
            self.assertIsNotNone(record)
            assert record is not None
            overview = _build_overview(record)
            self.assertEqual(overview["current_layer"], "consensus")
            self.assertEqual(overview["current_stage"], "scout")
            layer_states = {str(item.get("layer", "")): str(item.get("state", "")) for item in overview["layers"]}
            self.assertEqual(layer_states.get("business"), "done")
            self.assertEqual(layer_states.get("coordination"), "done")
            self.assertEqual(layer_states.get("consensus"), "running")
            stage_states = {str(item.get("role_name", "")): str(item.get("state", "")) for item in overview["stages"]}
            self.assertEqual(stage_states.get("scout"), "running")
            summary = dict(overview["stage_summary"])
            self.assertEqual(int(summary.get("total_duration_ms", 0)), 1000)

    def test_overview_failure_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "mission_id": "mission-fail",
                "run_id": "run-fail",
                "topic_namespace": "run-fail",
                "mission_payload": {"business_type": "risk_control", "business_context": {"scenario": "fail-demo"}},
                "business_flow_log": [
                    {"role_name": "scout", "state": "success", "timestamp": "2026-01-01T00:00:00+00:00"},
                    {
                        "step_index": 2,
                        "role_name": "guardian",
                        "state": "failed",
                        "timestamp": "2026-01-01T00:00:02+00:00",
                        "result_summary": {"reason": "policy_blocked"},
                    },
                ],
            }
            record = _load_mission_record(self._write_record(tmp, payload))
            self.assertIsNotNone(record)
            assert record is not None
            overview = _build_overview(record)
            self.assertEqual(overview["current_stage"], "guardian")
            stage_failure = dict(overview["stage_failure"])
            self.assertEqual(str(stage_failure.get("failed_stage", "")), "guardian")
            self.assertEqual(str(stage_failure.get("reason", "")), "policy_blocked")
            self.assertEqual(int(stage_failure.get("failed_step_index", 0)), 2)

    def test_agent_panels_include_local_and_shared_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "mission_id": "mission-agent-panels",
                "run_id": "run-agent-panels",
                "topic_namespace": "run-agent-panels",
                "mission_payload": {"business_type": "risk_control", "business_context": {"scenario": "demo"}},
                "all_success": True,
                "mission_complete": True,
                "proof_checks": {"proof_hash_ok": True},
                "role_identity_assignments": {
                    "scout": {"assigned_agent": "agent-a"},
                    "guardian": {"assigned_agent": "agent-b"},
                    "verifier": {"assigned_agent": "agent-c"},
                },
                "agent_announcements": [
                    {"agent_id": "agent-a", "roles": ["scout"], "timestamp": "2026-01-01T00:00:00+00:00"},
                    {"agent_id": "agent-b", "roles": ["guardian"], "timestamp": "2026-01-01T00:00:00+00:00"},
                ],
                "business_flow_log": [
                    {"step_index": 1, "role_name": "scout", "selected_agent": "agent-a", "task_type": "risk", "state": "success"},
                    {"step_index": 2, "role_name": "guardian", "selected_agent": "agent-b", "task_type": "guard", "state": "success"},
                ],
            }
            record = _load_mission_record(self._write_record(tmp, payload))
            self.assertIsNotNone(record)
            assert record is not None
            panels = _build_agent_panels(record, local_agent_id="")
            self.assertEqual(len(panels), 2)
            panel_a = next(item for item in panels if str(item.get("agent_id", "")) == "agent-a")
            local_view_a = dict(panel_a.get("local_view", {}))
            shared_view_a = dict(panel_a.get("swarm_shared_view", {}))
            self.assertEqual(int(local_view_a.get("handled_step_count", 0)), 1)
            self.assertEqual(int(shared_view_a.get("peer_count", 0)), 2)
            self.assertEqual(str(shared_view_a.get("current_layer", "")), "coordination")
            self.assertFalse(bool(panel_a.get("is_abnormal")))
            self.assertIn("is now at step", str(panel_a.get("current_step_sentence", "")))
            flow_sentences = list(panel_a.get("business_flow_sentences", []))
            self.assertGreaterEqual(len(flow_sentences), 1)
            tashi = dict(panel_a.get("tashi_primitives", {}))
            self.assertIn("discover_form", tashi)
            foxmq = dict(panel_a.get("foxmq_messages", {}))
            self.assertIn("summary", foxmq)

    def test_agent_panels_abnormal_and_current_stage_relation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "mission_id": "mission-agent-panels-fail",
                "run_id": "run-agent-panels-fail",
                "topic_namespace": "run-agent-panels-fail",
                "mission_payload": {"business_type": "risk_control", "business_context": {"scenario": "demo"}},
                "role_identity_assignments": {
                    "scout": {"assigned_agent": "agent-a"},
                    "guardian": {"assigned_agent": "agent-b"},
                    "verifier": {"assigned_agent": "agent-c"},
                },
                "agent_announcements": [
                    {"agent_id": "agent-a", "roles": ["scout"]},
                    {"agent_id": "agent-b", "roles": ["guardian"]},
                ],
                "business_flow_log": [
                    {"step_index": 1, "role_name": "scout", "selected_agent": "agent-a", "task_type": "risk", "state": "success"},
                    {
                        "step_index": 2,
                        "role_name": "guardian",
                        "selected_agent": "agent-b",
                        "task_type": "guard",
                        "state": "failed",
                        "result_summary": {"reason": "policy_blocked"},
                    },
                ],
            }
            record = _load_mission_record(self._write_record(tmp, payload))
            self.assertIsNotNone(record)
            assert record is not None
            panels = _build_agent_panels(record, local_agent_id="")
            panel_b = next(item for item in panels if str(item.get("agent_id", "")) == "agent-b")
            self.assertTrue(bool(panel_b.get("is_abnormal")))
            self.assertTrue(bool(panel_b.get("related_to_current_stage")))
            foxmq = dict(panel_b.get("foxmq_messages", {}))
            self.assertGreaterEqual(int(foxmq.get("received_count", 0)), 1)

    def test_timeline_limit_and_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "mission_id": "mission-timeline",
                "run_id": "run-timeline",
                "topic_namespace": "run-timeline",
                "business_flow_log": [
                    {"step_index": 1, "role_name": "scout", "task_type": "a", "selected_agent": "agent-a", "state": "success"},
                    {"step_index": 2, "role_name": "guardian", "task_type": "b", "selected_agent": "agent-b", "state": "success"},
                    {"step_index": 3, "role_name": "verifier", "task_type": "c", "selected_agent": "agent-c", "state": "success"},
                ],
            }
            record = _load_mission_record(self._write_record(tmp, payload))
            self.assertIsNotNone(record)
            assert record is not None
            timeline = _build_timeline(record, limit=2, offset=1)
            self.assertFalse(bool(timeline.get("truncated")))
            self.assertEqual(int(timeline.get("total", 0)), 3)
            self.assertEqual(int(timeline.get("offset", 0)), 1)
            rows = list(timeline.get("timeline", []))
            self.assertEqual(len(rows), 2)
            self.assertEqual(int(rows[0].get("step_index", 0)), 2)

    def test_pick_requester_agent_prefers_specific_then_random(self) -> None:
        agents = ["agent-a", "agent-b", "agent-c"]
        selected = _pick_requester_agent(agents, strategy="random", preferred_agent_id="agent-b")
        self.assertEqual(selected, "agent-b")
        selected_default = _pick_requester_agent(agents, strategy="first", preferred_agent_id="")
        self.assertEqual(selected_default, "agent-a")

    def test_business_template_payload_uses_supported_type(self) -> None:
        payload = _business_template_payload("threat_intel")
        self.assertEqual(str(payload.get("business_type", "")), "threat_intel")
        self.assertIsInstance(payload.get("business_context"), dict)


if __name__ == "__main__":
    unittest.main()
