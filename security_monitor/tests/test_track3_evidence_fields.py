import unittest

from security_monitor.track3.main import (
    _build_auditor_evidence_message,
    _build_self_healing_drill_events,
    _stable_state_hash,
    _state_transition_trace,
)


class Track3EvidenceFieldsTests(unittest.TestCase):
    def test_state_transition_trace_is_deterministic(self) -> None:
        chain = [
            {
                "mission_id": "mission-001",
                "role_name": "scout",
                "stage": "ASSESS",
                "task_id": "task-scout",
                "selected_agent": "agent-scout",
                "state": "success",
                "result": {"status": "ok", "score": 0.92},
            },
            {
                "mission_id": "mission-001",
                "role_name": "guardian",
                "stage": "MITIGATE",
                "task_id": "task-guardian",
                "selected_agent": "agent-guardian",
                "state": "success",
                "result": {"status": "ok", "action": "freeze"},
            },
        ]
        trace = _state_transition_trace(chain)
        transitions = list(trace.get("transitions", []))
        self.assertEqual(len(transitions), 2)
        self.assertTrue(bool(trace.get("convergence_check", {}).get("deterministic_replay_match")))
        self.assertEqual(
            str(trace.get("final_state_hash", "")),
            str(trace.get("replay_state_hash", "")),
        )

    def test_stable_state_hash_changes_with_payload(self) -> None:
        hash_a = _stable_state_hash({"steps": [{"k": 1}]})
        hash_b = _stable_state_hash({"steps": [{"k": 2}]})
        self.assertNotEqual(hash_a, hash_b)

    def test_auditor_evidence_message_contains_required_fields(self) -> None:
        payload = _build_auditor_evidence_message(
            mission_id="mission-002",
            selected_winner="agent-verifier",
            final_success=True,
            all_success=True,
            ttl_seconds=30.0,
            report_path="artifacts/multiprocess_mission_record.json",
            economy_rounds_path="artifacts/economy_rounds.json",
        )
        self.assertEqual(str(payload.get("role", "")), "auditor")
        self.assertEqual(str(payload.get("stage", "")), "CLOSE")
        self.assertTrue(str(payload.get("selected_winner", "")).strip())
        self.assertTrue(str(payload.get("signature", "")).strip())
        breakdown = dict(payload.get("economy_score_breakdown", {}))
        self.assertTrue(bool(breakdown))

    def test_self_healing_drill_events_cover_required_chain(self) -> None:
        events = _build_self_healing_drill_events(
            guardian_assigned="agent-guardian",
            redistributed_to="agent-verifier",
            quorum_required=2,
            event_time="2026-04-05T00:00:00+00:00",
        )
        event_types = [str(item.get("event_type", "")).strip() for item in events]
        self.assertIn("heartbeat_miss", event_types)
        self.assertIn("quorum_confirmed_dead", event_types)
        self.assertIn("role_redistributed", event_types)
        self.assertIn("agent_rejoined", event_types)
        states = [str(item.get("state_transition", "")).strip() for item in events]
        self.assertEqual(states, ["SUSPECT", "DEAD", "REDISTRIBUTE", "REJOINING", "ACTIVE"])


if __name__ == "__main__":
    unittest.main()
