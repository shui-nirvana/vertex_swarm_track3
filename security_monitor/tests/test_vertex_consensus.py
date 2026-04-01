"""Unit tests for Vertex DAG consensus ordering and proof verification.

Environment assumptions:
- Pure in-memory consensus engine (no external broker/process dependencies).
- Deterministic participant identities and secrets for reproducible signatures.
"""

import unittest
from typing import Dict, List

from security_monitor.swarm.vertex_consensus import VertexConsensus, make_vertex_event


class VertexConsensusTests(unittest.TestCase):
    """Validate round division, famous witnesses, order stability, and tamper checks."""

    def _build_engine(self) -> tuple[VertexConsensus, Dict[str, str], List[str]]:
        """Purpose: Build engine.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic build engine rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        participants = ["agent-a", "agent-b", "agent-c", "agent-d"]
        secrets = {item: f"secret-{item}" for item in participants}
        engine = VertexConsensus(participants)
        creator_last_event: Dict[str, str] = {}
        event_ids: List[str] = []
        logical_ts = 0
        for creator in participants:
            logical_ts += 1
            other_parents = list(event_ids)
            event = make_vertex_event(
                creator=creator,
                logical_ts=logical_ts,
                transactions=[{"kind": "tx", "creator": creator, "round": 1}],
                self_parent=creator_last_event.get(creator, ""),
                other_parents=other_parents,
                secret=secrets[creator],
            )
            engine.add_event(event)
            creator_last_event[creator] = event.event_id
            event_ids.append(event.event_id)
        for round_number in (2, 3):
            for creator in participants:
                logical_ts += 1
                other_parents = [item for item in event_ids if item != creator_last_event.get(creator, "")]
                event = make_vertex_event(
                    creator=creator,
                    logical_ts=logical_ts,
                    transactions=[{"kind": "tx", "creator": creator, "round": round_number}],
                    self_parent=creator_last_event.get(creator, ""),
                    other_parents=other_parents,
                    secret=secrets[creator],
                )
                engine.add_event(event)
                creator_last_event[creator] = event.event_id
                event_ids.append(event.event_id)
        return engine, secrets, event_ids

    def test_divide_rounds_and_famous_witnesses(self) -> None:
        """Goal: Validate divide rounds and famous witnesses.

        Setup: Construct a deterministic in-memory Vertex DAG with fixed participants/secrets and no external broker/process dependencies.
        Checks: Assert round/witness derivation, consensus ordering, and proof verification/tamper detection remain deterministic.
        """
        engine, _, _ = self._build_engine()
        rounds, witnesses = engine.divide_rounds()
        self.assertGreaterEqual(max(rounds.values()), 2)
        self.assertGreaterEqual(len(witnesses), 2)
        fame, decided_round, witness_round = engine.famous_witnesses()
        self.assertTrue(fame)
        self.assertTrue(all(witness_id in witness_round for witness_id in fame))
        self.assertTrue(all(round_number >= witness_round[witness_id] for witness_id, round_number in decided_round.items()))

    def test_consensus_order_preserves_self_parent_order(self) -> None:
        """Goal: Validate consensus order preserves self parent order.

        Setup: Construct a deterministic in-memory Vertex DAG with fixed participants/secrets and no external broker/process dependencies.
        Checks: Assert round/witness derivation, consensus ordering, and proof verification/tamper detection remain deterministic.
        """
        engine, _, event_ids = self._build_engine()
        ordering = engine.consensus_order()
        ordered_event_ids = list(ordering["ordered_event_ids"])
        self.assertTrue(ordered_event_ids)
        position = {event_id: index for index, event_id in enumerate(ordered_event_ids)}
        all_events = {event.event_id: event for event in engine.events()}
        for event_id in event_ids:
            event = all_events[event_id]
            if event.self_parent and event.self_parent in position and event_id in position:
                self.assertLess(position[event.self_parent], position[event_id])

    def test_proof_verification_and_tamper_detection(self) -> None:
        """Goal: Validate proof verification and tamper detection.

        Setup: Construct a deterministic in-memory Vertex DAG with fixed participants/secrets and no external broker/process dependencies.
        Checks: Assert round/witness derivation, consensus ordering, and proof verification/tamper detection remain deterministic.
        """
        engine, secrets, _ = self._build_engine()
        proof = engine.build_proof(secrets)
        checks = VertexConsensus.verify_proof(proof, secrets)
        self.assertTrue(all(checks.values()))
        tampered = dict(proof)
        tampered_payload = dict(tampered["proof_payload"])
        tampered_payload["ordered_event_ids"] = list(reversed(list(tampered_payload["ordered_event_ids"])))
        tampered["proof_payload"] = tampered_payload
        tampered_checks = VertexConsensus.verify_proof(tampered, secrets)
        self.assertFalse(tampered_checks["proof_hash_ok"])


if __name__ == "__main__":
    unittest.main()
