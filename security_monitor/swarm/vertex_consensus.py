"""Vertex DAG consensus primitives for deterministic ordering and verifiable proofs.

Implements event construction, round division, famous witness voting, consensus
ordering, and proof serialization/verification used by Track3 mission auditing.
"""

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from security_monitor.swarm.consensus import threshold_for
from security_monitor.swarm.security import sign_payload, verify_payload


def _canonical_json(data: Dict[str, Any]) -> str:
    """Purpose: Canonical json.

    Inputs:
    - Uses function parameters plus relevant in-memory runtime state.

    Behavior:
    - Validates/normalizes key fields before doing state transitions.
    - Executes deterministic canonical json rules so all nodes converge on the same result.

    Outputs:
    - Returns normalized data or state updates consumed by downstream logic.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _event_payload(
    creator: str,
    logical_ts: int,
    transactions: List[Dict[str, Any]],
    self_parent: str,
    other_parents: List[str],
) -> Dict[str, Any]:
    return {
        "creator": creator,
        "logical_ts": int(logical_ts),
        "transactions": transactions,
        "self_parent": self_parent,
        "other_parents": sorted(other_parents),
    }


def _event_id_from_payload(payload: Dict[str, Any]) -> str:
    """Purpose: Event id from payload.

    Inputs:
    - Uses function parameters plus relevant in-memory runtime state.

    Behavior:
    - Validates/normalizes key fields before doing state transitions.
    - Executes deterministic event id from payload rules so all nodes converge on the same result.

    Outputs:
    - Returns normalized data or state updates consumed by downstream logic.
    """
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VertexEvent:
    event_id: str
    creator: str
    logical_ts: int
    transactions: List[Dict[str, Any]]
    self_parent: str
    other_parents: List[str]
    signature: str

    def payload(self) -> Dict[str, Any]:
        """Purpose: Payload.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic payload rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return _event_payload(
            creator=self.creator,
            logical_ts=self.logical_ts,
            transactions=list(self.transactions),
            self_parent=self.self_parent,
            other_parents=list(self.other_parents),
        )


class VertexConsensus:
    def __init__(self, participants: Sequence[str]):
        """Purpose: Init.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic init rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        participant_set = {str(item).strip() for item in participants if str(item).strip()}
        if len(participant_set) < 3:
            raise ValueError("vertex consensus requires at least 3 participants")
        self.participants: List[str] = sorted(participant_set)
        self._events: Dict[str, VertexEvent] = {}
        self._children: Dict[str, Set[str]] = defaultdict(set)
        self._ancestor_cache: Dict[str, Set[str]] = {}

    def add_event(self, event: VertexEvent) -> None:
        """Purpose: Add event.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic add event rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if event.creator not in self.participants:
            raise ValueError(f"unknown participant: {event.creator}")
        if event.event_id in self._events:
            return
        if event.self_parent and event.self_parent not in self._events:
            raise ValueError(f"missing self parent: {event.self_parent}")
        for parent in event.other_parents:
            if parent and parent not in self._events:
                raise ValueError(f"missing other parent: {parent}")
        self._events[event.event_id] = event
        self._ancestor_cache.clear()
        if event.self_parent:
            self._children[event.self_parent].add(event.event_id)
        for parent in event.other_parents:
            if parent:
                self._children[parent].add(event.event_id)

    def events(self) -> List[VertexEvent]:
        """Purpose: Events.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic events rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        return sorted(self._events.values(), key=lambda item: (item.logical_ts, item.event_id))

    def ancestors(self, event_id: str) -> Set[str]:
        """Purpose: Ancestors.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic ancestors rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if event_id in self._ancestor_cache:
            return set(self._ancestor_cache[event_id])
        result: Set[str] = set()
        stack: List[str] = [event_id]
        while stack:
            current = stack.pop()
            event = self._events.get(current)
            if not event:
                continue
            for parent in [event.self_parent, *event.other_parents]:
                parent_id = str(parent).strip()
                if not parent_id or parent_id in result:
                    continue
                result.add(parent_id)
                stack.append(parent_id)
        self._ancestor_cache[event_id] = set(result)
        return result

    def can_see(self, observer_event_id: str, target_event_id: str) -> bool:
        """Purpose: Can see.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic can see rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if observer_event_id == target_event_id:
            return True
        return target_event_id in self.ancestors(observer_event_id)

    def _witnesses_by_round(self, rounds: Dict[str, int]) -> Dict[int, Dict[str, str]]:
        """Purpose: Witnesses by round.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic witnesses by round rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        witnesses: Dict[int, Dict[str, str]] = defaultdict(dict)
        for event in self.events():
            round_number = int(rounds.get(event.event_id, 1))
            creator_map = witnesses.setdefault(round_number, {})
            if event.creator not in creator_map:
                creator_map[event.creator] = event.event_id
        return witnesses

    def _strongly_sees_round(
        self,
        observer_event_id: str,
        witness_map: Dict[str, str],
    ) -> bool:
        if not witness_map:
            return False
        seen_creators: Set[str] = set()
        for creator, witness_event_id in witness_map.items():
            if self.can_see(observer_event_id, witness_event_id):
                seen_creators.add(creator)
        return len(seen_creators) >= threshold_for(len(self.participants))

    def divide_rounds(self) -> Tuple[Dict[str, int], Dict[int, Dict[str, str]]]:
        """Assign each event to a logical round and extract round witnesses.

        Round rule:
        - Start from max parent round.
        - Promote to next round only when event strongly sees prior-round witnesses.
        - Witnesses are first events by creator in each round.
        """
        rounds: Dict[str, int] = {}
        for event in self.events():
            parent_round = 1
            parent_ids = [event.self_parent, *event.other_parents]
            parent_rounds = [rounds[parent] for parent in parent_ids if parent]
            if parent_rounds:
                parent_round = max(parent_rounds)
            prior_witnesses = self._witnesses_by_round(rounds).get(parent_round, {})
            if prior_witnesses and self._strongly_sees_round(event.event_id, prior_witnesses):
                rounds[event.event_id] = parent_round + 1
            else:
                rounds[event.event_id] = parent_round
        return rounds, self._witnesses_by_round(rounds)

    def _vote_round(
        self,
        target_witness_id: str,
        current_witnesses: Dict[str, str],
        previous_witnesses: Dict[str, str],
        previous_votes: Dict[str, bool],
    ) -> Dict[str, bool]:
        result: Dict[str, bool] = {}
        for creator, witness_id in current_witnesses.items():
            visible_votes: List[bool] = []
            for prev_creator, prev_vote in previous_votes.items():
                prev_witness_id = previous_witnesses.get(prev_creator)
                if prev_witness_id and self.can_see(witness_id, prev_witness_id):
                    visible_votes.append(prev_vote)
            if visible_votes:
                trues = sum(1 for item in visible_votes if item)
                falses = len(visible_votes) - trues
                if trues > falses:
                    result[creator] = True
                elif falses > trues:
                    result[creator] = False
                else:
                    result[creator] = previous_votes.get(creator, self.can_see(witness_id, target_witness_id))
            else:
                result[creator] = self.can_see(witness_id, target_witness_id)
        return result

    def famous_witnesses(self) -> Tuple[Dict[str, bool], Dict[str, int], Dict[str, int]]:
        """Run deterministic witness voting to classify famous witnesses.

        Returns:
        - fame: whether each witness is considered famous.
        - decided_round: the round where each witness fame becomes decided.
        - witness_round: original round index for each witness event id.
        """
        rounds, witnesses = self.divide_rounds()
        witness_round: Dict[str, int] = {}
        for round_number, items in witnesses.items():
            for witness_id in items.values():
                witness_round[witness_id] = int(round_number)
        fame: Dict[str, bool] = {}
        decided_round: Dict[str, int] = {}
        max_round = max(witnesses.keys(), default=1)
        supermajority = threshold_for(len(self.participants))
        for witness_id, start_round in witness_round.items():
            previous_votes: Dict[str, bool] = {}
            first_vote_round = start_round + 1
            round_witnesses = witnesses.get(first_vote_round, {})
            for creator, voter_witness_id in round_witnesses.items():
                previous_votes[creator] = self.can_see(voter_witness_id, witness_id)
            for round_number in range(start_round + 2, max_round + 1):
                current_witnesses = witnesses.get(round_number, {})
                previous_witnesses = witnesses.get(round_number - 1, {})
                if not current_witnesses:
                    continue
                previous_votes = self._vote_round(
                    target_witness_id=witness_id,
                    current_witnesses=current_witnesses,
                    previous_witnesses=previous_witnesses,
                    previous_votes=previous_votes,
                )
                true_count = sum(1 for item in previous_votes.values() if item)
                false_count = len(previous_votes) - true_count
                if true_count >= supermajority:
                    fame[witness_id] = True
                    decided_round[witness_id] = int(round_number)
                    break
                if false_count >= supermajority:
                    fame[witness_id] = False
                    decided_round[witness_id] = int(round_number)
                    break
            if witness_id not in fame:
                total_true = sum(1 for item in previous_votes.values() if item)
                fame[witness_id] = total_true >= supermajority
                decided_round[witness_id] = int(max_round)
        return fame, decided_round, witness_round

    def _received_round(
        self,
        event_id: str,
        famous: Dict[str, bool],
        witness_round: Dict[str, int],
    ) -> Optional[int]:
        supermajority = threshold_for(len(self.participants))
        rounds, witnesses = self.divide_rounds()
        max_round = max(witnesses.keys(), default=1)
        for round_number in range(1, max_round + 1):
            round_witnesses = witnesses.get(round_number, {})
            count = 0
            for witness_id in round_witnesses.values():
                if not famous.get(witness_id, False):
                    continue
                if self.can_see(witness_id, event_id):
                    count += 1
            if count >= supermajority:
                _ = rounds
                return int(round_number)
        return None

    def _leaf_whitened_key(self, event: VertexEvent) -> str:
        """Purpose: Leaf whitened key.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic leaf whitened key rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        whitening = hashlib.sha256(f"{event.signature}:{event.event_id}".encode("utf-8")).hexdigest()
        return whitening

    def _order_event_subset(self, event_ids: Set[str]) -> List[str]:
        """Purpose: Order event subset.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic order event subset rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        remaining = set(event_ids)
        ordered: List[str] = []
        while remaining:
            leaves: List[VertexEvent] = []
            for event_id in list(remaining):
                children = self._children.get(event_id, set())
                if not any(child in remaining for child in children):
                    leaves.append(self._events[event_id])
            leaves.sort(key=lambda item: (self._leaf_whitened_key(item), item.event_id))
            for leaf in leaves:
                leaf_ancestors = self.ancestors(leaf.event_id)
                unique_ancestors = {aid for aid in leaf_ancestors if aid in remaining}
                shared: Set[str] = set()
                for other in leaves:
                    if other.event_id == leaf.event_id:
                        continue
                    shared |= self.ancestors(other.event_id)
                strict_unique = unique_ancestors - shared
                if strict_unique:
                    ancestor_order = sorted(
                        strict_unique,
                        key=lambda item: (
                            self._events[item].logical_ts,
                            self._leaf_whitened_key(self._events[item]),
                            item,
                        ),
                    )
                    for ancestor_id in ancestor_order:
                        if ancestor_id in remaining:
                            ordered.append(ancestor_id)
                            remaining.remove(ancestor_id)
                if leaf.event_id in remaining:
                    ordered.append(leaf.event_id)
                    remaining.remove(leaf.event_id)
        return ordered

    def consensus_order(self) -> Dict[str, Any]:
        """Produce finalized event order based on famous-witness visibility.

        Steps:
        - Compute fame and receiving rounds.
        - Group events by finalized round.
        - Order each round subset with deterministic whitening tie-break strategy.
        """
        fame, decided_round, witness_round = self.famous_witnesses()
        finalized_round: Dict[str, int] = {}
        for event in self.events():
            received = self._received_round(event.event_id, famous=fame, witness_round=witness_round)
            if received is not None:
                finalized_round[event.event_id] = int(received)
        rounds: Dict[int, Set[str]] = defaultdict(set)
        for event_id, round_number in finalized_round.items():
            rounds[round_number].add(event_id)
        ordered_event_ids: List[str] = []
        for round_number in sorted(rounds.keys()):
            ordered_event_ids.extend(self._order_event_subset(set(rounds[round_number])))
        return {
            "ordered_event_ids": ordered_event_ids,
            "famous_witnesses": fame,
            "witness_round": witness_round,
            "decided_round": decided_round,
            "finalized_round": finalized_round,
        }

    def build_proof(self, secret_by_participant: Dict[str, str]) -> Dict[str, Any]:
        """Build verifiable proof bundle from finalized consensus order.

        Bundle contains ordered event ids, fame/finalization metadata, proof hash,
        participant signatures over the proof hash, and serialized ordered events.
        """
        consensus = self.consensus_order()
        ordered_event_ids = list(consensus["ordered_event_ids"])
        ordered_events = [self._events[event_id] for event_id in ordered_event_ids]
        proof_payload = {
            "participants": list(self.participants),
            "ordered_event_ids": ordered_event_ids,
            "famous_witnesses": {key: bool(value) for key, value in consensus["famous_witnesses"].items()},
            "finalized_round": {key: int(value) for key, value in consensus["finalized_round"].items()},
        }
        proof_hash = hashlib.sha256(_canonical_json(proof_payload).encode("utf-8")).hexdigest()
        signatures: Dict[str, str] = {}
        for participant in self.participants:
            secret = str(secret_by_participant.get(participant, "")).strip()
            if not secret:
                continue
            signatures[participant] = sign_payload(secret, {"proof_hash": proof_hash, "participant": participant})
        return {
            "proof_payload": proof_payload,
            "proof_hash": proof_hash,
            "signatures": signatures,
            "ordered_events": [event.payload() | {"event_id": event.event_id, "signature": event.signature} for event in ordered_events],
        }

    @staticmethod
    def verify_proof(
        proof: Dict[str, Any],
        secret_by_participant: Dict[str, str],
    ) -> Dict[str, bool]:
        """Verify proof hash integrity and signature quorum against participant secrets."""
        payload = dict(proof.get("proof_payload", {}))
        expected_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
        proof_hash = str(proof.get("proof_hash", ""))
        proof_hash_ok = expected_hash == proof_hash
        signatures = dict(proof.get("signatures", {}))
        participants = [str(item).strip() for item in payload.get("participants", []) if str(item).strip()]
        verified = 0
        for participant in participants:
            signature = str(signatures.get(participant, "")).strip()
            secret = str(secret_by_participant.get(participant, "")).strip()
            if not signature or not secret:
                continue
            if verify_payload(secret, {"proof_hash": proof_hash, "participant": participant}, signature):
                verified += 1
        signature_quorum_ok = verified >= threshold_for(len(set(participants))) if participants else False
        return {
            "proof_hash_ok": proof_hash_ok,
            "signature_quorum_ok": signature_quorum_ok,
        }


def make_vertex_event(
    creator: str,
    logical_ts: int,
    transactions: List[Dict[str, Any]],
    self_parent: str,
    other_parents: Iterable[str],
    secret: str,
) -> VertexEvent:
    payload = _event_payload(
        creator=str(creator).strip(),
        logical_ts=int(logical_ts),
        transactions=list(transactions),
        self_parent=str(self_parent).strip(),
        other_parents=[str(item).strip() for item in other_parents if str(item).strip()],
    )
    event_id = _event_id_from_payload(payload)
    signature = sign_payload(secret, payload)
    return VertexEvent(
        event_id=event_id,
        creator=str(payload["creator"]),
        logical_ts=int(payload["logical_ts"]),
        transactions=list(payload["transactions"]),
        self_parent=str(payload["self_parent"]),
        other_parents=list(payload["other_parents"]),
        signature=signature,
    )
