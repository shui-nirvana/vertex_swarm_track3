"""Security module for Vertex Swarm Track3."""

import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional, Set, Tuple


def canonical_json(data: Dict[str, Any]) -> str:
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


def sign_payload(secret: str, data: Dict[str, Any]) -> str:
    """Purpose: Sign payload.

    Inputs:
    - Uses function parameters plus relevant in-memory runtime state.

    Behavior:
    - Validates/normalizes key fields before doing state transitions.
    - Executes deterministic sign payload rules so all nodes converge on the same result.

    Outputs:
    - Returns normalized data or state updates consumed by downstream logic.
    """
    payload = canonical_json(data).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_payload(secret: str, data: Dict[str, Any], signature: str) -> bool:
    """Purpose: Verify payload.

    Inputs:
    - Uses function parameters plus relevant in-memory runtime state.

    Behavior:
    - Validates/normalizes key fields before doing state transitions.
    - Executes deterministic verify payload rules so all nodes converge on the same result.

    Outputs:
    - Returns normalized data or state updates consumed by downstream logic.
    """
    expected = sign_payload(secret, data)
    return hmac.compare_digest(expected, signature)


class ReplayProtector:
    def __init__(self, max_skew_seconds: float = 30.0):
        """Purpose: Init.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic init rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        self.max_skew_seconds = max_skew_seconds
        self._seen: Set[Tuple[str, str]] = set()

    def check_and_mark(self, sender: str, nonce: str, ts: float) -> Tuple[bool, Optional[str]]:
        """Purpose: Check and mark.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic check and mark rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        now = time.time()
        if abs(now - ts) > self.max_skew_seconds:
            return False, "timestamp_out_of_window"
        key = (sender, nonce)
        if key in self._seen:
            return False, "replay_detected"
        self._seen.add(key)
        return True, None
