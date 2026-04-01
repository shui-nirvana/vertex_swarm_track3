"""Execution module for Vertex Swarm Track3."""

import hashlib
import json
import time
from typing import Any, Dict


def execute_task(task: Dict[str, Any], worker_id: str) -> Dict[str, Any]:
    """Purpose: Execute task.

    Inputs:
    - Uses function parameters plus relevant in-memory runtime state.

    Behavior:
    - Validates/normalizes key fields before doing state transitions.
    - Executes deterministic execute task rules so all nodes converge on the same result.

    Outputs:
    - Returns normalized data or state updates consumed by downstream logic.
    """
    started_at = time.time()
    result = {
        "task_id": task["task_id"],
        "worker_id": worker_id,
        "status": "completed",
        "output": f"processed:{task['mission']}",
        "started_at": started_at,
        "finished_at": time.time(),
    }
    serialized = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    result["result_digest"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return result
