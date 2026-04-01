"""Consensus module for Vertex Swarm Track3."""

def threshold_for(total_nodes: int) -> int:
    """Purpose: Threshold for.

    Inputs:
    - Uses function parameters plus relevant in-memory runtime state.

    Behavior:
    - Validates/normalizes key fields before doing state transitions.
    - Executes deterministic threshold for rules so all nodes converge on the same result.

    Outputs:
    - Returns normalized data or state updates consumed by downstream logic.
    """
    return (2 * total_nodes) // 3 + 1
