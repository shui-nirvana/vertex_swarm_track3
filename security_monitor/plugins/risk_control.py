"""Risk Control module for Vertex Swarm Track3."""

from typing import Any, Dict


class RiskControlPlugin:
    plugin_name = "risk_control"
    supported_task_types = ("risk_assessment", "risk_mitigation")

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
        if str(task_type) in self.supported_task_types:
            return True
        signal = str(payload.get("signal", "")).lower()
        return "risk" in signal or "withdraw" in signal

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
        signal = str(task_payload.get("signal", "unknown"))
        severity = "high" if "abnormal" in signal else "medium"
        return {
            "decision": "freeze_and_review" if severity == "high" else "manual_review",
            "severity": severity,
            "signal": signal,
            "status": "processed",
        }
