"""Cross Org Alert module for Vertex Swarm Track3."""

from typing import Any, Dict


class CrossOrgAlertPlugin:
    plugin_name = "cross_org_alert"
    supported_task_types = ("alert_sync",)

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
        return bool(payload.get("from_org")) and bool(payload.get("to_org"))

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
        from_org = str(task_payload.get("from_org", ""))
        to_org = str(task_payload.get("to_org", ""))
        alert_id = str(task_payload.get("alert_id", ""))
        return {
            "status": "synced",
            "from_org": from_org,
            "to_org": to_org,
            "alert_id": alert_id,
            "route": f"{from_org}->{to_org}",
        }
