from typing import Any, Dict


class VerificationPlugin:
    plugin_name = "verification"
    supported_task_types = ("verification",)

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        if str(task_type) in self.supported_task_types:
            return True
        return bool(payload.get("mission_id")) and bool(payload.get("mitigation_decision"))

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        decision = str(task_payload.get("mitigation_decision", "")).strip()
        status = str(task_payload.get("mitigation_status", "processed")).strip().lower()
        verified = bool(decision) and status in {"processed", "success", "done"}
        return {
            "status": "processed" if verified else "failed",
            "decision": "verification_passed" if verified else "verification_failed",
            "severity": "high" if not verified else "medium",
            "evidence_hash": str(task_payload.get("evidence_hash", "")).strip(),
            "mitigation_decision": decision,
            "mitigation_status": status,
        }
