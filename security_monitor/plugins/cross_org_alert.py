from typing import Any, Dict


class CrossOrgAlertPlugin:
    plugin_name = "cross_org_alert"
    supported_task_types = ("alert_sync",)

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        if str(task_type) in self.supported_task_types:
            return True
        return bool(payload.get("from_org")) and bool(payload.get("to_org"))

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
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
