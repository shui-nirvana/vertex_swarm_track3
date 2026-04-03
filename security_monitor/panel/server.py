"""Local read-only panel service for mission records."""

import argparse
import html
import json
import os
import random
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from security_monitor.scenarios.business_registry import BUSINESS_TEMPLATE_FILES, DEFAULT_BUSINESS_TYPE
from security_monitor.transports.factory import build_transport


@dataclass
class MissionRecord:
    mission_id: str
    run_id: str
    topic_namespace: str
    record_path: str
    updated_at: float
    payload: dict[str, Any]


def _safe_text(value: Any) -> str:
    return str(value).strip()


def _safe_optional_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in {"none", "null"}:
        return ""
    return text


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    return []


def _collect_record_files(artifacts_dir: str) -> list[str]:
    if not os.path.isdir(artifacts_dir):
        return []
    paths: list[str] = []
    for root, _, files in os.walk(artifacts_dir):
        for name in files:
            if not name.endswith(".json"):
                continue
            candidate = os.path.join(root, name)
            if name.endswith("_mission_record.json") or name == "multiprocess_mission_record.json":
                paths.append(candidate)
    paths.sort(key=lambda item: os.path.getmtime(item), reverse=True)
    return paths


def _business_template_payload(business_type: str) -> dict[str, Any]:
    normalized = _safe_text(business_type).lower() or DEFAULT_BUSINESS_TYPE
    template_name = BUSINESS_TEMPLATE_FILES.get(normalized, BUSINESS_TEMPLATE_FILES[DEFAULT_BUSINESS_TYPE])
    data_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "scenarios", "data"))
    template_path = os.path.join(data_dir, template_name)
    try:
        with open(template_path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (OSError, json.JSONDecodeError):
        loaded = {}
    payload = dict(loaded) if isinstance(loaded, dict) else {}
    payload["business_type"] = normalized
    payload["business_context"] = dict(payload.get("business_context", {}))
    return payload


def _pick_requester_agent(agent_ids: list[str], strategy: str, preferred_agent_id: str) -> str:
    preferred = _safe_text(preferred_agent_id)
    if preferred and preferred in agent_ids:
        return preferred
    if not agent_ids:
        return preferred
    normalized_strategy = _safe_text(strategy).lower()
    if normalized_strategy == "random":
        return random.choice(agent_ids)
    if normalized_strategy == "first":
        return agent_ids[0]
    return agent_ids[0]


def _load_mission_record(path: str) -> MissionRecord | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    mission_id = _safe_text(payload.get("mission_id"))
    run_id = _safe_text(payload.get("run_id"))
    topic_namespace = _safe_text(payload.get("topic_namespace"))
    if not mission_id:
        return None
    try:
        updated_at = float(os.path.getmtime(path))
    except OSError:
        updated_at = 0.0
    return MissionRecord(
        mission_id=mission_id,
        run_id=run_id,
        topic_namespace=topic_namespace,
        record_path=path,
        updated_at=updated_at,
        payload=dict(payload),
    )


def _build_local_agent_view(record: MissionRecord, local_agent_id: str) -> list[dict[str, Any]]:
    local = _safe_text(local_agent_id)
    announcements = list(record.payload.get("agent_announcements", []))
    result: list[dict[str, Any]] = []
    for item in announcements:
        if not isinstance(item, dict):
            continue
        agent_id = _safe_text(item.get("agent_id"))
        if local and agent_id != local:
            continue
        result.append(
            {
                "agent_id": agent_id,
                "roles": list(item.get("roles", [])),
                "timestamp": _safe_text(item.get("timestamp")),
                "metrics": dict(item.get("metrics", {})),
            }
        )
    return result


def _build_swarm_agent_view(record: MissionRecord) -> list[dict[str, Any]]:
    announcements = list(record.payload.get("agent_announcements", []))
    result: list[dict[str, Any]] = []
    for item in announcements:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "agent_id": _safe_text(item.get("agent_id")),
                "roles": list(item.get("roles", [])),
                "timestamp": _safe_text(item.get("timestamp")),
                "active_peer_count": int(item.get("active_peer_count", 0) or 0),
            }
        )
    return result


def _build_layer_status(record: MissionRecord) -> list[dict[str, Any]]:
    payload = _as_dict(record.payload)
    steps = _as_list(payload.get("steps"))
    proof_checks = _as_dict(payload.get("proof_checks"))
    standard_metrics = _as_dict(payload.get("standard_metrics"))
    step_metrics = _as_dict(payload.get("step_metrics"))
    done_flags = [
        bool(payload.get("mission_payload")),
        len(steps) > 0,
        bool(proof_checks),
        bool(step_metrics),
        bool(standard_metrics),
    ]
    layers = ["business", "coordination", "consensus", "runtime", "acceptance"]
    first_not_done = -1
    for index, flag in enumerate(done_flags):
        if not flag:
            first_not_done = index
            break
    result: list[dict[str, Any]] = []
    for index, layer_name in enumerate(layers):
        done = done_flags[index]
        if done:
            state = "done"
        elif first_not_done == index and (index == 0 or done_flags[index - 1]):
            state = "running"
        else:
            state = "pending"
        result.append({"layer": layer_name, "state": state})
    return result


def _current_layer(layers: list[dict[str, Any]]) -> tuple[str, int]:
    for index, item in enumerate(layers):
        state = _safe_text(item.get("state")).lower()
        if state != "done":
            return (_safe_text(item.get("layer")).lower(), index)
    if not layers:
        return ("business", 0)
    return ("completed", len(layers))


def _parse_timestamp_seconds(raw: Any) -> float | None:
    text = _safe_text(raw)
    if not text:
        return None
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        return datetime.fromisoformat(candidate).timestamp()
    except ValueError:
        return None


def _build_stage_status(record: MissionRecord) -> list[dict[str, Any]]:
    payload = _as_dict(record.payload)
    ordered_roles = ["scout", "guardian", "verifier"]
    flow_log = _as_list(payload.get("business_flow_log"))
    role_state: dict[str, str] = {}
    role_started_at: dict[str, float] = {}
    role_finished_at: dict[str, float] = {}
    for item in flow_log:
        if not isinstance(item, dict):
            continue
        role_name = _safe_text(item.get("role_name")).lower()
        state = _safe_text(item.get("state")).lower()
        if not role_name:
            continue
        if state in {"failed", "error"}:
            role_state[role_name] = "failed"
        elif state in {"success", "done", "completed"}:
            role_state[role_name] = "done"
        elif state:
            role_state[role_name] = "running"
        ts = _parse_timestamp_seconds(item.get("timestamp"))
        if ts is not None:
            if role_name not in role_started_at:
                role_started_at[role_name] = ts
            role_finished_at[role_name] = ts
    result: list[dict[str, Any]] = []
    first_open = True
    for role_name in ordered_roles:
        current = role_state.get(role_name, "")
        if current:
            state = current
        elif first_open:
            state = "running"
            first_open = False
        else:
            state = "pending"
        if current in {"done", "failed"}:
            pass
        elif current == "running":
            first_open = False
        started = role_started_at.get(role_name)
        finished = role_finished_at.get(role_name)
        duration_ms = None
        if started is not None and finished is not None and finished >= started:
            duration_ms = int(round((finished - started) * 1000.0))
        result.append({"role_name": role_name, "state": state, "duration_ms": duration_ms})
    return result


def _current_stage(stages: list[dict[str, Any]]) -> str:
    for item in stages:
        state = _safe_text(item.get("state")).lower()
        if state != "done":
            return _safe_text(item.get("role_name")).lower()
    return "completed"


def _build_stage_summary(stages: list[dict[str, Any]]) -> dict[str, Any]:
    duration_map: dict[str, int] = {}
    total = 0
    for item in stages:
        role_name = _safe_text(item.get("role_name")).lower()
        duration = item.get("duration_ms")
        if not role_name:
            continue
        normalized = int(duration) if isinstance(duration, int) and duration > 0 else 0
        duration_map[role_name] = normalized
        total += normalized
    ratio_map: dict[str, float] = {}
    if total > 0:
        for role_name, value in duration_map.items():
            ratio_map[role_name] = round((float(value) / float(total)) * 100.0, 2)
    return {
        "total_duration_ms": total,
        "role_duration_ms": duration_map,
        "role_duration_ratio_pct": ratio_map,
    }


def _build_stage_failure_summary(record: MissionRecord) -> dict[str, Any]:
    flow_log = _as_list(_as_dict(record.payload).get("business_flow_log"))
    for item in reversed(flow_log):
        if not isinstance(item, dict):
            continue
        state = _safe_text(item.get("state")).lower()
        if state not in {"failed", "error"}:
            continue
        role_name = _safe_text(item.get("role_name")).lower()
        result_summary = _as_dict(item.get("result_summary"))
        reason = _safe_text(result_summary.get("reason"))
        if not reason:
            reason = _safe_text(result_summary.get("status"))
        if not reason:
            reason = _safe_text(result_summary.get("decision"))
        if not reason:
            reason = "unknown_error"
        return {
            "failed_stage": role_name or "unknown",
            "reason": reason,
            "failed_step_index": int(item.get("step_index", 0) or 0),
        }
    return {"failed_stage": "", "reason": "", "failed_step_index": 0}


def _agent_current_step_sentence(agent_id: str, handled_steps: list[dict[str, Any]]) -> str:
    if not handled_steps:
        return f"{agent_id} has not received execution steps yet and is waiting for coordination."
    latest = sorted(handled_steps, key=lambda item: int(item.get("step_index", 0) or 0))[-1]
    step_index = int(latest.get("step_index", 0) or 0)
    role_name = _safe_text(latest.get("role_name"))
    task_type = _safe_text(latest.get("task_type"))
    state = _safe_text(latest.get("state")).lower() or "unknown"
    return f"{agent_id} is now at step #{step_index} (role {role_name} / task {task_type}), state={state}."


def _agent_business_flow_sentences(agent_id: str, handled_steps: list[dict[str, Any]]) -> list[str]:
    if not handled_steps:
        return [f"{agent_id} has no business execution records and remains on standby."]
    ordered = sorted(handled_steps, key=lambda item: int(item.get("step_index", 0) or 0))
    lines: list[str] = []
    for step in ordered:
        step_index = int(step.get("step_index", 0) or 0)
        role_name = _safe_text(step.get("role_name"))
        task_type = _safe_text(step.get("task_type"))
        state = _safe_text(step.get("state")).lower() or "unknown"
        lines.append(f"Step #{step_index}: handled {task_type} as {role_name}, result={state}.")
    return lines


def _agent_tashi_primitives(
    agent_id: str,
    assigned_roles: list[str],
    handled_steps: list[dict[str, Any]],
    active_peer_count: int,
    mission_complete: bool,
) -> dict[str, dict[str, str]]:
    discover_state = "done" if active_peer_count > 0 else "running"
    discover_desc = (
        f"{agent_id} discovered {active_peer_count} active peers and joined the temporary swarm."
        if active_peer_count > 0
        else f"{agent_id} is waiting for more peers to complete swarm formation."
    )
    negotiated = len(assigned_roles) > 0
    negotiate_state = "done" if negotiated else ("pending" if mission_complete else "running")
    if negotiated:
        negotiate_desc = f"{agent_id} won roles {', '.join(assigned_roles)} in leaderless negotiation and committed to tasks."
    else:
        negotiate_desc = f"{agent_id} has not won an execution role yet and continues participating in negotiation and voting."
    executed = len(handled_steps) > 0
    execute_state = "done" if executed else ("pending" if mission_complete else "running")
    if executed:
        execute_desc = f"{agent_id} executed {len(handled_steps)} steps and left verifiable traces in records."
    else:
        execute_desc = f"{agent_id} has not executed task steps yet, but will continue receiving and proving later execution."
    return {
        "discover_form": {"state": discover_state, "description": discover_desc},
        "negotiate_commit": {"state": negotiate_state, "description": negotiate_desc},
        "execute_prove": {"state": execute_state, "description": execute_desc},
    }


def _agent_foxmq_messages(agent_id: str, announcement: dict[str, Any], handled_steps: list[dict[str, Any]]) -> dict[str, Any]:
    sent: list[str] = []
    received: list[str] = []
    announcement_message_id = _safe_text(announcement.get("message_id"))
    announcement_timestamp = _safe_text(announcement.get("timestamp"))
    if announcement_message_id:
        sent.append(f"Heartbeat sent: message_id={announcement_message_id} timestamp={announcement_timestamp}")
    for step in sorted(handled_steps, key=lambda item: int(item.get("step_index", 0) or 0)):
        step_index = int(step.get("step_index", 0) or 0)
        task_id = _safe_text(step.get("task_id"))
        message_id = _safe_text(step.get("message_id"))
        role_name = _safe_text(step.get("role_name"))
        state = _safe_text(step.get("state")).lower() or "unknown"
        received.append(f"Task received: step#{step_index} role={role_name} task_id={task_id}")
        if message_id:
            sent.append(f"Result sent: step#{step_index} state={state} message_id={message_id}")
    return {
        "sent_count": len(sent),
        "received_count": len(received),
        "sent": sent[-6:],
        "received": received[-6:],
        "summary": f"{agent_id} sent {len(sent)} and received {len(received)} key messages via FoxMQ.",
    }


def _build_agent_panels(record: MissionRecord, local_agent_id: str) -> list[dict[str, Any]]:
    payload = _as_dict(record.payload)
    announcements = [item for item in _as_list(payload.get("agent_announcements")) if isinstance(item, dict)]
    flow_log = [item for item in _as_list(payload.get("business_flow_log")) if isinstance(item, dict)]
    role_assignments = _as_dict(payload.get("role_identity_assignments"))
    proof_checks = _as_dict(payload.get("proof_checks"))
    agent_ids = sorted({_safe_text(item.get("agent_id")) for item in announcements if _safe_text(item.get("agent_id"))})
    local_filter = _safe_text(local_agent_id)
    overview = _build_overview(record)
    failed_stage = _safe_text(dict(overview.get("stage_failure", {})).get("failed_stage")).lower()
    current_stage = _safe_text(overview.get("current_stage")).lower()
    role_assignment_summary: dict[str, str] = {}
    for role_name, value in role_assignments.items():
        role_assignment_summary[_safe_text(role_name)] = _safe_text(_as_dict(value).get("assigned_agent"))
    assigned_roles_by_agent: dict[str, set[str]] = {}
    for role_name, assigned_agent in role_assignment_summary.items():
        role_key = _safe_text(role_name).lower()
        agent_key = _safe_text(assigned_agent)
        if not role_key or not agent_key:
            continue
        if agent_key not in assigned_roles_by_agent:
            assigned_roles_by_agent[agent_key] = set()
        assigned_roles_by_agent[agent_key].add(role_key)
    result: list[dict[str, Any]] = []
    for agent_id in agent_ids:
        if local_filter and agent_id != local_filter:
            continue
        announcement = {}
        for item in announcements:
            if _safe_text(item.get("agent_id")) == agent_id:
                announcement = dict(item)
                break
        handled_steps = []
        has_failed_step = False
        for item in flow_log:
            if _safe_text(item.get("selected_agent")) == agent_id:
                step_state = _safe_text(item.get("state"))
                if step_state.strip().lower() in {"failed", "error"}:
                    has_failed_step = True
                handled_steps.append(
                    {
                        "step_index": int(item.get("step_index", 0) or 0),
                        "role_name": _safe_text(item.get("role_name")),
                        "task_type": _safe_text(item.get("task_type")),
                        "state": step_state,
                        "task_id": _safe_text(item.get("task_id")),
                        "message_id": _safe_text(item.get("message_id")),
                        "timestamp": _safe_text(item.get("timestamp")),
                        "task_payload": _as_dict(item.get("task_payload")),
                        "result_summary": _as_dict(item.get("result_summary")),
                    }
                )
        assigned_roles = sorted(assigned_roles_by_agent.get(agent_id, set()))
        active_peer_count = _safe_int(announcement.get("active_peer_count"), 0)
        mission_complete = bool(payload.get("mission_complete"))
        related_to_current_stage = bool(current_stage and current_stage in assigned_roles)
        abnormal = bool(
            has_failed_step
            or (failed_stage and failed_stage in assigned_roles)
        )
        current_step_sentence = _agent_current_step_sentence(agent_id, handled_steps)
        business_flow_sentences = _agent_business_flow_sentences(agent_id, handled_steps)
        tashi_primitives = _agent_tashi_primitives(
            agent_id=agent_id,
            assigned_roles=assigned_roles,
            handled_steps=handled_steps,
            active_peer_count=active_peer_count,
            mission_complete=mission_complete,
        )
        foxmq_messages = _agent_foxmq_messages(agent_id, announcement, handled_steps)
        result.append(
            {
                "agent_id": agent_id,
                "is_abnormal": abnormal,
                "related_to_current_stage": related_to_current_stage,
                "current_step_sentence": current_step_sentence,
                "business_flow_sentences": business_flow_sentences,
                "tashi_primitives": tashi_primitives,
                "foxmq_messages": foxmq_messages,
                "local_view": {
                    "agent_id": agent_id,
                    "roles": list(announcement.get("roles", [])),
                    "announcement_timestamp": _safe_text(announcement.get("timestamp")),
                    "handled_steps": handled_steps,
                    "handled_step_count": len(handled_steps),
                },
                "swarm_shared_view": {
                    "peer_count": len(agent_ids),
                    "role_assignments": role_assignment_summary,
                    "assigned_roles": assigned_roles,
                    "proof_checks": proof_checks,
                    "current_layer": _safe_text(overview.get("current_layer")),
                    "current_stage": _safe_text(overview.get("current_stage")),
                    "mission_complete": bool(payload.get("mission_complete")),
                    "all_success": bool(payload.get("all_success")),
                },
            }
        )
    return result


def _build_overview(record: MissionRecord) -> dict[str, Any]:
    payload = _as_dict(record.payload)
    mission_payload = _as_dict(payload.get("mission_payload"))
    layers = _build_layer_status(record)
    current_layer, current_layer_index = _current_layer(layers)
    stages = _build_stage_status(record)
    stage_summary = _build_stage_summary(stages)
    stage_failure = _build_stage_failure_summary(record)
    return {
        "mission_id": record.mission_id,
        "run_id": record.run_id,
        "topic_namespace": record.topic_namespace,
        "business_type": _safe_text(mission_payload.get("business_type") or mission_payload.get("business_context", {}).get("business_type")),
        "business_context": _as_dict(mission_payload.get("business_context")),
        "layers": layers,
        "stages": stages,
        "current_layer": current_layer,
        "current_layer_index": current_layer_index,
        "current_stage": _current_stage(stages),
        "stage_summary": stage_summary,
        "stage_failure": stage_failure,
        "all_success": bool(payload.get("all_success")),
        "mission_complete": bool(payload.get("mission_complete")),
        "step_count": len(list(payload.get("steps", []))),
        "updated_at": record.updated_at,
    }


def _build_timeline(record: MissionRecord, limit: int = 200, offset: int = 0) -> dict[str, Any]:
    entries = _as_list(_as_dict(record.payload).get("business_flow_log"))
    normalized_limit = max(1, min(500, _safe_int(limit, 200)))
    normalized_offset = max(0, _safe_int(offset, 0))
    sliced = entries[normalized_offset : normalized_offset + normalized_limit]
    timeline_rows: list[dict[str, Any]] = []
    for item in sliced:
        if not isinstance(item, dict):
            continue
        timeline_rows.append(
            {
                "step_index": int(item.get("step_index", 0) or 0),
                "role_name": _safe_text(item.get("role_name")),
                "task_type": _safe_text(item.get("task_type")),
                "selected_agent": _safe_text(item.get("selected_agent")),
                "state": _safe_text(item.get("state")),
                "task_payload": _as_dict(item.get("task_payload")),
                "result_summary": _as_dict(item.get("result_summary")),
                "timestamp": _safe_text(item.get("timestamp")),
            }
        )
    total = len(entries)
    return {
        "timeline": timeline_rows,
        "total": total,
        "offset": normalized_offset,
        "limit": normalized_limit,
        "truncated": normalized_offset + len(timeline_rows) < total,
    }


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


class PanelState:
    def __init__(self, artifacts_dir: str, local_agent_id: str):
        self.artifacts_dir = artifacts_dir
        self.local_agent_id = local_agent_id
        self._lock = threading.Lock()
        self._records: dict[str, MissionRecord] = {}
        self._records_by_run: dict[str, list[str]] = {}
        self._runtime_events_by_run: dict[str, list[dict[str, Any]]] = {}
        self._runtime_event_seq_by_run: dict[str, int] = {}
        self._runtime_listener_by_run: dict[str, Any] = {}
        self._runtime_seen_agents_by_run: dict[str, set[str]] = {}
        self._runtime_handshake_success_by_run: dict[str, bool] = {}
        self._runtime_heartbeat_count_by_run_agent: dict[str, dict[str, int]] = {}
        self._runtime_heartbeat_emit_at_by_run_agent: dict[str, dict[str, float]] = {}
        self._runtime_subscribed_topics_by_run: dict[str, set[str]] = {}
        self._preferred_run_id: str = ""
        self._preferred_topic_namespace: str = ""
        self.refresh()

    def set_preferred_run_context(self, run_id: str, topic_namespace: str) -> None:
        preferred_run = _safe_optional_text(run_id)
        preferred_namespace = _safe_optional_text(topic_namespace)
        with self._lock:
            self._preferred_run_id = preferred_run
            self._preferred_topic_namespace = preferred_namespace

    def _inject_placeholder_mission_locked(self, records: dict[str, MissionRecord], records_by_run: dict[str, list[str]]) -> None:
        preferred_run = _safe_optional_text(self._preferred_run_id)
        if not preferred_run:
            return
        existing = list(records_by_run.get(preferred_run, []))
        if existing:
            return
        placeholder_mission_id = f"mission-{preferred_run}"
        records[placeholder_mission_id] = MissionRecord(
            mission_id=placeholder_mission_id,
            run_id=preferred_run,
            topic_namespace=_safe_optional_text(self._preferred_topic_namespace),
            record_path="",
            updated_at=time.time(),
            payload={},
        )
        records_by_run[preferred_run] = [placeholder_mission_id]

    def refresh(self) -> None:
        new_records: dict[str, MissionRecord] = {}
        new_by_run: dict[str, list[str]] = {}
        for path in _collect_record_files(self.artifacts_dir):
            record = _load_mission_record(path)
            if record is None:
                continue
            new_records[record.mission_id] = record
            run_key = record.run_id or "unknown"
            if run_key not in new_by_run:
                new_by_run[run_key] = []
            new_by_run[run_key].append(record.mission_id)
        with self._lock:
            self._inject_placeholder_mission_locked(new_records, new_by_run)
            self._records = new_records
            self._records_by_run = new_by_run

    def runs(self) -> list[dict[str, Any]]:
        with self._lock:
            result = []
            for run_id, mission_ids in sorted(self._records_by_run.items()):
                result.append({"run_id": run_id, "mission_ids": list(mission_ids)})
            return result

    def mission(self, mission_id: str) -> MissionRecord | None:
        with self._lock:
            return self._records.get(mission_id)

    def latest_mission_id(self) -> str:
        with self._lock:
            if not self._records:
                return ""
            preferred_run = _safe_optional_text(self._preferred_run_id)
            if preferred_run:
                preferred_ids = list(self._records_by_run.get(preferred_run, []))
                if preferred_ids:
                    preferred_records = [self._records[mid] for mid in preferred_ids if mid in self._records]
                    if preferred_records:
                        ordered = sorted(preferred_records, key=lambda item: item.updated_at, reverse=True)
                        return ordered[0].mission_id
            ordered = sorted(self._records.values(), key=lambda item: item.updated_at, reverse=True)
            return ordered[0].mission_id

    def append_runtime_event(self, run_id: str, event: dict[str, Any]) -> None:
        run_key = _safe_text(run_id) or "unknown"
        with self._lock:
            if run_key not in self._runtime_events_by_run:
                self._runtime_events_by_run[run_key] = []
            event_seq = int(self._runtime_event_seq_by_run.get(run_key, 0)) + 1
            self._runtime_event_seq_by_run[run_key] = event_seq
            event_record = dict(event)
            event_record["event_order"] = event_seq
            self._runtime_events_by_run[run_key].append(event_record)
            self._runtime_events_by_run[run_key] = self._runtime_events_by_run[run_key][-500:]

    def runtime_events_for_run(self, run_id: str) -> list[dict[str, Any]]:
        run_key = _safe_text(run_id) or "unknown"
        with self._lock:
            return list(self._runtime_events_by_run.get(run_key, []))

    def runtime_events_since(self, run_id: str, since_event_order: int) -> list[dict[str, Any]]:
        run_key = _safe_text(run_id) or "unknown"
        normalized_since = max(0, int(since_event_order))
        with self._lock:
            events = list(self._runtime_events_by_run.get(run_key, []))
        return [item for item in events if _safe_int(item.get("event_order"), 0) > normalized_since]

    def active_agents_for_run(self, run_id: str) -> list[str]:
        run_key = _safe_text(run_id) or "unknown"
        with self._lock:
            active = sorted(self._runtime_seen_agents_by_run.get(run_key, set()))
        return [agent for agent in active if agent and agent.lower() not in {"none", "null", "undefined"}]

    def reset_runtime_for_run(self, run_id: str, reset_seen_agents: bool = False) -> None:
        run_key = _safe_text(run_id) or "unknown"
        with self._lock:
            self._runtime_events_by_run[run_key] = []
            self._runtime_event_seq_by_run[run_key] = 0
            self._runtime_handshake_success_by_run[run_key] = False
            self._runtime_heartbeat_count_by_run_agent[run_key] = {}
            self._runtime_heartbeat_emit_at_by_run_agent[run_key] = {}
            if reset_seen_agents:
                self._runtime_seen_agents_by_run[run_key] = set()

    def ensure_runtime_listener(self, run_id: str, topic_namespace: str, mqtt_addr: str) -> None:
        run_key = _safe_text(run_id) or "unknown"
        namespace = _safe_text(topic_namespace)
        if not namespace:
            return
        with self._lock:
            if run_key in self._runtime_listener_by_run:
                return
        topic_root = f"coordination/{namespace}"
        transport = build_transport(node_id=f"panel-runtime-listener-{run_key}", backend="mqtt", mqtt_addr=mqtt_addr)
        try:
            transport.connect()
            with self._lock:
                self._runtime_listener_by_run[run_key] = transport
        except Exception:
            try:
                transport.close()
            except Exception:
                pass
            return

        def _append(event: dict[str, Any]) -> None:
            self.append_runtime_event(run_id=run_key, event=event)

        def _try_emit_handshake_success() -> None:
            with self._lock:
                if self._runtime_handshake_success_by_run.get(run_key):
                    return
                seen = set(self._runtime_seen_agents_by_run.get(run_key, set()))
                if len(seen) < 3:
                    return
                self._runtime_handshake_success_by_run[run_key] = True
            _append(
                {
                    "kind": "handshake_success",
                    "state": "done",
                    "run_id": run_key,
                    "mission_id": "",
                    "agent_id": "",
                    "summary": f"Handshake success: collaboration set formed with {len(seen)} online nodes.",
                    "topic": f"{topic_root}/agents/announcements",
                    "message_id": "",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

        def _topic_ts(message: dict[str, Any]) -> str:
            return _safe_text(message.get("timestamp")) or datetime.utcnow().isoformat()

        def _on_mission_start(message: dict[str, Any]) -> None:
            _append(
                {
                    "kind": "mission_start",
                    "state": "running",
                    "run_id": run_key,
                    "mission_id": _safe_optional_text(message.get("mission_id")),
                    "agent_id": _safe_optional_text(message.get("requester_agent_id")) or _safe_optional_text(message.get("_sender")),
                    "business_type": _safe_optional_text(message.get("business_type")),
                    "summary": "Coordination layer received mission start and entered negotiation phase.",
                    "topic": f"{topic_root}/missions/start",
                    "message_id": _safe_text(message.get("message_id")),
                    "timestamp": _topic_ts(message),
                }
            )

        def _on_mission_stage(message: dict[str, Any]) -> None:
            role_name = _safe_optional_text(message.get("role_name"))
            state = _safe_text(message.get("state")).lower() or "running"
            selected_agent = _safe_optional_text(message.get("selected_agent"))
            task_type = _safe_optional_text(message.get("task_type"))
            task_id = _safe_optional_text(message.get("task_id"))
            result_payload = _as_dict(message.get("result"))
            decision = _safe_optional_text(result_payload.get("decision")) or _safe_optional_text(message.get("decision"))
            severity = _safe_optional_text(result_payload.get("severity")) or _safe_optional_text(message.get("severity"))
            result_status = _safe_optional_text(result_payload.get("status")) or _safe_optional_text(message.get("status"))
            source_confidence_level = _safe_optional_text(result_payload.get("source_confidence_level"))
            conflict_detected = bool(result_payload.get("conflict_detected"))
            resolved_claim = _safe_optional_text(result_payload.get("resolved_claim"))
            kill_chain_stage = _safe_optional_text(result_payload.get("kill_chain_stage"))
            attack_tactics = ",".join(str(item).strip() for item in result_payload.get("attack_tactics", []) if str(item).strip())
            attack_techniques = ",".join(
                str(item).strip() for item in result_payload.get("attack_techniques", []) if str(item).strip()
            )
            playbook_id = _safe_optional_text(result_payload.get("playbook_id"))
            rollback_required = bool(result_payload.get("rollback_required"))
            rollback_reason = _safe_optional_text(result_payload.get("rollback_reason"))
            monitoring_window_minutes = _safe_optional_text(result_payload.get("monitoring_window_minutes"))
            residual_risk = _safe_optional_text(result_payload.get("residual_risk"))
            residual_risk_threshold = _safe_optional_text(result_payload.get("residual_risk_threshold"))
            secondary_verify_triggered = bool(result_payload.get("secondary_verify_triggered"))
            monitoring_decision = _safe_optional_text(result_payload.get("monitoring_decision"))
            detail_parts = [f"{role_name or 'unknown'} executed by {selected_agent or 'unassigned'}", f"state {state}"]
            if task_type:
                detail_parts.append(f"task {task_type}")
            if task_id:
                detail_parts.append(f"task_id={task_id}")
            if decision:
                detail_parts.append(f"decision={decision}")
            if severity:
                detail_parts.append(f"severity={severity}")
            _append(
                {
                    "kind": "mission_stage",
                    "state": state,
                    "run_id": run_key,
                    "mission_id": _safe_optional_text(message.get("mission_id")),
                    "agent_id": selected_agent,
                    "role_name": role_name,
                    "task_type": task_type,
                    "task_id": task_id,
                    "decision": decision,
                    "severity": severity,
                    "result_status": result_status,
                    "source_confidence_level": source_confidence_level,
                    "conflict_detected": conflict_detected,
                    "resolved_claim": resolved_claim,
                    "kill_chain_stage": kill_chain_stage,
                    "attack_tactics": attack_tactics,
                    "attack_techniques": attack_techniques,
                    "playbook_id": playbook_id,
                    "rollback_required": rollback_required,
                    "rollback_reason": rollback_reason,
                    "monitoring_window_minutes": monitoring_window_minutes,
                    "residual_risk": residual_risk,
                    "residual_risk_threshold": residual_risk_threshold,
                    "secondary_verify_triggered": secondary_verify_triggered,
                    "monitoring_decision": monitoring_decision,
                    "summary": f"Stage progress: {', '.join(detail_parts)}.",
                    "topic": f"{topic_root}/missions/stage",
                    "message_id": _safe_text(message.get("message_id")),
                    "timestamp": _topic_ts(message),
                }
            )

        def _on_mission_complete(message: dict[str, Any]) -> None:
            ok = bool(message.get("all_success"))
            _append(
                {
                    "kind": "mission_complete",
                    "state": "done" if ok else "failed",
                    "run_id": run_key,
                    "mission_id": _safe_text(message.get("mission_id")),
                    "agent_id": _safe_optional_text(message.get("_sender")),
                    "summary": f"Mission complete: {'success' if ok else 'failed steps exist'}.",
                    "topic": f"{topic_root}/missions/complete",
                    "message_id": _safe_text(message.get("message_id")),
                    "timestamp": _topic_ts(message),
                }
            )

        def _on_agent_announcement(message: dict[str, Any]) -> None:
            agent_id = _safe_optional_text(message.get("agent_id"))
            if not agent_id:
                return
            normalized_agent_id = agent_id[:-10] if agent_id.endswith("-bootstrap") else agent_id
            with self._lock:
                if run_key not in self._runtime_seen_agents_by_run:
                    self._runtime_seen_agents_by_run[run_key] = set()
                if normalized_agent_id in self._runtime_seen_agents_by_run[run_key]:
                    return
                self._runtime_seen_agents_by_run[run_key].add(normalized_agent_id)
            _append(
                {
                    "kind": "agent_online",
                    "state": "running",
                    "run_id": run_key,
                    "mission_id": _safe_text(message.get("mission_id")),
                    "agent_id": normalized_agent_id,
                    "summary": f"Agent online: {normalized_agent_id} joined the cluster.",
                    "topic": f"{topic_root}/agents/announcements",
                    "message_id": _safe_text(message.get("message_id")),
                    "timestamp": _topic_ts(message),
                }
            )
            _try_emit_handshake_success()
            _subscribe_agent_runtime_topics(normalized_agent_id)

        def _on_agent_heartbeat(message: dict[str, Any]) -> None:
            agent_id = _safe_optional_text(message.get("agent_id")) or _safe_optional_text(message.get("_sender"))
            if not agent_id:
                return
            normalized_agent_id = agent_id[:-10] if agent_id.endswith("-bootstrap") else agent_id
            should_emit = False
            heartbeat_count = 0
            with self._lock:
                if run_key not in self._runtime_heartbeat_count_by_run_agent:
                    self._runtime_heartbeat_count_by_run_agent[run_key] = {}
                if run_key not in self._runtime_heartbeat_emit_at_by_run_agent:
                    self._runtime_heartbeat_emit_at_by_run_agent[run_key] = {}
                count_map = self._runtime_heartbeat_count_by_run_agent[run_key]
                emit_map = self._runtime_heartbeat_emit_at_by_run_agent[run_key]
                if bool(self._runtime_handshake_success_by_run.get(run_key, False)):
                    return
                heartbeat_count = int(count_map.get(normalized_agent_id, 0)) + 1
                count_map[normalized_agent_id] = heartbeat_count
                now_ts = time.time()
                last_emit = float(emit_map.get(normalized_agent_id, 0.0))
                if heartbeat_count == 1 or heartbeat_count % 5 == 0 or now_ts - last_emit >= 3.0:
                    emit_map[normalized_agent_id] = now_ts
                    should_emit = True
            if not should_emit:
                return
            _append(
                {
                    "kind": "handshake_heartbeat",
                    "state": "running",
                    "run_id": run_key,
                    "mission_id": _safe_text(message.get("mission_id")),
                    "agent_id": normalized_agent_id,
                    "summary": f"Handshake heartbeat sample: {normalized_agent_id} online, total {heartbeat_count}.",
                    "topic": f"{topic_root}/agents/heartbeats",
                    "message_id": _safe_text(message.get("message_id")),
                    "timestamp": _topic_ts(message),
                }
            )

        def _on_role_intent(message: dict[str, Any]) -> None:
            role_name = _safe_optional_text(message.get("role_name")) or _safe_optional_text(message.get("role"))
            agent_id = _safe_optional_text(message.get("agent_id")) or _safe_optional_text(message.get("_sender"))
            _append(
                {
                    "kind": "tashi_intent",
                    "state": "running",
                    "run_id": run_key,
                    "mission_id": _safe_text(message.get("mission_id")),
                    "agent_id": agent_id,
                    "role_name": role_name,
                    "task_type": _safe_optional_text(message.get("task_type")),
                    "task_id": _safe_optional_text(message.get("task_id")),
                    "summary": f"{agent_id or 'unknown'} submitted intent for {role_name}.",
                    "topic": f"{topic_root}/roles/{role_name}/intent",
                    "message_id": _safe_text(message.get("message_id")),
                    "timestamp": _topic_ts(message),
                }
            )

        def _on_role_claim(message: dict[str, Any]) -> None:
            role_name = _safe_optional_text(message.get("role_name")) or _safe_optional_text(message.get("role"))
            agent_id = _safe_optional_text(message.get("agent_id")) or _safe_optional_text(message.get("_sender"))
            _append(
                {
                    "kind": "tashi_claim",
                    "state": "running",
                    "run_id": run_key,
                    "mission_id": _safe_text(message.get("mission_id")),
                    "agent_id": agent_id,
                    "role_name": role_name,
                    "score": message.get("score"),
                    "load": message.get("load"),
                    "summary": f"{agent_id or 'unknown'} claimed responsibility for {role_name}.",
                    "topic": f"{topic_root}/roles/{role_name}/claim",
                    "message_id": _safe_text(message.get("message_id")),
                    "timestamp": _topic_ts(message),
                }
            )

        def _on_task_routed(message: dict[str, Any]) -> None:
            target_agent = (
                _safe_optional_text(message.get("target_agent"))
                or _safe_optional_text(message.get("selected_agent"))
                or _safe_optional_text(message.get("_receiver"))
                or _safe_optional_text(message.get("agent_id"))
            )
            task_type = _safe_text(message.get("task_type"))
            task_id = _safe_optional_text(message.get("task_id"))
            mission_id = _safe_text(message.get("mission_id"))
            detail = f"FoxMQ: task {task_type or 'unknown'}"
            if task_id:
                detail += f"({task_id})"
            detail += f" routed to {target_agent or 'unknown'}."
            _append(
                {
                    "kind": "foxmq_message",
                    "state": "running",
                    "run_id": run_key,
                    "mission_id": mission_id,
                    "agent_id": target_agent,
                    "task_type": task_type,
                    "task_id": task_id,
                    "summary": detail,
                    "topic": f"{topic_root}/tasks/+",
                    "message_id": _safe_text(message.get("message_id")),
                    "timestamp": _topic_ts(message),
                }
            )

        def _on_task_result(message: dict[str, Any]) -> None:
            sender = (
                _safe_optional_text(message.get("_sender"))
                or _safe_optional_text(message.get("agent_id"))
                or _safe_optional_text(message.get("target_agent"))
                or _safe_optional_text(message.get("selected_agent"))
            )
            state = _safe_text(message.get("state")).lower() or "running"
            task_id = _safe_optional_text(message.get("task_id"))
            task_type = _safe_optional_text(message.get("task_type"))
            result_payload = _as_dict(message.get("result"))
            decision = _safe_optional_text(result_payload.get("decision")) or _safe_optional_text(message.get("decision"))
            severity = _safe_optional_text(result_payload.get("severity")) or _safe_optional_text(message.get("severity"))
            result_status = _safe_optional_text(result_payload.get("status")) or _safe_optional_text(message.get("status"))
            detail = f"FoxMQ: {sender or 'unknown'} returned task result, state {state}"
            if task_type:
                detail += f", task {task_type}"
            if task_id:
                detail += f"，task_id={task_id}"
            if decision:
                detail += f"，decision={decision}"
            if severity:
                detail += f"，severity={severity}"
            detail += "。"
            _append(
                {
                    "kind": "foxmq_message",
                    "state": state,
                    "run_id": run_key,
                    "mission_id": _safe_text(message.get("mission_id")),
                    "agent_id": sender,
                    "task_type": task_type,
                    "task_id": task_id,
                    "decision": decision,
                    "severity": severity,
                    "result_status": result_status,
                    "summary": detail,
                    "topic": f"{topic_root}/results/+",
                    "message_id": _safe_text(message.get("message_id")),
                    "timestamp": _topic_ts(message),
                }
            )

        def _safe_subscribe(topic: str, callback: Any) -> None:
            with self._lock:
                if run_key not in self._runtime_subscribed_topics_by_run:
                    self._runtime_subscribed_topics_by_run[run_key] = set()
                if topic in self._runtime_subscribed_topics_by_run[run_key]:
                    return
            try:
                transport.subscribe(topic, callback)
                with self._lock:
                    self._runtime_subscribed_topics_by_run[run_key].add(topic)
            except Exception:
                return

        def _subscribe_agent_runtime_topics(agent_id: str) -> None:
            normalized_agent_id = _safe_optional_text(agent_id)
            if not normalized_agent_id:
                return
            task_topic = f"{topic_root}/tasks/{normalized_agent_id}"
            response_topic = f"{topic_root}/responses/{normalized_agent_id}"

            def _on_agent_task(message: dict[str, Any]) -> None:
                enriched = dict(message)
                enriched["target_agent"] = normalized_agent_id
                _on_task_routed(enriched)

            _safe_subscribe(task_topic, _on_agent_task)
            _safe_subscribe(response_topic, _on_task_result)

        _safe_subscribe(f"{topic_root}/missions/start", _on_mission_start)
        _safe_subscribe(f"{topic_root}/missions/stage", _on_mission_stage)
        _safe_subscribe(f"{topic_root}/missions/complete", _on_mission_complete)
        _safe_subscribe(f"{topic_root}/agents/announcements", _on_agent_announcement)
        _safe_subscribe(f"{topic_root}/agents/heartbeats", _on_agent_heartbeat)
        _safe_subscribe(f"{topic_root}/roles/scout/intent", _on_role_intent)
        _safe_subscribe(f"{topic_root}/roles/guardian/intent", _on_role_intent)
        _safe_subscribe(f"{topic_root}/roles/verifier/intent", _on_role_intent)
        _safe_subscribe(f"{topic_root}/roles/scout/claim", _on_role_claim)
        _safe_subscribe(f"{topic_root}/roles/guardian/claim", _on_role_claim)
        _safe_subscribe(f"{topic_root}/roles/verifier/claim", _on_role_claim)
        _safe_subscribe(f"{topic_root}/results", _on_task_result)
        _safe_subscribe(f"{topic_root}/tasks/+", _on_task_routed)
        _safe_subscribe(f"{topic_root}/results/+", _on_task_result)


class PanelRequestHandler(BaseHTTPRequestHandler):
    state: PanelState

    def _write_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = _json_bytes(payload)
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK.value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        raw_len = _safe_int(self.headers.get("Content-Length"), 0)
        body = self.rfile.read(raw_len) if raw_len > 0 else b""
        if not body:
            return {}
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        self.state.refresh()
        if path == "/":
            initial_cards = _initial_agent_columns_html(self.state)
            self._write_html(_panel_html(initial_cards))
            return
        if path == "/api/runs":
            self._write_json({"runs": self.state.runs()})
            return
        if path == "/api/latest":
            self._write_json({"mission_id": self.state.latest_mission_id()})
            return
        if path.startswith("/api/missions/"):
            self._serve_mission_api(path=path, query=query)
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/missions/") and path.endswith("/trigger-business"):
            self._serve_trigger_business(path=path, payload=self._read_json_body())
            return
        if path.startswith("/api/missions/") and path.endswith("/handshake-refresh"):
            self._serve_handshake_refresh(path=path, payload=self._read_json_body())
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def _serve_handshake_refresh(self, path: str, payload: dict[str, Any]) -> None:
        parts = [item for item in path.split("/") if item]
        if len(parts) < 4:
            self._write_json({"error": "bad request"}, status=HTTPStatus.BAD_REQUEST)
            return
        mission_id = parts[2]
        record = self.state.mission(mission_id)
        if record is None:
            self._write_json({"error": "mission not found"}, status=HTTPStatus.NOT_FOUND)
            return
        run_id = _safe_optional_text(payload.get("run_id")) or _safe_optional_text(record.run_id) or "unknown"
        topic_namespace = _safe_text(record.topic_namespace)
        mqtt_addr = _safe_optional_text(os.getenv("FOXMQ_MQTT_ADDR")) or "127.0.0.1:1883"
        self.state.ensure_runtime_listener(run_id=run_id, topic_namespace=topic_namespace, mqtt_addr=mqtt_addr)
        self.state.reset_runtime_for_run(run_id=run_id, reset_seen_agents=True)
        self.state.append_runtime_event(
            run_id=run_id,
            event={
                "kind": "handshake_refresh",
                "state": "running",
                "run_id": run_id,
                "mission_id": mission_id,
                "agent_id": "",
                "summary": "Handshake refresh triggered, waiting for agents to re-announce online status.",
                "topic": f"coordination/{topic_namespace}/agents/announcements",
                "message_id": "",
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
        self._write_json({"ok": True, "run_id": run_id, "mission_id": mission_id})

    def _serve_trigger_business(self, path: str, payload: dict[str, Any]) -> None:
        parts = [item for item in path.split("/") if item]
        if len(parts) < 4:
            self._write_json({"error": "bad request"}, status=HTTPStatus.BAD_REQUEST)
            return
        mission_id = parts[2]
        record = self.state.mission(mission_id)
        if record is None:
            self._write_json({"error": "mission not found"}, status=HTTPStatus.NOT_FOUND)
            return
        topic_namespace = _safe_text(record.topic_namespace)
        if not topic_namespace:
            self._write_json({"error": "topic namespace not found"}, status=HTTPStatus.BAD_REQUEST)
            return
        run_id = _safe_optional_text(payload.get("run_id")) or _safe_optional_text(record.run_id)
        if not run_id:
            run_id = f"run-{uuid4().hex[:10]}"
        mqtt_addr = (
            _safe_optional_text(payload.get("foxmq_mqtt_addr"))
            or _safe_optional_text(os.getenv("FOXMQ_MQTT_ADDR"))
            or "127.0.0.1:1883"
        )
        self.state.ensure_runtime_listener(run_id=run_id, topic_namespace=topic_namespace, mqtt_addr=mqtt_addr)
        active_agents = self.state.active_agents_for_run(run_id)
        local_agent = _safe_text(self.state.local_agent_id)
        candidate_agents = [local_agent] if local_agent and local_agent in active_agents else list(active_agents)
        preferred_agent_id = _safe_optional_text(payload.get("requester_agent_id"))
        if preferred_agent_id.lower() in {"none", "null", "undefined"}:
            preferred_agent_id = ""
        requester_agent = _pick_requester_agent(
            agent_ids=candidate_agents,
            strategy=_safe_text(payload.get("selection_strategy") or "random"),
            preferred_agent_id=preferred_agent_id,
        )
        if _safe_optional_text(requester_agent).lower() in {"none", "null", "undefined"}:
            requester_agent = ""
        if not requester_agent:
            self._write_json({"error": "no available agent to trigger business"}, status=HTTPStatus.BAD_REQUEST)
            return
        business_type = _safe_optional_text(payload.get("business_type")).lower() or DEFAULT_BUSINESS_TYPE
        mission_payload = _business_template_payload(business_type)
        context_override = payload.get("business_context")
        if isinstance(context_override, dict):
            mission_payload["business_context"].update(dict(context_override))
        mission_start_payload = {
            "mission_id": f"mission-{uuid4().hex[:12]}",
            "run_id": run_id,
            "namespace": topic_namespace,
            "scout_signal": _safe_text(mission_payload.get("scout_signal") or "abnormal_withdraw"),
            "evidence_hash": _safe_text(mission_payload.get("evidence_hash") or f"proof-chain-{uuid4().hex[:8]}"),
            "business_type": business_type,
            "business_context": dict(mission_payload.get("business_context", {})),
            "pre_guardian_delay_seconds": _safe_float(payload.get("pre_guardian_delay_seconds"), 0.0),
            "role_identity_negotiation": True,
            "timestamp": datetime.utcnow().isoformat(),
            "requester_agent_id": requester_agent,
        }
        topic = f"coordination/{topic_namespace}/missions/start"
        self.state.append_runtime_event(
            run_id=run_id,
            event={
                "kind": "business_begin",
                "state": "running",
                "run_id": run_id,
                "mission_id": mission_start_payload["mission_id"],
                "agent_id": requester_agent,
                "business_type": business_type,
                "summary": f"Running business {business_type}, mission start has been sent.",
                "topic": topic,
                "message_id": "",
                "timestamp": mission_start_payload["timestamp"],
                "scenario": _safe_optional_text(dict(mission_payload.get("business_context", {})).get("scenario")),
                "ioc_count": _safe_int(dict(mission_payload.get("business_context", {})).get("ioc_count"), 0),
                "affected_nodes": _safe_int(dict(mission_payload.get("business_context", {})).get("affected_nodes"), 0),
                "intel_sources": list(dict(mission_payload.get("business_context", {})).get("intel_sources", [])),
                "attack_hints": list(dict(mission_payload.get("business_context", {})).get("attack_hints", [])),
                "assessment_resource_units": _safe_int(
                    dict(mission_payload.get("business_context", {})).get("assessment_resource_units"), 1
                ),
                "assessment_budget_ceiling": _safe_float(
                    dict(mission_payload.get("business_context", {})).get("assessment_budget_ceiling"), 18.0
                ),
            },
        )
        transport = build_transport(
            node_id=f"panel-trigger-{requester_agent}",
            backend="mqtt",
            mqtt_addr=mqtt_addr,
        )
        try:
            transport.connect()
            message_id = transport.publish(topic, mission_start_payload)
        except Exception as exc:
            self._write_json({"error": f"trigger failed: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        finally:
            try:
                transport.close()
            except Exception:
                pass
        self._write_json(
            {
                "ok": True,
                "message_id": message_id,
                "topic": topic,
                "requester_agent_id": requester_agent,
                "mission_id": mission_start_payload["mission_id"],
                "business_type": business_type,
            }
        )
        self.state.append_runtime_event(
            run_id=run_id,
            event={
                "kind": "trigger_sent",
                "state": "running",
                "run_id": run_id,
                "mission_id": mission_start_payload["mission_id"],
                "agent_id": requester_agent,
                "business_type": business_type,
                "message_id": message_id,
                "topic": topic,
                "summary": f"Business {business_type} triggered, start request sent by {requester_agent}.",
                "timestamp": mission_start_payload["timestamp"],
                "scenario": _safe_optional_text(dict(mission_payload.get("business_context", {})).get("scenario")),
                "ioc_count": _safe_int(dict(mission_payload.get("business_context", {})).get("ioc_count"), 0),
                "affected_nodes": _safe_int(dict(mission_payload.get("business_context", {})).get("affected_nodes"), 0),
                "intel_sources": list(dict(mission_payload.get("business_context", {})).get("intel_sources", [])),
                "attack_hints": list(dict(mission_payload.get("business_context", {})).get("attack_hints", [])),
                "assessment_resource_units": _safe_int(
                    dict(mission_payload.get("business_context", {})).get("assessment_resource_units"), 1
                ),
                "assessment_budget_ceiling": _safe_float(
                    dict(mission_payload.get("business_context", {})).get("assessment_budget_ceiling"), 18.0
                ),
            },
        )

    def _serve_mission_api(self, path: str, query: dict[str, list[str]]) -> None:
        parts = [item for item in path.split("/") if item]
        if len(parts) < 4:
            self._write_json({"error": "bad request"}, status=HTTPStatus.BAD_REQUEST)
            return
        mission_id = parts[2]
        action = parts[3]
        record = self.state.mission(mission_id)
        if record is None:
            self._write_json({"error": "mission not found"}, status=HTTPStatus.NOT_FOUND)
            return
        if action == "overview":
            self._write_json(_build_overview(record))
            return
        if action == "timeline":
            limit = _safe_int((query.get("limit") or ["200"])[0], 200)
            offset = _safe_int((query.get("offset") or ["0"])[0], 0)
            self._write_json(_build_timeline(record, limit=limit, offset=offset))
            return
        if action == "proof":
            self._write_json(
                {
                    "coordination_proof": _as_dict(record.payload.get("coordination_proof")),
                    "proof_checks": _as_dict(record.payload.get("proof_checks")),
                }
            )
            return
        if action == "metrics":
            self._write_json(
                {
                    "standard_metrics": _as_dict(record.payload.get("standard_metrics")),
                    "step_metrics": _as_dict(record.payload.get("step_metrics")),
                }
            )
            return
        if action == "agents":
            scope = _safe_text((query.get("scope") or ["swarm"])[0]).lower()
            if scope == "local":
                self._write_json({"agents": _build_local_agent_view(record, self.state.local_agent_id)})
                return
            self._write_json({"agents": _build_swarm_agent_view(record)})
            return
        if action == "agent-panels":
            self._write_json({"agent_panels": _build_agent_panels(record, self.state.local_agent_id)})
            return
        if action == "runtime-events":
            mqtt_addr = _safe_optional_text(os.getenv("FOXMQ_MQTT_ADDR")) or "127.0.0.1:1883"
            self.state.ensure_runtime_listener(run_id=record.run_id, topic_namespace=record.topic_namespace, mqtt_addr=mqtt_addr)
            since_event_order = _safe_int((query.get("since_event_order") or ["0"])[0], 0)
            if since_event_order > 0:
                events = self.state.runtime_events_since(record.run_id, since_event_order)
            else:
                events = self.state.runtime_events_for_run(record.run_id)
            all_events = self.state.runtime_events_for_run(record.run_id)
            latest_event_order = 0
            if all_events:
                latest_event_order = max(_safe_int(item.get("event_order"), 0) for item in all_events)
            self._write_json(
                {
                    "events": events,
                    "run_id": record.run_id,
                    "since_event_order": since_event_order,
                    "latest_event_order": latest_event_order,
                }
            )
            return
        self._write_json({"error": "unsupported action"}, status=HTTPStatus.BAD_REQUEST)


def _panel_html(initial_agent_columns_html: str) -> str:
    html_doc = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Vertex Swarm Timeline Panel</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 16px; background: #0f172a; color: #e2e8f0; }
    h1 { margin: 0 0 12px; font-size: 20px; }
    .toolbar { background: #1e293b; border-radius: 8px; padding: 10px; margin-bottom: 12px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    select, button { padding: 6px 8px; }
    .status-line { display: none; }
    .agent-columns { display: flex; gap: 10px; overflow-x: auto; padding-bottom: 4px; min-height: 180px; align-items: stretch; }
    .agent-col { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 10px; min-width: 360px; max-width: 360px; flex: 0 0 360px; }
    .agent-col.abnormal { border-color: #ef4444; }
    .agent-col.related { outline: 2px solid #f59e0b; }
    .agent-title { font-weight: bold; font-size: 15px; margin-bottom: 8px; }
    .agent-sentence { font-size: 12px; margin-bottom: 8px; background: #0b1220; border-radius: 6px; padding: 8px; }
    .line { font-size: 12px; margin: 4px 0; }
    .badge { display: inline-block; border-radius: 999px; padding: 1px 8px; font-size: 11px; margin-right: 6px; }
    .done { background: #14532d; color: #dcfce7; }
    .running { background: #78350f; color: #fef3c7; }
    .pending { background: #1f2937; color: #cbd5e1; }
    .failed { background: #7f1d1d; color: #fee2e2; }
    .timeline { display: flex; flex-direction: column; gap: 8px; position: relative; padding-left: 12px; margin-top: 8px; }
    .timeline-step-wrap { position: relative; }
    .timeline-step-wrap::before { content: ''; position: absolute; left: -8px; top: 0; bottom: -8px; width: 2px; background: #334155; }
    .timeline-step-wrap:last-child::before { bottom: 50%; }
    .timeline-step { border: 1px solid #334155; border-radius: 6px; padding: 6px; position: relative; background: #111827; }
    .timeline-step::before { content: ''; position: absolute; left: -13px; top: 50%; width: 8px; height: 8px; border-radius: 999px; transform: translateY(-50%); background: #64748b; }
    .timeline-step.done::before { background: #22c55e; }
    .timeline-step.running::before { background: #f59e0b; }
    .timeline-step.failed::before { background: #ef4444; }
    .timeline-step.pending::before { background: #64748b; }
    .timeline-step.message::before { background: #38bdf8; }
    .timeline-step.stage::before { background: #a78bfa; }
    .timeline-step .business-chain { font-size: 12px; color: #86efac; font-weight: 600; margin-bottom: 4px; white-space: pre-line; }
    .timeline-step .protocol-line { font-size: 12px; color: #e2e8f0; }
    .timeline-step.tag-tashi > div:first-child { color: #c4b5fd; }
    .timeline-step.tag-foxmq > div:first-child { color: #67e8f9; }
    .timeline-detail { display: none; margin-top: 6px; background: #0f172a; border-radius: 6px; padding: 6px; font-size: 11px; white-space: pre-wrap; word-break: break-word; }
    .timeline-step:hover .timeline-detail { display: block; }
  </style>
</head>
<body>
  <h1>Vertex Swarm Timeline Panel</h1>
  <div class="toolbar">
    <label>Business:</label>
    <select id="businessTypeSelect">
      <option value="threat_intel">Threat Intel</option>
    </select>
    <button onclick="triggerBusiness()">Trigger Business</button>
    <span id="refreshStatus" class="status-line"></span>
  </div>
  <div id="agentColumns" class="agent-columns">__INITIAL_AGENT_COLUMNS__</div>
  <script>
    let currentMissionId = '';
    let refreshErrorCount = 0;
    let lastAgentPanelsPayload = {agent_panels: []};
    let lastPanelSignature = '';
    let lastOverviewSignature = '';
    let lastRuntimeEventsPayload = {events: []};
    let lastRuntimeEventOrder = 0;
    let pendingRuntimeEvents = [];
    let runtimeFlushTimer = null;
    let runtimeBaselineReady = false;
    let inBusinessPhase = false;
    let businessStartEventOrder = 0;
    let currentBusinessType = 'threat_intel';
    const businessMap = {
      risk_control: 'Risk Control',
      threat_intel: 'Threat Intel',
      agent_marketplace: 'Agent Marketplace',
      distributed_rag: 'Distributed RAG',
      compute_marketplace: 'Compute Marketplace',
    };
    function businessNameByType(businessType) {
      const key = String(businessType || '');
      return String(businessMap[key] || key || 'Unknown Business');
    }
    function stateClass(state) {
      const normalized = String(state || '').toLowerCase();
      if (normalized === 'done') return 'done';
      if (normalized === 'running') return 'running';
      if (normalized === 'failed') return 'failed';
      return 'pending';
    }
    function businessSemanticProfile(businessType) {
      const key = String(businessType || '').toLowerCase();
      const common = {
        stageEntry: 'Stage 1/7 Event Intake',
        stageEvaluate: 'Stage 2/7 Parallel Evaluation',
        stageAggregate: 'Stage 3/7 Consensus Convergence',
        stageNegotiation: 'Coordination Protocol: Role Negotiation/Intent Submission',
        stageDecide: 'Stage 4/7 Strategy Decision',
        stageExecute: 'Stage 5/7 Action Execution',
        stageFeedback: 'Stage 6/7 Result Feedback',
        stageIterate: 'Stage 7/7 Continuous Adjustment',
      };
      if (key === 'threat_intel') {
        return {
          ...common,
          label: 'Threat Intel',
          stageEntry: 'S0 Lead Intake',
          stageEvaluate: 'S1 Source Scoring and Conflict Resolution',
          stageNegotiation: 'Coordination Protocol: Role Negotiation/Intent Submission',
          stageAggregate: 'S2 ATT&CK/Kill-Chain Mapping',
          stageDecide: 'S3 Playbook Planning and Execution',
          stageExecute: 'S4 Monitoring Window and Secondary Verification',
          stageIterate: 'S5 Completion/Rollback',
          taskMap: {
            risk_assessment: 'Threat Assessment',
            risk_mitigation: 'Threat Mitigation',
            verification: 'Threat Verification',
            threat_assessment: 'Threat Assessment',
            threat_conflict_resolution: 'Conflict Resolution',
            threat_mitigation: 'Playbook Mitigation',
            threat_verification: 'Monitoring and Secondary Verification',
          },
        };
      }
      if (key === 'agent_marketplace') {
        return {
          ...common,
          label: 'Agent Marketplace',
          taskMap: {risk_assessment: 'Supply Risk Assessment', risk_mitigation: 'Matching Risk Mitigation', verification: 'Fulfillment Verification'},
        };
      }
      if (key === 'distributed_rag') {
        return {
          ...common,
          label: 'Distributed RAG',
          taskMap: {risk_assessment: 'Source Credibility Assessment', risk_mitigation: 'Retrieval Risk Mitigation', verification: 'Answer Consistency Verification'},
        };
      }
      if (key === 'compute_marketplace') {
        return {
          ...common,
          label: 'Compute Marketplace',
          taskMap: {risk_assessment: 'Resource Risk Assessment', risk_mitigation: 'Allocation Risk Mitigation', verification: 'Resource Audit Verification'},
        };
      }
      return {
        ...common,
        label: 'Risk Control',
        taskMap: {risk_assessment: 'Risk Assessment', risk_mitigation: 'Risk Mitigation', verification: 'Result Verification'},
      };
    }
    function buildPhaseByOrder(runtimeEvents) {
      const phaseByOrder = {};
      let globalPhase = 0;
      const sorted = (Array.isArray(runtimeEvents) ? runtimeEvents.slice() : []).sort((a, b) => Number(a.event_order || 0) - Number(b.event_order || 0));
      for (const evt of sorted) {
        const kind = String((evt || {}).kind || '');
        const evtState = String((evt || {}).state || '').trim().toLowerCase();
        const resultStatus = String((evt || {}).result_status || '').trim().toLowerCase();
        let target = globalPhase;
        if (kind === 'business_begin') target = Math.max(target, 1);
        else if (kind === 'trigger_sent') target = Math.max(target, 2);
        else if (kind === 'tashi_intent') target = Math.max(target, 2);
        else if (kind === 'tashi_claim') target = Math.max(target, 3);
        else if (kind === 'mission_start') target = Math.max(target, 4);
        else if (kind === 'mission_stage') target = Math.max(target, 5);
        else if (kind === 'foxmq_message') {
          const hasResultSignal = evtState === 'done' || evtState === 'failed' || resultStatus === 'processed';
          target = Math.max(target, hasResultSignal ? 6 : 5);
        } else if (kind === 'mission_complete') target = Math.max(target, 7);
        globalPhase = target;
        phaseByOrder[String(Number(evt.event_order || 0))] = globalPhase;
      }
      return phaseByOrder;
    }
    function businessChainText(evt, semanticState, phaseHint) {
      const kind = String((evt || {}).kind || '');
      const taskType = String((evt || {}).task_type || '').trim();
      const taskId = String((evt || {}).task_id || '').trim();
      const roleName = String((evt || {}).role_name || '').trim();
      const evtState = String((evt || {}).state || '').trim().toLowerCase();
      const decisionRaw = String((evt || {}).decision || '').trim().toLowerCase();
      const severityRaw = String((evt || {}).severity || '').trim().toLowerCase();
      const resultStatus = String((evt || {}).result_status || '').trim().toLowerCase();
      const agent = String((evt || {}).agent_id || '').trim() || 'unknown';
      const businessName = businessNameByType(String((evt || {}).business_type || currentBusinessType || 'risk_control'));
      const profile = businessSemanticProfile(String((evt || {}).business_type || currentBusinessType || 'risk_control'));
      const sourceConfidence = String((evt || {}).source_confidence_level || '').trim();
      const conflictDetected = Boolean((evt || {}).conflict_detected);
      const resolvedClaim = String((evt || {}).resolved_claim || '').trim();
      const killChain = String((evt || {}).kill_chain_stage || '').trim();
      const attackTactics = String((evt || {}).attack_tactics || '').trim();
      const playbookId = String((evt || {}).playbook_id || '').trim();
      const rollbackRequired = String((evt || {}).rollback_required || '').trim();
      const rollbackReason = String((evt || {}).rollback_reason || '').trim();
      const monitoringDecision = String((evt || {}).monitoring_decision || '').trim();
      const secondaryVerifyTriggered = String((evt || {}).secondary_verify_triggered || '').trim();
      const decisionMap = {
        allow: 'Allow',
        pass: 'Allow',
        limit: 'Limit',
        throttle: 'Limit',
        step_up_verify: 'Secondary Verification',
        challenge: 'Secondary Verification',
        manual_review: 'Manual Review',
        review: 'Manual Review',
        freeze: 'Temporary Freeze',
        freeze_and_review: 'Temporary Freeze + Manual Review',
      };
      const decisionText = decisionMap[decisionRaw] || (decisionRaw ? `strategy=${decisionRaw}` : '');
      const severityText = severityRaw ? `risk=${severityRaw}` : '';
      const taskText = profile.taskMap[taskType] || taskType || 'Business Task';
      const idText = taskId ? `(${taskId})` : '';
      const stateRef = semanticState || {phase: 0, lastRole: '', lastTaskType: '', lastTaskId: '', lastDecision: '', lastSeverity: '', lastResultStatus: ''};
      if (roleName) stateRef.lastRole = roleName;
      if (taskType) stateRef.lastTaskType = taskType;
      if (taskId) stateRef.lastTaskId = taskId;
      if (decisionRaw) stateRef.lastDecision = decisionRaw;
      if (severityRaw) stateRef.lastSeverity = severityRaw;
      if (resultStatus) stateRef.lastResultStatus = resultStatus;
      let phase = Number(stateRef.phase || 0);
      const hinted = Number(phaseHint || 0);
      if (hinted > phase) {
        phase = hinted;
      }
      function usePhase(targetPhase, text) {
        if (targetPhase < phase) {
          return {text: `${text}`, phase};
        }
        phase = targetPhase;
        stateRef.phase = phase;
        return {text: `${text}`, phase};
      }
      if (kind === 'business_begin') {
        return usePhase(1, `${profile.stageEntry}: ${businessName} request accepted.`);
      }
      if (kind === 'trigger_sent') {
        return usePhase(2, `Coordination Protocol: start request sent (requester=${agent}).`);
      }
      if (kind === 'tashi_intent' && taskType) {
        const intentTarget = roleName || taskText || 'role';
        return usePhase(2, `${profile.stageNegotiation || 'Coordination Protocol: Role Negotiation/Intent Submission'}: ${agent} submitted intent for ${intentTarget}${idText}.`);
      }
      if (kind === 'tashi_claim' && roleName) {
        return usePhase(3, `${profile.stageNegotiation || 'Coordination Protocol: Role Negotiation/Intent Submission'}: ${agent} confirmed responsibility for ${roleName}.`);
      }
      if (kind === 'mission_start') {
        return usePhase(3, 'Coordination Protocol: mission accepted by coordination layer, entering negotiation/allocation preparation.');
      }
      if (kind === 'mission_stage' && (taskType || roleName)) {
        const resolvedRoleName = roleName || (taskType.includes('assessment') ? 'scout' : (taskType.includes('mitigation') ? 'guardian' : (taskType.includes('verification') ? 'verifier' : 'unknown')));
        const rulePrefix = `Role assignment rule: score descending + load ascending + agent_id lexicographic; this round ${agent} takes ${resolvedRoleName}.`;
        if (String(currentBusinessType || '').toLowerCase() === 'threat_intel') {
          if (taskType === 'threat_assessment' || taskType === 'threat_conflict_resolution') {
            const s1 = `${profile.stageEvaluate}: ${agent} completed source scoring, confidence=${sourceConfidence || '-'}, conflict=${conflictDetected ? 'yes' : 'no'}, claim=${resolvedClaim || '-'}`;
            const s2 = `${profile.stageAggregate}: mapped to ${killChain || '-'}, ATT&CK=${attackTactics || '-'}`;
            return usePhase(3, `${rulePrefix}\n${s1}\n${s2}`);
          }
          if (taskType === 'threat_mitigation') {
            const rollbackText = rollbackRequired === 'True' || rollbackRequired === 'true' ? `rollback triggered (${rollbackReason || 'unknown'})` : 'no rollback required';
            return usePhase(4, `${rulePrefix}\n${profile.stageDecide}: ${agent} executed playbook=${playbookId || '-'}, ${rollbackText}.`);
          }
          if (taskType === 'threat_verification') {
            const verifyText = secondaryVerifyTriggered === 'True' || secondaryVerifyTriggered === 'true' ? `secondary verification triggered (${monitoringDecision || '-'})` : `monitoring passed (${monitoringDecision || '-'})`;
            return usePhase(5, `${rulePrefix}\n${profile.stageExecute}: ${agent} completed monitoring-window decision, ${verifyText}.`);
          }
        }
        const decisionPart = [decisionText, severityText].filter(Boolean).join(', ');
        if (decisionPart) {
          return usePhase(4, `${profile.stageDecide}: ${agent} produced conclusion ${decisionPart} (${taskText}${idText}).`);
        }
        return usePhase(5, `${profile.stageExecute}: ${agent} executed ${taskText}${idText}, state=${evtState || 'running'}.`);
      }
      if (kind === 'foxmq_message' && taskType) {
        const hasResultSignal = evtState === 'done' || evtState === 'failed' || resultStatus === 'processed';
        if (hasResultSignal) {
          const decisionPart = [decisionText, severityText].filter(Boolean).join(', ');
          if (decisionPart) {
            return usePhase(6, `${profile.stageFeedback}: ${agent} returned ${taskText}${idText}, conclusion=${decisionPart}.`);
          }
          const fallbackDecision = stateRef.lastDecision ? (decisionMap[String(stateRef.lastDecision).toLowerCase()] || `strategy=${stateRef.lastDecision}`) : '';
          const suffix = fallbackDecision ? `, latest conclusion=${fallbackDecision}` : '';
          return usePhase(6, `${profile.stageFeedback}: ${agent} returned ${taskText}${idText} result${suffix}.`);
        }
        return usePhase(5, `${profile.stageExecute}: FoxMQ routed ${taskText}${idText} to execution node.`);
      }
      if (kind === 'mission_complete') {
        const finalDecision = stateRef.lastDecision ? (decisionMap[String(stateRef.lastDecision).toLowerCase()] || `strategy=${stateRef.lastDecision}`) : '';
        const suffix = finalDecision ? `, final decision=${finalDecision}` : '';
        return usePhase(7, `${profile.stageIterate}: loop completed, state=${evtState || 'done'}${suffix}.`);
      }
      return {text: '', phase};
    }
    function readableDetailText(evt, bizInfo) {
      const kind = String((evt || {}).kind || '');
      const role = String((evt || {}).role_name || '').trim() || 'unknown';
      const agent = String((evt || {}).agent_id || '').trim() || 'unknown';
      const taskType = String((evt || {}).task_type || '').trim();
      const decision = String((evt || {}).decision || '').trim();
      const severity = String((evt || {}).severity || '').trim();
      const state = String((evt || {}).state || '').trim() || 'running';
      const sourceConfidence = String((evt || {}).source_confidence_level || '').trim();
      const resolvedClaim = String((evt || {}).resolved_claim || '').trim();
      const killChain = String((evt || {}).kill_chain_stage || '').trim();
      const playbookId = String((evt || {}).playbook_id || '').trim();
      const rollbackRequired = String((evt || {}).rollback_required || '').trim().toLowerCase();
      const rollbackReason = String((evt || {}).rollback_reason || '').trim();
      const monitoringDecision = String((evt || {}).monitoring_decision || '').trim();
      const secondaryVerifyTriggered = String((evt || {}).secondary_verify_triggered || '').trim().toLowerCase();
      const scenario = String((evt || {}).scenario || '').trim();
      const iocCount = String((evt || {}).ioc_count || '').trim();
      const affectedNodes = String((evt || {}).affected_nodes || '').trim();
      const intelSources = Array.isArray((evt || {}).intel_sources) ? evt.intel_sources : [];
      const attackHints = Array.isArray((evt || {}).attack_hints) ? evt.attack_hints : [];
      const assessmentUnits = String((evt || {}).assessment_resource_units || '').trim();
      const assessmentBudget = String((evt || {}).assessment_budget_ceiling || '').trim();
      const lines = [];
      if (String((bizInfo && bizInfo.text) || '').trim()) {
        lines.push(String(bizInfo.text));
      }
      if (kind === 'business_begin' || kind === 'trigger_sent') {
        lines.push(`Input: scenario=${scenario || '-'}, IOC=${iocCount || '0'}, impacted asset nodes=${affectedNodes || '0'} (excluding coordination agents), intel_sources=${intelSources.length}, attack_hints=${attackHints.length}.`);
        lines.push(`Action: mission triggered, scout will receive the threat_assessment task.`);
        lines.push(`Output: computable payload generated, assessment_budget=${assessmentBudget || '-'}, resource_units=${assessmentUnits || '-'}, intel_source_entries=${intelSources.length}.`);
      } else if (kind === 'mission_stage' && taskType === 'threat_assessment') {
        lines.push(`${agent} as ${role} completed source scoring and conflict resolution.`);
        lines.push(`confidence=${sourceConfidence || '-'}, claim=${resolvedClaim || '-'}.`);
      } else if (kind === 'mission_stage' && taskType === 'threat_mitigation') {
        const rollbackText = rollbackRequired === 'true' ? `rollback triggered (${rollbackReason || '-'})` : 'no rollback triggered';
        lines.push(`${agent} as ${role} executed playbook ${playbookId || '-'}, ${rollbackText}.`);
      } else if (kind === 'mission_stage' && taskType === 'threat_verification') {
        const verifyText = secondaryVerifyTriggered === 'true' ? `secondary verification triggered (${monitoringDecision || '-'})` : `monitoring passed (${monitoringDecision || '-'})`;
        lines.push(`${agent} as ${role} completed monitoring-window decision, ${verifyText}.`);
      } else if (kind === 'mission_stage') {
        const parts = [`${agent} as ${role} executed ${taskType || 'task'}, state=${state}`];
        if (decision) parts.push(`decision=${decision}`);
        if (severity) parts.push(`risk=${severity}`);
        lines.push(`${parts.join(', ')}.`);
      } else if (kind === 'mission_complete') {
        lines.push(`Mission loop completed, final state=${state}.`);
      } else if (kind === 'tashi_intent' || kind === 'tashi_claim') {
        lines.push(`Coordination primitive action: ${kind}, participated by ${agent}.`);
      } else {
        lines.push(`${agent} received event ${kind || 'unknown'}, state=${state}.`);
      }
      if (killChain) {
        lines.push(`kill_chain_stage=${killChain}.`);
      }
      return lines.join('\\n');
    }
    function structuredDetailText(evt, evtKind) {
      const intelSources = Array.isArray((evt || {}).intel_sources) ? evt.intel_sources : [];
      const attackHints = Array.isArray((evt || {}).attack_hints) ? evt.attack_hints : [];
      return `mission=${String(evt.mission_id || '-')}\nrun=${String(evt.run_id || '-')}\nmessage_id=${String(evt.message_id || '-')}\ntopic=${String(evt.topic || '-')}\nkind=${String(evtKind || '-')}\nrole=${String(evt.role_name || '-')}\ntask_type=${String(evt.task_type || '-')}\ntask_id=${String(evt.task_id || '-')}\ndecision=${String(evt.decision || '-')}\nseverity=${String(evt.severity || '-')}\nresult_status=${String(evt.result_status || '-')}\nscenario=${String(evt.scenario || '-')}\nioc_count=${String(evt.ioc_count || '-')}\naffected_nodes=${String(evt.affected_nodes || '-')}\nintel_sources_count=${String(intelSources.length)}\nintel_sources=${JSON.stringify(intelSources)}\nattack_hints=${JSON.stringify(attackHints)}\nassessment_resource_units=${String(evt.assessment_resource_units || '-')}\nassessment_budget_ceiling=${String(evt.assessment_budget_ceiling || '-')}\nsource_confidence=${String(evt.source_confidence_level || '-')}\nconflict_detected=${String(evt.conflict_detected || '-')}\nresolved_claim=${String(evt.resolved_claim || '-')}\nkill_chain_stage=${String(evt.kill_chain_stage || '-')}\nattack_tactics=${String(evt.attack_tactics || '-')}\nattack_techniques=${String(evt.attack_techniques || '-')}\nplaybook_id=${String(evt.playbook_id || '-')}\nrollback_required=${String(evt.rollback_required || '-')}\nrollback_reason=${String(evt.rollback_reason || '-')}\nmonitoring_window_minutes=${String(evt.monitoring_window_minutes || '-')}\nresidual_risk=${String(evt.residual_risk || '-')}\nresidual_risk_threshold=${String(evt.residual_risk_threshold || '-')}\nsecondary_verify_triggered=${String(evt.secondary_verify_triggered || '-')}\nmonitoring_decision=${String(evt.monitoring_decision || '-')}\ntimestamp=${String(evt.timestamp || '-')}`;
    }
    function objSignature(obj) {
      return JSON.stringify(obj || {});
    }
    async function fetchJson(url) {
      const res = await fetch(url);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      return await res.json();
    }
    async function postJson(url, payload) {
      const res = await fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload || {}),
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      return await res.json();
    }
    async function initializeRuntimeBaseline(missionId) {
      const runtime = await fetchJson(`/api/missions/${missionId}/runtime-events?since_event_order=0`);
      const latestOrder = Number(runtime.latest_event_order || 0);
      lastRuntimeEventOrder = latestOrder;
      pendingRuntimeEvents = [];
      const baselineEvents = Array.isArray(runtime.events)
        ? runtime.events.filter((evt) => {
            const kind = String(((evt || {}).kind) || '');
            return kind === 'agent_online' || kind === 'handshake_success' || kind === 'handshake_refresh';
          }).slice(-500)
        : [];
      lastRuntimeEventsPayload = {events: baselineEvents};
      inBusinessPhase = false;
      businessStartEventOrder = latestOrder + 1;
      runtimeBaselineReady = true;
    }
    function renderAgentColumns(payload, runtimePayload) {
      try {
      let holder = document.getElementById('agentColumns');
      if (!holder) {
        holder = document.createElement('div');
        holder.id = 'agentColumns';
        holder.className = 'agent-columns';
        document.body.appendChild(holder);
      }
      holder.innerHTML = '';
      const panels = Array.isArray(payload.agent_panels) ? payload.agent_panels : [];
      const runtimeEvents = Array.isArray((runtimePayload || {}).events) ? runtimePayload.events : [];
      const phaseByOrder = buildPhaseByOrder(runtimeEvents);
      function normalizeAgentId(value) {
        const text = String(value || '').trim();
        const lower = text.toLowerCase();
        if (!text || lower === 'none' || lower === 'null' || lower === 'undefined') return '';
        if (lower.endsWith('-bootstrap')) return text.slice(0, -10);
        return text;
      }
      const panelByAgent = {};
      for (const panel of panels) {
        if (!panel || typeof panel !== 'object') {
          continue;
        }
        const agentId = normalizeAgentId(panel.agent_id);
        if (agentId) {
          panelByAgent[agentId] = panel;
        }
      }
      const snapshotAgentIds = Array.from(new Set(Object.keys(panelByAgent))).sort();
      if (snapshotAgentIds.length && !runtimeEvents.length) {
        let renderedCount = 0;
        for (const agentId of snapshotAgentIds) {
          const panel = panelByAgent[agentId] || {agent_id: agentId};
          const abnormal = Boolean(panel.is_abnormal);
          const card = document.createElement('div');
          card.className = 'agent-col';
          if (abnormal) card.classList.add('abnormal');
          if (Boolean(panel.related_to_current_stage)) card.classList.add('related');
          const title = document.createElement('div');
          title.className = 'agent-title';
          title.textContent = String(agentId || '-');
          card.appendChild(title);
          const timeline = document.createElement('div');
          timeline.className = 'timeline';
          const step = document.createElement('div');
          step.className = 'timeline-step stage';
          const business = document.createElement('div');
          business.className = 'business-chain';
          business.textContent = inBusinessPhase
            ? String(panel.current_step_sentence || `${agentId} waiting for business trigger.`)
            : `${agentId} waiting for new business trigger.`;
          const flowSentences = Array.isArray(panel.business_flow_sentences) ? panel.business_flow_sentences : [];
          const protocol = document.createElement('div');
          protocol.className = 'protocol-line';
          protocol.textContent = inBusinessPhase
            ? String(flowSentences.slice(0, 3).join('; ') || 'No business execution records yet.')
            : 'Initial view: historical flow before refresh is not loaded.';
          step.appendChild(business);
          step.appendChild(protocol);
          timeline.appendChild(step);
          card.appendChild(timeline);
          holder.appendChild(card);
          renderedCount += 1;
        }
        return renderedCount;
      }
      const eventAgents = new Set();
      for (const evt of runtimeEvents) {
        const evtObj = evt && typeof evt === 'object' ? evt : {};
        if (String((evtObj || {}).kind || '') === 'foxmq_message') {
          continue;
        }
        const evtAgent = normalizeAgentId(evtObj.agent_id);
        if (evtAgent) {
          eventAgents.add(evtAgent);
        }
      }
      let agentIds = Array.from(new Set([...Object.keys(panelByAgent), ...Array.from(eventAgents)])).sort();
      if (!agentIds.length) {
        agentIds = ['agent-scout', 'agent-guardian', 'agent-verifier', 'agent-worker-4', 'agent-worker-5'];
      }
      let renderedCount = 0;
      for (const agentId of agentIds) {
        const panel = panelByAgent[agentId] || {agent_id: agentId, is_abnormal: false, related_to_current_stage: false};
        const abnormal = Boolean(panel.is_abnormal);
        const card = document.createElement('div');
        card.className = 'agent-col';
        if (abnormal) card.classList.add('abnormal');
        if (Boolean(panel.related_to_current_stage)) card.classList.add('related');
        const title = document.createElement('div');
        title.className = 'agent-title';
        title.textContent = String(agentId || '-');
        card.appendChild(title);
        const timeline = document.createElement('div');
        timeline.className = 'timeline';
        const events = [];
        const semanticState = {phase: 0, lastRole: '', lastTaskType: '', lastTaskId: '', lastDecision: '', lastSeverity: '', lastResultStatus: ''};
        for (const evt of runtimeEvents) {
          const evtObj = evt && typeof evt === 'object' ? evt : {};
          const evtOrder = Number(evtObj.event_order || 0);
          const evtKind = String(evtObj.kind || '');
          if (inBusinessPhase && businessStartEventOrder && evtOrder < businessStartEventOrder) {
            continue;
          }
          const evtAgent = normalizeAgentId(evtObj.agent_id);
          if (!evtAgent || evtAgent !== agentId) {
            continue;
          }
          const evtState = String(evtObj.state || 'running').toLowerCase();
          if (evtKind === 'foxmq_message') {
            continue;
          }
          if (evtKind === 'handshake_heartbeat' && inBusinessPhase) {
            continue;
          }
          let evtCls = stateClass(evtState);
          let evtTag = '';
          if (evtKind === 'agent_online') evtCls = 'message';
          if (evtKind === 'mission_stage') evtCls = 'stage';
          if (evtKind === 'tashi_intent' || evtKind === 'tashi_claim') { evtCls = 'stage'; evtTag = 'tag-tashi'; }
          if (evtKind === 'handshake_refresh' || evtKind === 'tashi_hint') evtCls = 'stage';
          if (evtKind === 'handshake_heartbeat') evtCls = 'message';
          const bizInfo = businessChainText(evtObj, semanticState, Number(phaseByOrder[String(evtOrder)] || 0));
          const summaryText = String(evtObj.summary || 'Trigger event received');
          events.push({
            order: evtOrder,
            cls: evtCls,
            tag: evtTag,
            businessHead: String((bizInfo && bizInfo.text) || ''),
            head: `Coordination Layer: ${summaryText}`,
            detail: `${readableDetailText(evtObj, bizInfo)}\n\n----\nStructured Raw Fields\n${structuredDetailText(evtObj, evtKind)}`,
          });
        }
        if (!events.length) {
          events.push({
            order: 0,
            cls: 'pending',
            head: businessStartEventOrder ? 'Realtime: No new events for current business.' : 'Realtime: Waiting for business trigger.',
            detail: '',
          });
        }
        const sorted = events.sort((a, b) => Number(a.order || 0) - Number(b.order || 0));
        for (const event of sorted) {
          const wrap = document.createElement('div');
          wrap.className = 'timeline-step-wrap';
          const line = document.createElement('div');
          line.className = `timeline-step ${String(event.cls || '')} ${String(event.tag || '')}`.trim();
          const biz = document.createElement('div');
          biz.className = 'business-chain';
          biz.textContent = String(event.businessHead || '');
          const head = document.createElement('div');
          head.className = 'protocol-line';
          head.textContent = String(event.head || '');
          const detail = document.createElement('div');
          detail.className = 'timeline-detail';
          detail.textContent = String(event.detail || '');
          if (String(event.businessHead || '').trim()) {
            line.appendChild(biz);
          }
          line.appendChild(head);
          line.appendChild(detail);
          wrap.appendChild(line);
          timeline.appendChild(wrap);
        }
        card.appendChild(timeline);
        holder.appendChild(card);
        renderedCount += 1;
      }
      if (!renderedCount) {
        const card = document.createElement('div');
        card.className = 'agent-col';
        const title = document.createElement('div');
        title.className = 'agent-title';
        title.textContent = 'No displayable agent';
        const line = document.createElement('div');
        line.className = 'agent-sentence';
        line.textContent = `panel=${panels.length}, events=${runtimeEvents.length}`;
        card.appendChild(title);
        card.appendChild(line);
        holder.appendChild(card);
      }
      return renderedCount;
      } catch (err) {
        const card = document.createElement('div');
        card.className = 'agent-col';
        const title = document.createElement('div');
        title.className = 'agent-title';
        title.textContent = 'Render failed';
        const line = document.createElement('div');
        line.className = 'agent-sentence';
        line.textContent = String((err && err.message) || err || 'unknown_error');
        card.appendChild(title);
        card.appendChild(line);
        holder.appendChild(card);
        return 0;
      }
    }
    window.addEventListener('error', (event) => {
      const statusEl = document.getElementById('refreshStatus');
      if (statusEl) {
        statusEl.textContent = `Status: Frontend script error | ${String((event && event.message) || 'unknown_error')}`;
      }
    });
    window.addEventListener('unhandledrejection', (event) => {
      const statusEl = document.getElementById('refreshStatus');
      if (statusEl) {
        const msg = String((event && event.reason && event.reason.message) || (event && event.reason) || 'unknown_error');
        statusEl.textContent = `Status: Frontend async error | ${msg}`;
      }
    });
    function enqueueRuntimeEvents(newEvents) {
      const incoming = Array.isArray(newEvents) ? newEvents : [];
      if (!incoming.length) return;
      for (const evt of incoming) {
        const kind = String((evt || {}).kind || '');
        if (kind === 'business_begin' || kind === 'trigger_sent') {
          const evtBusinessType = String((evt || {}).business_type || '').trim().toLowerCase();
          if (evtBusinessType) {
            currentBusinessType = evtBusinessType;
          }
          const nextOrder = Number((evt || {}).event_order || 0);
          if (nextOrder > 0 && (!businessStartEventOrder || nextOrder < Number(businessStartEventOrder || 0))) {
            businessStartEventOrder = nextOrder;
          }
          inBusinessPhase = true;
        }
      }
      pendingRuntimeEvents.push(...incoming);
      if (runtimeFlushTimer) return;
      runtimeFlushTimer = setInterval(() => {
        if (!pendingRuntimeEvents.length) {
          clearInterval(runtimeFlushTimer);
          runtimeFlushTimer = null;
          return;
        }
        const batch = pendingRuntimeEvents.splice(0, 4);
        const merged = Array.isArray(lastRuntimeEventsPayload.events) ? lastRuntimeEventsPayload.events.slice() : [];
        merged.push(...batch);
        lastRuntimeEventsPayload = {events: merged.slice(-500)};
        renderAgentColumns(lastAgentPanelsPayload, lastRuntimeEventsPayload);
      }, 120);
    }
    async function triggerBusiness() {
      if (!currentMissionId) return;
      const businessType = String(document.getElementById('businessTypeSelect').value || 'threat_intel');
      const businessName = businessNameByType(businessType);
      currentBusinessType = businessType;
      runtimeBaselineReady = true;
      const statusEl = document.getElementById('refreshStatus');
      pendingRuntimeEvents = [];
      lastRuntimeEventsPayload = {events: []};
      businessStartEventOrder = 0;
      renderAgentColumns(lastAgentPanelsPayload, lastRuntimeEventsPayload);
      inBusinessPhase = true;
      statusEl.textContent = `Status: Triggering business ${businessName} ...`;
      try {
        const result = await postJson(`/api/missions/${currentMissionId}/trigger-business`, {
          business_type: businessType,
          selection_strategy: 'random',
        });
        statusEl.textContent = `Status: Trigger succeeded | business=${businessName} | requester=${result.requester_agent_id} | mission=${result.mission_id}`;
      } catch (err) {
        const msg = String((err && err.message) ? err.message : err || 'unknown_error');
        statusEl.textContent = `Status: Trigger failed | ${msg}`;
      }
    }
    async function refreshStructural() {
      try {
        const latest = await fetchJson('/api/latest');
        const missionId = String(latest.mission_id || '');
        if (!missionId) {
          document.getElementById('refreshStatus').textContent = 'Status: No mission record yet';
          return;
        }
        if (currentMissionId && currentMissionId !== missionId) {
          lastAgentPanelsPayload = {agent_panels: []};
          lastRuntimeEventsPayload = {events: []};
          lastPanelSignature = '';
          lastRuntimeEventOrder = 0;
          pendingRuntimeEvents = [];
          runtimeBaselineReady = false;
          inBusinessPhase = false;
          businessStartEventOrder = 0;
        }
        currentMissionId = missionId;
        if (!runtimeBaselineReady) {
          await initializeRuntimeBaseline(missionId);
        }
        const overview = await fetchJson(`/api/missions/${missionId}/overview`);
        const overviewBusinessType = String(overview.business_type || '').toLowerCase();
        if (!currentBusinessType && overviewBusinessType) {
          currentBusinessType = overviewBusinessType;
        }
        const agentPanels = await fetchJson(`/api/missions/${missionId}/agent-panels`);
        const panelSig = objSignature(agentPanels);
        const panelChanged = panelSig !== lastPanelSignature;
        if (panelChanged) {
          lastAgentPanelsPayload = agentPanels;
          lastPanelSignature = panelSig;
          renderAgentColumns(lastAgentPanelsPayload, lastRuntimeEventsPayload);
        }
        const overviewSig = objSignature(overview);
        if (overviewSig !== lastOverviewSignature) {
          lastOverviewSignature = overviewSig;
        }
        const updatedAt = Number(overview.updated_at || 0) * 1000;
        const updatedText = updatedAt > 0 ? new Date(updatedAt).toLocaleString() : '-';
        const runtimeEvents = Array.isArray(lastRuntimeEventsPayload.events) ? lastRuntimeEventsPayload.events : [];
        let runtimeBusinessType = '';
        for (let i = runtimeEvents.length - 1; i >= 0; i -= 1) {
          const bt = String(((runtimeEvents[i] || {}).business_type) || '').trim().toLowerCase();
          if (bt) {
            runtimeBusinessType = bt;
            break;
          }
        }
        const businessType = String(runtimeBusinessType || currentBusinessType || overviewBusinessType || '');
        const businessName = businessNameByType(businessType);
        const runName = String(overview.run_id || '-');
        const totalRuntimeEvents = Array.isArray(lastRuntimeEventsPayload.events) ? lastRuntimeEventsPayload.events.length : 0;
        const panelCount = Array.isArray(agentPanels.agent_panels) ? agentPanels.agent_panels.length : 0;
        const holder = document.getElementById('agentColumns');
        const renderedCount = holder ? holder.querySelectorAll('.agent-col').length : 0;
        document.getElementById('refreshStatus').textContent = `Status: OK | run: ${runName} | business: ${businessName} | stage: ${String(overview.current_stage || '-')} | panel_agents: ${panelCount} | displayed_agents: ${renderedCount} | realtime_events: ${totalRuntimeEvents} | updated_at: ${updatedText} | failures: ${refreshErrorCount}`;
      } catch (err) {
        refreshErrorCount += 1;
        const msg = String((err && err.message) ? err.message : err || 'unknown_error');
        document.getElementById('refreshStatus').textContent = `Status: Error | message: ${msg} | failures: ${refreshErrorCount}`;
      }
    }
    async function refreshRuntimeEvents() {
      try {
        if (!currentMissionId || !runtimeBaselineReady) return;
        const runtimeEvents = await fetchJson(`/api/missions/${currentMissionId}/runtime-events?since_event_order=${Number(lastRuntimeEventOrder || 0)}`);
        const incomingEvents = Array.isArray(runtimeEvents.events) ? runtimeEvents.events : [];
        const latestOrder = Number(runtimeEvents.latest_event_order || lastRuntimeEventOrder || 0);
        if (!incomingEvents.length && latestOrder === Number(lastRuntimeEventOrder || 0)) {
          return;
        }
        lastRuntimeEventOrder = latestOrder;
        enqueueRuntimeEvents(incomingEvents);
      } catch (err) {
      }
    }
    async function loadAll() {
      await refreshStructural();
      await refreshRuntimeEvents();
    }
    async function boot() {
      await loadAll();
      setInterval(refreshRuntimeEvents, 250);
      setInterval(refreshStructural, 2000);
    }
    boot();
  </script>
</body>
</html>
"""
    return html_doc.replace("__INITIAL_AGENT_COLUMNS__", initial_agent_columns_html)


def _initial_agent_columns_html(state: "PanelState") -> str:
    mission_id = _safe_optional_text(state.latest_mission_id())
    if not mission_id:
        return (
            '<div class="agent-col">'
            '<div class="agent-title">Panel initializing</div>'
            '<div class="agent-sentence">Waiting for mission and agent data...</div>'
            "</div>"
        )
    record = state.mission(mission_id)
    if record is None:
        return (
            '<div class="agent-col">'
            '<div class="agent-title">Panel initializing</div>'
            '<div class="agent-sentence">Waiting for mission and agent data...</div>'
            "</div>"
        )
    panels = _build_agent_panels(record, state.local_agent_id)
    if not panels:
        return (
            '<div class="agent-col">'
            '<div class="agent-title">No displayable agent</div>'
            '<div class="agent-sentence">Current mission has not produced an agent snapshot yet.</div>'
            "</div>"
        )
    blocks: list[str] = []
    for panel in panels:
        agent_id = html.escape(_safe_text(panel.get("agent_id")) or "-")
        sentence = html.escape(_safe_text(panel.get("current_step_sentence")) or "Waiting for business trigger.")
        flow_items = panel.get("business_flow_sentences")
        if isinstance(flow_items, list):
            flow_text = "; ".join(_safe_text(item) for item in flow_items[:3])
        else:
            flow_text = ""
        flow = html.escape(flow_text or "No business execution records yet.")
        blocks.append(
            '<div class="agent-col">'
            f'<div class="agent-title">{agent_id}</div>'
            '<div class="timeline">'
            '<div class="timeline-step stage">'
            f'<div class="business-chain">{sentence}</div>'
            f'<div class="protocol-line">{flow}</div>'
            "</div>"
            "</div>"
            "</div>"
        )
    return "".join(blocks)


def run_panel_server(
    host: str,
    port: int,
    artifacts_dir: str,
    local_agent_id: str,
    startup_run_id: str,
    startup_topic_namespace: str,
    startup_mqtt_addr: str,
) -> None:
    state = PanelState(artifacts_dir=artifacts_dir, local_agent_id=local_agent_id)
    state.set_preferred_run_context(run_id=startup_run_id, topic_namespace=startup_topic_namespace)
    state.refresh()
    if _safe_optional_text(startup_run_id) and _safe_optional_text(startup_topic_namespace):
        state.ensure_runtime_listener(
            run_id=_safe_optional_text(startup_run_id),
            topic_namespace=_safe_optional_text(startup_topic_namespace),
            mqtt_addr=_safe_optional_text(startup_mqtt_addr) or "127.0.0.1:1883",
        )
    handler = PanelRequestHandler
    handler.state = state
    server = ThreadingHTTPServer((host, port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local read-only panel for mission records")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--artifacts-dir", default=os.path.join(os.getcwd(), "artifacts"))
    parser.add_argument("--local-agent-id", default=os.getenv("AGENT_ID", ""))
    parser.add_argument("--run-id", default="")
    parser.add_argument("--topic-namespace", default="")
    parser.add_argument("--foxmq-mqtt-addr", default=os.getenv("FOXMQ_MQTT_ADDR", "127.0.0.1:1883"))
    args = parser.parse_args()
    run_panel_server(
        host=_safe_text(args.host) or "127.0.0.1",
        port=int(args.port),
        artifacts_dir=str(args.artifacts_dir),
        local_agent_id=_safe_text(args.local_agent_id),
        startup_run_id=_safe_optional_text(args.run_id),
        startup_topic_namespace=_safe_optional_text(args.topic_namespace),
        startup_mqtt_addr=_safe_optional_text(args.foxmq_mqtt_addr),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
