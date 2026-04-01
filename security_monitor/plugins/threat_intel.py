from typing import Any, Dict, List


class ThreatIntelPlugin:
    plugin_name = "threat_intel"
    supported_task_types = ("threat_assessment", "threat_mitigation", "threat_verification", "threat_conflict_resolution")

    def _as_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return int(default)

    def _as_float(self, value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    def _source_claim(self, source: Dict[str, Any]) -> str:
        return str(source.get("claim", "")).strip().lower()

    def _normalize_sources(self, task_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw = task_payload.get("intel_sources")
        sources = raw if isinstance(raw, list) else []
        normalized: List[Dict[str, Any]] = []
        for item in sources:
            if not isinstance(item, dict):
                continue
            source_id = str(item.get("source_id", "")).strip()
            if not source_id:
                continue
            trust = min(1.0, max(0.0, self._as_float(item.get("trust_score", 0.5), 0.5)))
            freshness = min(1.0, max(0.0, self._as_float(item.get("freshness", 0.5), 0.5)))
            confidence = round(trust * freshness, 4)
            normalized.append(
                {
                    "source_id": source_id,
                    "trust_score": trust,
                    "freshness": freshness,
                    "claim": str(item.get("claim", "")).strip().lower(),
                    "evidence_hash": str(item.get("evidence_hash", "")).strip(),
                    "confidence": confidence,
                }
            )
        return normalized

    def _resolve_conflict(self, sources: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not sources:
            return {
                "source_weights": {},
                "source_confidence_level": "unknown",
                "conflict_detected": False,
                "conflict_set": [],
                "resolved_claim": "unknown",
                "resolution_reason": "no_source_input",
                "weighted_confidence": 0.0,
            }
        source_weights = {str(item.get("source_id", "")): float(item.get("confidence", 0.0)) for item in sources}
        total_confidence = sum(source_weights.values())
        claim_groups: Dict[str, float] = {}
        for item in sources:
            claim = self._source_claim(item)
            if not claim:
                continue
            claim_groups[claim] = claim_groups.get(claim, 0.0) + float(item.get("confidence", 0.0))
        has_conflict = len([claim for claim in claim_groups.keys() if claim]) >= 2
        ranked_claims = sorted(claim_groups.items(), key=lambda entry: (-entry[1], entry[0]))
        resolved_claim = ranked_claims[0][0] if ranked_claims else "unknown"
        confidence_value = round(total_confidence / max(1.0, float(len(sources))), 4)
        if confidence_value >= 0.75:
            confidence_level = "high"
        elif confidence_value >= 0.45:
            confidence_level = "medium"
        else:
            confidence_level = "low"
        conflict_items = sorted(
            [(key, round(value, 4)) for key, value in claim_groups.items() if key],
            key=lambda item: (-item[1], item[0]),
        )
        conflict_set = [{"claim": claim, "score": score} for claim, score in conflict_items]
        return {
            "source_weights": source_weights,
            "source_confidence_level": confidence_level,
            "conflict_detected": has_conflict,
            "conflict_set": conflict_set,
            "resolved_claim": resolved_claim,
            "resolution_reason": "max_weighted_confidence",
            "weighted_confidence": confidence_value,
        }

    def _attack_mapping(self, task_payload: Dict[str, Any], resolved_claim: str) -> Dict[str, Any]:
        hints_raw = task_payload.get("attack_hints")
        hints = [str(item).strip().lower() for item in (hints_raw if isinstance(hints_raw, list) else []) if str(item).strip()]
        scenario = str(task_payload.get("scenario", "")).strip().lower()
        if "lateral" in resolved_claim or "lateral" in scenario or "lateral" in hints:
            tactics = ["TA0008"]
            techniques = ["T1021", "T1078"]
            kill_chain_stage = "lateral_movement"
        elif "c2" in hints or "command" in hints:
            tactics = ["TA0011"]
            techniques = ["T1071"]
            kill_chain_stage = "command_and_control"
        else:
            tactics = ["TA0001"]
            techniques = ["T1595"]
            kill_chain_stage = "reconnaissance"
        return {
            "mapping_version": "attack-v1",
            "attack_tactics": tactics,
            "attack_techniques": techniques,
            "kill_chain_stage": kill_chain_stage,
        }

    def _playbook_plan(self, task_payload: Dict[str, Any], attack_mapping: Dict[str, Any]) -> Dict[str, Any]:
        tactics = list(task_payload.get("attack_tactics", attack_mapping.get("attack_tactics", [])))
        kill_chain_stage = str(task_payload.get("kill_chain_stage", attack_mapping.get("kill_chain_stage", "unknown")))
        severity = str(task_payload.get("scout_severity", "high")).strip().lower()
        default_plan = ["isolate_segment", "block_ioc", "snapshot_evidence", "notify_soc"]
        if "TA0011" in tactics:
            default_plan = ["block_c2_channel", "rotate_credentials", "snapshot_evidence", "notify_soc"]
        if severity in {"critical"}:
            default_plan.insert(0, "emergency_quarantine")
        playbook_id = str(task_payload.get("playbook_id", "")).strip() or f"pb-{kill_chain_stage}-{severity}"
        execution_steps = [{"step": step, "status": "done"} for step in default_plan]
        rollback_steps = ["restore_segment_routes", "revert_rule_push", "reopen_controlled_access"]
        return {
            "playbook_id": playbook_id,
            "playbook_steps": default_plan,
            "playbook_execution_steps": execution_steps,
            "rollback_plan": rollback_steps,
        }

    def _rollback_decision(self, task_payload: Dict[str, Any], conflict_resolution: Dict[str, Any]) -> Dict[str, Any]:
        confidence = float(conflict_resolution.get("weighted_confidence", 0.0))
        conflict_detected = bool(conflict_resolution.get("conflict_detected", False))
        rollback_threshold = self._as_float(task_payload.get("rollback_confidence_threshold", 0.45), 0.45)
        rollback_requested = bool(task_payload.get("force_rollback", False))
        rollback_required = rollback_requested or (conflict_detected and confidence <= rollback_threshold)
        return {
            "rollback_required": rollback_required,
            "rollback_reason": "low_confidence_conflict" if rollback_required and not rollback_requested else ("manual_override" if rollback_requested else "not_required"),
            "rollback_confidence_threshold": rollback_threshold,
        }

    def _monitoring_window(self, task_payload: Dict[str, Any], conflict_resolution: Dict[str, Any]) -> Dict[str, Any]:
        minutes = max(5, self._as_int(task_payload.get("monitoring_window_minutes", 30), 30))
        ioc_count = max(0, self._as_int(task_payload.get("ioc_count", 0), 0))
        affected_nodes = max(0, self._as_int(task_payload.get("affected_nodes", 0), 0))
        confidence = float(conflict_resolution.get("weighted_confidence", 0.0))
        residual_risk = round(min(1.0, 0.2 + ioc_count * 0.012 + affected_nodes * 0.03 + (0.4 - min(0.4, confidence))), 4)
        residual_threshold = self._as_float(task_payload.get("residual_risk_threshold", 0.55), 0.55)
        secondary_verify_required = bool(task_payload.get("secondary_verify_required", True))
        secondary_verify_triggered = secondary_verify_required and residual_risk >= residual_threshold
        return {
            "monitoring_window_minutes": minutes,
            "residual_risk": residual_risk,
            "residual_risk_threshold": residual_threshold,
            "secondary_verify_required": secondary_verify_required,
            "secondary_verify_triggered": secondary_verify_triggered,
            "monitoring_decision": "reopen_mitigation" if secondary_verify_triggered else "monitoring_passed",
        }

    def supports(self, task_type: str, payload: Dict[str, Any], metadata: Dict[str, Any]) -> bool:
        if str(task_type) in self.supported_task_types:
            return True
        scenario = str(payload.get("scenario", "")).lower()
        signal = str(payload.get("signal", "")).lower()
        return "threat" in scenario or "lateral" in signal

    def handle(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        task_type = str(task_payload.get("task_type", "")).strip().lower()
        ioc_count = max(0, self._as_int(task_payload.get("ioc_count", 0), 0))
        affected_nodes = max(0, self._as_int(task_payload.get("affected_nodes", 0), 0))
        source_bundle = self._normalize_sources(task_payload)
        conflict_resolution = self._resolve_conflict(source_bundle)
        attack_mapping = self._attack_mapping(task_payload, str(conflict_resolution.get("resolved_claim", "")))
        if task_type in {"threat_assessment", "threat_conflict_resolution"}:
            threat_score = round(min(0.99, 0.35 + ioc_count * 0.01 + affected_nodes * 0.04), 3)
            severity = "critical" if threat_score >= 0.85 else ("high" if threat_score >= 0.7 else "medium")
            verdict = "confirmed_lateral_movement" if severity in {"critical", "high"} else "suspected_lateral_movement"
            return {
                "status": "processed",
                "decision": "escalate_and_contain" if severity in {"critical", "high"} else "monitor_and_collect",
                "severity": severity,
                "threat_score": threat_score,
                "verdict": verdict,
                "observed_nodes": affected_nodes,
                "ioc_count": ioc_count,
                "source_weights": dict(conflict_resolution.get("source_weights", {})),
                "source_confidence_level": str(conflict_resolution.get("source_confidence_level", "unknown")),
                "conflict_detected": bool(conflict_resolution.get("conflict_detected", False)),
                "conflict_set": list(conflict_resolution.get("conflict_set", [])),
                "resolved_claim": str(conflict_resolution.get("resolved_claim", "unknown")),
                "resolution_reason": str(conflict_resolution.get("resolution_reason", "unknown")),
                "weighted_confidence": float(conflict_resolution.get("weighted_confidence", 0.0)),
                "attack_tactics": list(attack_mapping.get("attack_tactics", [])),
                "attack_techniques": list(attack_mapping.get("attack_techniques", [])),
                "kill_chain_stage": str(attack_mapping.get("kill_chain_stage", "unknown")),
                "mapping_version": str(attack_mapping.get("mapping_version", "attack-v1")),
            }
        if task_type == "threat_mitigation":
            scout_severity = str(task_payload.get("scout_severity", "high")).lower()
            decision = "isolate_segments_and_block_iocs" if scout_severity in {"critical", "high"} else "tighten_rules_and_watchlist"
            playbook = self._playbook_plan(task_payload, attack_mapping)
            rollback = self._rollback_decision(task_payload, conflict_resolution)
            return {
                "status": "processed",
                "decision": decision,
                "severity": scout_severity,
                "mitigation_scope_nodes": affected_nodes,
                "blocked_iocs": max(ioc_count, int(round(ioc_count * 0.8))),
                "kill_chain_stage": str(task_payload.get("kill_chain_stage", attack_mapping.get("kill_chain_stage", "unknown"))),
                "attack_tactics": list(task_payload.get("attack_tactics", attack_mapping.get("attack_tactics", []))),
                "attack_techniques": list(task_payload.get("attack_techniques", attack_mapping.get("attack_techniques", []))),
                "resolved_claim": str(task_payload.get("resolved_claim", conflict_resolution.get("resolved_claim", "unknown"))),
                "playbook_id": str(playbook.get("playbook_id", "")),
                "playbook_steps": list(playbook.get("playbook_steps", [])),
                "playbook_execution_steps": list(playbook.get("playbook_execution_steps", [])),
                "rollback_plan": list(playbook.get("rollback_plan", [])),
                "rollback_required": bool(rollback.get("rollback_required", False)),
                "rollback_reason": str(rollback.get("rollback_reason", "not_required")),
                "rollback_confidence_threshold": float(rollback.get("rollback_confidence_threshold", 0.45)),
            }
        consensus_target = max(2, self._as_int(task_payload.get("consensus_target", 3), 3))
        votes = max(consensus_target, min(consensus_target + 2, consensus_target + (1 if ioc_count > 10 else 0)))
        consensus_ok = votes >= consensus_target
        monitoring = self._monitoring_window(task_payload, conflict_resolution)
        if bool(monitoring.get("secondary_verify_triggered", False)) and consensus_ok:
            status = "failed"
            decision = "secondary_verification_required"
        else:
            status = "processed" if consensus_ok else "failed"
            decision = "consensus_validated" if consensus_ok else "consensus_insufficient"
        return {
            "status": status,
            "decision": decision,
            "severity": "critical" if ioc_count > 15 else "high",
            "consensus_ok": consensus_ok,
            "consensus_votes": votes,
            "consensus_target": consensus_target,
            "source_confidence_level": str(conflict_resolution.get("source_confidence_level", "unknown")),
            "conflict_detected": bool(conflict_resolution.get("conflict_detected", False)),
            "resolved_claim": str(conflict_resolution.get("resolved_claim", "unknown")),
            "attack_tactics": list(task_payload.get("attack_tactics", attack_mapping.get("attack_tactics", []))),
            "attack_techniques": list(task_payload.get("attack_techniques", attack_mapping.get("attack_techniques", []))),
            "kill_chain_stage": str(task_payload.get("kill_chain_stage", attack_mapping.get("kill_chain_stage", "unknown"))),
            "mapping_version": str(attack_mapping.get("mapping_version", "attack-v1")),
            "monitoring_window_minutes": int(monitoring.get("monitoring_window_minutes", 30)),
            "residual_risk": float(monitoring.get("residual_risk", 0.0)),
            "residual_risk_threshold": float(monitoring.get("residual_risk_threshold", 0.55)),
            "secondary_verify_required": bool(monitoring.get("secondary_verify_required", True)),
            "secondary_verify_triggered": bool(monitoring.get("secondary_verify_triggered", False)),
            "monitoring_decision": str(monitoring.get("monitoring_decision", "monitoring_passed")),
        }
