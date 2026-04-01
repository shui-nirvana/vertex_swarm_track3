"""Scout module for Vertex Swarm Track3."""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict

from security_monitor.integration.ai_engine import AIRiskEngine
from security_monitor.swarm.agent_node import AgentNode
from security_monitor.swarm.messages import THREAT_GOSSIP

logger = logging.getLogger(__name__)

@dataclass
class ScoutAgent(AgentNode):
    """
    Scout Agent: Responsible for threat detection and initial risk assessment.
    Uses AIRiskEngine to analyze potential threats.
    """
    ai_engine: AIRiskEngine = field(default_factory=AIRiskEngine)
    
    def __post_init__(self):
        """Purpose: Post init.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic post init rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        # Override capability
        self.capability = "scout"

    def analyze_target(self, target_address: str, amount: float = 0.0) -> Dict[str, Any]:
        """Analyze a target using the AI Risk Engine."""
        logger.info(f"Scout {self.agent_id} analyzing target {target_address}")
        risk_assessment = self.ai_engine.analyze_defense_request(target_address, amount)
        
        if not risk_assessment.get("safe", False):
            logger.warning(f"Threat detected by {self.agent_id}: {risk_assessment}")
            self.broadcast_threat(target_address, risk_assessment)
            
        return risk_assessment

    def create_business_request(
        self,
        task_id: str,
        target_address: str,
        amount: float,
        latency_ms_max: int = 500,
        resource_units: int = 1,
    ) -> Dict[str, Any]:
        assessment = self.analyze_target(target_address=target_address, amount=amount)
        accepted = bool(assessment.get("safe", False))
        suggested_price = float(assessment.get("suggested_price", 0.0))
        estimated_cost = round(max(0.1, suggested_price), 6)
        budget_ceiling = round(max(0.1, estimated_cost * 10.0), 6)
        requirement = {
            "accepted": accepted,
            "task_id": str(task_id),
            "mission": str(target_address),
            "estimated_cost": estimated_cost,
            "budget_ceiling": budget_ceiling,
            "constraints": {
                "latency_ms_max": int(latency_ms_max),
                "resource_units": max(1, int(resource_units)),
                "required_quota": max(1, int(resource_units)),
                "estimated_cost": estimated_cost,
                "budget_limit": budget_ceiling,
                "risk": str(assessment.get("risk", "UNKNOWN")),
            },
            "assessment": assessment,
        }
        if not accepted:
            self.broadcast_threat(str(target_address), assessment)
        return requirement

    def propose_business_task(self, requirement: Dict[str, Any]) -> bool:
        """Purpose: Propose business task.

        Inputs:
        - Uses function parameters plus relevant in-memory runtime state.

        Behavior:
        - Validates/normalizes key fields before doing state transitions.
        - Executes deterministic propose business task rules so all nodes converge on the same result.

        Outputs:
        - Returns normalized data or state updates consumed by downstream logic.
        """
        if not bool(requirement.get("accepted", False)):
            return False
        self.offer_task(
            task_id=str(requirement["task_id"]),
            mission=str(requirement["mission"]),
            budget_ceiling=float(requirement["budget_ceiling"]),
            constraints=dict(requirement.get("constraints", {})),
        )
        return True

    def broadcast_threat(self, target: str, details: Dict[str, Any]) -> None:
        """Broadcast threat intelligence to the Hive Memory."""
        payload = {
            "threat_id": target,
            "details": str(details),
            "reporter": self.agent_id,
        }
        self._broadcast(THREAT_GOSSIP, payload)
