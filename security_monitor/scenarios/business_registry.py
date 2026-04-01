"""Business scenario registry for type-driven bootstrap missions."""

from security_monitor.scenarios import (
    agent_marketplace,
    compute_marketplace,
    distributed_rag,
    risk_control,
    threat_intel,
)

BUSINESS_TEMPLATE_FILES: dict[str, str] = {
    risk_control.BUSINESS_TYPE: risk_control.DEFAULT_TEMPLATE_FILENAME,
    threat_intel.BUSINESS_TYPE: threat_intel.DEFAULT_TEMPLATE_FILENAME,
    agent_marketplace.BUSINESS_TYPE: agent_marketplace.DEFAULT_TEMPLATE_FILENAME,
    distributed_rag.BUSINESS_TYPE: distributed_rag.DEFAULT_TEMPLATE_FILENAME,
    compute_marketplace.BUSINESS_TYPE: compute_marketplace.DEFAULT_TEMPLATE_FILENAME,
}

DEFAULT_BUSINESS_TYPE = risk_control.BUSINESS_TYPE
