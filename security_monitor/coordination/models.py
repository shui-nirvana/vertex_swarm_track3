from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict


class TaskState(str, Enum):
    PENDING = "pending"
    ROUTED = "routed"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass(slots=True)
class CoordinationTask:
    task_id: str
    task_type: str
    payload: Dict[str, Any]
    source_agent: str = ""
    target_agent: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class TransportMessage:
    topic: str
    payload: Dict[str, Any]
    message_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
