"""Data models for agent-call-audit (generic, de-identified edition)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, List, Optional

# Ordered by severity. The index is the severity score used by the engine.
ACTION_TYPES = ("read", "write", "outbound", "spend")
DATA_CLASSES = ("public", "internal", "sensitive", "restricted")

ACTION_SEVERITY = {name: idx for idx, name in enumerate(ACTION_TYPES)}
DATA_SEVERITY = {name: idx for idx, name in enumerate(DATA_CLASSES)}

DECISIONS = ("allow", "deny", "human")
RISK_LEVELS = ("low", "medium", "high")


@dataclass
class AuditRequest:
    """A single tool call awaiting a verdict.

    ``payload`` is optional and only used to re-verify ``request_hash`` on the
    server side. Whatever you pass in ``payload`` is **never persisted**.
    """

    caller_id: str
    credential: str
    target_capability: str
    action_type: str
    data_class: str
    request_hash: str
    nonce: str
    timestamp: float
    idempotency_key: Optional[str] = None
    amount: Optional[float] = None
    payload: Optional[Any] = None
    currency: str = "CNY"


@dataclass
class AuditVerdict:
    decision: str                  # allow | deny | human
    reason_code: str               # machine-readable, e.g. ERR_REPLAY
    risk_level: str                # low | medium | high
    matched_rules: List[str] = field(default_factory=list)
    trace_id: str = ""
    created_at: float = 0.0
    idempotent_replay: bool = False
    expires_at: Optional[float] = None   # only set for decision == "human"

    def as_dict(self) -> dict:
        return asdict(self)
