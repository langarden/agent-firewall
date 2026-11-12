"""Rule containers. Rules are data, not code."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import ACTION_SEVERITY, DATA_SEVERITY

DEFAULT_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    "data.lookup": {"description": "read-only data lookup", "action_types": ["read"]},
    "content.publish": {
        "description": "publish prepared content",
        "action_types": ["read", "write", "outbound"],
    },
    "money.transfer": {
        "description": "transfer within fence limits",
        "action_types": ["read", "spend"],
    },
}


@dataclass
class RedLineRule:
    """A hard rule. If it matches, the verdict is ``deny`` regardless of anything else."""

    id: str
    description: str = ""
    action_types: Optional[tuple] = None
    data_classes: Optional[tuple] = None
    capabilities: Optional[tuple] = None
    amount_gte: Optional[float] = None
    effect: str = "deny"

    def matches(self, req: Any) -> bool:
        if self.action_types and getattr(req, "action_type", None) not in self.action_types:
            return False
        if self.data_classes and getattr(req, "data_class", None) not in self.data_classes:
            return False
        if self.capabilities and getattr(req, "target_capability", None) not in self.capabilities:
            return False
        if self.amount_gte is not None:
            amount = getattr(req, "amount", None) or 0.0
            if float(amount) < float(self.amount_gte):
                return False
        return True


@dataclass
class FenceLimits:
    """Spend fence. Amounts are in ``currency`` units, ``units`` decimal places."""

    per_call: float = 500.0
    per_day: float = 2000.0
    per_month: float = 5000.0
    currency: str = "CNY"
    units: int = 2


@dataclass
class RuleSet:
    capabilities: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    permissions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    red_lines: List[RedLineRule] = field(default_factory=list)
    fence: FenceLimits = field(default_factory=FenceLimits)

    # ---------------------------------------------------------------- helpers
    def register_caller(
        self,
        caller_id: str,
        capabilities: Optional[List[str]] = None,
        max_action: str = "read",
        max_data_class: str = "public",
    ) -> None:
        if max_action not in ACTION_SEVERITY:
            raise ValueError("unknown max_action: %s" % max_action)
        if max_data_class not in DATA_SEVERITY:
            raise ValueError("unknown max_data_class: %s" % max_data_class)
        self.permissions[caller_id] = {
            "capabilities": list(capabilities or []),
            "max_action": max_action,
            "max_data_class": max_data_class,
        }

    # ------------------------------------------------------------ factories
    @classmethod
    def demo(cls) -> "RuleSet":
        """Generic example rule set — intentionally free of any private rule."""
        red_lines = [
            RedLineRule(
                id="DEMO-RL-001",
                description="outbound transfer of restricted data is never allowed",
                action_types=("outbound",),
                data_classes=("restricted",),
            ),
            RedLineRule(
                id="DEMO-RL-002",
                description="writing restricted data is never allowed",
                action_types=("write",),
                data_classes=("restricted",),
            ),
            RedLineRule(
                id="DEMO-RL-003",
                description="single payment above the hard cap is never allowed",
                action_types=("spend",),
                amount_gte=100000.0,
            ),
        ]
        return cls(
            capabilities=json.loads(json.dumps(DEFAULT_CAPABILITIES)),
            permissions={},
            red_lines=red_lines,
            fence=FenceLimits(),
        )

    @classmethod
    def from_json(cls, path: str) -> "RuleSet":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        red_lines = [
            RedLineRule(
                id=item["id"],
                description=item.get("description", ""),
                action_types=tuple(item["action_types"]) if item.get("action_types") else None,
                data_classes=tuple(item["data_classes"]) if item.get("data_classes") else None,
                capabilities=tuple(item["capabilities"]) if item.get("capabilities") else None,
                amount_gte=item.get("amount_gte"),
            )
            for item in raw.get("red_lines", [])
        ]
        fence_raw = raw.get("fence", {})
        fence = FenceLimits(
            per_call=float(fence_raw.get("per_call", 500.0)),
            per_day=float(fence_raw.get("per_day", 2000.0)),
            per_month=float(fence_raw.get("per_month", 5000.0)),
            currency=fence_raw.get("currency", "CNY"),
            units=int(fence_raw.get("units", 2)),
        )
        return cls(
            capabilities=raw.get("capabilities", json.loads(json.dumps(DEFAULT_CAPABILITIES))),
            permissions={},
            red_lines=red_lines,
            fence=fence,
        )
