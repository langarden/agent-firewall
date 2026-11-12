# -*- coding: utf-8 -*-
"""Data models for agent-firewall.

MCP servers speak JSON-RPC 2.0. The firewall sits in front of a server and
inspects every ``tools/call`` request on the wire. Policy is data, not code.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RedLinePattern:
    """A deny-when-matched rule. Fields are ANDed; empty fields match anything."""

    id: str
    description: str = ""
    tool: Optional[str] = None              # exact tool name ('' means any)
    argument: Optional[str] = None          # JSON path (dotted) into arguments
    argument_regex: Optional[str] = None    # regex against the extracted value
    effect: str = "deny"

    def matches_tool(self, tool: str) -> bool:
        if self.tool and self.tool != "*" and self.tool != tool:
            return False
        return True

    def matches_arguments(self, arguments: Dict[str, Any]) -> bool:
        if not self.argument:
            return True
        value = _dig(arguments, self.argument)
        if value is None:
            return False
        if self.argument_regex:
            import re

            try:
                return re.search(self.argument_regex, str(value)) is not None
            except re.error:
                return False
        return True

    def matches(self, tool: str, arguments: Dict[str, Any]) -> bool:
        return self.matches_tool(tool) and self.matches_arguments(arguments)


@dataclass
class ToolPolicy:
    """Declarative allow/deny policy for MCP tool calls.

    Default posture is FAIL-CLOSED: with an empty policy, every tool call is
    denied. ``allowed_tools`` grants entry; empty means nothing is allowed.
    ``blocked_tools`` plus argument-level red lines always win, regardless of
    the allowlist.
    """

    allowed_tools: List[str] = field(default_factory=list)   # exact names; ['*'] = allow all
    blocked_tools: List[str] = field(default_factory=list)   # exact names, highest priority
    red_lines: List[RedLinePattern] = field(default_factory=list)  # argument-level denies
    notes: str = ""

    def allows(self, tool: str) -> bool:
        if tool in self.blocked_tools:
            return False
        if "*" in self.allowed_tools:
            return True
        return tool in self.allowed_tools

    def red_line_match(self, tool: str, arguments: Dict[str, Any]) -> Optional[RedLinePattern]:
        for rule in self.red_lines:
            if rule.matches(tool, arguments):
                return rule
        return None


@dataclass
class FirewallResult:
    """Outcome of inspecting one JSON-RPC message."""

    decision: str              # allow | deny
    reason_code: str           # ALLOWED / ERR_TOOL_BLOCKED / ERR_TOOL_NOT_ALLOWED / ERR_RED_LINE
    tool: str = ""
    request_id: Any = None
    matched_rules: List[str] = field(default_factory=list)
    note: str = ""
    trace_id: str = ""         # hash-chain trace id ('' for non tool-call messages)

    def as_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- loading
def load_policy(path: str) -> ToolPolicy:
    """Load a ToolPolicy from a JSON file (schema-friendly)."""
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    red_lines = [
        RedLinePattern(
            id=item["id"],
            description=item.get("description", ""),
            tool=item.get("tool"),
            argument=item.get("argument"),
            argument_regex=item.get("argument_regex"),
            effect=item.get("effect", "deny"),
        )
        for item in raw.get("red_lines", [])
    ]
    return ToolPolicy(
        allowed_tools=list(raw.get("allowed_tools", [])),
        blocked_tools=list(raw.get("blocked_tools", [])),
        red_lines=red_lines,
        notes=raw.get("notes", ""),
    )


def _dig(obj: Any, path: str) -> Any:
    """Dotted-path lookup into a dict (e.g. 'command' or 'nested.value')."""
    current = obj
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current