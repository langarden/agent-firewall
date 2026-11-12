# -*- coding: utf-8 -*-
"""Demo scenarios for agent-firewall (all data is synthetic)."""

from __future__ import annotations

from .firewall import McpFirewall
from .models import RedLinePattern, ToolPolicy


def demo_policy() -> ToolPolicy:
    """A generic, safe-by-default policy for the demo."""
    return ToolPolicy(
        allowed_tools=["files.read", "files.write", "search.query"],
        blocked_tools=["shell.exec", "network.namespace"],
        red_lines=[
            RedLinePattern(
                id="DEMO-RL-001",
                description="files.write must never touch the system secrets path",
                tool="files.write",
                argument="path",
                argument_regex=r"(/etc/|system32|secrets|\.env)",
            ),
            RedLinePattern(
                id="DEMO-RL-002",
                description="search.query must not accept sql keywords (injection probe)",
                tool="search.query",
                argument="q",
                argument_regex=r"(DROP TABLE|DELETE FROM|OR 1=1)",
            ),
        ],
        notes="demo policy — deny by default, allowlist only",
    )


def run_demo() -> list:
    fw = McpFirewall(policy=demo_policy())
    messages = [
        # 1. non-tool message passes through
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        # 2. allowed tool
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "files.read", "arguments": {"path": "docs/notes.md"}},
        },
        # 3. blocked tool (high priority)
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "shell.exec", "arguments": {"command": "rm -rf /"}},
        },
        # 4. tool not in allowlist (default deny)
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "db.drop", "arguments": {}},
        },
        # 5. argument red line
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "files.write", "arguments": {"path": "/etc/hosts", "content": "x"}},
        },
        # 6. sql injection red line
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "search.query", "arguments": {"q": "users; DROP TABLE users"}},
        },
    ]
    results = []
    for msg in messages:
        result, response = fw.inspect(msg)
        results.append(
            {
                "request_id": msg.get("id"),
                "method": msg.get("method", ""),
                "tool": result.tool,
                "decision": result.decision,
                "reason_code": result.reason_code,
                "forwarded": result.decision == "allow",
            }
        )
    return results


if __name__ == "__main__":
    for row in run_demo():
        print(row)