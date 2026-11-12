# -*- coding: utf-8 -*-
"""agent-firewall — a fail-closed MCP tool-call firewall.

Public surface::

    from agent_firewall import (
        McpFirewall, FirewallResult,
        ToolPolicy, RedLinePattern, load_policy,
        parse_tool_call, make_error, is_tool_call,
    )
"""

from .models import FirewallResult, RedLinePattern, ToolPolicy, load_policy
from .rpc import is_tool_call, make_error, make_success, parse_tool_call
from .firewall import McpFirewall

__version__ = "0.1.0"

__all__ = [
    "McpFirewall",
    "FirewallResult",
    "ToolPolicy",
    "RedLinePattern",
    "load_policy",
    "parse_tool_call",
    "is_tool_call",
    "make_error",
    "make_success",
    "__version__",
]