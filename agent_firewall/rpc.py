# -*- coding: utf-8 -*-
"""JSON-RPC 2.0 helpers for MCP message inspection and denial responses.

The firewall never guesses about the wire format: only ``tools/call`` requests
are adjudicated, everything else passes through untouched (recorded only).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

# MCP method names (MCP over JSON-RPC 2.0)
M_TOOLS_CALL = "tools/call"
M_TOOLS_LIST = "tools/list"

JSONRPC = "2.0"

# JSON-RPC standard error codes
ERR_CODE_PARSE = -32700
ERR_CODE_INVALID_REQUEST = -32600
ERR_CODE_METHOD_NOT_FOUND = -32601
ERR_CODE_INVALID_PARAMS = -32602
ERR_CODE_INTERNAL = -32603
ERR_CODE_TOOL_DENIED = -32000  # firewall denial (application error range)


def is_tool_call(message: Dict[str, Any]) -> bool:
    """True if the message is a JSON-RPC request invoking ``tools/call``."""
    return (
        isinstance(message, dict)
        and message.get("method") == M_TOOLS_CALL
        and "id" in message
    )


def parse_tool_call(message: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any], Any]]:
    """Extract (tool_name, arguments, id) from a tools/call request.

    Returns None when the message is malformed in a way that cannot yield a
    tool name; the caller may then either pass through or deny.
    """
    if not is_tool_call(message):
        return None
    params = message.get("params")
    if not isinstance(params, dict):
        return None
    tool = params.get("name")
    if not isinstance(tool, str) or not tool:
        return None
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return None
    return tool, arguments, message.get("id")


def make_success(request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    """Build a JSON-RPC success response."""
    return {"jsonrpc": JSONRPC, "id": request_id, "result": result}


def make_error(
    request_id: Any,
    code: int = ERR_CODE_TOOL_DENIED,
    message: str = "tool call denied by firewall",
    data: Any = None,
) -> Dict[str, Any]:
    """Build a JSON-RPC error response (the shape the client sees on deny)."""
    error: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": JSONRPC, "id": request_id, "error": error}


def to_denial_response(
    request_id: Any,
    reason_code: str = "ERR_TOOL_DENIED",
    note: str = "",
    matched_rules: Optional[list] = None,
) -> Dict[str, Any]:
    """Build the JSON-RPC error response returned to the MCP client on deny."""
    return make_error(
        request_id,
        code=ERR_CODE_TOOL_DENIED,
        message="firewall: %s" % reason_code,
        data={"reason_code": reason_code, "note": note, "matched_rules": list(matched_rules or [])},
    )