# -*- coding: utf-8 -*-
"""McpFirewall — fail-closed, hash-chained MCP tool-call firewall.

Design axioms (shared with the Verifiable-agent family):

  * Rule priority:  blocked_tools > red_lines > allowed_tools > default deny
  * Fail-closed:  any unexpected fault resolves to ``deny``, never ``allow``
  * Privacy by default:  raw tool arguments are NEVER persisted; only a
    sha256 of the canonical payload is recorded in the hash chain
  * Tamper-evident trail:  every adjudication appends a JSONL entry whose
    hash links to the previous entry; ``verify_trail()`` proves the chain
  * Rules are data:  policy is loaded from a JSON file, not hard-coded

The ``inspect()`` method accepts a single JSON-RPC message (dict) exactly as
it arrived from an MCP client. Return semantics:

  * ``decision == "allow"``  -> forward ``response`` (the original message) to
    the MCP server untouched
  * ``decision == "deny"``   -> respond with ``response`` (a JSON-RPC error)
    and never contact the MCP server

For non tool-call messages (initialize, tools/list, ping, ...) the message
passes through with ``decision == "allow"`` and ``reason_code == "PASSTHROUGH"``.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from .models import FirewallResult, ToolPolicy
from .rpc import is_tool_call, parse_tool_call, to_denial_response

GENESIS_HASH = "0" * 64

ALLOWED = "ALLOWED"
PASSTHROUGH = "PASSTHROUGH"
ERR_BLOCKED = "ERR_TOOL_BLOCKED"
ERR_NOT_ALLOWED = "ERR_TOOL_NOT_ALLOWED"
ERR_RED_LINE = "ERR_RED_LINE"
ERR_INTERNAL = "ERR_INTERNAL_FAIL_CLOSED"
ERR_MALFORMED = "ERR_MALFORMED_REQUEST"


def _canonical(record: Dict[str, Any]) -> bytes:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class McpFirewall:
    """Inspect MCP JSON-RPC messages and deny disallowed tool calls."""

    def __init__(
        self,
        policy: Optional[ToolPolicy] = None,
        trail_path: Optional[str] = None,
        clock=None,
        record_passthrough: bool = False,
    ) -> None:
        self.policy = policy if policy is not None else ToolPolicy()  # default: deny all
        self.trail_path = trail_path
        self.clock = clock or time.time
        self.record_passthrough = record_passthrough
        self._entries: list = []
        self._lock = threading.Lock()
        if trail_path:
            import os

            directory = os.path.dirname(os.path.abspath(trail_path))
            if directory:
                os.makedirs(directory, exist_ok=True)

    # ------------------------------------------------------------------ API
    def inspect(self, message: Dict[str, Any]) -> Tuple[FirewallResult, Dict[str, Any]]:
        """Inspect one JSON-RPC message.

        Returns (result, response). When result.decision == "allow", ``response``
        is the original message and should be forwarded. When "deny", ``response``
        is a JSON-RPC error meant for the client; do NOT contact the MCP server.
        """
        try:
            return self._inspect(message)
        except Exception as exc:  # noqa: BLE001 - intentional fail-closed
            result = FirewallResult(
                decision="deny",
                reason_code=ERR_INTERNAL,
                request_id=message.get("id") if isinstance(message, dict) else None,
                note="firewall internal error: %s" % type(exc).__name__,
            )
            return result, to_denial_response(
                result.request_id, result.reason_code, result.note, result.matched_rules
            )

    # --------------------------------------------------------------- helpers
    def verify_trail(self) -> bool:
        """Offline-verifiable integrity check of the whole hash chain."""
        prev = GENESIS_HASH
        for entry in self._entries:
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            if body.get("prev_hash") != prev:
                return False
            if _sha256(_canonical(body)) != entry.get("entry_hash"):
                return False
            prev = entry["entry_hash"]
        return True

    @property
    def trail(self) -> list:
        """A defensive copy of the in-memory trail (JSONL entries)."""
        with self._lock:
            return list(self._entries)

    # ------------------------------------------------------------- internals
    def _inspect(self, message: Dict[str, Any]) -> Tuple[FirewallResult, Dict[str, Any]]:
        if not isinstance(message, dict):
            # Cannot verify content -> never forward (fail-closed).
            result = FirewallResult(decision="deny", reason_code=ERR_INTERNAL,
                                    request_id=None,
                                    note="message is not a JSON-RPC object")
            return result, to_denial_response(None, ERR_INTERNAL,
                                              "message is not a JSON-RPC object")

        if "id" not in message:
            # A notification (no id) — not a request we can adjudicate; pass
            # through only the protocol-level handshake, never a tool call.
            if is_tool_call(message):
                result = FirewallResult(decision="deny", reason_code=ERR_MALFORMED,
                                        request_id=None)
                return result, to_denial_response(None, ERR_MALFORMED,
                                                  "tools/call notification without id")
            result = FirewallResult(decision="allow", reason_code=PASSTHROUGH,
                                    request_id=None)
            return result, message

        request_id = message.get("id")
        if not is_tool_call(message):
            if self.record_passthrough:
                self._append("passthrough", request_id, "", "")
            result = FirewallResult(decision="allow", reason_code=PASSTHROUGH,
                                    request_id=request_id)
            return result, message

        parsed = parse_tool_call(message)
        if parsed is None:
            # tools/call but malformed: fail-closed — deny before the server
            # gets a chance to interpret garbage.
            result = FirewallResult(decision="deny", reason_code=ERR_MALFORMED,
                                    request_id=request_id)
            return result, to_denial_response(request_id, ERR_MALFORMED,
                                              "malformed tools/call request")

        tool, arguments, req_id = parsed

        # hash only, never the raw arguments
        payload_hash = _sha256(_canonical({"tool": tool, "arguments": arguments}))

        # 1. blocked tools (highest priority)
        if tool in self.policy.blocked_tools:
            return self._deny(req_id, tool, ERR_BLOCKED, [], payload_hash,
                              "tool is on the blocklist")

        # 2. argument-level red lines
        red = self.policy.red_line_match(tool, arguments)
        if red is not None:
            return self._deny(req_id, tool, ERR_RED_LINE, [red.id], payload_hash,
                              red.description or "argument red line matched")

        # 3. allowlist (default deny)
        if not self.policy.allows(tool):
            return self._deny(req_id, tool, ERR_NOT_ALLOWED, [], payload_hash,
                              "tool not in allowlist (fail-closed)")

        # 4. allow
        return self._allow(req_id, tool, payload_hash, message)

    def _deny(self, req_id: Any, tool: str, reason: str, matched_rules: list,
              payload_hash: str, note: str) -> Tuple[FirewallResult, Dict[str, Any]]:
        trace_id = uuid.uuid4().hex
        self._append("deny", req_id, tool, payload_hash, reason, matched_rules, note)
        result = FirewallResult(
            decision="deny",
            reason_code=reason,
            tool=tool,
            request_id=req_id,
            matched_rules=list(matched_rules),
            note=note,
            trace_id=trace_id,
        )
        response = to_denial_response(req_id, reason, note, matched_rules)
        return result, response

    def _allow(self, req_id: Any, tool: str, payload_hash: str,
               original: Dict[str, Any]) -> Tuple[FirewallResult, Dict[str, Any]]:
        trace_id = uuid.uuid4().hex
        self._append("allow", req_id, tool, payload_hash)
        result = FirewallResult(
            decision="allow",
            reason_code=ALLOWED,
            tool=tool,
            request_id=req_id,
            trace_id=trace_id,
        )
        return result, original

    def _append(self, decision: str, request_id: Any, tool: str, payload_hash: str,
                reason_code: str = ALLOWED, matched_rules: Optional[list] = None,
                note: str = "") -> None:
        with self._lock:
            entry = {
                "ts": self.clock(),
                "trace_id": uuid.uuid4().hex,
                "request_id": request_id,
                "tool": tool,                     # tool name has no secrets
                "payload_hash": payload_hash,     # sha256 only: no raw arguments
                "decision": decision,
                "reason_code": reason_code,
                "matched_rules": list(matched_rules or []),
                "note": note,
            }
            entry["prev_hash"] = self._entries[-1]["entry_hash"] if self._entries else GENESIS_HASH
            entry["entry_hash"] = _sha256(_canonical(entry))
            self._entries.append(entry)
            if self.trail_path:
                with open(self.trail_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")