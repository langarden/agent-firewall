"""Semantic layer over stdio JSON lines (transport-agnostic).

Methods
-------
``audit.call``     params: AuditRequest fields        -> AuditVerdict dict
``audit.resolve``  params: {trace_id, approve}        -> AuditVerdict dict
``audit.pending``  params: {}                         -> {"pending": int}
``exit``                                              -> shuts the loop down

Binding this to MCP / A2A / HTTP is a transport concern and is intentionally not
implemented here.
"""

from __future__ import annotations

import json
from dataclasses import fields
from typing import Any, Dict, TextIO

from .engine import AuditGuard
from .models import AuditRequest

_REQUEST_FIELDS = {f.name for f in fields(AuditRequest)}


def handle(guard: AuditGuard, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if method == "audit.call":
        unknown = set(params) - _REQUEST_FIELDS
        if unknown:
            raise ValueError("unknown request fields: %s" % sorted(unknown))
        return guard.evaluate(AuditRequest(**params)).as_dict()

    if method == "audit.resolve":
        verdict = guard.resolve(params["trace_id"], bool(params.get("approve", False)))
        if verdict is None:
            return {"error": "ERR_UNKNOWN_TRACE", "trace_id": params["trace_id"]}
        return verdict.as_dict()

    if method == "audit.pending":
        return {"pending": guard.pending_count()}

    if method == "audit.trail.verify":
        return {"valid": guard.trail.verify(), "entries": len(guard.trail.entries)}

    raise ValueError("ERR_UNKNOWN_METHOD: %s" % method)


def serve(guard: AuditGuard, instream: TextIO, outstream: TextIO) -> None:
    for line in instream:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            outstream.write(json.dumps({"error": "ERR_BAD_JSON", "detail": str(exc)}) + "\n")
            outstream.flush()
            continue

        method = message.get("method", "")
        if method == "exit":
            outstream.write(json.dumps({"ok": True}) + "\n")
            outstream.flush()
            return

        try:
            result = handle(guard, method, message.get("params", {}) or {})
            response = {"id": message.get("id"), "result": result}
        except Exception as exc:  # noqa: BLE001 - the transport never crashes the guard
            response = {"id": message.get("id"), "error": str(exc)}
        outstream.write(json.dumps(response, ensure_ascii=False) + "\n")
        outstream.flush()
