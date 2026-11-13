# -*- coding: utf-8 -*-
"""agent-firewall — fail-closed MCP tool-call firewall CLI (zero-dep).

Adjudicate one JSON-RPC message against a policy, or verify the trail.

Usage:
    agent-firewall check --request-json '<msg>' [--policy policy.json] [--trail t.jsonl]
    agent-firewall check --request-file req.json [--policy policy.json] [--trail t.jsonl]
    agent-firewall verify --trail t.jsonl
    agent-firewall status [--policy policy.json]

Exit codes: 0 = allow / OK, 2 = deny / fail, 3 = error.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional

from agent_firewall import McpFirewall, ToolPolicy, load_policy


def _load_policy(path: Optional[str]) -> ToolPolicy:
    if path:
        return load_policy(path)
    # default: deny all (fail-closed); caller must pass a policy for real use
    return ToolPolicy()


def cmd_check(args: argparse.Namespace) -> int:
    if args.request_file:
        try:
            with open(args.request_file, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"error": "bad request file: %s" % exc}, ensure_ascii=False))
            return 3
    else:
        try:
            raw = json.loads(args.request_json or "{}")
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"error": "bad request json: %s" % exc}, ensure_ascii=False))
            return 3

    try:
        fw = McpFirewall(policy=_load_policy(args.policy), trail_path=args.trail)
        result, response = fw.inspect(raw)
        out = {
            "decision": result.decision,
            "reason_code": result.reason_code,
            "tool": getattr(result, "tool", None),
            "request_id": result.request_id,
            "matched_rules": list(getattr(result, "matched_rules", []) or []),
            "trace_id": getattr(result, "trace_id", None),
            "fail_closed": True,
            "response": response,
        }
        print(json.dumps(out, ensure_ascii=False, sort_keys=True))
        return 0 if result.decision == "allow" else 2
    except Exception as exc:  # noqa: BLE001 - fail-closed boundary
        print(json.dumps({"error": "firewall failure (fail-closed): %s" % exc},
                         ensure_ascii=False))
        return 3


def cmd_verify(args: argparse.Namespace) -> int:
    # Rebuild the trail by re-verifying from disk (independent of in-memory state).
    entries = []
    try:
        with open(args.trail, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": "cannot read trail: %s" % exc},
                         ensure_ascii=False))
        return 2

    import hashlib

    prev = "0" * 64
    ok = True
    for entry in entries:
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        if body.get("prev_hash") != prev:
            ok = False
            break
        if hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, default=str).encode("utf-8")).hexdigest() != entry.get("entry_hash"):
            ok = False
            break
        prev = entry["entry_hash"]
    print(json.dumps({"ok": ok, "entries": len(entries), "trail": args.trail},
                     ensure_ascii=False, sort_keys=True))
    return 0 if ok else 2


def cmd_status(args: argparse.Namespace) -> int:
    try:
        policy = _load_policy(args.policy)
        problems = []
        # install/engine is OK even with deny-all default; warn if no policy
        if not policy.allowed_tools and not policy.blocked_tools:
            problems.append("empty policy (deny-all default) - pass --policy for real use")
        # install check: engine loads, command reachable -> ok:true for Connector auth
        print(json.dumps({"ok": True, "warning": problems,
                          "allowed": len(policy.allowed_tools),
                          "blocked": len(policy.blocked_tools)},
                         ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "problems": ["%s" % exc]}, ensure_ascii=False))
        return 3


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-firewall",
                                     description="Fail-closed MCP tool-call firewall.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="adjudicate one JSON-RPC message")
    p_check.add_argument("--request-json", default=None)
    p_check.add_argument("--request-file", default=None)
    p_check.add_argument("--policy", default=None, help="policy JSON (default deny-all)")
    p_check.add_argument("--trail", default=None, help="append verdict to hash-chained trail")
    p_check.set_defaults(fn=cmd_check)

    p_verify = sub.add_parser("verify", help="verify a hash-chained trail")
    p_verify.add_argument("--trail", required=True)
    p_verify.set_defaults(fn=cmd_verify)

    p_status = sub.add_parser("status", help="self-check install and policy")
    p_status.add_argument("--policy", default=None)
    p_status.set_defaults(fn=cmd_status)

    args = parser.parse_args(argv)
    try:
        return int(args.fn(args))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": "unexpected: %s" % exc}, ensure_ascii=False))
        return 3


if __name__ == "__main__":
    sys.exit(main())
