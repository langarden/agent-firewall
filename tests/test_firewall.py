# -*- coding: utf-8 -*-
"""agent-firewall tests — rpc + models + firewall + fail-closed + trail."""

import json
import os
import tempfile
import unittest

from agent_firewall import (
    McpFirewall,
    RedLinePattern,
    ToolPolicy,
    is_tool_call,
    make_error,
    parse_tool_call,
)
from agent_firewall.demo import demo_policy
from agent_firewall.models import load_policy


class RpcTest(unittest.TestCase):
    def test_is_tool_call_positive(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}}
        self.assertTrue(is_tool_call(msg))

    def test_is_tool_call_false_for_other_methods(self):
        self.assertFalse(is_tool_call({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        self.assertFalse(is_tool_call({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        self.assertFalse(is_tool_call(None))
        self.assertFalse(is_tool_call("not a dict"))

    def test_parse_tool_call(self):
        msg = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "files.read", "arguments": {"path": "a.txt"}},
        }
        parsed = parse_tool_call(msg)
        self.assertIsNotNone(parsed)
        tool, arguments, req_id = parsed
        self.assertEqual(tool, "files.read")
        self.assertEqual(arguments, {"path": "a.txt"})
        self.assertEqual(req_id, 7)

    def test_parse_malformed_returns_none(self):
        self.assertIsNone(parse_tool_call({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}))
        self.assertIsNone(parse_tool_call({"jsonrpc": "2.0", "id": 1,
                                           "method": "tools/call",
                                           "params": {"name": "x", "arguments": "bad"}}))

    def test_make_error_shape(self):
        err = make_error(3, message="denied", data={"reason": "x"})
        self.assertEqual(err["jsonrpc"], "2.0")
        self.assertEqual(err["id"], 3)
        self.assertIn("error", err)


class PolicyTest(unittest.TestCase):
    def test_default_deny(self):
        p = ToolPolicy()
        self.assertFalse(p.allows("anything"))

    def test_allowlist(self):
        p = ToolPolicy(allowed_tools=["a", "b"])
        self.assertTrue(p.allows("a"))
        self.assertFalse(p.allows("c"))

    def test_allow_all_wildcard(self):
        p = ToolPolicy(allowed_tools=["*"])
        self.assertTrue(p.allows("anything"))

    def test_blocked_wins_over_allowlist(self):
        p = ToolPolicy(allowed_tools=["*"], blocked_tools=["shell.exec"])
        self.assertFalse(p.allows("shell.exec"))
        self.assertTrue(p.allows("files.read"))

    def test_red_line_match(self):
        rule = RedLinePattern(id="r1", tool="files.write", argument="path",
                              argument_regex=r"(/etc/|secrets)")
        self.assertTrue(rule.matches("files.write", {"path": "/etc/hosts"}))
        self.assertFalse(rule.matches("files.write", {"path": "docs/ok.txt"}))
        self.assertFalse(rule.matches("other.tool", {"path": "/etc/hosts"}))

    def test_load_policy_from_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump(
                {
                    "allowed_tools": ["files.read"],
                    "blocked_tools": ["shell.exec"],
                    "red_lines": [{"id": "R1", "tool": "shell.exec"}],
                },
                fh,
            )
            path = fh.name
        try:
            p = load_policy(path)
            self.assertTrue(p.allows("files.read"))
            self.assertFalse(p.allows("shell.exec"))
        finally:
            os.unlink(path)


class FirewallTest(unittest.TestCase):
    def setUp(self):
        self.fw = McpFirewall(policy=demo_policy())

    def test_passthrough_non_tool(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        result, response = self.fw.inspect(msg)
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.reason_code, "PASSTHROUGH")
        self.assertIs(response, msg)

    def test_allow_allowed_tool(self):
        msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "files.read", "arguments": {"path": "a.txt"}}}
        result, response = self.fw.inspect(msg)
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.reason_code, "ALLOWED")
        self.assertIs(response, msg)

    def test_deny_blocked_tool(self):
        msg = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
               "params": {"name": "shell.exec", "arguments": {"command": "rm -rf /"}}}
        result, response = self.fw.inspect(msg)
        self.assertEqual(result.decision, "deny")
        self.assertEqual(result.reason_code, "ERR_TOOL_BLOCKED")
        self.assertIn("error", response)

    def test_deny_not_in_allowlist(self):
        msg = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
               "params": {"name": "db.drop", "arguments": {}}}
        result, response = self.fw.inspect(msg)
        self.assertEqual(result.decision, "deny")
        self.assertEqual(result.reason_code, "ERR_TOOL_NOT_ALLOWED")

    def test_deny_argument_red_line(self):
        msg = {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
               "params": {"name": "files.write",
                          "arguments": {"path": "/etc/hosts", "content": "hack"}}}
        result, _ = self.fw.inspect(msg)
        self.assertEqual(result.decision, "deny")
        self.assertEqual(result.reason_code, "ERR_RED_LINE")
        self.assertEqual(result.matched_rules, ["DEMO-RL-001"])

    def test_deny_sql_injection_red_line(self):
        msg = {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
               "params": {"name": "search.query",
                          "arguments": {"q": "users; DROP TABLE users"}}}
        result, _ = self.fw.inspect(msg)
        self.assertEqual(result.decision, "deny")
        self.assertEqual(result.matched_rules, ["DEMO-RL-002"])

    def test_fail_closed_on_garbage(self):
        # malformed tools/call must never be forwarded
        msg = {"jsonrpc": "2.0", "id": 9, "method": "tools/call"}
        result, response = self.fw.inspect(msg)
        self.assertEqual(result.decision, "deny")
        self.assertEqual(result.reason_code, "ERR_MALFORMED_REQUEST")

    def test_fail_closed_on_inspect_exception(self):
        result, response = self.fw.inspect("not-a-dict")
        # inspect() never raises and returns deny shape on unexpected input type
        self.assertEqual(result.decision, "deny")

    def test_no_raw_arguments_in_trail(self):
        msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "files.read",
                          "arguments": {"path": "secret-token-value-xyz"}}}
        self.fw.inspect(msg)
        raw = json.dumps(self.fw.trail, ensure_ascii=False)
        self.assertNotIn("secret-token-value-xyz", raw)
        self.assertNotIn("path", raw.replace("payload_hash", ""))

    def test_trail_verify(self):
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "files.read", "arguments": {"path": "a"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "shell.exec", "arguments": {"command": "rm"}}},
        ]
        for m in msgs:
            self.fw.inspect(m)
        self.assertTrue(self.fw.verify_trail())

    def test_trail_tamper_detected(self):
        self.fw.inspect({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "files.read", "arguments": {}}})
        first = self.fw.trail[0]
        tampered = dict(first)
        tampered["tool"] = "files.write"
        self.fw._entries[0] = tampered  # noqa: SLF001 - intentional test hook
        self.assertFalse(self.fw.verify_trail())

    def test_trail_file_is_append_only_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "trail.jsonl")
            fw = McpFirewall(policy=demo_policy(), trail_path=path)
            fw.inspect({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "files.read", "arguments": {}}})
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["decision"], "allow")
            self.assertIn("entry_hash", entry)


# Allow running the demo policy inspect as a quick smoke test
class DemoSmokeTest(unittest.TestCase):
    def test_run_demo(self):
        from agent_firewall.demo import run_demo

        rows = run_demo()
        decisions = [r["decision"] for r in rows]
        self.assertEqual(decisions, ["allow", "allow", "deny", "deny", "deny", "deny"])


if __name__ == "__main__":
    unittest.main()