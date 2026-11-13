# agent-firewall

> **Fail-closed MCP tool-call firewall for AI agents.**  
> Give your agent's MCP tools a local firewall — deny by default, allowlist only, every verdict hash-chained.

```bash
pip install frt-agent-firewall       # zero deps, Python 3.9+
```

<a href="https://gitcode.com/gcw_MKhSyoGN/agent-firewall"><img src="https://img.shields.io/badge/GitCode-gcw_MKhSyoGN%2Fagent-firewall-blue" alt="GitCode"></a>
<a href="https://github.com/langarden/agent-firewall"><img src="https://img.shields.io/badge/GitHub-langarden%2Fagent-firewall-black" alt="GitHub"></a>
<img src="https://img.shields.io/badge/tests-24%20passed-green" alt="tests">
<img src="https://img.shields.io/badge/license-MIT-yellow" alt="license">
<img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="python">

`agent-firewall` is a zero-dependency Python library that sits **between an MCP client and its server** and inspects every `tools/call` message on the wire. It is part of the **Verifiable-agent family** — same design language as `agent-call-audit`, `agent-memory-ledger`, `agent-audit-gateway`, `agent-route-grid`.

> ⚠️ **Research prototype — AI-assisted development.** This is an open-source
> research/experimental prototype produced with AI assistance. It is provided
> **AS IS**, without warranty of any kind, and is not a commercial or
> production-grade product. Use at your own risk.

## Verifiable-agent family

| Repo | Role |
|:--|:--|
| **agent-firewall** | MCP tool-call **firewall** (this repo) |
| [agent-call-audit](https://gitcode.com/gcw_MKhSyoGN/agent-call-audit) | audit **engine** |
| [agent-memory-ledger](https://gitcode.com/gcw_MKhSyoGN/agent-memory-ledger) | verifiable **memory** layer |
| [agent-audit-gateway](https://gitcode.com/gcw_MKhSyoGN/agent-audit-gateway) | HTTP **gateway** |
| [agent-route-grid](https://gitcode.com/gcw_MKhSyoGN/agent-route-grid) | audited multi-agent **routing** |

## Why

MCP servers hand your agent **arbitrary tool access**. A single `shell.exec` or `db.query` call with user-controlled arguments is enough to lose a machine or a database. The ecosystem's answer has been security gateways in Go — but if you are already on Python and want **provable, auditable enforcement** (not just a wall), this is the lightweight, dependency-free option.

**What you get:**

- **Deny by default** — empty policy denies every tool call (fail-closed).
- **Blocklist beats allowlist** — `blocked_tools` and argument-level red lines always win.
- **Argument-level red lines** — regex against a JSON path inside `arguments` (e.g. reject `path=/etc/*`, reject SQL injection probes).
- **Tamper-evident trail** — every verdict appends to a JSONL hash chain; `verify_trail()` detects any tampering.
- **Privacy by default** — raw tool arguments are **never persisted**, only a sha256 of the canonical payload.
- **Rules are data** — policy is a JSON file, not hard-coded.
- **Fail-closed on fault** — malformed requests and internal errors resolve to `deny`, never `allow`.

## Install

```bash
pip install frt-agent-firewall
```

Zero runtime dependencies (Python 3.9+).

## Quick start

```python
from agent_firewall import McpFirewall, ToolPolicy

policy = ToolPolicy(
    allowed_tools=["files.read", "files.write", "search.query"],
    blocked_tools=["shell.exec", "network.namespace"],
)

fw = McpFirewall(policy=policy, trail_path="./firewall_trail.jsonl")

# In your MCP server request handler, inspect before dispatch:
def handle(request):  # request is a JSON-RPC 2.0 dict
    result, response = fw.inspect(request)
    if result.decision == "deny":
        return response          # a JSON-RPC error — do NOT run the tool
    return dispatch(request)     # result.decision == "allow" → forward original
```

## Proof of life

```python
from agent_firewall.demo import run_demo
for row in run_demo():
    print(row)
```

```
{'request_id': 1, 'method': 'tools/list',      'decision': 'allow', 'reason_code': 'PASSTHROUGH'}
{'request_id': 2, 'method': 'tools/call', 'tool': 'files.read',    'decision': 'allow', 'reason_code': 'ALLOWED'}
{'request_id': 3, 'method': 'tools/call', 'tool': 'shell.exec',    'decision': 'deny',  'reason_code': 'ERR_TOOL_BLOCKED'}
{'request_id': 4, 'method': 'tools/call', 'tool': 'db.drop',       'decision': 'deny',  'reason_code': 'ERR_TOOL_NOT_ALLOWED'}
{'request_id': 5, 'method': 'tools/call', 'tool': 'files.write',   'decision': 'deny',  'reason_code': 'ERR_RED_LINE'}
{'request_id': 6, 'method': 'tools/call', 'tool': 'search.query',  'decision': 'deny',  'reason_code': 'ERR_RED_LINE'}
```

## Invariants

| # | Invariant | Enforced by |
|:--|:--|:--|
| 1 | Empty policy denies everything | `ToolPolicy.allows` default |
| 2 | Blocklist > red lines > allowlist | `McpFirewall._inspect` order |
| 3 | Any unexpected fault → `deny` | `inspect()` try/except |
| 4 | Raw arguments never persisted | `payload_hash` only |
| 5 | Trail is a hash chain | `_append` → `verify_trail` |
| 6 | Malformed `tools/call` never forwarded | `parse_tool_call` None → deny |

## Architecture

```
MCP client ──tools/call──> [ agent-firewall ] ──allow──> MCP server
                              │      │
                              │      └──deny──> JSON-RPC error to client
                              └── hash-chain trail (JSONL)
```

`agent-firewall` reuses the **`audit_guard`** engine (vendored from `agent-call-audit` under MIT) for its hash-chain trail; adjudication itself is a small, focused policy layer that never re-implements the core guard.

## Roadmap ideas

- HTTP/SSE proxy wrapper (`POST /mcp`), for network-deployed MCP servers.
- Policy reload on file change (hot reload).
- `tools/list` filtering: hide blocked tools from the client entirely.

## License

MIT. Note the vendored `audit_guard` module is MIT from `agent-call-audit` (see `LICENSE`).

[中文版](docs/README.zh-CN.md)