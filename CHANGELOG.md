# Changelog

## v0.1.0 (2026-11-12)

- Initial public release.
- `McpFirewall.inspect()` — fail-closed adjudication of MCP `tools/call` JSON-RPC messages.
- `ToolPolicy` — declarative allowlist/blocklist with argument-level red lines (JSON file driven).
- Tamper-evident JSONL hash-chain trail with `verify_trail()`.
- Privacy by default: raw tool arguments never persisted, only sha256 payload hashes.
- Vendored `audit_guard` (from agent-call-audit, MIT) for the hash-chain trail.
- 20 unit tests (`Ran 20 tests OK`).