# agent-firewall（中文）

> **面向 AI Agent 的 fail-closed MCP 工具调用防火墙。**  
> 给你的 MCP 工具加一道本地防火墙——默认拒绝、仅白名单放行、每一次判定都写入哈希链留痕。

`agent-firewall` 是一个零依赖 Python 库，位于 **MCP 客户端与其服务器之间**，检查链路上的每一个 `tools/call` 消息。它是 **Verifiable-agent 家族**成员，与 `agent-call-audit`、`agent-memory-ledger`、`agent-audit-gateway`、`agent-route-grid` 共享同一套设计语言。

> ⚠️ **研究原型 — AI 辅助开发。** 这是一个开源研究/实验原型，由 AI 辅助产出。
> 按 **AS IS** 提供，不含任何形式的担保，非商业或生产级产品。使用者自担风险。

## 产品家族（Verifiable-agent 家族）

| 仓库 | 角色 |
|:--|:--|
| **agent-firewall** | MCP 工具调用**防火墙**（本仓库） |
| [agent-call-audit](https://gitcode.com/gcw_MKhSyoGN/agent-call-audit) | 审计**引擎** |
| [agent-memory-ledger](https://gitcode.com/gcw_MKhSyoGN/agent-memory-ledger) | 可验证**记忆层** |
| [agent-audit-gateway](https://gitcode.com/gcw_MKhSyoGN/agent-audit-gateway) | HTTP **网关** |
| [agent-route-grid](https://gitcode.com/gcw_MKhSyoGN/agent-route-grid) | 可审计多 Agent **路由** |

## 为什么需要它

MCP 服务器会给你的 Agent **任意工具访问权**。一个携带用户可控参数的 `shell.exec` 或 `db.query` 调用，就足以让一台机器或一个数据库失守。生态里已有 Go 实现的安全网关——但如果你在 Python 技术栈上，并且想要**可证明、可审计的执行**（而不只是一堵墙），这是一个轻量、零依赖的选择。

**你能得到：**

- **默认拒绝** —— 空策略拒绝所有工具调用（fail-closed）
- **黑名单优先于白名单** —— `blocked_tools` 和参数级红线永远优先
- **参数级红线** —— 对 `arguments` 内的 JSON 路径做正则匹配（如拒绝 `path=/etc/*`、拒绝 SQL 注入试探）
- **防篡改留痕** —— 每次判定追加到 JSONL 哈希链，`verify_trail()` 可检出任何篡改
- **默认隐私** —— 工具原始参数**永不落盘**，只记录规范化 payload 的 sha256
- **规则即数据** —— 策略是 JSON 文件，不是硬编码
- **故障即拒绝** —— 畸形请求与内部错误一律解析为 `deny`，绝不 `allow`

## 安装

```bash
pip install agent-firewall
```

零运行时依赖（Python 3.9+）。

## 快速开始

```python
from agent_firewall import McpFirewall, ToolPolicy

policy = ToolPolicy(
    allowed_tools=["files.read", "files.write", "search.query"],
    blocked_tools=["shell.exec", "network.namespace"],
)

fw = McpFirewall(policy=policy, trail_path="./firewall_trail.jsonl")

# 在 MCP 服务器请求处理函数里，dispatch 前先检查：
def handle(request):  # request 是 JSON-RPC 2.0 dict
    result, response = fw.inspect(request)
    if result.decision == "deny":
        return response          # 返回 JSON-RPC error —— 绝不要执行该工具
    return dispatch(request)     # decision == "allow" → 原样转发
```

## 实测输出

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

## 设计不变量

| # | 不变量 | 由谁保证 |
|:--|:--|:--|
| 1 | 空策略拒绝一切 | `ToolPolicy.allows` 默认行为 |
| 2 | 黑名单 > 红线 > 白名单 | `McpFirewall._inspect` 判定顺序 |
| 3 | 任何意外故障 → `deny` | `inspect()` 的 try/except |
| 4 | 原始参数永不落盘 | 只记录 `payload_hash` |
| 5 | 留痕是哈希链 | `_append` → `verify_trail` |
| 6 | 畸形 `tools/call` 永不转发 | `parse_tool_call` 返回 None → deny |

## 架构

```
MCP 客户端 ──tools/call──> [ agent-firewall ] ──allow──> MCP 服务器
                              │      │
                              │      └──deny──> 返回 JSON-RPC error
                              └── 哈希链留痕（JSONL）
```

`agent-firewall` 复用 **`audit_guard`** 引擎（从 `agent-call-audit` vendored，MIT 协议）的哈希链留痕能力；判定本身是一个专注的小策略层，绝不重复实现核心守卫。

## Roadmap 想法

- HTTP/SSE 代理封装（`POST /mcp`），用于网络部署的 MCP 服务器
- 策略文件变更热加载
- `tools/list` 过滤：对客户端完全隐藏被禁用的工具

## 许可证

MIT。注意 vendored 的 `audit_guard` 模块来自 `agent-call-audit`（MIT），详见 `LICENSE`。