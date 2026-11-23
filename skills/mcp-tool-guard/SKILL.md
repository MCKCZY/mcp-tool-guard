---
name: mcp-tool-guard
description: >-
  Runtime security firewall, secret/injection scanner, and transparent stdio MCP proxy
  for AI agents. Use when wrapping an untrusted or privileged MCP server, validating
  tool arguments (paths, shell commands, URLs) before execution, redacting leaked secrets
  from tool outputs, or inspecting untrusted documents for indirect prompt injection.
---

# mcp-tool-guard: Runtime Agent & MCP Security Firewall

Enforce least-privilege tool boundaries outside the LLM prompt. Wrap stdio MCP servers
transparently or validate individual tool calls and untrusted outputs via
[mcp_tool_guard.py](./scripts/mcp_tool_guard.py).

## Core Workflows

### 1. Wrap an Upstream MCP Server (`proxy`)
Place `mcp-tool-guard` in front of any stdio MCP server (such as `ctx-pager-mcp` or a
filesystem/shell server):

```bash
python3 ./scripts/mcp_tool_guard.py proxy \
  --policy ctx_pager_hardened \
  --workspace . \
  --audit .tool_guard/audit.db \
  -- python3 -m ctx_pager.mcp_server --db .ctx_pager/memory.db
```

### 2. Pre-Flight Tool Argument Check (`check`)
Dry-run ingress validation before executing risky file, shell, or HTTP arguments
(exits `0` if allowed, `2` if blocked):

```bash
python3 ./scripts/mcp_tool_guard.py check \
  --policy coding_agent --workspace . \
  --tool fetch_url --args '{"url": "http://169.254.169.254/latest/meta-data/"}'
```

### 3. Scan Untrusted Tool Output (`scan`)
Detect and redact leaked credentials (`sk-`, `ghp_`, `AKIA`, PEM keys, high-entropy
assignments) and indirect prompt injection (including Unicode Tag smuggling and Base64):

```bash
python3 ./scripts/mcp_tool_guard.py scan --policy coding_agent --file ./untrusted_doc.txt
```

### 4. Generate Custom Policy & Verify Audit Integrity
```bash
python3 ./scripts/mcp_tool_guard.py init-policy --preset strict_sandbox --output ./policy.json
python3 ./scripts/mcp_tool_guard.py audit-verify --audit .tool_guard/audit.db
python3 ./scripts/mcp_tool_guard.py audit-stats --audit .tool_guard/audit.db
```

## References (Load Only When Needed)
- Policy schema, presets (`strict_sandbox`, `coding_agent`, `read_only_audit`, `ctx_pager_hardened`), and taint tracking: [policy_guide.md](./references/policy_guide.md)
- OWASP LLM Top 10 / MCP threat mapping and bypass coverage: [threat_mapping.md](./references/threat_mapping.md)
