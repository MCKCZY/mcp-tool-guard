#!/usr/bin/env python3
"""Example composing mcp-tool-guard (`ctx_pager_hardened` preset) in front of ctx-pager MCP."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp_tool_guard.engine import ToolGuardEngine
from mcp_tool_guard.mcp_proxy import McpSecurityProxy


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    ctx_pager_src = repo_root.parent / "ctx-pager" / "src"
    if not (ctx_pager_src / "ctx_pager").is_dir():
        print(f"Sibling ctx-pager repository not found at {ctx_pager_src}; skipping live wrap.")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        mem_db = Path(tmp) / "ctx.db"
        audit_db = Path(tmp) / "guard_audit.db"
        fake_gh = "ghp_" + "9X8Y7Z6W5V4U3T2S1R0Q9P8O7N6M5L4K3J2I"

        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "ctx_commit",
                    "arguments": {
                        "kind": "constraint",
                        "scope": "db",
                        "title": "MySQL 5.7 utf8mb4 index <= 191",
                        "summary": "Enforce prefix length <= 191 on indexed varchar columns",
                        "pinned": True,
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "ctx_commit",
                    "arguments": {
                        "kind": "fact",
                        "scope": "ops",
                        "title": "Accidentally pasted secret",
                        "summary": f"Token is {fake_gh}",
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "ctx_recall", "arguments": {"query": "MySQL", "budget": 1024}},
            },
        ]
        cin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
        cout = io.StringIO()

        env = {"PYTHONPATH": f"{ctx_pager_src}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}
        with ToolGuardEngine("ctx_pager_hardened", audit_db=audit_db) as eng:
            proxy = McpSecurityProxy(eng)
            code = proxy.run_stdio_bridge(
                [sys.executable, "-m", "ctx_pager.mcp_server", "--db", str(mem_db)],
                client_in=cin,
                client_out=cout,
                env=env,
            )
            assert code == 0
            responses = {
                r["id"]: r
                for r in (json.loads(line) for line in cout.getvalue().strip().splitlines())
            }
            print("Hardened ctx-pager commit (clean):", not responses[3]["result"]["isError"])
            print("Secret commit blocked before reaching SQLite:", responses[4]["result"]["content"][0]["text"])
            assert responses[4]["result"]["isError"] is True
            print("Recall succeeded:", "191" in responses[5]["result"]["content"][0]["text"])
            print("Audit chain valid:", eng.audit.verify_chain()[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
