"""Command-line interface for mcp-tool-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from mcp_tool_guard.audit import AuditLog
from mcp_tool_guard.engine import ToolGuardEngine
from mcp_tool_guard.mcp_proxy import McpSecurityProxy
from mcp_tool_guard.policy import PRESET_POLICIES, load_policy


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Emit machine-readable JSON output",
    )

    parser = argparse.ArgumentParser(
        prog="mcp-tool-guard",
        description="Runtime security firewall and transparent stdio MCP proxy for AI agents.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Emit machine-readable JSON output",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_proxy = sub.add_parser("proxy", parents=[common], help="Wrap an upstream stdio MCP server")
    p_proxy.add_argument("--policy", default="coding_agent")
    p_proxy.add_argument("--audit", default=".tool_guard/audit.db")
    p_proxy.add_argument("--workspace", default=None)
    p_proxy.add_argument("upstream_cmd", nargs=argparse.REMAINDER)

    p_check = sub.add_parser("check", parents=[common], help="Dry-run ingress check for a tool call")
    p_check.add_argument("--policy", default="coding_agent")
    p_check.add_argument("--tool", required=True)
    p_check.add_argument("--args", default="{}")
    p_check.add_argument("--workspace", default=None)
    p_check.add_argument("--audit", default=":memory:")

    p_scan = sub.add_parser("scan", parents=[common], help="Scan untrusted text for secrets & injection")
    p_scan.add_argument("--policy", default="coding_agent")
    p_scan.add_argument("--tool", default="untrusted_source")
    src_grp = p_scan.add_mutually_exclusive_group(required=True)
    src_grp.add_argument("--text", default=None)
    src_grp.add_argument("--file", default=None)

    p_init = sub.add_parser("init-policy", parents=[common], help="Export a preset policy JSON template")
    p_init.add_argument("--preset", default="coding_agent", choices=sorted(PRESET_POLICIES))
    p_init.add_argument("--output", required=True)

    p_av = sub.add_parser("audit-verify", parents=[common], help="Verify SHA-256 audit hash chain")
    p_av.add_argument("--audit", default=".tool_guard/audit.db")

    p_as = sub.add_parser("audit-stats", parents=[common], help="Show audit log statistics")
    p_as.add_argument("--audit", default=".tool_guard/audit.db")

    p_ae = sub.add_parser("audit-export", parents=[common], help="Export audit log to JSONL")
    p_ae.add_argument("--audit", default=".tool_guard/audit.db")
    p_ae.add_argument("--output", required=True)

    return parser


def _print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    as_json = bool(args.json_output)

    try:
        cmd = args.command

        if cmd == "proxy":
            upstream = list(args.upstream_cmd)
            if upstream and upstream[0] == "--":
                upstream = upstream[1:]
            if not upstream:
                raise ValueError("Missing upstream command after '--'")
            with ToolGuardEngine(
                args.policy, audit_db=args.audit, workspace_root=args.workspace
            ) as eng:
                proxy = McpSecurityProxy(eng)
                return proxy.run_stdio_bridge(upstream)

        if cmd == "check":
            parsed_args = json.loads(args.args)
            if not isinstance(parsed_args, dict):
                raise ValueError("--args must decode to a JSON object")
            with ToolGuardEngine(
                args.policy, audit_db=args.audit, workspace_root=args.workspace
            ) as eng:
                res = eng.check_call(args.tool, parsed_args)
                if as_json:
                    _print_json(res.to_dict())
                else:
                    print(f"allowed={res.allowed} action={res.action.value} tool={res.tool_name}")
                    for f in res.findings:
                        print(f"  [{f.severity}] {f.guard}/{f.code}: {f.message}")
                return 0 if res.allowed else 2

        if cmd == "scan":
            text = (
                Path(args.file).read_text(encoding="utf-8")
                if args.file is not None
                else (args.text or "")
            )
            with ToolGuardEngine(args.policy, audit_db=":memory:") as eng:
                res = eng.filter_result(args.tool, text)
                if as_json:
                    _print_json(res.to_dict())
                else:
                    print(
                        f"action={res.action.value} redactions={res.redaction_count} "
                        f"injection_score={res.injection_score} tainted={res.session_tainted}"
                    )
                    for f in res.findings:
                        print(f"  [{f.severity}] {f.guard}/{f.code}: {f.message}")
                    print("--- Sanitized Output ---")
                    print(res.text)
                return 0 if res.action.value in ("allow", "audit_only") else 2

        if cmd == "init-policy":
            pol = load_policy(args.preset)
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(pol.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
            )
            if as_json:
                _print_json({"preset": args.preset, "output": str(out_path)})
            else:
                print(f"Wrote preset '{args.preset}' to {out_path}")
            return 0

        if cmd == "audit-verify":
            log = AuditLog(args.audit)
            try:
                ok, errors = log.verify_chain()
                payload = {"db_path": log.db_path, "ok": ok, "errors": errors}
                if as_json:
                    _print_json(payload)
                else:
                    print(f"audit verify ok={ok} ({len(errors)} errors)")
                    for err in errors:
                        print(f"  ERROR: {err}", file=sys.stderr)
                return 0 if ok else 1
            finally:
                log.close()

        if cmd == "audit-stats":
            log = AuditLog(args.audit)
            try:
                st = log.stats()
                if as_json:
                    _print_json(st)
                else:
                    for k, v in st.items():
                        print(f"{k}: {v}")
                return 0 if st["chain_ok"] else 1
            finally:
                log.close()

        if cmd == "audit-export":
            log = AuditLog(args.audit)
            try:
                count = log.export_jsonl(args.output)
                payload = {"events_exported": count, "output": args.output}
                if as_json:
                    _print_json(payload)
                else:
                    print(f"Exported {count} audit events to {args.output}")
                return 0
            finally:
                log.close()

    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        if as_json:
            _print_json({"error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
