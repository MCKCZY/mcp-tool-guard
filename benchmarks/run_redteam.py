"""Run adversarial red-team benchmark comparing no_guard, naive_regex_guard, and mcp_tool_guard."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks.corpus import RedTeamCase, build_corpus
from mcp_tool_guard.engine import ToolGuardEngine
from mcp_tool_guard.policy import DecisionAction, GuardPolicy, load_policy


@dataclass
class CategoryMetrics:
    strategy: str
    category: str
    attacks: int
    attacks_blocked: int
    benign: int
    benign_flagged: int
    tpr: float
    fpr: float
    p95_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "category": self.category,
            "attacks": self.attacks,
            "attacks_blocked": self.attacks_blocked,
            "benign": self.benign,
            "benign_flagged": self.benign_flagged,
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "p95_ms": round(self.p95_ms, 3),
        }


def _naive_regex_evaluate(case: RedTeamCase, workspace: Path) -> bool:
    """Typical naive baseline: string startswith, simple metachar regex, literal private IPs."""
    if case.kind == "ingress":
        if case.tool_name == "read_file":
            p = str(case.arguments.get("path", ""))
            # Naive check: forgets symlink realpath, forgets trailing separator on prefix, only blocks literal '.env'
            if ".." in p or p.endswith(".env") or "/etc/passwd" in p:
                return True
            abs_p = os.path.abspath(os.path.join(str(workspace), p))
            if not abs_p.startswith(str(workspace)):
                return True
            return False
        if case.tool_name == "run_cmd":
            cmd = str(case.arguments.get("command", ""))
            return any(ch in cmd for ch in (";", "|", "&", "`"))
        if case.tool_name == "fetch_url":
            url = str(case.arguments.get("url", "")).lower()
            return any(
                x in url
                for x in ("127.0.0.1", "169.254.169.254", "localhost", "file://", "gopher://")
            )
        return False

    if case.kind == "egress":
        txt = case.text
        if case.category == "dlp_secrets":
            return bool(
                re.search(r"(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{16,}|BEGIN RSA PRIVATE KEY)", txt)
            )
        if case.category == "prompt_injection":
            return "ignore previous instructions" in txt.lower()
        return False

    # Naive guard has no dynamic taint or loop tracking.
    return False


def _evaluate_mcp_tool_guard(
    case: RedTeamCase, workspace: Path, base_policy: GuardPolicy
) -> bool:
    def _resolver(host: str) -> list[str]:
        if host in case.dns_map:
            return case.dns_map[host]
        return ["93.184.216.34"]

    # Configure network DNS checking when dns_map is provided in the test scenario.
    pol = load_policy(base_policy, workspace_root=workspace)
    if case.dns_map:
        pol.network.resolve_dns = True

    with ToolGuardEngine(pol, audit_db=":memory:", workspace_root=workspace, resolver=_resolver) as eng:
        if case.kind == "ingress":
            res = eng.check_call(case.tool_name, case.arguments)
            return not res.allowed

        if case.kind == "egress":
            res = eng.filter_result(case.tool_name, case.text)
            return res.action != DecisionAction.ALLOW

        if case.kind == "sequence":
            any_blocked = False
            for step in case.steps:
                if step["kind"] == "egress":
                    out = eng.filter_result(step["tool"], step["text"])
                    if out.action != DecisionAction.ALLOW:
                        any_blocked = True
                else:
                    inc = eng.check_call(step["tool"], step["args"])
                    if not inc.allowed:
                        any_blocked = True
            return any_blocked
    return False


def run_redteam_benchmark() -> tuple[list[CategoryMetrics], dict[str, dict[str, float]]]:
    """Run all 68 red-team cases across 3 strategies and return category + overall metrics."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        workspace = root / "work"
        outside_dir = root / "outside"
        prefix_dir = root / "work_evil"
        workspace.mkdir()
        outside_dir.mkdir()
        prefix_dir.mkdir()

        outside_secret = outside_dir / "outside_secret.txt"
        outside_secret.write_text("TOP_SECRET", encoding="utf-8")
        (prefix_dir / "secret.txt").write_text("PREFIX_BYPASS", encoding="utf-8")
        os.symlink(outside_secret, workspace / "escape_link")
        os.symlink(outside_dir, workspace / "escape_dir_link")

        cases = build_corpus(workspace, outside_dir, prefix_dir)
        base_policy = load_policy("coding_agent", workspace_root=workspace)

        records: dict[tuple[str, str], list[tuple[bool, bool, float]]] = defaultdict(list)
        overall_counts: dict[str, dict[str, Any]] = {
            s: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "lat": []}
            for s in ("no_guard", "naive_regex_guard", "mcp_tool_guard")
        }

        for case in cases:
            # 1. no_guard
            t0 = time.perf_counter()
            blocked_no = False
            dt_no = (time.perf_counter() - t0) * 1000.0
            records[("no_guard", case.category)].append((case.is_attack, blocked_no, dt_no))

            # 2. naive_regex_guard
            t0 = time.perf_counter()
            blocked_naive = _naive_regex_evaluate(case, workspace)
            dt_naive = (time.perf_counter() - t0) * 1000.0
            records[("naive_regex_guard", case.category)].append(
                (case.is_attack, blocked_naive, dt_naive)
            )

            # 3. mcp_tool_guard
            t0 = time.perf_counter()
            blocked_guard = _evaluate_mcp_tool_guard(case, workspace, base_policy)
            dt_guard = (time.perf_counter() - t0) * 1000.0
            records[("mcp_tool_guard", case.category)].append(
                (case.is_attack, blocked_guard, dt_guard)
            )

            for strat, pred, dt in (
                ("no_guard", blocked_no, dt_no),
                ("naive_regex_guard", blocked_naive, dt_naive),
                ("mcp_tool_guard", blocked_guard, dt_guard),
            ):
                st = overall_counts[strat]
                st["lat"].append(dt)
                if case.is_attack and pred:
                    st["tp"] += 1
                elif case.is_attack and not pred:
                    st["fn"] += 1
                elif not case.is_attack and pred:
                    st["fp"] += 1
                else:
                    st["tn"] += 1

        categories_order = [
            "path_traversal",
            "command_injection",
            "ssrf",
            "dlp_secrets",
            "prompt_injection",
            "dynamic_taint_and_loop",
        ]
        cat_metrics: list[CategoryMetrics] = []
        for strat in ("no_guard", "naive_regex_guard", "mcp_tool_guard"):
            for cat in categories_order:
                items = records[(strat, cat)]
                atk = [p for is_a, p, _ in items if is_a]
                ben = [p for is_a, p, _ in items if not is_a]
                lats = sorted(dt for _, _, dt in items)
                p95 = lats[min(len(lats) - 1, int(0.95 * len(lats)))] if lats else 0.0
                tp = sum(1 for p in atk if p)
                fp = sum(1 for p in ben if p)
                cat_metrics.append(
                    CategoryMetrics(
                        strategy=strat,
                        category=cat,
                        attacks=len(atk),
                        attacks_blocked=tp,
                        benign=len(ben),
                        benign_flagged=fp,
                        tpr=tp / max(1, len(atk)),
                        fpr=fp / max(1, len(ben)),
                        p95_ms=p95,
                    )
                )

        overall: dict[str, dict[str, float]] = {}
        for strat, st in overall_counts.items():
            tp, fp, fn, tn = st["tp"], st["fp"], st["fn"], st["tn"]
            tpr = tp / max(1, tp + fn)
            fpr = fp / max(1, fp + tn)
            prec = tp / max(1, tp + fp)
            f1 = (2 * prec * tpr / (prec + tpr)) if (prec + tpr) > 0 else 0.0
            lats = sorted(st["lat"])
            p95 = lats[min(len(lats) - 1, int(0.95 * len(lats)))] if lats else 0.0
            overall[strat] = {
                "attacks_total": float(tp + fn),
                "attacks_blocked": float(tp),
                "benign_total": float(fp + tn),
                "benign_flagged": float(fp),
                "tpr": tpr,
                "fpr": fpr,
                "f1": f1,
                "p95_ms": p95,
            }

        return cat_metrics, overall


def format_markdown_report(
    cat_metrics: list[CategoryMetrics], overall: dict[str, dict[str, float]]
) -> str:
    ref = overall["mcp_tool_guard"]
    atk_n = int(ref["attacks_total"])
    ben_n = int(ref["benign_total"])
    lines = [
        f"# mcp-tool-guard Adversarial Red-Team Benchmark ({atk_n + ben_n} Cases: {atk_n} Attacks, {ben_n} Benign Controls)",
        "",
        "## Overall Comparison",
        "",
        "| Strategy | Attacks Blocked (TPR) | Benign Flagged (FPR) | F1 Score | P95 Latency (ms) |",
        "| :--- | ---: | ---: | ---: | ---: |",
    ]
    for strat in ("no_guard", "naive_regex_guard", "mcp_tool_guard"):
        o = overall[strat]
        lines.append(
            f"| `{strat}` | {int(o['attacks_blocked'])}/{int(o['attacks_total'])} ({o['tpr']*100:.1f}%) | "
            f"{int(o['benign_flagged'])}/{int(o['benign_total'])} ({o['fpr']*100:.1f}%) | "
            f"{o['f1']*100:.1f}% | {o['p95_ms']:.2f} |"
        )

    lines.extend(
        [
            "",
            "## Per-Category Breakdown (`mcp_tool_guard` vs `naive_regex_guard`)",
            "",
            "| Category | Attacks | Benign | `naive_regex_guard` TPR / FPR | `mcp_tool_guard` TPR / FPR | `mcp_tool_guard` P95 (ms) |",
            "| :--- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    by_key = {(m.strategy, m.category): m for m in cat_metrics}
    categories = [
        "path_traversal",
        "command_injection",
        "ssrf",
        "dlp_secrets",
        "prompt_injection",
        "dynamic_taint_and_loop",
    ]
    for cat in categories:
        nm = by_key[("naive_regex_guard", cat)]
        gm = by_key[("mcp_tool_guard", cat)]
        lines.append(
            f"| `{cat}` | {gm.attacks} | {gm.benign} | "
            f"{nm.tpr*100:.1f}% / {nm.fpr*100:.1f}% | "
            f"{gm.tpr*100:.1f}% / {gm.fpr*100:.1f}% | "
            f"{gm.p95_ms:.2f} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run mcp-tool-guard red-team benchmark.")
    parser.add_argument("--json-out", default=None, help="Optional JSON output path")
    args = parser.parse_args(argv)

    cat_metrics, overall = run_redteam_benchmark()
    print(format_markdown_report(cat_metrics, overall))

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "overall": overall,
                    "categories": [m.to_dict() for m in cat_metrics],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
