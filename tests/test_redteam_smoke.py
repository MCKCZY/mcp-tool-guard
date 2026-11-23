from __future__ import annotations

import unittest

from benchmarks.run_redteam import run_redteam_benchmark


class TestRedTeamSmoke(unittest.TestCase):
    def test_redteam_benchmark_beats_naive_baseline(self) -> None:
        cat_metrics, overall = run_redteam_benchmark()
        guard = overall["mcp_tool_guard"]
        naive = overall["naive_regex_guard"]

        self.assertGreaterEqual(guard["tpr"], 0.95)
        self.assertLessEqual(guard["fpr"], 0.05)
        self.assertGreater(guard["tpr"], naive["tpr"])
        self.assertLessEqual(guard["fpr"], naive["fpr"])

        by_cat = {m.category: m for m in cat_metrics if m.strategy == "mcp_tool_guard"}
        for cat, m in by_cat.items():
            self.assertGreaterEqual(m.tpr, 0.90, f"Low TPR in {cat}")
            self.assertLessEqual(m.fpr, 0.05, f"High FPR in {cat}")


if __name__ == "__main__":
    unittest.main()
