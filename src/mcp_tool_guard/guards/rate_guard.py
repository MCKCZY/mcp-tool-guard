"""Sliding-window rate limiter and repeated-call loop breaker."""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from typing import Any, Callable

from mcp_tool_guard.guards import GuardFinding
from mcp_tool_guard.policy import RateLimitPolicy


class RateAndLoopGuard:
    """Detects runaway RPM bursts and stuck identical tool-call loops."""

    def __init__(
        self,
        policy: RateLimitPolicy,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.policy = policy
        self.clock = clock or time.monotonic
        self._timestamps: deque[float] = deque()
        self._recent_sigs: deque[str] = deque(maxlen=max(16, policy.max_identical_window * 2))
        self._last_sig: str | None = None
        self._consecutive_count: int = 0

    @staticmethod
    def _call_signature(tool_name: str, arguments: dict[str, Any]) -> str:
        canonical = json.dumps(
            {"tool": tool_name, "args": arguments},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def check_and_record(self, tool_name: str, arguments: dict[str, Any]) -> list[GuardFinding]:
        now = self.clock()
        cutoff = now - 60.0
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()

        findings: list[GuardFinding] = []
        if len(self._timestamps) >= self.policy.max_calls_per_minute:
            findings.append(
                GuardFinding(
                    guard="rate_guard",
                    code="RATE_LIMIT_EXCEEDED",
                    severity="high",
                    message=(
                        f"Tool call rate exceeded {self.policy.max_calls_per_minute} calls/min"
                    ),
                    detail={"window_calls": len(self._timestamps)},
                )
            )

        sig = self._call_signature(tool_name, arguments)
        if sig == self._last_sig:
            self._consecutive_count += 1
        else:
            self._last_sig = sig
            self._consecutive_count = 1

        if self._consecutive_count > self.policy.max_identical_consecutive:
            findings.append(
                GuardFinding(
                    guard="rate_guard",
                    code="CONSECUTIVE_LOOP_DETECTED",
                    severity="high",
                    message=(
                        f"Identical call to '{tool_name}' repeated {self._consecutive_count} "
                        f"consecutive times (limit {self.policy.max_identical_consecutive})"
                    ),
                    detail={"consecutive_count": self._consecutive_count},
                )
            )

        window_matches = sum(1 for prev in self._recent_sigs if prev == sig)
        if window_matches >= self.policy.max_identical_window:
            findings.append(
                GuardFinding(
                    guard="rate_guard",
                    code="WINDOW_LOOP_DETECTED",
                    severity="high",
                    message=(
                        f"Identical call to '{tool_name}' repeated {window_matches + 1} times in recent window"
                    ),
                    detail={"window_repeats": window_matches + 1},
                )
            )

        self._timestamps.append(now)
        self._recent_sigs.append(sig)
        return findings
