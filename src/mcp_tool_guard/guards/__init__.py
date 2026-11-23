"""Deterministic runtime security guards for MCP and agent tool boundaries."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class GuardFinding:
    guard: str
    code: str
    severity: str  # "critical" | "high" | "medium" | "low"
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["GuardFinding"]
