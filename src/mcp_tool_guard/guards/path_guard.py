"""Canonical path containment, symlink escape detection, and sensitive file guard."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from mcp_tool_guard.guards import GuardFinding
from mcp_tool_guard.policy import FilesystemPolicy


def _matches_denied_pattern(path_str: str, patterns: list[str]) -> str | None:
    posix = path_str.replace("\\", "/")
    parts = [p for p in posix.split("/") if p]
    basename = parts[-1] if parts else ""

    for pat in patterns:
        pat_norm = pat.replace("\\", "/")
        if pat_norm.startswith("/"):
            if fnmatch.fnmatch(posix, pat_norm) or posix == pat_norm:
                return pat
        else:
            if fnmatch.fnmatch(basename, pat_norm):
                return pat
            if fnmatch.fnmatch(posix, f"*/{pat_norm}") or fnmatch.fnmatch(posix, pat_norm):
                return pat
            for seg in parts:
                if fnmatch.fnmatch(seg, pat_norm):
                    return pat
    return None


def check_path(
    raw_path: object,
    policy: FilesystemPolicy,
    *,
    base_dir: str | Path | None = None,
) -> list[GuardFinding]:
    """Validate a filesystem path against allowed roots, symlinks, and denied patterns."""
    findings: list[GuardFinding] = []
    if not isinstance(raw_path, str) or not raw_path.strip():
        return [
            GuardFinding(
                guard="path_guard",
                code="INVALID_PATH",
                severity="high",
                message="Path must be a non-empty string",
            )
        ]

    if "\x00" in raw_path or "\n" in raw_path or "\r" in raw_path:
        return [
            GuardFinding(
                guard="path_guard",
                code="PATH_CONTROL_CHARS",
                severity="critical",
                message="Path contains null byte or control characters",
            )
        ]

    if len(raw_path) > policy.max_path_length:
        return [
            GuardFinding(
                guard="path_guard",
                code="PATH_TOO_LONG",
                severity="medium",
                message=f"Path length exceeds limit ({len(raw_path)} > {policy.max_path_length})",
            )
        ]

    expanded = os.path.expanduser(raw_path.strip())
    if base_dir is not None:
        anchor = Path(base_dir)
    elif policy.allowed_roots:
        anchor = Path(os.path.expanduser(policy.allowed_roots[0]))
    else:
        anchor = Path.cwd()

    raw_obj = Path(expanded)
    logical_path = raw_obj if raw_obj.is_absolute() else (anchor / raw_obj)
    norm_logical = os.path.normpath(str(logical_path))
    resolved = os.path.realpath(norm_logical)
    resolved_path = Path(resolved)

    # Check sensitive patterns against both normalized logical path and symlink-resolved target.
    for candidate in (raw_path.strip(), norm_logical, resolved):
        hit = _matches_denied_pattern(candidate, policy.denied_patterns)
        if hit is not None:
            findings.append(
                GuardFinding(
                    guard="path_guard",
                    code="SENSITIVE_PATH_DENIED",
                    severity="critical",
                    message=f"Path matches denied sensitive pattern '{hit}'",
                    detail={"pattern": hit, "resolved_path": resolved},
                )
            )
            break

    if policy.allowed_roots:
        canonical_roots = [
            Path(os.path.realpath(os.path.expanduser(r))) for r in policy.allowed_roots
        ]
        target_to_check = Path(norm_logical) if policy.allow_symlinks_outside else resolved_path
        contained = any(target_to_check.is_relative_to(root) for root in canonical_roots)
        if not contained:
            code = (
                "SYMLINK_ESCAPE"
                if Path(norm_logical).resolve() != resolved_path
                and any(Path(os.path.abspath(norm_logical)).is_relative_to(r) for r in canonical_roots)
                else "PATH_OUTSIDE_ALLOWED_ROOTS"
            )
            findings.append(
                GuardFinding(
                    guard="path_guard",
                    code=code,
                    severity="critical",
                    message="Path escapes allowed filesystem roots",
                    detail={
                        "logical_path": norm_logical,
                        "resolved_path": resolved,
                        "allowed_roots": [str(r) for r in canonical_roots],
                    },
                )
            )

    return findings
