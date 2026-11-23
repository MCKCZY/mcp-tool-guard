"""Structured + Shannon-entropy Data Loss Prevention (DLP) secret scanner and redactor."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass

from mcp_tool_guard.policy import DlpPolicy

_STRUCTURED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "PEM_PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{10,4096}?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
    ),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "DB_URL_CREDS",
        re.compile(
            r"\b(?:postgres|postgresql|mysql|mariadb|redis|mongodb(?:\+srv)?|amqp|mssql)://[^:/\s]+:[^@\s]+@[^\s/]+"
        ),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._-]{20,})\b"),
    ),
]

_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b([a-z0-9_.-]*(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|access[_-]?key|client[_-]?secret)[a-z0-9_.-]*)
    \s*(?:=|:)\s*
    (["']?)([A-Za-z0-9/+_.=~!@#$%^&*-]{16,})\2
    """
)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_PLACEHOLDER_CUES = (
    "your_",
    "example",
    "placeholder",
    "replace_me",
    "dummy",
    "changeme",
    "xxxx",
    "redacted",
)


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    start: int
    end: int
    masked_preview: str
    fingerprint: str
    entropy: float


def shannon_entropy(token: str) -> float:
    """Compute Shannon entropy (bits/char) of a candidate token."""
    if not token:
        return 0.0
    counts = Counter(token)
    n = float(len(token))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder_or_benign(val: str) -> bool:
    low = val.lower()
    if _UUID_RE.match(low):
        return True
    if "/" in val and not val.startswith("sk-") and "://" not in val:
        return True
    if any(cue in low for cue in _PLACEHOLDER_CUES):
        return True
    if len(set(val)) <= 4:
        return True
    return False


def _mask_preview(raw: str) -> str:
    if len(raw) <= 8:
        return "***"
    return f"{raw[:4]}...{raw[-3:]}"


def _fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:6]


def scan_secrets(text: str, policy: DlpPolicy) -> list[SecretFinding]:
    """Detect structured credentials and high-entropy secret assignments without raw storage."""
    if not text:
        return []

    raw_hits: list[SecretFinding] = []
    for kind, pattern in _STRUCTURED_PATTERNS:
        for match in pattern.finditer(text):
            if kind == "BEARER_TOKEN":
                start, end = match.start(1), match.end(1)
                secret_val = match.group(1)
            else:
                start, end = match.start(), match.end()
                secret_val = match.group(0)
            if len(set(secret_val)) <= 4:
                continue
            raw_hits.append(
                SecretFinding(
                    kind=kind,
                    start=start,
                    end=end,
                    masked_preview=_mask_preview(secret_val),
                    fingerprint=_fingerprint(secret_val),
                    entropy=round(shannon_entropy(secret_val), 3),
                )
            )

    for match in _ASSIGNMENT_RE.finditer(text):
        secret_val = match.group(3)
        start, end = match.start(3), match.end(3)
        if _is_placeholder_or_benign(secret_val):
            continue
        ent = shannon_entropy(secret_val)
        # Contextual assignments with >= min_entropy_token_len or strong mixed charsets pass threshold.
        if (
            len(secret_val) >= policy.min_entropy_token_len and ent >= policy.entropy_threshold
        ) or (len(secret_val) >= 20 and ent >= policy.entropy_threshold + 0.15):
            raw_hits.append(
                SecretFinding(
                    kind="HIGH_ENTROPY_SECRET",
                    start=start,
                    end=end,
                    masked_preview=_mask_preview(secret_val),
                    fingerprint=_fingerprint(secret_val),
                    entropy=round(ent, 3),
                )
            )

    # Deduplicate overlapping spans, preferring structured / longer spans first.
    raw_hits.sort(key=lambda h: (h.start, -(h.end - h.start), h.kind == "HIGH_ENTROPY_SECRET"))
    non_overlapping: list[SecretFinding] = []
    last_end = -1
    for hit in raw_hits:
        if hit.start >= last_end:
            non_overlapping.append(hit)
            last_end = hit.end
    return non_overlapping


def redact_secrets(text: str, policy: DlpPolicy) -> tuple[str, list[SecretFinding]]:
    """Replace detected secrets with deterministic `[REDACTED:KIND:hash6]` placeholders."""
    findings = scan_secrets(text, policy)
    if not findings:
        return text, []

    chunks: list[str] = []
    cursor = 0
    for f in findings:
        chunks.append(text[cursor : f.start])
        chunks.append(f"[REDACTED:{f.kind}:{f.fingerprint}]")
        cursor = f.end
    chunks.append(text[cursor:])
    return "".join(chunks), findings
