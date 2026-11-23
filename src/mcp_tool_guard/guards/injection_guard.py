"""Indirect prompt injection detector with Unicode tag/NFKC normalization and Base64 decoding."""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field

from mcp_tool_guard.policy import InjectionPolicy

_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_BIDI_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
_BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass(frozen=True)
class InjectionRule:
    category: str
    weight: float
    pattern: re.Pattern[str]
    description: str


_INJECTION_RULES: list[InjectionRule] = [
    InjectionRule(
        category="instruction_override",
        weight=0.60,
        pattern=re.compile(
            r"(?i)(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+)?"
            r"(?:the\s+)?(?:previous|prior|above|earlier|system|developer)\s+"
            r"(?:instructions?|prompts?|rules?|directives?|constraints?)"
        ),
        description="English instruction override phrase",
    ),
    InjectionRule(
        category="instruction_override",
        weight=0.60,
        pattern=re.compile(
            r"(?:忽略|无视|忘掉|覆盖|绕过)(?:上面|之前|以上|先前|所有|全部|系统|开发者)*(?:所有|全部)?(?:指令|规则|提示词|约束|限制)"
        ),
        description="Chinese instruction override phrase",
    ),
    InjectionRule(
        category="role_delimiter_hijack",
        weight=0.60,
        pattern=re.compile(
            r"(?im)(?:<\|im_start\|>\s*system\b|<\|system\|>|\[SYSTEM\s*(?:OVERRIDE|PROMPT|MESSAGE)\]|"
            r"^###\s*(?:SYSTEM\s*OVERRIDE|NEW\s*(?:SYSTEM\s*)?INSTRUCTIONS?)\b|"
            r"you\s+are\s+now\s+in\s+(?:DAN|developer|unrestricted|jailbreak)\s+mode|"
            r"进入(?:开发者|管理员|DAN|无限制)模式)"
        ),
        description="Role boundary or system prompt delimiter hijack",
    ),
    InjectionRule(
        category="exfil_coercion",
        weight=0.60,
        pattern=re.compile(
            r"(?i)(?:read|cat|dump|exfiltrate|steal|leak|send|post|upload|curl)\b.{0,65}"
            r"(?:\.ssh|id_rsa|id_ed25519|\.env\b|/etc/passwd|/etc/shadow|api[_-]?key|secret[_-]?key|access[_-]?token)"
        ),
        description="Coerced secret/credential exfiltration instruction",
    ),
    InjectionRule(
        category="exfil_coercion",
        weight=0.60,
        pattern=re.compile(
            r"(?:读取|窃取|导出|发送|上传).{0,35}(?:密钥|私钥|凭据|\.env|id_rsa|id_ed25519|环境变量)"
        ),
        description="Chinese coerced secret exfiltration instruction",
    ),
    InjectionRule(
        category="stealth_bypass",
        weight=0.35,
        pattern=re.compile(
            r"(?i)(?:do\s+not|don't|never)\s+(?:tell|inform|mention\s+to|notify|alert)\s+(?:the\s+)?user\b|"
            r"\bhide\s+this\s+from\s+(?:the\s+)?user\b|"
            r"(?:不要|别|切勿)告诉用户"
        ),
        description="Stealth concealment instruction",
    ),
    InjectionRule(
        category="covert_execution",
        weight=0.35,
        pattern=re.compile(
            r"(?i)\bsilently\s+(?:run|execute|send|exfiltrate|delete|modify|call)\b|"
            r"悄悄(?:执行|运行|发送)"
        ),
        description="Covert execution directive",
    ),
]


@dataclass(frozen=True)
class InjectionMatch:
    category: str
    weight: float
    description: str
    snippet: str


@dataclass(frozen=True)
class InjectionReport:
    score: float
    triggered: bool
    matches: list[InjectionMatch] = field(default_factory=list)
    obfuscation_signals: list[str] = field(default_factory=list)
    decoded_snippets: list[str] = field(default_factory=list)


def _decode_unicode_tags(text: str) -> tuple[str, str]:
    """Extract hidden ASCII payload from Unicode Tag block (U+E0000..U+E007F)."""
    visible_chars: list[str] = []
    hidden_chars: list[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            mapped = cp - 0xE0000
            if mapped == 0x0A or 0x20 <= mapped <= 0x7E:
                hidden_chars.append(chr(mapped))
        else:
            visible_chars.append(ch)
    return "".join(visible_chars), "".join(hidden_chars)


def _try_decode_base64_snippets(text: str) -> list[str]:
    decoded_list: list[str] = []
    for match in _BASE64_CANDIDATE_RE.finditer(text):
        chunk = match.group(0)
        if len(chunk) > 4096:
            continue
        padded = chunk + ("=" * ((4 - len(chunk) % 4) % 4))
        try:
            raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode("utf-8")
        except Exception:
            continue
        if len(decoded) < 12:
            continue
        printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
        if printable / len(decoded) >= 0.90:
            decoded_list.append(decoded)
    return decoded_list


def normalize_for_scan(
    text: str, policy: InjectionPolicy
) -> tuple[str, list[str], list[str]]:
    """Normalize obfuscated text and extract Unicode Tag / Base64 hidden payloads."""
    signals: list[str] = []
    extra_texts: list[str] = []

    if policy.normalize_unicode:
        visible, tag_hidden = _decode_unicode_tags(text)
        if tag_hidden:
            signals.append("unicode_tag_smuggling")
            extra_texts.append(tag_hidden)
        if _ZERO_WIDTH_RE.search(visible):
            signals.append("zero_width_obfuscation")
            visible = _ZERO_WIDTH_RE.sub("", visible)
        if _BIDI_RE.search(visible):
            signals.append("bidi_override")
            visible = _BIDI_RE.sub("", visible)
        normalized = unicodedata.normalize("NFKC", visible)
        if normalized != visible:
            signals.append("unicode_nfkc_folded")
    else:
        normalized = text

    if policy.decode_base64:
        b64_snippets = _try_decode_base64_snippets(normalized)
        if b64_snippets:
            extra_texts.extend(b64_snippets)

    return normalized, signals, extra_texts


def scan_injection(text: str, policy: InjectionPolicy) -> InjectionReport:
    """Detect direct or obfuscated indirect prompt injection payloads in untrusted text."""
    if not text:
        return InjectionReport(score=0.0, triggered=False)

    normalized, signals, extra_texts = normalize_for_scan(text, policy)
    scan_targets = [("primary", normalized)] + [
        ("decoded", snip) for snip in extra_texts
    ]

    matches: list[InjectionMatch] = []
    category_best: dict[str, float] = {}
    decoded_rule_hit = False

    for source_kind, target in scan_targets:
        for rule in _INJECTION_RULES:
            m = rule.pattern.search(target)
            if m:
                if source_kind == "decoded":
                    decoded_rule_hit = True
                prev = category_best.get(rule.category, 0.0)
                if rule.weight > prev:
                    category_best[rule.category] = rule.weight
                matches.append(
                    InjectionMatch(
                        category=rule.category,
                        weight=rule.weight,
                        description=rule.description,
                        snippet=m.group(0)[:120],
                    )
                )

    score = sum(category_best.values())
    if (decoded_rule_hit or "unicode_tag_smuggling" in signals or "bidi_override" in signals) and matches:
        score += 0.25
        if decoded_rule_hit and "base64_hidden_payload" not in signals:
            signals.append("base64_hidden_payload")

    score = round(min(1.0, score), 4)
    return InjectionReport(
        score=score,
        triggered=score >= policy.score_threshold,
        matches=matches,
        obfuscation_signals=signals,
        decoded_snippets=extra_texts,
    )
