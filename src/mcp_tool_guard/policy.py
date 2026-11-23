"""Security policy schemas, JSON loader/serializer, and hardened preset profiles."""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

DEFAULT_DENIED_PATH_PATTERNS: list[str] = [
    ".env",
    ".env.*",
    "*.env",
    ".ssh",
    ".ssh/*",
    "*/.ssh/*",
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    ".git/config",
    "*/.git/config",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/proc/*",
    "/sys/*",
]

DEFAULT_DENIED_BINARIES: list[str] = [
    "rm",
    "dd",
    "mkfs",
    "fdisk",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "iptables",
    "nft",
    "nc",
    "ncat",
    "socat",
    "telnet",
    "ssh",
    "scp",
    "rsync",
    "chroot",
    "nsenter",
    "mount",
    "umount",
    "modprobe",
    "insmod",
]


class GuardMode(str, Enum):
    ENFORCE = "enforce"
    AUDIT = "audit"


class DecisionAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    WARN = "warn"
    AUDIT_ONLY = "audit_only"


@dataclass
class FilesystemPolicy:
    allowed_roots: list[str] = field(default_factory=lambda: ["."])
    denied_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_DENIED_PATH_PATTERNS))
    allow_symlinks_outside: bool = False
    max_path_length: int = 4096


@dataclass
class CommandPolicy:
    allowed_binaries: list[str] = field(default_factory=list)
    denied_binaries: list[str] = field(default_factory=lambda: list(DEFAULT_DENIED_BINARIES))
    forbid_shell_metachars: bool = True
    forbid_dangerous_flags: bool = True
    max_command_length: int = 2048


@dataclass
class NetworkPolicy:
    allowed_schemes: list[str] = field(default_factory=lambda: ["https", "http"])
    allowed_domains: list[str] = field(default_factory=list)
    denied_domains: list[str] = field(default_factory=list)
    block_private_ips: bool = True
    block_metadata_ips: bool = True
    resolve_dns: bool = False


@dataclass
class DlpPolicy:
    redact_responses: bool = True
    block_secrets_in_args: bool = True
    entropy_threshold: float = 4.3
    min_entropy_token_len: int = 24


@dataclass
class InjectionPolicy:
    action: str = "tag"  # "warn" | "tag" | "block"
    score_threshold: float = 0.60
    decode_base64: bool = True
    normalize_unicode: bool = True
    taint_ttl_calls: int = 5


@dataclass
class RateLimitPolicy:
    max_calls_per_minute: int = 60
    max_identical_consecutive: int = 4
    max_identical_window: int = 8
    max_response_bytes: int = 65536


@dataclass
class ToolRule:
    path_args: list[str] = field(default_factory=list)
    command_args: list[str] = field(default_factory=list)
    url_args: list[str] = field(default_factory=list)
    required_args: list[str] = field(default_factory=list)
    arg_types: dict[str, str] = field(default_factory=dict)
    max_arg_bytes: int = 32768
    taint_sensitive: bool = False


@dataclass
class GuardPolicy:
    name: str = "coding_agent"
    mode: GuardMode = GuardMode.ENFORCE
    default_action: str = "allow"  # "allow" | "deny"
    allowed_tools: list[str] = field(default_factory=list)
    denied_tools: list[str] = field(default_factory=list)
    tool_rules: dict[str, ToolRule] = field(default_factory=dict)
    filesystem: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    command: CommandPolicy = field(default_factory=CommandPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    dlp: DlpPolicy = field(default_factory=DlpPolicy)
    injection: InjectionPolicy = field(default_factory=InjectionPolicy)
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            self.mode = GuardMode(self.mode)
        if self.default_action not in ("allow", "deny"):
            raise ValueError(f"Invalid default_action: {self.default_action}")
        if self.injection.action not in ("warn", "tag", "block"):
            raise ValueError(f"Invalid injection action: {self.injection.action}")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["mode"] = self.mode.value
        return data

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "GuardPolicy":
        rules_raw = raw.get("tool_rules") or {}
        tool_rules = {name: ToolRule(**cfg) for name, cfg in rules_raw.items()}
        return cls(
            name=raw.get("name", "custom"),
            mode=GuardMode(raw.get("mode", "enforce")),
            default_action=raw.get("default_action", "allow"),
            allowed_tools=list(raw.get("allowed_tools", [])),
            denied_tools=list(raw.get("denied_tools", [])),
            tool_rules=tool_rules,
            filesystem=FilesystemPolicy(**(raw.get("filesystem") or {})),
            command=CommandPolicy(**(raw.get("command") or {})),
            network=NetworkPolicy(**(raw.get("network") or {})),
            dlp=DlpPolicy(**(raw.get("dlp") or {})),
            injection=InjectionPolicy(**(raw.get("injection") or {})),
            rate_limit=RateLimitPolicy(**(raw.get("rate_limit") or {})),
        )


def _common_dev_tool_rules() -> dict[str, ToolRule]:
    return {
        "read_file": ToolRule(
            path_args=["path", "file_path"],
            required_args=["path"],
            arg_types={"path": "str"},
        ),
        "write_file": ToolRule(
            path_args=["path", "file_path"],
            required_args=["path", "content"],
            arg_types={"path": "str", "content": "str"},
            taint_sensitive=True,
        ),
        "list_dir": ToolRule(
            path_args=["path", "dir"],
            arg_types={"path": "str"},
        ),
        "run_cmd": ToolRule(
            command_args=["command", "cmd"],
            required_args=["command"],
            arg_types={"command": "str"},
            taint_sensitive=True,
        ),
        "fetch_url": ToolRule(
            url_args=["url", "uri"],
            required_args=["url"],
            arg_types={"url": "str"},
            taint_sensitive=True,
        ),
    }


def _ctx_pager_tool_rules() -> dict[str, ToolRule]:
    return {
        "ctx_commit": ToolRule(
            required_args=["kind", "title", "summary"],
            arg_types={"kind": "str", "title": "str", "summary": "str", "detail": "str"},
            taint_sensitive=True,
        ),
        "ctx_recall": ToolRule(
            arg_types={"query": "str", "budget": "int", "profile": "str"},
        ),
        "ctx_page_in": ToolRule(
            required_args=["ids"],
            arg_types={"ids": "list", "include_neighbors": "bool"},
        ),
        "ctx_supersede": ToolRule(
            required_args=["old_id", "title", "summary"],
            arg_types={"old_id": "str", "title": "str", "summary": "str", "detail": "str"},
            taint_sensitive=True,
        ),
        "ctx_link": ToolRule(
            required_args=["src_id", "dst_id", "relation"],
            arg_types={"src_id": "str", "dst_id": "str", "relation": "str"},
            taint_sensitive=True,
        ),
        "ctx_resolve": ToolRule(
            required_args=["memory_id"],
            arg_types={"memory_id": "str"},
            taint_sensitive=True,
        ),
        "ctx_checkpoint": ToolRule(
            required_args=["goal", "state_summary"],
            arg_types={"goal": "str", "state_summary": "str"},
            taint_sensitive=True,
        ),
        "ctx_compact": ToolRule(
            arg_types={"older_than_turns": "int", "min_group_size": "int"},
            taint_sensitive=True,
        ),
        "ctx_stats": ToolRule(),
    }


PRESET_POLICIES: dict[str, GuardPolicy] = {
    "strict_sandbox": GuardPolicy(
        name="strict_sandbox",
        mode=GuardMode.ENFORCE,
        default_action="deny",
        allowed_tools=["read_file", "list_dir", "run_cmd", "fetch_url"],
        denied_tools=["shell_exec", "raw_eval", "drop_database"],
        tool_rules=_common_dev_tool_rules(),
        command=CommandPolicy(
            allowed_binaries=["ls", "cat", "head", "tail", "grep", "rg", "git", "python3"],
        ),
        network=NetworkPolicy(allowed_schemes=["https"]),
        injection=InjectionPolicy(action="block", score_threshold=0.55, taint_ttl_calls=6),
        rate_limit=RateLimitPolicy(max_calls_per_minute=30, max_identical_consecutive=3),
    ),
    "coding_agent": GuardPolicy(
        name="coding_agent",
        mode=GuardMode.ENFORCE,
        default_action="allow",
        denied_tools=["shell_exec", "raw_eval", "sudo_exec"],
        tool_rules=_common_dev_tool_rules(),
        command=CommandPolicy(
            allowed_binaries=[
                "ls",
                "cat",
                "head",
                "tail",
                "wc",
                "grep",
                "rg",
                "find",
                "git",
                "python3",
                "pytest",
                "ruff",
                "curl",
            ]
        ),
        injection=InjectionPolicy(action="tag", score_threshold=0.60, taint_ttl_calls=5),
    ),
    "read_only_audit": GuardPolicy(
        name="read_only_audit",
        mode=GuardMode.AUDIT,
        default_action="allow",
        tool_rules=_common_dev_tool_rules(),
        command=CommandPolicy(
            allowed_binaries=["ls", "cat", "grep", "rg", "git", "python3", "pytest"],
        ),
        injection=InjectionPolicy(action="warn", score_threshold=0.60, taint_ttl_calls=5),
    ),
    "ctx_pager_hardened": GuardPolicy(
        name="ctx_pager_hardened",
        mode=GuardMode.ENFORCE,
        default_action="deny",
        allowed_tools=list(_ctx_pager_tool_rules().keys()),
        tool_rules=_ctx_pager_tool_rules(),
        dlp=DlpPolicy(redact_responses=True, block_secrets_in_args=True),
        injection=InjectionPolicy(action="block", score_threshold=0.58, taint_ttl_calls=5),
        rate_limit=RateLimitPolicy(max_calls_per_minute=90, max_identical_consecutive=4),
    ),
}


def load_policy(
    policy_or_path: str | Path | GuardPolicy,
    *,
    workspace_root: str | Path | None = None,
) -> GuardPolicy:
    """Load a GuardPolicy from a preset name, JSON file path, or existing policy instance."""
    if isinstance(policy_or_path, GuardPolicy):
        policy = copy.deepcopy(policy_or_path)
    else:
        key = str(policy_or_path)
        if key in PRESET_POLICIES:
            policy = copy.deepcopy(PRESET_POLICIES[key])
        else:
            raw = json.loads(Path(key).read_text(encoding="utf-8"))
            policy = GuardPolicy.from_dict(raw)

    if workspace_root is not None:
        ws = str(Path(workspace_root).resolve())
        updated_roots: list[str] = []
        for root in policy.filesystem.allowed_roots:
            if root in (".", "{workspace}"):
                updated_roots.append(ws)
            else:
                updated_roots.append(root.replace("{workspace}", ws))
        policy.filesystem.allowed_roots = updated_roots
    return policy
