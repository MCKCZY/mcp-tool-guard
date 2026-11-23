"""mcp-tool-guard: Runtime security firewall and transparent stdio MCP proxy for AI agents."""

from mcp_tool_guard.audit import AuditLog
from mcp_tool_guard.engine import EgressDecision, IngressDecision, ToolGuardEngine, guard_callable
from mcp_tool_guard.guards import GuardFinding
from mcp_tool_guard.mcp_proxy import McpSecurityProxy
from mcp_tool_guard.policy import (
    PRESET_POLICIES,
    CommandPolicy,
    DecisionAction,
    DlpPolicy,
    FilesystemPolicy,
    GuardMode,
    GuardPolicy,
    InjectionPolicy,
    NetworkPolicy,
    RateLimitPolicy,
    ToolRule,
    load_policy,
)

__all__ = [
    "AuditLog",
    "CommandPolicy",
    "DecisionAction",
    "DlpPolicy",
    "EgressDecision",
    "FilesystemPolicy",
    "GuardFinding",
    "GuardMode",
    "GuardPolicy",
    "IngressDecision",
    "InjectionPolicy",
    "McpSecurityProxy",
    "NetworkPolicy",
    "PRESET_POLICIES",
    "RateLimitPolicy",
    "ToolGuardEngine",
    "ToolRule",
    "guard_callable",
    "load_policy",
]

__version__ = "0.1.0"
