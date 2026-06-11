"""MCP Core Defense — 5-phase security proxy for MCP agents."""

from .engine import MCPSecurityPolicyEngine, AccessDeniedError

__all__ = ["MCPSecurityPolicyEngine", "AccessDeniedError"]
__version__ = "0.1.0"
