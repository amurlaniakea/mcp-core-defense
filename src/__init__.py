"""MCP Core Defense — Source package."""

from .pipeline import MCPSecurityProxy, PipelineResult
from .sdk_integration import MCPSecuritySDKAdapter

__all__ = ["MCPSecurityProxy", "PipelineResult", "MCPSecuritySDKAdapter"]
__version__ = "0.1.0"
