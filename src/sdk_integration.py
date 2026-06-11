"""
Fase 7: MCP Client Integration — SDK Adapter

Adaptador para integrar MCPSecurityProxy con el SDK oficial de MCP.
Permite interceptar y validar tool calls antes de su ejecución.
"""

from typing import Any, Dict, Callable, Awaitable
from pipeline import MCPSecurityProxy, PipelineResult

class MCPSecuritySDKAdapter:
    def __init__(self, proxy: MCPSecurityProxy):
        self.proxy = proxy

    async def secure_tool_execution(
        self, 
        tool_name: str, 
        arguments: Dict[str, Any], 
        original_execute_func: Callable[[str, Dict[str, Any]], Awaitable[Any]]
    ) -> Any:
        """
        Intercepta y valida la ejecucion de una herramienta.
        """
        # Ejecutar pipeline con la firma correcta
        result = self.proxy.check(tool_name=tool_name, input_data=arguments)

        if result.passed:
            return await original_execute_func(tool_name, arguments)
        else:
            reason = getattr(result, "blocked_reason", "Policy violation")
            raise Exception(f"Security Policy Violation: {reason}")
