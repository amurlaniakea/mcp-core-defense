# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fase 7: MCP Client Integration — SDK Adapter.

Adaptador para integrar MCPSecurityProxy con el SDK oficial de MCP.
Intercepta y valida tool calls antes de su ejecución.

Flujo:
    LLM → secure_tool_execution() → pipeline.check() → execute() o reject()
"""

from typing import Any, Dict, Callable, Awaitable
from pipeline import MCPSecurityProxy, PipelineResult
from policy_engine import AccessDeniedError
from validators import SchemaValidationError
from detectors import DCIInconsistencyError, TDPAttackDetected
from auth import CertificateVerificationError


class SecurityPolicyViolation(Exception):
    """Violación de política de seguridad MCP."""

    def __init__(self, tool_name: str, phase: str, reason: str):
        self.tool_name = tool_name
        self.phase = phase
        self.reason = reason
        super().__init__(
            f"Security violation for '{tool_name}' at phase '{phase}': {reason}"
        )


class MCPSecuritySDKAdapter:
    """
    Adaptador de seguridad para integrar MCPSecurityProxy con el SDK de MCP.

    Intercepta tool calls del LLM y los valida contra el pipeline de 5 fases
    antes de permitir su ejecución.

    Uso:
        proxy = MCPSecurityProxy(allowlist=["filesystem::read_file"])
        adapter = MCPSecuritySDKAdapter(proxy)

        result = await adapter.secure_tool_execution(
            tool_name="filesystem::read_file",
            arguments={"path": "/test.txt"},
            tool_description=mcp_tool_description,
            code_params=["path"],
            original_execute_func=mcp_client.execute,
        )
    """

    def __init__(self, proxy: MCPSecurityProxy):
        """
        Args:
            proxy: Instancia configurada de MCPSecurityProxy.
        """
        self.proxy = proxy

    async def secure_tool_execution(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        original_execute_func: Callable[[str, Dict[str, Any]], Awaitable[Any]],
        tool_description: dict | None = None,
        code_params: list | None = None,
    ) -> Any:
        """
        Intercepta y valida la ejecución de una herramienta.

        Ejecuta el pipeline completo (5 fases) antes de llamar
        a la función de ejecución original.

        Args:
            tool_name: Nombre de la herramienta MCP.
            arguments: Argumentos de la tool call.
            original_execute_func: Función original de ejecución MCP (async).
            tool_description: Descripción MCP de la herramienta (fases 3-4).
            code_params: Parámetros del código real (fase 3).

        Returns:
            Resultado de la ejecución de la herramienta.

        Raises:
            SecurityPolicyViolation: Si el pipeline rechaza la tool call.
        """
        result = self.proxy.check(
            tool_name=tool_name,
            input_data=arguments,
            tool_description=tool_description,
            code_params=code_params,
        )

        if result.passed:
            return await original_execute_func(tool_name, arguments)

        # Construir mensaje de error informativo
        phase = result.phase_passed
        error = result.error
        reason = str(error) if error else "unknown"

        raise SecurityPolicyViolation(
            tool_name=tool_name,
            phase=phase,
            reason=reason,
        )

    def validate_only(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        tool_description: dict | None = None,
        code_params: list | None = None,
    ) -> bool:
        """
        Valida una tool call sin ejecutarla (modo dry-run).

        Args:
            tool_name: Nombre de la herramienta.
            arguments: Argumentos de la tool call.
            tool_description: Descripción MCP de la herramienta.
            code_params: Parámetros del código real.

        Returns:
            True si pasa todas las fases del pipeline.
        """
        result = self.proxy.check(
            tool_name=tool_name,
            input_data=arguments,
            tool_description=tool_description,
            code_params=code_params,
        )
        return result.passed
