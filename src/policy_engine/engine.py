"""
Fase 1: Policy Engine — MCPSecurityPolicyEngine

Motor de políticas deny-by-default para MCP Security Proxy.
Soporta:
- Allowlist explícita de herramientas (server::action)
- Wildcards (server::*)
- Restricciones por contexto (read-only mode)
"""


class AccessDeniedError(Exception):
    """Excepción lanzada cuando una herramienta no está permitida por la política."""
    pass


class MCPSecurityPolicyEngine:
    """
    Motor de políticas de seguridad MCP con enfoque deny-by-default.

    Args:
        allowlist: Lista de herramientas permitidas (ej: ["filesystem::read_file", "git::*"]).
        context: Diccionario de contexto (ej: {"mode": "read-only"}).
    """

    # Sufijos que se consideran operaciones de escritura
    WRITE_ACTIONS = {"write", "delete", "create", "update", "remove", "push", "commit", "drop", "truncate"}

    def __init__(self, allowlist: list[str], context: dict | None = None):
        self._allowlist = allowlist or []
        self._context = context or {}

    def check(self, tool_name: str) -> bool:
        """
        Verifica si una herramienta está permitida por la política.

        Args:
            tool_name: Nombre de la herramienta (ej: "filesystem::read_file").

        Returns:
            True si la herramienta está permitida.

        Raises:
            AccessDeniedError: Si la herramienta no está permitida.
        """
        if not tool_name:
            raise AccessDeniedError(f"Empty tool name denied")

        # Verificar si la herramienta está en la allowlist (exacta o wildcard)
        if not self._is_in_allowlist(tool_name):
            raise AccessDeniedError(f"Tool '{tool_name}' not in allowlist")

        # Verificar restricciones de contexto (read-only)
        if self._is_read_only() and self._is_write_action(tool_name):
            raise AccessDeniedError(
                f"Tool '{tool_name}' denied in read-only mode"
            )

        return True

    def _is_in_allowlist(self, tool_name: str) -> bool:
        """Verifica si la herramienta coincide con alguna entrada de la allowlist."""
        for entry in self._allowlist:
            # Match exacto
            if tool_name == entry:
                return True
            # Wildcard: "server::*" permite cualquier acción de ese servidor
            if entry.endswith("::*"):
                server = entry[:-3]  # Quitar "::*"
                if tool_name.startswith(f"{server}::"):
                    return True
        return False

    def _is_read_only(self) -> bool:
        """Verifica si el contexto actual es de solo lectura."""
        return self._context.get("mode") == "read-only"

    def _is_write_action(self, tool_name: str) -> bool:
        """Determina si una herramienta es de escritura basándose en su nombre."""
        parts = tool_name.split("::")
        if len(parts) < 2:
            return False
        action = parts[-1].lower()
        # Coincidencia exacta
        if action in self.WRITE_ACTIONS:
            return True
        # Substring: "write_file" contiene "write", "delete_file" contiene "delete"
        return any(write_word in action for write_word in self.WRITE_ACTIONS)
