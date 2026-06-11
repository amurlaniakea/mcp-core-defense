"""
Fase 1: Policy Engine — Tests (RED)

Tests para MCPSecurityPolicyEngine siguiendo TDD:
- Caso 1: Deny-by-default (herramienta no en whitelist = AccessDeniedError)
- Caso 2: Allow list (herramienta permitida = autorizada)
- Caso 3: Wildcards y restricciones por contexto (read-only)
"""

import pytest
import sys
import os

# Añadir src/ al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from policy_engine.engine import MCPSecurityPolicyEngine, AccessDeniedError


# ──────────────────────────────────────────────
# Caso 1: Deny-by-default
# ──────────────────────────────────────────────

class TestDenyByDefault:
    """Herramientas no explícitamente permitidas deben ser denegadas."""

    def test_unknown_tool_denied(self):
        """Una herramienta desconocida debe lanzar AccessDeniedError."""
        engine = MCPSecurityPolicyEngine(allowlist=[])
        with pytest.raises(AccessDeniedError):
            engine.check("malicious::exec")

    def test_unknown_tool_with_non_empty_allowlist(self):
        """Una herramienta que NO está en la whitelist debe ser denegada
        incluso cuando la whitelist tiene otras herramientas."""
        engine = MCPSecurityPolicyEngine(allowlist=["filesystem::read_file"])
        with pytest.raises(AccessDeniedError):
            engine.check("filesystem::write_file")

    def test_empty_tool_name_denied(self):
        """Un nombre de herramienta vacío debe ser denegado."""
        engine = MCPSecurityPolicyEngine(allowlist=[])
        with pytest.raises(AccessDeniedError):
            engine.check("")


# ──────────────────────────────────────────────
# Caso 2: Allow list
# ──────────────────────────────────────────────

class TestAllowList:
    """Herramientas explícitamente permitidas deben ser autorizadas."""

    def test_allowed_tool_returns_true(self):
        """filesystem::read_file en la whitelist debe ser autorizada."""
        engine = MCPSecurityPolicyEngine(allowlist=["filesystem::read_file"])
        result = engine.check("filesystem::read_file")
        assert result is True

    def test_multiple_allowed_tools(self):
        """Varias herramientas en la whitelist deben ser autorizadas."""
        engine = MCPSecurityPolicyEngine(allowlist=[
            "filesystem::read_file",
            "git::status",
            "web::fetch",
        ])
        assert engine.check("filesystem::read_file") is True
        assert engine.check("git::status") is True
        assert engine.check("web::fetch") is True

    def test_allowed_tool_not_affecting_others(self):
        """Permitir una herramienta no permite otras del mismo servidor."""
        engine = MCPSecurityPolicyEngine(allowlist=["filesystem::read_file"])
        assert engine.check("filesystem::read_file") is True
        with pytest.raises(AccessDeniedError):
            engine.check("filesystem::delete")


# ──────────────────────────────────────────────
# Caso 3: Wildcards y contexto
# ──────────────────────────────────────────────

class TestWildcardsAndContext:
    """Soporte para comodines (wildcards) y restricciones por contexto."""

    def test_wildcard_allows_all_actions_for_server(self):
        """git::* debe permitir cualquier acción del servidor git."""
        engine = MCPSecurityPolicyEngine(allowlist=["git::*"])
        assert engine.check("git::status") is True
        assert engine.check("git::commit") is True
        assert engine.check("git::push") is True

    def test_wildcard_does_not_affect_other_servers(self):
        """git::* NO debe permitir herramientas de otros servidores."""
        engine = MCPSecurityPolicyEngine(allowlist=["git::*"])
        with pytest.raises(AccessDeniedError):
            engine.check("filesystem::read_file")

    def test_read_only_mode_denies_writes(self):
        """En modo read-only, las operaciones de escritura deben ser denegadas."""
        engine = MCPSecurityPolicyEngine(
            allowlist=["filesystem::read_file", "filesystem::write_file"],
            context={"mode": "read-only"},
        )
        assert engine.check("filesystem::read_file") is True
        with pytest.raises(AccessDeniedError):
            engine.check("filesystem::write_file")

    def test_read_only_mode_allows_reads(self):
        """En modo read-only, las operaciones de lectura deben ser permitidas."""
        engine = MCPSecurityPolicyEngine(
            allowlist=["filesystem::read_file", "git::status"],
            context={"mode": "read-only"},
        )
        assert engine.check("filesystem::read_file") is True
        assert engine.check("git::status") is True

    def test_wildcard_combined_with_specific_rules(self):
        """Wildcards y reglas específicas pueden coexistir."""
        engine = MCPSecurityPolicyEngine(allowlist=[
            "git::*",
            "filesystem::read_file",
        ])
        # git::* aplica
        assert engine.check("git::log") is True
        # filesystem::read_file aplica (pero no write)
        assert engine.check("filesystem::read_file") is True
        with pytest.raises(AccessDeniedError):
            engine.check("filesystem::write_file")
        # Otros servidores denegados
        with pytest.raises(AccessDeniedError):
            engine.check("web::fetch")
