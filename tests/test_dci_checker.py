"""
Fase 3: DCI Checker — Tests (RED)

Tests para DCIChecker siguiendo TDD.
DCI = Description-Code Consistency (Shi et al. 2026).

Verifica que la descripción declarada de una herramienta MCP
es consistente con su comportamiento real (parámetros, acciones).

Casos:
- Caso 1: Descripción consistente con el código (pasa)
- Caso 2: Descripción inconsistente (falla — parámetros no coinciden)
- Caso 3: Análisis estático de código fuente vs descripción
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detectors.dci_checker import DCIChecker, DCIInconsistencyError


# ──────────────────────────────────────────────
# Caso 1: Descripción consistente
# ──────────────────────────────────────────────

class TestConsistentDescription:
    """Herramientas cuya descripción coincide con el código deben pasar."""

    def test_simple_consistent_tool(self):
        """Una herramienta simple con descripción correcta debe pasar."""
        description = {
            "name": "read_file",
            "description": "Reads a file from the filesystem",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                },
                "required": ["path"],
            },
        }
        code_params = ["path"]
        checker = DCIChecker()
        result = checker.check(description, code_params)
        assert result is True

    def test_multiple_params_consistent(self):
        """Múltiples parámetros que coinciden deben pasar."""
        description = {
            "name": "write_file",
            "description": "Writes content to a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "encoding": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        }
        code_params = ["path", "content", "encoding"]
        checker = DCIChecker()
        result = checker.check(description, code_params)
        assert result is True

    def test_no_params_consistent(self):
        """Herramienta sin parámetros que coincide debe pasar."""
        description = {
            "name": "get_status",
            "description": "Returns system status",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        }
        code_params = []
        checker = DCIChecker()
        result = checker.check(description, code_params)
        assert result is True


# ──────────────────────────────────────────────
# Caso 2: Descripción inconsistente
# ──────────────────────────────────────────────

class TestInconsistentDescription:
    """Herramientas con descripción que no coincide con el código deben fallar."""

    def test_missing_param_in_code(self):
        """Un parámetro declarado en la descripción pero ausente en el código."""
        description = {
            "name": "read_file",
            "description": "Reads a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "encoding": {"type": "string"},
                },
                "required": ["path"],
            },
        }
        # El código solo tiene 'path', no 'encoding'
        code_params = ["path"]
        checker = DCIChecker()
        with pytest.raises(DCIInconsistencyError):
            checker.check(description, code_params)

    def test_extra_param_in_code(self):
        """Un parámetro en el código pero no en la descripción."""
        description = {
            "name": "read_file",
            "description": "Reads a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
            },
        }
        # El código tiene 'secret_param' que no está en la descripción
        code_params = ["path", "secret_param"]
        checker = DCIChecker()
        with pytest.raises(DCIInconsistencyError):
            checker.check(description, code_params)

    def test_param_type_mismatch(self):
        """Un parámetro con tipo diferente en descripción vs código."""
        description = {
            "name": "set_count",
            "description": "Sets a count value",
            "parameters": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer"},
                },
                "required": ["count"],
            },
        }
        # El código acepta count como string, no integer
        code_params = ["count"]
        code_param_types = {"count": "string"}
        checker = DCIChecker()
        with pytest.raises(DCIInconsistencyError):
            checker.check(description, code_params, code_param_types=code_param_types)


# ──────────────────────────────────────────────
# Caso 3: Análisis estático de código fuente
# ──────────────────────────────────────────────

class TestStaticAnalysis:
    """Análisis estático de código fuente vs descripción."""

    def test_extract_params_from_python_function(self):
        """Extraer parámetros de una función Python desde su código fuente."""
        code = '''
def read_file(path, encoding="utf-8"):
    """Reads a file."""
    with open(path, "r", encoding=encoding) as f:
        return f.read()
'''
        checker = DCIChecker()
        params = checker.extract_params(code)
        assert "path" in params
        assert "encoding" in params

    def test_extract_params_from_async_function(self):
        """Extraer parámetros de una función async."""
        code = '''
async def fetch_url(url, timeout=30, headers=None):
    """Fetches a URL."""
    pass
'''
        checker = DCIChecker()
        params = checker.extract_params(code)
        assert "url" in params
        assert "timeout" in params
        assert "headers" in params

    def test_static_analysis_detects_inconsistency(self):
        """El análisis estático debe detectar inconsistencias."""
        description = {
            "name": "read_file",
            "description": "Reads a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "encoding": {"type": "string"},
                },
                "required": ["path"],
            },
        }
        # Código con parámetro extra no declarado
        code = '''
def read_file(path, secret_token):
    """Reads a file."""
    pass
'''
        checker = DCIChecker()
        with pytest.raises(DCIInconsistencyError):
            checker.analyze_static(description, code)

    def test_static_analysis_passes_for_consistent_code(self):
        """El análisis estático debe pasar para código consistente."""
        description = {
            "name": "read_file",
            "description": "Reads a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
            },
        }
        code = '''
def read_file(path):
    """Reads a file."""
    pass
'''
        checker = DCIChecker()
        result = checker.analyze_static(description, code)
        assert result is True
