# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fase 3: DCI Checker — Tests (RED)

Tests para DCIChecker siguiendo TDD.
DCI = Description-Code Consistency (Shi et al. 2026).

Verifica que la descripcion declarada de una herramienta MCP
es consistente con su comportamiento real (parametros, acciones).

Casos:
- Caso 1: Descripcion consistente con el codigo (pasa)
- Caso 2: Descripcion inconsistente (falla — parametros no coinciden)
- Caso 3: Analisis estatico de codigo fuente vs descripcion
- Caso 4: Soporte multi-lenguaje (JavaScript/TypeScript)
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detectors.dci_checker import DCIChecker, DCIInconsistencyError


# ──────────────────────────────────────────────
# Caso 1: Descripcion consistente
# ──────────────────────────────────────────────

class TestConsistentDescription:
    """Herramientas cuya descripcion coincide con el codigo deben pasar."""

    def test_simple_consistent_tool(self):
        """Una herramienta simple con descripcion correcta debe pasar."""
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
        """Multiples parametros que coinciden deben pasar."""
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
        """Herramienta sin parametros que coincide debe pasar."""
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
# Caso 2: Descripcion inconsistente
# ──────────────────────────────────────────────

class TestInconsistentDescription:
    """Herramientas con descripcion que no coincide con el codigo deben fallar."""

    def test_missing_param_in_code(self):
        """Un parametro declarado en la descripcion pero ausente en el codigo."""
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
        code_params = ["path"]
        checker = DCIChecker()
        with pytest.raises(DCIInconsistencyError):
            checker.check(description, code_params)

    def test_extra_param_in_code(self):
        """Un parametro en el codigo pero no en la descripcion."""
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
        code_params = ["path", "secret_param"]
        checker = DCIChecker()
        with pytest.raises(DCIInconsistencyError):
            checker.check(description, code_params)

    def test_param_type_mismatch(self):
        """Un parametro con tipo diferente en descripcion vs codigo."""
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
        code_params = ["count"]
        code_param_types = {"count": "string"}
        checker = DCIChecker()
        with pytest.raises(DCIInconsistencyError):
            checker.check(description, code_params, code_param_types=code_param_types)


# ──────────────────────────────────────────────
# Caso 3: Analisis estatico de codigo fuente
# ──────────────────────────────────────────────

class TestStaticAnalysis:
    """Analisis estatico de codigo fuente vs descripcion."""

    def test_extract_params_from_python_function(self):
        """Extraer parametros de una funcion Python desde su codigo fuente."""
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
        """Extraer parametros de una funcion async."""
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
        """El analisis estatico debe detectar inconsistencias."""
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
        code = '''
def read_file(path, secret_token):
    """Reads a file."""
    pass
'''
        checker = DCIChecker()
        with pytest.raises(DCIInconsistencyError):
            checker.analyze_static(description, code)

    def test_static_analysis_passes_for_consistent_code(self):
        """El analisis estatico debe pasar para codigo consistente."""
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


# ──────────────────────────────────────────────
# Caso 4: Soporte multi-lenguaje
# ──────────────────────────────────────────────

class TestMultiLanguageSupport:
    """Soporte multi-lenguaje (JavaScript/TypeScript)."""

    def test_detect_python(self):
        code = "def hello(name):\n    return name"
        checker = DCIChecker()
        assert checker._detect_language(code) == "python"

    def test_detect_javascript(self):
        code = "function hello(name) { return name; }"
        checker = DCIChecker()
        assert checker._detect_language(code) == "javascript"

    def test_detect_typescript(self):
        code = "function hello(name: string): string { return name; }"
        checker = DCIChecker()
        assert checker._detect_language(code) == "typescript"

    def test_extract_params_js_function(self):
        code = "function read_file(path, encoding) { return path; }"
        checker = DCIChecker()
        params = checker.extract_params(code, language="javascript")
        assert "path" in params
        assert "encoding" in params

    def test_extract_params_js_arrow(self):
        code = "const read_file = (path, encoding) => { return path; }"
        checker = DCIChecker()
        params = checker.extract_params(code, language="javascript")
        assert "path" in params
        assert "encoding" in params

    def test_extract_params_typescript(self):
        code = "function read_file(path: string, encoding: string = 'utf-8'): string { return path; }"
        checker = DCIChecker()
        params = checker.extract_params(code, language="typescript")
        assert "path" in params
        assert "encoding" in params

    def test_extract_params_js_destructuring(self):
        code = "function read_file({ path, encoding }) { return path; }"
        checker = DCIChecker()
        params = checker.extract_params(code, language="javascript")
        assert "path" in params
        assert "encoding" in params

    def test_dci_analysis_javascript(self):
        description = {
            "name": "read_file",
            "description": "Reads a file",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
        code = "function read_file(path) { return path; }"
        checker = DCIChecker()
        result = checker.analyze_static(description, code, language="javascript")
        assert result is True

    def test_dci_analysis_typescript_inconsistency(self):
        description = {
            "name": "read_file",
            "description": "Reads a file",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "secret": {"type": "string"}},
                "required": ["path"],
            },
        }
        code = "function read_file(path: string): string { return path; }"
        checker = DCIChecker()
        with pytest.raises(DCIInconsistencyError):
            checker.analyze_static(description, code, language="typescript")

    def test_auto_detect_extract_params(self):
        """Auto-deteccion de lenguaje al extraer parametros."""
        checker = DCIChecker()
        py_params = checker.extract_params("def foo(x, y): pass")
        assert "x" in py_params
        assert "y" in py_params
        js_params = checker.extract_params("function foo(x, y) { }")
        assert "x" in js_params
        assert "y" in js_params
