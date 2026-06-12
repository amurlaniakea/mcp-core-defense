# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fase 3: DCI Checker — Description-Code Consistency

Basado en Shi et al. (2026): "Description-Code Inconsistency in MCP Servers".

Verifica que la descripcion declarada de una herramienta MCP
es consistente con su implementacion real (codigo fuente).

Modos:
1. check(): comparacion directa de params declarados vs params del codigo
2. analyze_static(): analisis estatico de codigo (Python/JS/TS) + comparacion

Soporte multi-lenguaje:
- Python: analisis AST nativo
- JavaScript/TypeScript: regex-based (funciones arrow, function, class methods)
"""

import ast
import re


class DCIInconsistencyError(Exception):
    """Excepcion lanzada cuando se detecta inconsistencia descripcion-codigo."""
    pass


class DCIChecker:
    """
    Detector de inconsistencias descripcion-codigo (DCI) para herramientas MCP.

    Implementa dos estrategias:
    - Comparacion directa de parametros declarados vs parametros reales
    - Analisis estatico de codigo fuente (Python, JavaScript, TypeScript)
    """

    # Lenguajes soportados
    SUPPORTED_LANGUAGES = ["python", "javascript", "typescript"]

    def check(
        self,
        description: dict,
        code_params: list,
        code_param_types: dict = None,
    ) -> bool:
        """
        Compara los parametros declarados en la descripcion con los del codigo.

        Args:
            description: Descripcion MCP de la herramienta (JSON schema).
            code_params: Lista de nombres de parametros en el codigo real.
            code_param_types: Tipos de parametros en el codigo (opcional).

        Returns:
            True si la descripcion es consistente con el codigo.

        Raises:
            DCIInconsistencyError: Si se detecta inconsistencia.
        """
        if code_param_types is None:
            code_param_types = {}

        params_desc = description.get("parameters", {})
        properties = params_desc.get("properties", {})
        required_desc = set(params_desc.get("required", []))
        declared_params = set(properties.keys())
        code_params_set = set(code_params)

        missing_in_code = declared_params - code_params_set
        if missing_in_code:
            raise DCIInconsistencyError(
                "Parameters declared in description but missing in code: "
                + str(sorted(missing_in_code))
            )

        extra_in_code = code_params_set - declared_params
        if extra_in_code:
            raise DCIInconsistencyError(
                "Parameters in code but not declared in description: "
                + str(sorted(extra_in_code))
            )

        for param_name, declared_type in code_param_types.items():
            if param_name in properties:
                desc_type = properties[param_name].get("type")
                if desc_type and desc_type != declared_type:
                    raise DCIInconsistencyError(
                        "Type mismatch for '" + param_name + "': "
                        "description says '" + desc_type + "', code uses '" + declared_type + "'"
                    )

        return True

    def extract_params(self, code: str, language: str = "auto") -> list:
        """
        Extrae los nombres de parametros de una funcion.

        Args:
            code: Codigo fuente.
            language: "python", "javascript", "typescript", o "auto" (detecta automaticamente).

        Returns:
            Lista de nombres de parametros.
        """
        if language == "auto":
            language = self._detect_language(code)

        if language == "python":
            return self._extract_params_python(code)
        elif language in ("javascript", "typescript"):
            return self._extract_params_js(code)
        else:
            return self._extract_params_regex(code)

    def _detect_language(self, code: str) -> str:
        """Detecta el lenguaje de codigo fuente."""
        # Python: def, import, self, :
        if re.search(r"^\s*(def |class |import |from \w+ import)", code, re.MULTILINE):
            return "python"
        # TypeScript: type annotations, interface, as, <>
        if re.search(r":\s*(string|number|boolean|any)\b|interface\s+\w+|:\s*\w+\s*=>", code):
            return "typescript"
        # JavaScript: function, const, let, var, =>
        if re.search(r"\b(function|const|let|var)\b|=>", code):
            return "javascript"
        return "python"  # Default

    def _extract_params_python(self, code: str) -> list:
        """Extrae parametros de codigo Python via AST."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return self._extract_params_regex(code)

        params = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                for arg in node.args.args:
                    params.append(arg.arg)
                for arg in node.args.kwonlyargs:
                    params.append(arg.arg)
                break

        return params

    def _extract_params_js(self, code: str) -> list:
        """
        Extrae parametros de codigo JavaScript/TypeScript.
        Soporta:
        - function name(params)
        - const name = (params) =>
        - const name = function(params)
        - class { method(params) }
        """
        # function name(params) o async function name(params)
        match = re.search(
            r"(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)", code
        )
        if match:
            return self._parse_js_params(match.group(2))

        # const/let/var name = (params) => o function(params)
        match = re.search(
            r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\(([^)]*)\)|function\s*\(([^)]*))\)\s*=>",
            code
        )
        if match:
            params_str = match.group(2) or match.group(3) or ""
            return self._parse_js_params(params_str)

        # Arrow function directa: (params) =>
        match = re.search(
            r"\(([^)]*)\)\s*=>", code
        )
        if match:
            return self._parse_js_params(match.group(1))

        # method(params) en clase
        match = re.search(
            r"(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{", code
        )
        if match:
            return self._parse_js_params(match.group(2))

        return []

    def _parse_js_params(self, params_str: str) -> list:
        """Parsea una string de parametros JS/TS."""
        params = []
        # Preprocesar: extraer destructuring {a, b} antes de splitear
        params_str = self._expand_js_destructuring(params_str)
        for param in params_str.split(","):
            param = param.strip()
            if not param:
                continue
            # Quitar valor por defecto
            param = param.split("=")[0].strip()
            # Quitar anotacion de tipo TypeScript
            param = param.split(":")[0].strip()
            if param and param != "self":
                params.append(param)
        return params

    def _expand_js_destructuring(self, params_str: str) -> str:
        """Expande destructuring {a, b} y [a, b] en params separados por coma."""
        # Reemplazar {a, b, c} por a, b, c
        result = re.sub(r"\{([^}]*)\}", lambda m: m.group(1), params_str)
        # Reemplazar [a, b, c] por a, b, c
        result = re.sub(r"\[([^\]]*)\]", lambda m: m.group(1), result)
        return result

    def _extract_params_regex(self, code: str) -> list:
        """Fallback: extraer parametros con regex generico."""
        match = re.search(
            r"(?:def|function)\s+\w+\s*\(([^)]*)\)", code
        )
        if not match:
            return []

        params_str = match.group(1)
        params = []
        for param in params_str.split(","):
            param = param.strip()
            if param:
                param_name = param.split("=")[0].split(":")[0].strip()
                if param_name and param_name != "self":
                    params.append(param_name)
        return params

    def analyze_static(self, description: dict, code: str, language: str = "auto") -> bool:
        """
        Analiza estaticamente codigo fuente y lo compara con la descripcion.

        Args:
            description: Descripcion MCP de la herramienta.
            code: Codigo fuente de la herramienta.
            language: "python", "javascript", "typescript", o "auto".

        Returns:
            True si el codigo es consistente con la descripcion.

        Raises:
            DCIInconsistencyError: Si se detecta inconsistencia.
        """
        code_params = self.extract_params(code, language=language)
        return self.check(description, code_params)
