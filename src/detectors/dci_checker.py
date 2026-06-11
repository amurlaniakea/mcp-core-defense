"""
Fase 3: DCI Checker — Description-Code Consistency

Basado en Shi et al. (2026): "Description-Code Inconsistency in MCP Servers".

Verifica que la descripción declarada de una herramienta MCP
es consistente con su implementación real (código fuente).

Dos modos:
1. check(): comparación directa de params declarados vs params del código
2. analyze_static(): análisis estático de código Python + comparación
"""

import ast
import re


class DCIInconsistencyError(Exception):
    """Excepción lanzada cuando se detecta inconsistencia descripción-código."""
    pass


class DCIChecker:
    """
    Detector de inconsistencias descripción-código (DCI) para herramientas MCP.

    Implementa dos estrategias:
    - Comparación directa de parámetros declarados vs parámetros reales
    - Análisis estático de código Python para extraer parámetros
    """

    def check(
        self,
        description: dict,
        code_params: list,
        code_param_types: dict = None,
    ) -> bool:
        """
        Compara los parámetros declarados en la descripción con los del código.

        Args:
            description: Descripción MCP de la herramienta (JSON schema).
            code_params: Lista de nombres de parámetros en el código real.
            code_param_types: Tipos de parámetros en el código (opcional).

        Returns:
            True si la descripción es consistente con el código.

        Raises:
            DCIInconsistencyError: Si se detecta inconsistencia.
        """
        if code_param_types is None:
            code_param_types = {}

        # Extraer parámetros de la descripción
        params_desc = description.get("parameters", {})
        properties = params_desc.get("properties", {})
        required_desc = set(params_desc.get("required", []))
        declared_params = set(properties.keys())
        code_params_set = set(code_params)

        # Verificar: parámetros declarados pero ausentes en el código
        missing_in_code = declared_params - code_params_set
        if missing_in_code:
            raise DCIInconsistencyError(
                "Parameters declared in description but missing in code: "
                + str(sorted(missing_in_code))
            )

        # Verificar: parámetros en el código pero no en la descripción
        extra_in_code = code_params_set - declared_params
        if extra_in_code:
            raise DCIInconsistencyError(
                "Parameters in code but not declared in description: "
                + str(sorted(extra_in_code))
            )

        # Verificar: tipos de parámetros
        for param_name, declared_type in code_param_types.items():
            if param_name in properties:
                desc_type = properties[param_name].get("type")
                if desc_type and desc_type != declared_type:
                    raise DCIInconsistencyError(
                        "Type mismatch for '" + param_name + "': "
                        "description says '" + desc_type + "', code uses '" + declared_type + "'"
                    )

        return True

    def extract_params(self, code: str) -> list:
        """
        Extrae los nombres de parámetros de una función Python
        mediante análisis estático (AST).

        Args:
            code: Código fuente Python.

        Returns:
            Lista de nombres de parámetros.
        """
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

    def _extract_params_regex(self, code: str) -> list:
        """Fallback: extraer parámetros con regex."""
        match = re.search(
            r"def\s+\w+\s*\(([^)]*)\)", code
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

    def analyze_static(self, description: dict, code: str) -> bool:
        """
        Analiza estáticamente código Python y lo compara con la descripción.

        Args:
            description: Descripción MCP de la herramienta.
            code: Código fuente Python de la herramienta.

        Returns:
            True si el código es consistente con la descripción.

        Raises:
            DCIInconsistencyError: Si se detecta inconsistencia.
        """
        code_params = self.extract_params(code)
        return self.check(description, code_params)
