# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fase 2: Schema Validator — MCPSchemaValidator

Validación estricta de JSON schema para inputs/outputs de herramientas MCP.
Soporta:
- Validación de tipos (string, integer, boolean, object, array)
- Campos requeridos
- Objetos anidados
- Arrays con tipo de items
- Modo estricto (rechaza campos extra)
- Esquemas malformados
"""


class SchemaValidationError(Exception):
    """Excepción lanzada cuando un input/output no cumple el schema."""
    pass


class MCPSchemaValidator:
    """
    Validador de JSON schema para llamadas MCP.

    Args:
        schema: JSON Schema (draft-07 subset) como dict.
        strict: Si True, rechaza campos no definidos en properties.
    """

    def __init__(self, schema: dict, strict: bool = False):
        if not isinstance(schema, dict) or "type" not in schema:
            raise SchemaValidationError(
                "Malformed schema: must be a dict with 'type' field"
            )
        self._schema = schema
        self._strict = strict

    def validate_input(self, data: dict) -> bool:
        """Valida un input contra el schema."""
        self._validate(data, self._schema, context="input")
        return True

    def validate_output(self, data: dict) -> bool:
        """Valida un output/resultado contra el schema."""
        self._validate(data, self._schema, context="output")
        return True

    def _validate(self, data: any, schema: dict, context: str = "data") -> None:
        """Valida recursivamente un valor contra un schema."""
        # Verificar que el schema tenga type
        if "type" not in schema:
            raise SchemaValidationError(
                f"Malformed schema: missing 'type' at {context}"
            )

        expected_type = schema["type"]
        self._check_type(data, expected_type, context)

        # Validaciones específicas por tipo
        if expected_type == "object" and isinstance(data, dict):
            self._validate_object(data, schema, context)
        elif expected_type == "array" and isinstance(data, list):
            self._validate_array(data, schema, context)

    def _check_type(self, value: any, expected_type: str, context: str) -> None:
        """Verifica que el valor sea del tipo esperado."""
        type_map = {
            "string": str,
            "integer": int,
            "boolean": bool,
            "object": dict,
            "array": list,
            "number": (int, float),
        }

        if expected_type == "integer" and isinstance(value, bool):
            # bool es subclase de int en Python — rechazar explícitamente
            raise SchemaValidationError(
                f"{context}: expected {expected_type}, got bool"
            )

        if expected_type == "number" and isinstance(value, bool):
            raise SchemaValidationError(
                f"{context}: expected {expected_type}, got bool"
            )

        python_type = type_map.get(expected_type)
        if python_type is None:
            raise SchemaValidationError(
                f"Unknown type '{expected_type}' in schema at {context}"
            )

        if not isinstance(value, python_type):
            raise SchemaValidationError(
                f"{context}: expected {expected_type}, got {type(value).__name__}"
            )

    def _validate_object(self, data: dict, schema: dict, context: str) -> None:
        """Valida un objeto dict contra las properties del schema."""
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # Verificar campos requerados
        for field in required:
            if field not in data:
                raise SchemaValidationError(
                    f"{context}: required field '{field}' is missing"
                )

        # Modo estricto: rechazar campos no definidos
        if self._strict:
            for field in data:
                if field not in properties:
                    raise SchemaValidationError(
                        f"{context}: extra field '{field}' not allowed in strict mode"
                    )

        # Validar cada campo presente contra su schema
        for field, value in data.items():
            if field in properties:
                field_schema = properties[field]
                self._validate(
                    value, field_schema, context=f"{context}.{field}"
                )

    def _validate_array(self, data: list, schema: dict, context: str) -> None:
        """Valida un array contra el schema de items."""
        items_schema = schema.get("items")
        if items_schema is None:
            return  # Sin schema de items, cualquier contenido es válido

        for i, item in enumerate(data):
            self._validate(item, items_schema, context=f"{context}[{i}]")
