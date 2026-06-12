# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fase 2: Schema Validator — Tests (RED)

Tests para MCPSchemaValidator siguiendo TDD:
- Caso 1: Validación de inputs (JSON schema estricto)
- Caso 2: Validación de outputs (resultados de herramientas)
- Caso 3: Rechazo de tipos incorrectos, campos extra, y esquemas malformados
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from validators.schema_validator import MCPSchemaValidator, SchemaValidationError


# ──────────────────────────────────────────────
# Caso 1: Validación de inputs
# ──────────────────────────────────────────────

class TestInputValidation:
    """Los inputs de herramientas MCP deben validarse contra su schema."""

    def test_valid_input_passes(self):
        """Un input que cumple el schema debe ser validado sin errores."""
        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "encoding": {"type": "string"},
            },
            "required": ["path"],
        }
        validator = MCPSchemaValidator(schema)
        result = validator.validate_input({"path": "/home/sil/file.txt", "encoding": "utf-8"})
        assert result is True

    def test_required_field_missing(self):
        """Un input sin un campo requerido debe lanzar SchemaValidationError."""
        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        }
        validator = MCPSchemaValidator(schema)
        with pytest.raises(SchemaValidationError):
            validator.validate_input({"encoding": "utf-8"})

    def test_wrong_type_rejected(self):
        """Un input con tipo incorrecto debe ser rechazado."""
        schema = {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
            },
            "required": ["count"],
        }
        validator = MCPSchemaValidator(schema)
        with pytest.raises(SchemaValidationError):
            validator.validate_input({"count": "not_a_number"})

    def test_extra_fields_rejected_in_strict_mode(self):
        """En modo estricto, campos extra no definidos en el schema deben ser rechazados."""
        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        }
        validator = MCPSchemaValidator(schema, strict=True)
        with pytest.raises(SchemaValidationError):
            validator.validate_input({"path": "/file.txt", "extra_field": "oops"})


# ──────────────────────────────────────────────
# Caso 2: Validación de outputs
# ──────────────────────────────────────────────

class TestOutputValidation:
    """Los outputs/resultados de herramientas MCP deben validarse."""

    def test_valid_output_passes(self):
        """Un output que cumple el schema debe ser validado."""
        schema = {
            "type": "object",
            "properties": {
                "content": {"type": "string"},
                "size": {"type": "integer"},
            },
            "required": ["content"],
        }
        validator = MCPSchemaValidator(schema)
        result = validator.validate_output({"content": "file contents here", "size": 17})
        assert result is True

    def test_output_missing_required_field(self):
        """Un output sin campo requerido debe lanzar SchemaValidationError."""
        schema = {
            "type": "object",
            "properties": {
                "content": {"type": "string"},
                "size": {"type": "integer"},
            },
            "required": ["content"],
        }
        validator = MCPSchemaValidator(schema)
        with pytest.raises(SchemaValidationError):
            validator.validate_output({"size": 42})

    def test_output_wrong_type(self):
        """Un output con tipo incorrecto debe ser rechazado."""
        schema = {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
            },
            "required": ["success"],
        }
        validator = MCPSchemaValidator(schema)
        with pytest.raises(SchemaValidationError):
            validator.validate_output({"success": "yes"})


# ──────────────────────────────────────────────
# Caso 3: Edge cases y esquemas complejos
# ──────────────────────────────────────────────

class TestEdgeCases:
    """Casos límite y esquemas complejos."""

    def test_nested_object_validation(self):
        """Validación de objetos anidados."""
        schema = {
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "timeout": {"type": "integer"},
                        "retries": {"type": "integer"},
                    },
                    "required": ["timeout"],
                },
            },
            "required": ["config"],
        }
        validator = MCPSchemaValidator(schema)
        assert validator.validate_input({"config": {"timeout": 30, "retries": 3}}) is True

    def test_nested_object_missing_required(self):
        """Objeto anidado sin campo requerido debe fallar."""
        schema = {
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "timeout": {"type": "integer"},
                    },
                    "required": ["timeout"],
                },
            },
            "required": ["config"],
        }
        validator = MCPSchemaValidator(schema)
        with pytest.raises(SchemaValidationError):
            validator.validate_input({"config": {"retries": 3}})

    def test_array_type_validation(self):
        """Validación de arrays."""
        schema = {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["items"],
        }
        validator = MCPSchemaValidator(schema)
        assert validator.validate_input({"items": ["a", "b", "c"]}) is True

    def test_array_wrong_item_type(self):
        """Array con items de tipo incorrecto debe fallar."""
        schema = {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["items"],
        }
        validator = MCPSchemaValidator(schema)
        with pytest.raises(SchemaValidationError):
            validator.validate_input({"items": ["a", 123, "c"]})

    def test_malformed_schema_raises_error(self):
        """Un schema malformado (sin 'type') debe lanzar SchemaValidationError."""
        schema = {
            "properties": {
                "path": {"type": "string"},
            },
        }
        with pytest.raises(SchemaValidationError):
            MCPSchemaValidator(schema)

    def test_empty_object_with_no_required_passes(self):
        """Un objeto vacío con campos no requeridos debe pasar."""
        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
        }
        validator = MCPSchemaValidator(schema)
        assert validator.validate_input({}) is True

    def test_non_dict_input_rejected(self):
        """Un input que no es dict debe ser rechazado."""
        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
        }
        validator = MCPSchemaValidator(schema)
        with pytest.raises(SchemaValidationError):
            validator.validate_input("not a dict")
