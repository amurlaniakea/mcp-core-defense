# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Phase 2: Schema Validator — strict JSON I/O validation for MCP tool calls."""

from .schema_validator import MCPSchemaValidator, SchemaValidationError

__all__ = ["MCPSchemaValidator", "SchemaValidationError"]
