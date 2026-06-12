# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""MCP Core Defense — 7-phase security proxy for MCP agents."""

from .engine import MCPSecurityPolicyEngine, AccessDeniedError

__all__ = ["MCPSecurityPolicyEngine", "AccessDeniedError"]
__version__ = "0.1.0"
