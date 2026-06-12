# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""MCP Core Defense — Source package."""

from .pipeline import MCPSecurityProxy, PipelineResult
from .sdk_integration import MCPSecuritySDKAdapter

__all__ = ["MCPSecurityProxy", "PipelineResult", "MCPSecuritySDKAdapter"]
__version__ = "0.1.0"
