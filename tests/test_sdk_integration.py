# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests para MCP Client Integration
"""

import pytest
from sdk_integration import MCPSecuritySDKAdapter, SecurityPolicyViolation
from pipeline import MCPSecurityProxy


@pytest.mark.asyncio
async def test_sdk_adapter_allows_safe_execution():
    """Safe tool call passes pipeline and executes."""
    proxy = MCPSecurityProxy(allowlist=["read_file"])
    adapter = MCPSecuritySDKAdapter(proxy)

    async def mock_execute(name, args):
        return "success"

    result = await adapter.secure_tool_execution(
        "read_file", {"path": "test.txt"}, mock_execute
    )
    assert result == "success"


@pytest.mark.asyncio
async def test_sdk_adapter_blocks_unsafe_execution():
    """Unsafe tool call is blocked by pipeline."""
    proxy = MCPSecurityProxy(allowlist=["read_file"])
    adapter = MCPSecuritySDKAdapter(proxy)

    async def mock_execute(name, args):
        return "should not reach here"

    with pytest.raises(SecurityPolicyViolation) as exc_info:
        await adapter.secure_tool_execution(
            "malicious::exec", {"cmd": "rm -rf /"}, mock_execute
        )
    assert exc_info.value.phase == "policy"
    assert exc_info.value.tool_name == "malicious::exec"


def test_validate_only_returns_true_for_safe():
    """Dry-run validation returns True for allowed tools."""
    proxy = MCPSecurityProxy(allowlist=["read_file"])
    adapter = MCPSecuritySDKAdapter(proxy)
    assert adapter.validate_only("read_file", {"path": "test.txt"}) is True


def test_validate_only_returns_false_for_unsafe():
    """Dry-run validation returns False for blocked tools."""
    proxy = MCPSecurityProxy(allowlist=["read_file"])
    adapter = MCPSecuritySDKAdapter(proxy)
    assert adapter.validate_only("malicious::exec", {"cmd": "whoami"}) is False
