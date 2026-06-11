"""
Tests para MCP Client Integration
"""

import pytest
from sdk_integration import MCPSecuritySDKAdapter
from pipeline import MCPSecurityProxy

@pytest.mark.asyncio
async def test_sdk_adapter_allows_safe_execution():
    # Setup
    proxy = MCPSecurityProxy()
    adapter = MCPSecuritySDKAdapter(proxy)
    
    # Mock de ejecucion
    async def mock_execute(name, args):
        return "success"
    
    # Ejecutar via adaptador
    # Inicializar el proxy con la herramienta permitida
    proxy = MCPSecurityProxy(allowlist=["read_file"])
    adapter = MCPSecuritySDKAdapter(proxy)
    
    result = await adapter.secure_tool_execution("read_file", {"path": "test.txt"}, mock_execute)
    assert result == "success"
