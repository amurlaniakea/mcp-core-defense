"""
Tests para Sandbox — Jaula de FS (Chroot/TempDir)
"""

import pytest
from sandbox.sandbox import Sandbox, SandboxError
import os

def test_sandbox_creates_temp_dir():
    with Sandbox() as jail:
        assert os.path.exists(jail)
        assert "mcp_jail_" in jail

def test_sandbox_executes_in_jail():
    with Sandbox() as jail:
        sb = Sandbox()
        sb.jail_dir = jail
        result = sb.execute_in_jail([], "echo 'hello'")
        assert jail in result

def test_sandbox_copies_files():
    # Crear archivo dummy
    with open("dummy.txt", "w") as f:
        f.write("data")
    
    with Sandbox() as jail:
        sb = Sandbox()
        sb.jail_dir = jail
        sb.execute_in_jail(["dummy.txt"], "cat dummy.txt")
        assert os.path.exists(os.path.join(jail, "dummy.txt"))
    
    os.remove("dummy.txt")
