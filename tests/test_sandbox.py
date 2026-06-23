# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests para Sandbox — Fase 6."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sandbox.sandbox import Sandbox, SandboxError, PathTraversalError


class TestSandboxLifecycle:
    """Ciclo de vida de la sandbox."""

    def test_sandbox_creates_temp_dir(self):
        """La sandbox crea un directorio temporal al entrar."""
        with Sandbox() as s:
            assert s.is_active
            assert s.jail_dir.exists()
        # Al salir, se limpia
        assert not s.jail_dir.exists()

    def test_sandbox_not_active_outside_context(self):
        """La sandbox no está activa fuera del context manager."""
        s = Sandbox()
        assert not s.is_active

    def test_sandbox_error_outside_context(self):
        """Operar fuera del context manager lanza error."""
        s = Sandbox()
        with pytest.raises(SandboxError):
            s.resolve("test.txt")


class TestPathResolution:
    """Resolución y validación de paths."""

    def test_resolve_simple_path(self):
        """Un path simple se resuelve dentro de la jaula."""
        with Sandbox() as s:
            p = s.resolve("test.txt")
            assert str(p).startswith(str(s.jail_dir))

    def test_resolve_nested_path(self):
        """Un path anidado se resuelve correctamente."""
        with Sandbox() as s:
            p = s.resolve("data/subdir/file.txt")
            assert str(p).startswith(str(s.jail_dir))

    def test_path_traversal_blocked(self):
        """Path traversal con ../ es bloqueado."""
        with Sandbox() as s:
            with pytest.raises(PathTraversalError):
                s.resolve("../../etc/passwd")

    def test_path_traversal_prefix_bypass_blocked(self):
        """Bypass de prefijo sin separador (jail_evil/) es bloqueado."""
        with Sandbox() as s:
            jail = s.jail_dir
            # Crear directorio hermano con nombre que extiende el prefijo del jail
            evil_dir = jail.parent / (jail.name + "_evil")
            evil_dir.mkdir(exist_ok=True)
            evil_file = evil_dir / "secret.txt"
            evil_file.write_text("stolen")
            try:
                with pytest.raises(PathTraversalError):
                    s.resolve("../" + jail.name + "_evil/secret.txt")
            finally:
                evil_file.unlink()
                evil_dir.rmdir()

    def test_path_traversal_with_valid_prefix(self):
        """Path traversal disfrazado con prefijo válido es bloqueado."""
        with Sandbox() as s:
            with pytest.raises(PathTraversalError):
                s.resolve("data/../../etc/shadow")

    def test_absolute_path_blocked(self):
        """Un path absoluto fuera de la jaula es bloqueado."""
        with Sandbox() as s:
            with pytest.raises(PathTraversalError):
                s.resolve("/etc/passwd")


class TestFileOperations:
    """Operaciones de archivos dentro de la sandbox."""

    def test_write_and_read_file(self):
        """Escribir y leer un archivo dentro de la sandbox."""
        with Sandbox() as s:
            s.write_file("test.txt", "hello world")
            content = s.read_file("test.txt")
            assert content == "hello world"

    def test_write_creates_subdirs(self):
        """write_file crea subdirectorios automáticamente."""
        with Sandbox() as s:
            s.write_file("data/output/result.json", '{"ok": true}')
            assert s.read_file("data/output/result.json") == '{"ok": true}'

    def test_read_missing_file_raises(self):
        """Leer un archivo inexistente lanza error."""
        with Sandbox() as s:
            with pytest.raises(SandboxError):
                s.read_file("nonexistent.txt")

    def test_list_files(self):
        """Lista archivos dentro de la sandbox."""
        with Sandbox() as s:
            s.write_file("a.txt", "a")
            s.write_file("b.txt", "b")
            s.write_file("sub/c.txt", "c")
            files = s.list_files()
            assert "a.txt" in files
            assert "b.txt" in files
            assert "sub/c.txt" in files


class TestExtensionFilter:
    """Filtrado por extensión de archivo."""

    def test_allowed_extension_passes(self):
        """Archivos con extensión permitida pasan."""
        with Sandbox(allowed_extensions=[".txt", ".csv"]) as s:
            p = s.resolve("data.txt")
            assert p.suffix == ".txt"

    def test_disallowed_extension_blocked(self):
        """Archivos con extensión no permitida son bloqueados."""
        with Sandbox(allowed_extensions=[".txt"]) as s:
            with pytest.raises(SandboxError):
                s.resolve("script.sh")

    def test_no_extension_passes_when_filter_active(self):
        """Archivos sin extensión pasan incluso con filtro activo."""
        with Sandbox(allowed_extensions=[".txt"]) as s:
            p = s.resolve("Makefile")
            assert str(p).startswith(str(s.jail_dir))
