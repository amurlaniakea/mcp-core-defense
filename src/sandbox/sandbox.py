# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fase 6: Sandbox — Jaula de FileSystem con validación de paths.

Aislamiento ligero basado en directorios temporarios restringidos.
Valida que los paths no escapen del directorio de trabajo (path traversal).
"""

import os
import shutil
import tempfile
from pathlib import Path


class SandboxError(Exception):
    """Error de sandbox."""
    pass


class PathTraversalError(SandboxError):
    """Se detectó un intento de path traversal fuera de la sandbox."""
    pass


class Sandbox:
    """
    Sandbox ligera basada en directorio temporal.

    Crea un directorio temporal como jaula y valida que todas
    las operaciones de archivos permanezcan dentro de ella.
    Previene ataques de path traversal (../etc/passwd).

    Uso:
        with Sandbox() as jail_dir:
            safe_path = sandbox.resolve("data/file.txt")
            # Operar sobre safe_path
    """

    def __init__(self, allowed_extensions: list | None = None):
        """
        Args:
            allowed_extensions: Lista de extensiones permitidas (ej: ['.txt', '.csv']).
                              None = todas permitidas.
        """
        self.jail_dir = None
        self._allowed_extensions = allowed_extensions

    def __enter__(self):
        self.jail_dir = Path(tempfile.mkdtemp(prefix="mcp_jail_"))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.jail_dir and self.jail_dir.exists():
            shutil.rmtree(self.jail_dir, ignore_errors=True)

    def resolve(self, path: str) -> Path:
        """
        Resuelve un path relativo dentro de la sandbox.

        Valida que el path resultante esté dentro del directorio jaula.
        Previene path traversal attacks (../, symlinks fuera de jaula).

        Args:
            path: Path relativo dentro de la sandbox.

        Returns:
            Path absoluto validado dentro de la jaula.

        Raises:
            PathTraversalError: Si el path intenta escapar de la sandbox.
            SandboxError: Si la extensión no está permitida.
        """
        if not self.jail_dir:
            raise SandboxError("Sandbox no inicializada. Usar 'with Sandbox() as s:'")

        # Resolver el path
        target = (self.jail_dir / path).resolve()
        jail_resolved = self.jail_dir.resolve()

        # Validar que está dentro de la jaula
        if not str(target).startswith(str(jail_resolved)):
            raise PathTraversalError(
                f"Path traversal detectado: '{path}' resuelve a '{target}' "
                f"fuera de la sandbox '{jail_resolved}'"
            )

        # Validar extensión
        if self._allowed_extensions:
            suffix = target.suffix.lower()
            if suffix and suffix not in self._allowed_extensions:
                raise SandboxError(
                    f"Extensión '{suffix}' no permitida. "
                    f"Permitidas: {self._allowed_extensions}"
                )

        return target

    def write_file(self, path: str, content: str) -> Path:
        """
        Escribe un archivo dentro de la sandbox.

        Args:
            path: Path relativo dentro de la sandbox.
            content: Contenido a escribir.

        Returns:
            Path absoluto del archivo escrito.
        """
        target = self.resolve(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target

    def read_file(self, path: str) -> str:
        """
        Lee un archivo dentro de la sandbox.

        Args:
            path: Path relativo dentro de la sandbox.

        Returns:
            Contenido del archivo.
        """
        target = self.resolve(path)
        if not target.exists():
            raise SandboxError(f"Archivo no encontrado: '{path}'")
        return target.read_text()

    def copy_in(self, source: str, dest: str) -> Path:
        """
        Copia un archivo externo dentro de la sandbox.

        Args:
            source: Path absoluto del archivo fuente.
            path de destino relativo dentro de la sandbox.

        Returns:
            Path absoluto del archivo en la sandbox.
        """
        src = Path(source)
        if not src.exists():
            raise SandboxError(f"Archivo fuente no encontrado: '{source}'")
        target = self.resolve(dest)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        return target

    def list_files(self) -> list:
        """
        Lista todos los archivos dentro de la sandbox.

        Returns:
            Lista de paths relativos dentro de la sandbox.
        """
        if not self.jail_dir:
            raise SandboxError("Sandbox no inicializada")
        files = []
        for f in self.jail_dir.rglob("*"):
            if f.is_file():
                files.append(str(f.relative_to(self.jail_dir)))
        return sorted(files)

    @property
    def is_active(self) -> bool:
        """True si la sandbox está activa."""
        return self.jail_dir is not None and self.jail_dir.exists()
