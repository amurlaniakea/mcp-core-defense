"""
Fase 6: Sandbox — Jaula de FS (Chroot/TempDir)

Aislamiento ligero basado en directorios temporales restringidos.
Evita el acceso a archivos del sistema fuera del directorio de trabajo.
"""

import os
import shutil
import tempfile
from pathlib import Path

class SandboxError(Exception):
    pass

class Sandbox:
    def __init__(self):
        self.jail_dir = None

    def __enter__(self):
        self.jail_dir = tempfile.mkdtemp(prefix="mcp_jail_")
        return self.jail_dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.jail_dir:
            shutil.rmtree(self.jail_dir)

    def execute_in_jail(self, files_to_copy: list, command: str):
        """Copia archivos a la jaula y ejecuta un comando."""
        if not self.jail_dir:
            raise SandboxError("Sandbox no inicializado")

        # Copiar archivos permitidos a la jaula
        for file in files_to_copy:
            dest = Path(self.jail_dir) / os.path.basename(file)
            shutil.copy2(file, dest)

        # Ejecutar en el directorio de la jaula
        cwd = os.getcwd()
        os.chdir(self.jail_dir)
        try:
            # En producción esto usaría subprocesos restringidos
            # Aquí simulamos la ejecución limitada
            return f"Ejecutando '{command}' en {self.jail_dir}..."
        finally:
            os.chdir(cwd)
