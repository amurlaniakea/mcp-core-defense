"""
Fase 4: TDP Detector — Tool Description Poisoning

Basado en Liu et al. (2026): "Tool Description Poisoning Benchmark".

Detecta instrucciones maliciosas ocultas en descripciones de herramientas MCP
que pueden manipular al LLM para ejecutar acciones no deseadas.

Estrategias de deteccion:
- Patrones de exfiltracion de datos (send, upload, exfiltrate, leak)
- Patrones de ejecucion de comandos (run, execute, eval, shell, bash)
- Patrones de ofuscamiento (ignore safety, ignore instructions, decode+execute)
- Escaneo de todos los campos de texto en la descripcion
"""

import re


class TDPAttackDetected(Exception):
    """Excepcion lanzada cuando se detecta tool description poisoning."""
    pass


class TDPDetector:
    """
    Detector de Tool Description Poisoning (TDP) para herramientas MCP.

    Escanea las descripciones de herramientas en busca de instrucciones
    maliciosas que intentan manipular al LLM.
    """

    # Patrones de exfiltracion de datos
    EXFIL_PATTERNS = [
        r"send\s+(?:the|all|every)?\s*(?:data|content|result|output|file|secret|key|token|password|credential)",
        r"upload\s+(?:the|all|every)?\s*(?:data|content|result|output|file|secret)",
        r"exfiltrat",
        r"leak\s+(?:the|all|every)?\s*(?:data|content|secret|key|token)",
        r"transmit\s+(?:the|all|every)?\s*(?:data|content|result)",
        r"forward\s+(?:the|all|every)?\s*(?:data|content|result)",
        r"post\s+(?:the|all|every)?\s*(?:data|content|result)\s+to",
    ]

    # Patrones de ejecucion de comandos
    EXEC_PATTERNS = [
        r"run\s+['\"]?(?:curl|wget|bash|sh|cmd|powershell|python)",
        r"execute\s+(?:arbitrary|system|shell|os|remote)",
        r"eval(?:uate)?\s+(?:the\s+)?(?:result|input|data|code)",
        r"(?:pipe|redirect)\s+(?:to|into)\s+(?:bash|sh|cmd|shell)",
        r"system\s+command",
        r"shell\s+command",
        r"os\.(?:system|popen|exec)",
        r"subprocess\.",
    ]

    # Patrones de ofuscamiento / manipulacion
    OBFUSCATION_PATTERNS = [
        r"ignore\s+(?:all\s+)?(?:previous|prior|safety|security)\s+(?:instruction|rule|guideline|policy)",
        r"disregard\s+(?:all\s+)?(?:safety|security|previous)",
        r"override\s+(?:safety|security|restriction)",
        r"bypass\s+(?:safety|security|restriction|filter)",
        r"decode\s+.*(?:execute|run)",
        r"after\s+decoding.*(?:execute|run)",
    ]

    def __init__(self):
        self._all_patterns = (
            self.EXFIL_PATTERNS + self.EXEC_PATTERNS + self.OBFUSCATION_PATTERNS
        )
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self._all_patterns]

    def check(self, description: dict) -> bool:
        """
        Escanea la descripcion de una herramienta MCP en busca de TDP.

        Args:
            description: Descripcion MCP de la herramienta.

        Returns:
            True si la descripcion es limpia.

        Raises:
            TDPAttackDetected: Si se detecta una instruccion maliciosa.
        """
        # Recopilar todos los campos de texto de la descripcion
        text_fields = self._extract_text_fields(description)

        # Escanear cada campo
        for field_name, text in text_fields:
            for pattern in self._compiled:
                match = pattern.search(text)
                if match:
                    raise TDPAttackDetected(
                        "TDP attack detected in '" + field_name + "': "
                        "suspicious pattern '" + match.group() + "'"
                    )

        return True

    def _extract_text_fields(self, description: dict) -> list:
        """
        Extrae todos los campos de texto de una descripcion MCP.

        Returns:
            Lista de (nombre_campo, texto) tuples.
        """
        fields = []

        # Campo description principal
        if "description" in description and isinstance(description["description"], str):
            fields.append(("description", description["description"]))

        # Campo name
        if "name" in description and isinstance(description["name"], str):
            fields.append(("name", description["name"]))

        # Descripciones de parametros
        params = description.get("parameters", {})
        properties = params.get("properties", {})
        for param_name, param_def in properties.items():
            if isinstance(param_def, dict):
                if "description" in param_def and isinstance(param_def["description"], str):
                    fields.append(
                        ("parameters." + param_name + ".description", param_def["description"])
                    )

        return fields
