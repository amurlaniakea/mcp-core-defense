# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fase 4: TDP Detector — Tool Description Poisoning

Basado en Liu et al. (2026): "Tool Description Poisoning Benchmark".

Detecta instrucciones maliciosas ocultas en descripciones de herramientas MCP
que pueden manipular al LLM para ejecutar acciones no deseadas.

Estrategias de deteccion:
- Normalizacion anti-evasion (NFKC, zero-width, bidi, homoglifos, leetspeak)
- Patrones de exfiltracion de datos (send, upload, exfiltrate, leak)
- Patrones de ejecucion de comandos (run, execute, eval, shell, bash)
- Patrones de ofuscamiento (ignore safety, ignore instructions, decode+execute)
- Escaneo de todos los campos de texto en la descripcion
"""

import re
import unicodedata


class TDPAttackDetected(Exception):
    """Excepcion lanzada cuando se detecta tool description poisoning."""
    pass


# ════════════════════════════════════════════════════════════════════════════
# Normalización anti-evasión (evita bypass con unicode, homoglifos, leetspeak)
# ════════════════════════════════════════════════════════════════════════════

# Caracteres invisibles usados para evadir filtros
_ZERO_WIDTH_RE = re.compile(
    '[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060\u2061\u2062\u2063'
    '\u202a\u202b\u202c\u202d\u202e'  # bidi overrides
    '\u00ad'                          # soft hyphen
    '\u034f'                          # combining grapheme joiner
    '\u2028\u2029'                    # line/paragraph separators
    ']'
)

# Homoglifos cirílicos → ASCII
_HOMOGLYPH_MAP = str.maketrans({
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E',
    '\u041d': 'H', '\u041a': 'K', '\u041c': 'M', '\u041e': 'O',
    '\u0420': 'P', '\u0422': 'T', '\u0425': 'X',
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
})

# Leetspeak → ASCII
_LEET_MAP = str.maketrans({
    '@': 'a', '4': 'a', '3': 'e', '1': 'i', '0': 'o',
    '5': 's', '7': 't', '$': 's', '+': 't', '9': 'g',
    '(': 'c', '!': 'i', '|': 'l', '&': 'and',
})


def normalize_text(text: str) -> str:
    """
    Normaliza texto para deteccion robusta de TDP.

    Pasos:
    1. Unicode NFKC normalization
    2. Eliminar zero-width chars y bidi overrides
    3. Homoglifos cirilicos → ASCII
    4. Leetspeak → ASCII
    5. Colapsar whitespace
    """
    # 1. NFKC
    text = unicodedata.normalize('NFKC', text)
    # 2. Zero-width + bidi
    text = _ZERO_WIDTH_RE.sub('', text)
    # 3. Homoglifos
    text = text.translate(_HOMOGLYPH_MAP)
    # 4. Leetspeak
    text = text.translate(_LEET_MAP)
    # 5. Colapsar whitespace
    return ' '.join(text.split())


# ════════════════════════════════════════════════════════════════════════════
# Patrones de detección
# ════════════════════════════════════════════════════════════════════════════

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

        # Escanear cada campo (con normalizacion anti-evasion)
        for field_name, text in text_fields:
            normalized = normalize_text(text)
            for pattern in self._compiled:
                match = pattern.search(normalized)
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
