# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
MCP Security Proxy — Pipeline Orchestrator

Orquesta las 7 fases del MCP Security Proxy en un único punto de entrada:
1. Policy Engine → 2. Schema Validator → 3. DCI Checker → 4. TDP Detector → 5. Auth → 6. Sandbox → 7. SDK Adapter

Fases 1-5: Se ejecutan siempre en secuencia (cortocircuitables).
Fase 6 (Sandbox): Se activa opcionalmente con sandbox=True.
Fase 7 (SDK Adapter): Se usa externamente para interceptar tool calls del SDK de MCP.

Uso básico (fases 1-5):
    proxy = MCPSecurityProxy(allowlist=["filesystem::read_file"])
    result = proxy.check(tool_description, code_params, input_data)

Uso con Sandbox (fases 1-7):
    proxy = MCPSecurityProxy(allowlist=["filesystem::read_file"], sandbox=True)
    with proxy.sandbox_session() as sandbox:
        result = proxy.check(input_data={"path": "safe/path.txt"})
        # Sandbox valida que los paths no escapen del directorio jaula
"""

from policy_engine import MCPSecurityPolicyEngine, AccessDeniedError
from validators import MCPSchemaValidator, SchemaValidationError
from detectors import DCIChecker, DCIInconsistencyError, TDPDetector, TDPAttackDetected
from auth import MutualTLSHandler, CertificateVerificationError, MITMDetectedError
from sandbox import Sandbox, SandboxError, PathTraversalError
# SDK adapter se importa lazy para evitar circular import


class PipelineResult:
    """Resultado de la ejecucion del pipeline de seguridad."""

    def __init__(self, phase_passed: str, tool_name: str, blocked: bool = False,
                 error: Exception | None = None):
        self.phase_passed = phase_passed
        self.tool_name = tool_name
        self.blocked = blocked
        self.error = error

    def __repr__(self):
        if self.blocked:
            return (
                "PipelineResult(tool=" + self.tool_name
                + ", BLOCKED at=" + self.phase_passed
                + ", error=" + repr(self.error) + ")"
            )
        return "PipelineResult(tool=" + self.tool_name + ", ALL_PASSED)"

    @property
    def passed(self) -> bool:
        return not self.blocked


class MCPSecurityProxy:
    """
    Orquestador del pipeline de seguridad MCP de 5 fases.

    Todas las fases se ejecutan en secuencia. Si cualquier fase falla,
    el pipeline se detiene inmediatamente y retorna un PipelineResult
    con la informacion del bloqueo.

    Args:
        allowlist: Lista de herramientas permitidas (ej: ["filesystem::read_file"]).
        schema: JSON Schema para validacion de inputs/outputs.
        context: Diccionario de contexto (ej: {"mode": "read-only"}).
        trusted_certs: Lista de certificados PEM confiables para Fase 5.
        strict_schema: Si True, rechaza campos extra en schema validation.
    """

    def __init__(
        self,
        allowlist: list | None = None,
        schema: dict | None = None,
        context: dict | None = None,
        trusted_certs: list | None = None,
        strict_schema: bool = False,
        sandbox: bool = False,
        sandbox_allowed_extensions: list | None = None,
    ):
        self._policy = MCPSecurityPolicyEngine(
            allowlist=allowlist or [],
            context=context,
        )
        self._schema = MCPSchemaValidator(schema=schema, strict=strict_schema) if schema else None
        self._dci = DCIChecker()
        self._tdp = TDPDetector()
        self._auth = MutualTLSHandler(trusted_certs=trusted_certs) if trusted_certs else None
        self._sandbox_enabled = sandbox
        self._sandbox_allowed_extensions = sandbox_allowed_extensions
        self._sandbox = None

    def sandbox_session(self):
        """Context manager para usar la Sandbox (Fase 6)."""
        if not self._sandbox_enabled:
            raise SandboxError("Sandbox no está habilitada. Usar sandbox=True en el constructor.")
        self._sandbox = Sandbox(allowed_extensions=self._sandbox_allowed_extensions)
        return self._sandbox

    @property
    def sdk_adapter(self):
        """Adapter para integrar con SDK de MCP (Fase 7)."""
        from sdk_integration import MCPSecuritySDKAdapter
        return MCPSecuritySDKAdapter(self)

    def check(
        self,
        tool_name: str,
        tool_description: dict | None = None,
        code_params: list | None = None,
        input_data: dict | None = None,
        server_cert: str | None = None,
        expected_hostname: str | None = None,
    ) -> PipelineResult:
        """
        Ejecuta el pipeline completo de 5 fases.

        Args:
            tool_name: Nombre de la herramienta (ej: "filesystem::read_file").
            tool_description: Descripcion MCP completa de la herramienta.
            code_params: Lista de parametros en el codigo real.
            input_data: Datos de entrada a validar contra el schema.
            server_cert: Certificado PEM del servidor (Fase 5).
            expected_hostname: Hostname esperado del servidor.

        Returns:
            PipelineResult indicando si paso o fue bloqueada en alguna fase.
        """
        # Fase 1: Policy Engine
        try:
            self._policy.check(tool_name)
        except AccessDeniedError as e:
            return PipelineResult("policy", tool_name, blocked=True, error=e)

        # Fase 2: Schema Validator
        if self._schema and input_data is not None:
            try:
                self._schema.validate_input(input_data)
            except SchemaValidationError as e:
                return PipelineResult("schema", tool_name, blocked=True, error=e)

        # Fase 3: DCI Checker
        if tool_description and code_params is not None:
            try:
                self._dci.check(tool_description, code_params)
            except DCIInconsistencyError as e:
                return PipelineResult("dci", tool_name, blocked=True, error=e)

        # Fase 4: TDP Detector
        if tool_description:
            try:
                self._tdp.check(tool_description)
            except TDPAttackDetected as e:
                return PipelineResult("tdp", tool_name, blocked=True, error=e)

        # Fase 5: Auth Mutual TLS
        if self._auth and server_cert:
            try:
                kwargs = {"expected_hostname": expected_hostname} if expected_hostname else {}
                self._auth.verify_certificate(server_cert, **kwargs)
            except (CertificateVerificationError, MITMDetectedError) as e:
                return PipelineResult("auth", tool_name, blocked=True, error=e)

        return PipelineResult("all", tool_name)

    @property
    def phases(self) -> list:
        """Lista de fases activas en el pipeline."""
        phases = ["policy"]
        if self._schema:
            phases.append("schema")
        phases.append("dci")
        phases.append("tdp")
        if self._auth:
            phases.append("auth")
        if self._sandbox_enabled:
            phases.append("sandbox")
        phases.append("sdk_adapter")
        return phases
