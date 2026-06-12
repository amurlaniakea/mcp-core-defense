# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fase 5: Auth — Mutual TLS y verificacion de certificados

Basado en Zhou et al. (2026): "Authentication Security in Remote MCP Servers".

Implementa autenticacion mutua TLS entre el MCP Security Proxy
y los servidores MCP remotos.

Caracteristicas:
- Verificacion de certificados con cadena de confianza
- Certificate pinning (por cert completo o fingerprint SHA256)
- Verificacion de hostname contra CN y SANs
- Deteccion de certificados expirados
- Deteccion de MITM via pinning mismatch
- Creacion de SSLContext con mutual TLS
"""

import ssl
import hashlib
import re

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.x509.oid import NameOID, ExtensionOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class CertificateVerificationError(Exception):
    """Excepcion lanzada cuando un certificado no pasa la verificacion."""
    pass


class MITMDetectedError(CertificateVerificationError):
    """Excepcion lanzada cuando se detecta un posible ataque MITM."""
    pass


class MutualTLSHandler:
    """
    Handler de autenticacion mutua TLS para conexiones MCP.

    Verifica certificados de servidores MCP remotos contra
    una lista de certificados confiables y opcionalmente
    con certificate pinning.

    Args:
        trusted_certs: Lista de certificados PEM confiables.
        pinned_cert: Certificado PEM exacto esperado (opcional).
        pinned_fingerprint: Fingerprint SHA256 esperado (opcional).
    """

    def __init__(
        self,
        trusted_certs: list = None,
        pinned_cert: str = None,
        pinned_fingerprint: str = None,
    ):
        if not HAS_CRYPTOGRAPHY:
            raise ImportError(
                "The 'cryptography' package is required. "
                "Install it with: pip install cryptography"
            )

        self._trusted_certs = trusted_certs or []
        self._pinned_cert = pinned_cert
        self._pinned_fingerprint = pinned_fingerprint

        # Parsear certificados confiables
        self._trusted_parsed = []
        for cert_pem in self._trusted_certs:
            try:
                cert = self._parse_cert(cert_pem)
                self._trusted_parsed.append(cert)
            except Exception:
                continue

    def verify_certificate(self, cert_pem: str, expected_hostname: str = None) -> bool:
        """
        Verifica un certificado contra las politicas de confianza.

        Args:
            cert_pem: Certificado en formato PEM.
            expected_hostname: Hostname esperado del servidor.

        Returns:
            True si el certificado es valido y confiable.

        Raises:
            CertificateVerificationError: Si el certificado no es valido.
            MITMDetectedError: Si se detecta un posible MITM.
        """
        cert = self._parse_cert(cert_pem)

        # 1. Verificar expiracion
        self._check_expiration(cert)

        # 2. Verificar pinneo de certificado (MITM detection)
        self._check_pinning(cert_pem, cert)

        # 3. Verificar que esta en los trusted
        self._check_trusted(cert_pem, cert)

        # 4. Verificar hostname
        if expected_hostname:
            self._check_hostname(cert, expected_hostname)

        return True

    def get_cert_fingerprint(self, cert_pem: str) -> str:
        """
        Calcula el fingerprint SHA256 de un certificado.

        Args:
            cert_pem: Certificado en formato PEM.

        Returns:
            Fingerprint como string hex con dos puntos (AA:BB:CC:...).
        """
        cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)
        digest = hashlib.sha256(cert_der).hexdigest().upper()
        return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))

    def create_ssl_context(
        self,
        cert_file: str = None,
        key_file: str = None,
        ca_certs: list = None,
    ) -> ssl.SSLContext:
        """
        Crea un SSLContext configurado para mutual TLS.

        Args:
            cert_file: Ruta al certificado del cliente (opcional).
            key_file: Ruta a la clave privada del cliente (opcional).
            ca_certs: Lista de certificados PEM de CAs confiables.

        Returns:
            ssl.SSLContext configurado.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True

        # Cargar CA certs
        if ca_certs:
            for ca_cert in ca_certs:
                ctx.load_verify_locations(cadata=ca_cert)

        # Cargar certificado del cliente (mutual TLS)
        if cert_file and key_file:
            ctx.load_cert_chain(cert_file, key_file)

        # Deshabilitar protocolos inseguros
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        return ctx

    # ──────────────────────────────────────────
    # Metodos privados
    # ──────────────────────────────────────────

    def _parse_cert(self, cert_pem: str):
        """Parsea un certificado PEM usando cryptography."""
        return x509.load_pem_x509_certificate(cert_pem.encode())

    def _check_expiration(self, cert):
        """Verifica que el certificado no este expirado."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc:
            raise CertificateVerificationError(
                "Certificate is not yet valid (valid from "
                + cert.not_valid_before_utc.isoformat() + ")"
            )
        if now > cert.not_valid_after_utc:
            raise CertificateVerificationError(
                "Certificate has expired (expired on "
                + cert.not_valid_after_utc.isoformat() + ")"
            )

    def _check_pinning(self, cert_pem: str, cert):
        """Verifica certificate pinning."""
        # Pinning por certificado exacto
        if self._pinned_cert:
            pinned_parsed = self._parse_cert(self._pinned_cert)
            if cert.public_key().public_numbers() != pinned_parsed.public_key().public_numbers():
                raise MITMDetectedError(
                    "Certificate pinning failed: public key mismatch. "
                    "Possible MITM attack."
                )

        # Pinning por fingerprint
        if self._pinned_fingerprint:
            actual_fingerprint = self.get_cert_fingerprint(cert_pem)
            expected = self._pinned_fingerprint.upper().replace(" ", "")
            if actual_fingerprint != expected:
                raise MITMDetectedError(
                    "Certificate fingerprint pinning failed: "
                    "expected " + expected + ", got " + actual_fingerprint + ". "
                    "Possible MITM attack."
                )

    def _check_trusted(self, cert_pem: str, cert):
        """Verifica que el certificado este en la lista de trusted."""
        if not self._trusted_parsed:
            raise CertificateVerificationError(
                "No trusted certificates configured"
            )

        # Comparar por subject CN
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cert_cn = cn[0].value if cn else ""

        for trusted in self._trusted_parsed:
            trusted_cn = trusted.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            trusted_cn = trusted_cn[0].value if trusted_cn else ""

            # Mismo CN y misma clave publica = confiable
            if cert_cn == trusted_cn:
                if cert.public_key().public_numbers() == trusted.public_key().public_numbers():
                    return

        raise CertificateVerificationError(
            "Certificate for '" + cert_cn + "' is not in the trusted list"
        )

    def _check_hostname(self, cert, expected_hostname: str):
        """Verifica el hostname contra CN y SANs del certificado."""
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cert_cn = cn[0].value if cn else ""

        # Verificar CN
        if self._match_hostname(cert_cn, expected_hostname):
            return

        # Verificar SANs (DNS names e IPs)
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            # Verificar DNS names
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            for name in san_names:
                if self._match_hostname(name, expected_hostname):
                    return
            # Verificar IP addresses
            from cryptography.x509 import IPAddress
            import ipaddress
            san_ips = san_ext.value.get_values_for_type(IPAddress)
            for ip in san_ips:
                if str(ip) == expected_hostname:
                    return
        except x509.ExtensionNotFound:
            pass

        raise CertificateVerificationError(
            "Hostname '" + expected_hostname + "' does not match "
            "certificate CN '" + cert_cn + "' or SANs"
        )

    def _match_hostname(self, pattern: str, hostname: str) -> bool:
        """Match de hostname con soporte para wildcard."""
        if pattern == hostname:
            return True
        if pattern.startswith("*."):
            # Wildcard: *.example.com coincide con foo.example.com
            suffix = pattern[1:]  # .example.com
            if hostname.endswith(suffix):
                return True
        # Match IP exacto
        if pattern == hostname:
            return True
        return False
