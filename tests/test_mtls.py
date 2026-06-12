"""
Fase 5: Auth — Tests (RED)

Tests para MutualTLSHandler siguiendo TDD.
Basado en Zhou et al. (2026): Authentication Security in Remote MCP Servers.

Verifica la autenticacion mutua TLS entre el MCP Security Proxy
y los servidores MCP remotos.

Casos:
- Caso 1: Certificado valido y confiable (pasa)
- Caso 2: Certificado invalido/expirado (falla)
- Caso 3: Certificado de servidor no confiable / MITM (falla)
- Caso 4: Verificacion de hostname y certificate pinning
"""

import pytest
import sys
import os
import ssl
import tempfile
import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from auth.mtls import (
    MutualTLSHandler,
    CertificateVerificationError,
    MITMDetectedError,
)


# ──────────────────────────────────────────────
# Helpers para generar certificados de test
# ──────────────────────────────────────────────

def _generate_self_signed_cert(cn="localhost", expired=False, alt_names=None):
    """
    Genera un certificado self-signed para tests.
    Retorna (cert_pem, key_pem) como strings.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        pytest.skip("cryptography package not installed")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    if expired:
        not_before = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        not_after = datetime.datetime(2020, 12, 31, tzinfo=datetime.timezone.utc)
    else:
        now = datetime.datetime.now(datetime.timezone.utc)
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if alt_names:
        san_list = []
        for name in alt_names:
            if name.startswith("IP:"):
                from cryptography.x509 import IPAddress
                import ipaddress
                san_list.append(x509.IPAddress(ipaddress.ip_address(name[3:])))
            else:
                san_list.append(x509.DNSName(name))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    return cert_pem, key_pem


# ──────────────────────────────────────────────
# Caso 1: Certificado valido
# ──────────────────────────────────────────────

class TestValidCertificate:
    """Certificados validos y confiables deben pasar."""

    def test_trusted_cert_passes(self):
        """Un certificado self-signed anadido a los trusted debe pasar."""
        cert_pem, _ = _generate_self_signed_cert(cn="mcp-server.local")
        handler = MutualTLSHandler(trusted_certs=[cert_pem])
        result = handler.verify_certificate(cert_pem, expected_hostname="mcp-server.local")
        assert result is True

    def test_valid_cert_with_san(self):
        """Un certificado con SAN matching el hostname debe pasar."""
        cert_pem, _ = _generate_self_signed_cert(
            cn="mcp-server.local",
            alt_names=["mcp-server.local", "localhost"],
        )
        handler = MutualTLSHandler(trusted_certs=[cert_pem])
        result = handler.verify_certificate(cert_pem, expected_hostname="mcp-server.local")
        assert result is True

    def test_valid_cert_with_ip_san(self):
        """Un certificado con IP SAN debe pasar para conexion por IP."""
        cert_pem, _ = _generate_self_signed_cert(
            cn="mcp-server",
            alt_names=["IP:127.0.0.1"],
        )
        handler = MutualTLSHandler(trusted_certs=[cert_pem])
        result = handler.verify_certificate(cert_pem, expected_hostname="127.0.0.1")
        assert result is True


# ──────────────────────────────────────────────
# Caso 2: Certificado invalido / expirado
# ──────────────────────────────────────────────

class TestInvalidCertificate:
    """Certificados invalidos o expirados deben fallar."""

    def test_expired_cert_rejected(self):
        """Un certificado expirado debe ser rechazado."""
        cert_pem, _ = _generate_self_signed_cert(cn="mcp-server.local", expired=True)
        handler = MutualTLSHandler(trusted_certs=[cert_pem])
        with pytest.raises(CertificateVerificationError):
            handler.verify_certificate(cert_pem, expected_hostname="mcp-server.local")

    def test_untrusted_cert_rejected(self):
        """Un certificado que no esta en los trusted debe ser rechazado."""
        cert_pem, _ = _generate_self_signed_cert(cn="mcp-server.local")
        handler = MutualTLSHandler(trusted_certs=[])  # Sin certs confiables
        with pytest.raises(CertificateVerificationError):
            handler.verify_certificate(cert_pem, expected_hostname="mcp-server.local")

    def test_hostname_mismatch_rejected(self):
        """Un certificado con hostname que no coincide debe ser rechazado."""
        cert_pem, _ = _generate_self_signed_cert(cn="legit-server.local")
        handler = MutualTLSHandler(trusted_certs=[cert_pem])
        with pytest.raises(CertificateVerificationError):
            handler.verify_certificate(cert_pem, expected_hostname="evil-server.local")


# ──────────────────────────────────────────────
# Caso 3: MITM / servidor no confiable
# ──────────────────────────────────────────────

class TestMITMDetection:
    """Intentos de man-in-the-middle deben ser detectados."""

    def test_wrong_ca_rejected(self):
        """Un certificado firmado por una CA diferente debe ser rechazado."""
        # Certificado "legitimo"
        legit_cert, _ = _generate_self_signed_cert(cn="legit-server.local")
        # Certificado "atacante" con mismo CN pero diferente clave
        attacker_cert, _ = _generate_self_signed_cert(cn="legit-server.local")

        handler = MutualTLSHandler(trusted_certs=[legit_cert])

        # El certificado del atacante no esta en trusted
        with pytest.raises((CertificateVerificationError, MITMDetectedError)):
            handler.verify_certificate(attacker_cert, expected_hostname="legit-server.local")

    def test_certificate_pinning_mismatch(self):
        """Si hay pinning, un cert diferente debe ser rechazado."""
        cert_pem, _ = _generate_self_signed_cert(cn="mcp-server.local")
        other_cert, _ = _generate_self_signed_cert(cn="mcp-server.local")

        # Pinnear el primer certificado
        handler = MutualTLSHandler(
            trusted_certs=[cert_pem],
            pinned_cert=cert_pem,
        )

        # El segundo cert (diferente clave, mismo CN) debe fallar
        with pytest.raises(MITMDetectedError):
            handler.verify_certificate(other_cert, expected_hostname="mcp-server.local")

    def test_certificate_pinning_match_passes(self):
        """Si el cert coincide con el pinned, debe pasar."""
        cert_pem, _ = _generate_self_signed_cert(cn="mcp-server.local")

        handler = MutualTLSHandler(
            trusted_certs=[cert_pem],
            pinned_cert=cert_pem,
        )

        result = handler.verify_certificate(cert_pem, expected_hostname="mcp-server.local")
        assert result is True


# ──────────────────────────────────────────────
# Caso 4: Certificate pinning y contexto
# ──────────────────────────────────────────────

class TestCertificatePinning:
    """Verificacion de certificate pinning."""

    def test_pinning_with_fingerprint(self):
        """Pinning por fingerprint (SHA256) del certificado."""
        cert_pem, _ = _generate_self_signed_cert(cn="mcp-server.local")

        # Calcular fingerprint
        handler = MutualTLSHandler(trusted_certs=[cert_pem])
        fingerprint = handler.get_cert_fingerprint(cert_pem)

        # Verificar con pinning por fingerprint
        handler2 = MutualTLSHandler(
            trusted_certs=[cert_pem],
            pinned_fingerprint=fingerprint,
        )
        result = handler2.verify_certificate(cert_pem, expected_hostname="mcp-server.local")
        assert result is True

    def test_pinning_fingerprint_mismatch(self):
        """Fingerprint incorrecto debe fallar."""
        cert_pem, _ = _generate_self_signed_cert(cn="mcp-server.local")

        handler = MutualTLSHandler(
            trusted_certs=[cert_pem],
            pinned_fingerprint="AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
        )
        with pytest.raises(MITMDetectedError):
            handler.verify_certificate(cert_pem, expected_hostname="mcp-server.local")

    def test_create_ssl_context(self):
        """Crear un SSLContext con mutual TLS configurado."""
        cert_pem, key_pem = _generate_self_signed_cert(cn="mcp-server.local")

        handler = MutualTLSHandler(trusted_certs=[cert_pem])
        ctx = handler.create_ssl_context(
            cert_file=None,
            key_file=None,
            ca_certs=[cert_pem],
        )

        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
