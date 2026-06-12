# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Phase 5: Auth Module — mutual TLS and certificate verification for MCP servers."""

from .mtls import (
    MutualTLSHandler,
    CertificateVerificationError,
    MITMDetectedError,
)

__all__ = ["MutualTLSHandler", "CertificateVerificationError", "MITMDetectedError"]
