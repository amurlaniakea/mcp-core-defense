# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.0   | Yes       |

## Reporting a Security Vulnerability

If you discover a security vulnerability in MCP Core Defense, please report it responsibly.

**Do NOT open a public GitHub Issue for security vulnerabilities.**

Instead, report via email:
- **Email:** amurlaniakea@gmail.com
- **Subject:** `[SECURITY] MCP Core Defense vulnerability`

Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Affected component (phase number)
4. Potential impact assessment
5. Suggested fix (if any)

You will receive a response within 48 hours.

## Security Considerations

MCP Core Defense is a security tool, but it is not a silver bullet:

- **Phase 1 (Policy Engine):** Effectiveness depends on the quality of your allowlist. An overly permissive allowlist reduces protection.
- **Phase 3 (DCI Checker):** Static analysis has limitations. Obfuscated code may evade detection.
- **Phase 4 (TDP Detector):** Regex-based detection can be bypassed by novel poisoning techniques.
- **Phase 5 (Mutual TLS):** Requires proper certificate management. Compromised CA certificates break the trust chain.
- **Phase 6 (Sandbox):** Filesystem sandbox only protects against path traversal. It does not protect against resource exhaustion or side-channel attacks.

**Always use MCP Core Defense as one layer in a defense-in-depth strategy.**

## Dependencies

Runtime dependency: `cryptography>=41.0`

All dependencies are pinned in `pyproject.toml`. Run `pip install -e "."` to install with verified versions.
