# Changelog

All notable changes to MCP Core Defense will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-22

### Added
- Phase 1: Policy Engine — deny-by-default allowlist with wildcard support
- Phase 2: Schema Validator — strict JSON schema validation for tool inputs/outputs
- Phase 3: DCI Checker — Description-Code Inconsistency detection (Python + JS/TS)
- Phase 4: TDP Detector — Tool Description Poisoning scan (exfil/execution/obfuscation)
- Phase 5: Mutual TLS — certificate verification, pinning, hostname validation, MITM detection
- Phase 6: Sandbox — filesystem jail with path traversal prevention
- Phase 7: SDK Adapter — async MCP client integration with interceptor pattern
- Pipeline Orchestrator — sequential 5-phase pipeline with short-circuit evaluation
- CLI audit tool (`scripts/mcp_audit.py`) for standalone server auditing
- 127 tests across all phases (unit + integration + performance)
- CI/CD via GitHub Actions (Python 3.10, 3.11, 3.12)
- Makefile with targets per phase
- Pre-commit hooks (ruff, black, mypy)
- Coverage configuration (minimum 80%)
- CONTRIBUTING.md with TDD rules and code standards

### Security
- Threat mitigation matrix covering 9 attack vectors
- Certificate pinning (full cert + SHA256 fingerprint)
- Path traversal prevention via resolved path validation
- TLS 1.2 minimum version enforcement
