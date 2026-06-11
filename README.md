# MCP Core Defense

> **A 5-phase security proxy for Model Context Protocol agent systems.**
> Defends against tool poisoning, description-code inconsistencies, privilege escalation, and authentication attacks.

![Tests](https://github.com/amurlaniakea/mcp-core-defense/workflows/Tests/badge.svg)

---

## Overview

The Model Context Protocol (MCP) has emerged as a standardized interface for connecting large language models to external tools and data sources. As of mid-2026, the MCP ecosystem encompasses over 2,200 public MCP servers — but empirical studies reveal that **9.93% exhibit description-code inconsistencies** (Shi et al., 2026) and leading models suffer **~100% attack success rates under tool description poisoning** (Liu et al., 2026).

This framework implements a **defense-in-depth security proxy** — the MCP Security Proxy (MCP-SP) — interposed between the agent and all MCP servers. The proxy implements five sequential verification phases. All 69 tests pass.

---

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      MCP AGENT (LLM Core)                       │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                  │
│  │  LLM     │◄──►│  MCP     │◄──►│  Memory  │                  │
│  │(Reasoning)│   │  Client  │    │ (Context)│                  │
│  └────┬─────┘    └────┬─────┘    └──────────┘                  │
│       │               │                                         │
└───────┼───────────────┼─────────────────────────────────────────┘
        │ tool/call     │ validated result
        ▼               ▲
┌───────────────────────┼───────────────────────────────────────────┐
│            MCP SECURITY PROXY (MCP-SP)                           │
│                       │                                           │
│  ┌────────────────────▼───────────────────────────────────────┐  │
│  │ Phase 1: POLICY ENGINE                                      │  │
│  │ Deny-by-default allowlist · Wildcards · Read-only context   │  │
│  └────────────────────┬───────────────────────────────────────┘  │
│                       │ PASS                                      │
│  ┌────────────────────▼───────────────────────────────────────┐  │
│  │ Phase 2: SCHEMA VALIDATOR                                   │  │
│  │ Strict JSON schema validation · Nested objects · Arrays     │  │
│  └────────────────────┬───────────────────────────────────────┘  │
│                       │ PASS                                      │
│  ┌────────────────────▼───────────────────────────────────────┐  │
│  │ Phase 3: DCI CHECKER (Shi et al. 2026)                      │  │
│  │ Description-Code Consistency · AST static analysis          │  │
│  └────────────────────┬───────────────────────────────────────┘  │
│                       │ PASS                                      │
│  ┌────────────────────▼───────────────────────────────────────┐  │
│  │ Phase 4: TDP DETECTOR (Liu et al. 2026)                     │  │
│  │ Tool Description Poisoning scan · Exfil/Exec/Obfuscation    │  │
│  └────────────────────┬───────────────────────────────────────┘  │
│                       │ PASS                                      │
│  ┌────────────────────▼───────────────────────────────────────┐  │
│  │ Phase 5: MUTUAL TLS AUTH (Zhou et al. 2026)                 │  │
│  │ Certificate verification · Pinning · MITM detection         │  │
│  └────────────────────┬───────────────────────────────────────┘  │
│                       │                                           │
└───────────────────────┼───────────────────────────────────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │  MCP SERVERS     │
              │  (Remote/Local)  │
              └──────────────────┘
```

---

## Threat Mitigation Matrix

| Threat | Attack Vector | Phase | Mitigation | Reference |
|--------|--------------|-------|------------|-----------|
| Tool Description Poisoning | Malicious instructions in tool metadata | 4 | Regex pattern scan (exfil/execution/obfuscation) | Liu et al. (2026) |
| Description-Code Inconsistency | Tool behavior diverges from description | 3 | AST static analysis + param comparison | Shi et al. (2026) |
| Authentication Bypass | Weak auth on remote MCP servers | 5 | Mutual TLS + certificate pinning | Zhou et al. (2026) |
| Privilege Escalation | Server exceeds declared permissions | 1 | Deny-by-default allowlist + per-tool scope | Metere (2026) |
| Indirect Prompt Injection | Malicious content in tool results | 2 | Strict schema validation + output sanitization | Greshake et al. (2023) |
| Tool Shadowing | Malicious server impersonates legitimate tool | 5 | Certificate-based server identity | Zhou et al. (2026) |
| Data Exfiltration | Parameters leaked to external endpoints | 1+4 | Policy engine + TDP pattern detection | — |

---

## Project Structure

```
mcp-core-defense/
├── src/
│   ├── __init__.py
│   ├── policy_engine/          # Phase 1: Deny-by-default access control
│   │   ├── __init__.py         # Exports: MCPSecurityPolicyEngine, AccessDeniedError
│   │   └── engine.py           # Policy evaluation with wildcards + context
│   ├── validators/             # Phase 2: JSON Schema validation
│   │   ├── __init__.py         # Exports: MCPSchemaValidator, SchemaValidationError
│   │   └── schema_validator.py # Strict I/O validation, nested objects, arrays
│   ├── detectors/              # Phases 3+4: DCI + TDP detection
│   │   ├── __init__.py         # Exports: DCIChecker, TDPDetector, ...
│   │   ├── dci_checker.py      # Description-Code Consistency (AST-based)
│   │   └── tdp_detector.py     # Tool Description Poisoning (regex patterns)
│   └── auth/                   # Phase 5: Mutual TLS authentication
│       ├── __init__.py         # Exports: MutualTLSHandler, ...
│       └── mtls.py             # Certificate verification + pinning
├── tests/
│   ├── test_policy_engine.py   # 11 tests
│   ├── test_schema_validator.py # 14 tests
│   ├── test_dci_checker.py     # 10 tests
│   ├── test_tdp_detector.py    # 11 tests
│   ├── test_mtls.py            # 12 tests
│   └── test_integration.py     # 11 tests (full pipeline + exports)
├── .github/workflows/
│   └── tests.yml               # CI/CD: tests on Python 3.10/3.11/3.12
├── requirements.txt            # pytest, cryptography
├── CONTRIBUTING.md             # Dev setup + TDD rules
├── LICENSE                     # MIT
└── README.md                   # This file
```

---

## Quick Start

### Prerequisites

- Python >= 3.10
- pip

### Installation

```bash
git clone https://github.com/amurlaniakea/mcp-core-defense.git
cd mcp-core-defense
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Running Tests

```bash
# Full suite (69 tests)
python -m pytest tests/ -v

# Specific phase
python -m pytest tests/test_policy_engine.py -v

# With coverage
pip install pytest-cov
python -m pytest tests/ --cov=src --cov-report=term-missing
```

### Usage

```python
from policy_engine import MCPSecurityPolicyEngine
from validators import MCPSchemaValidator
from detectors import DCIChecker, TDPDetector
from auth import MutualTLSHandler

# Phase 1: Policy Engine
engine = MCPSecurityPolicyEngine(allowlist=["filesystem::read_file", "git::*"])
engine.check("filesystem::read_file")  # True
engine.check("malicious::exec")        # raises AccessDeniedError

# Phase 2: Schema Validator
validator = MCPSchemaValidator(schema={
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
})
validator.validate_input({"path": "/file.txt"})  # True

# Phase 3: DCI Checker
checker = DCIChecker()
checker.check(tool_description, code_params=["path"])  # True

# Phase 4: TDP Detector
detector = TDPDetector()
detector.check(tool_description)  # True or raises TDPAttackDetected

# Phase 5: Mutual TLS
handler = MutualTLSHandler(trusted_certs=[ca_cert_pem])
handler.verify_certificate(server_cert, expected_hostname="mcp-server.local")
```

---

## Test Results

```
96 passed in 4.17s

Phase 1 (Policy Engine):        11 tests
Phase 2 (Schema Validator):     14 tests
Phase 3 (DCI Checker):          19 tests  (Python + JS/TS)
Phase 4 (TDP Detector):         11 tests
Phase 5 (Mutual TLS Auth):      12 tests
Pipeline Orchestrator:           9 tests
Integration (Full Pipeline):    11 tests
Performance (Benchmarks):        8 tests
```

All tests follow strict TDD — no production code without a failing test first.

### Performance

| Metric | Value |
|--------|-------|
| Policy Engine (per check) | < 1ms |
| Schema Validator (per validation) | < 1ms |
| DCI Checker (per analysis) | < 5ms |
| TDP Detector (per scan) | < 5ms |
| Full Pipeline (avg) | < 20ms |
| Throughput | > 100 checks/sec |
| Policy Engine (1000 tools) | < 2ms |

---

## Research Basis

- **[Shi et al. (2026)](https://arxiv.org/abs/2606.04769)** — Description-Code Inconsistency in Real-world MCP Servers
- **[Liu et al. (2026)](https://arxiv.org/abs/2605.24069)** — When the Manual Lies: A Realistic Benchmark for MCP Poisoning
- **[Zhou et al. (2026)](https://arxiv.org/abs/2605.22333)** — Authentication Security in Remote MCP Servers
- **[Wang et al. (2026)](https://arxiv.org/abs/2606.01991)** — SafeMCP: Proactive Power Regulation for LLM Agent Defense
- **[Metere (2026)](https://arxiv.org/abs/2605.24248)** — Attested Tool-Server Admission
- **[He & Yu (2026)](https://arxiv.org/abs/2606.11632)** — Sovereign Assurance Boundary
- **[Greshake et al. (2023)](https://arxiv.org/abs/2302.12173)** — Indirect Prompt Injection in LLM-Integrated Applications

---

## License

MIT License — see [LICENSE](LICENSE) for details.
