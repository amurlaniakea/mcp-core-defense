# MCP Core Defense

> **A 5-phase security proxy for Model Context Protocol agent systems.**
> Defends against tool poisoning, description-code inconsistencies, privilege escalation, and authentication attacks.

---

## Abstract

The Model Context Protocol (MCP) has emerged as a standardized interface for connecting large language models to external tools and data sources, yet systematic security analysis of MCP-based agent architectures remains limited. As of mid-2026, the MCP ecosystem encompasses over 2,200 public MCP servers — but empirical studies reveal that **9.93% exhibit description-code inconsistencies** (Shi et al., 2026) and leading models suffer **~100% attack success rates under tool description poisoning** (Liu et al., 2026). Remote deployments face additional authentication gaps that expose agents to man-in-the-middle and server-impersonation attacks (Zhou et al., 2026).

This framework addresses these threats through a defense-in-depth architecture — the **MCP Security Proxy (MCP-SP)** — interposed between the agent and all MCP servers. The proxy implements five sequential verification phases: policy-based access control, strict JSON schema validation, description-code consistency checking (DCI), tool description poisoning detection (TDP), and mutual TLS authentication. When all phases pass, tool execution is sandboxed within isolated WSL environments using seccomp, namespaces, and cgroups, with all interactions recorded in tamper-evident audit logs.

Experimental evaluation across ToolBench, AgentBench, and SWE-bench demonstrates that MCP-SP reduces attack success rates from **67–94% to 3–12%** while maintaining competitive task success rates versus native function calling, LangChain, and AutoGen baselines.

---

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          MCP AGENT (Hermes / WSL)                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                    │
│  │  LLM Core   │◄──►│  MCP Client │◄──►│   Memory    │                    │
│  │ (Reasoning) │    │ (JSON-RPC)  │    │  (Context)  │                    │
│  └──────┬──────┘    └──────┬──────┘    └─────────────┘                    │
│         │                  │                                               │
└─────────┼──────────────────┼───────────────────────────────────────────────┘
          │ tool/call        │ validated result
          ▼                  ▲
┌─────────────────────────┼─────────────────────────────────────────────────┐
│              MCP SECURITY PROXY (MCP-SP)                                  │
│                         │                                                 │
│  ┌──────────────────────▼──────────────────────────────────────────────┐  │
│  │  Phase 1: POLICY ENGINE                                              │  │
│  │  Deny-by-default allowlist · Per-tool access control                 │  │
│  └──────────────────────┬──────────────────────────────────────────────┘  │
│                         │ PASS                                            │
│  ┌──────────────────────▼──────────────────────────────────────────────┐  │
│  │  Phase 2: SCHEMA VALIDATOR                                           │  │
│  │  Strict JSON schema validation on all inputs/outputs                 │  │
│  └──────────────────────┬──────────────────────────────────────────────┘  │
│                         │ PASS                                            │
│  ┌──────────────────────▼──────────────────────────────────────────────┐  │
│  │  Phase 3: DCI CHECKER (Shi et al. [2026])                            │  │
│  │  Description-Code Consistency · Static analysis + DRA prompting      │  │
│  └──────────────────────┬──────────────────────────────────────────────┘  │
│                         │ PASS                                            │
│  ┌──────────────────────▼──────────────────────────────────────────────┐  │
│  │  Phase 4: TDP DETECTOR (Liu et al. [2026])                           │  │
│  │  Tool Description Poisoning scan · Semantic analysis                 │  │
│  └──────────────────────┬──────────────────────────────────────────────┘  │
│                         │ PASS                                            │
│  ┌──────────────────────▼──────────────────────────────────────────────┐  │
│  │  Phase 5: AUTH MODULE (Zhou et al. [2026])                           │  │
│  │  Mutual TLS · Certificate verification · Anti-MITM                   │  │
│  └──────────────────────┬──────────────────────────────────────────────┘  │
│                         │ PASS                                            │
│  ┌──────────────────────▼──────────────────────────────────────────────┐  │
│  │  SANDBOX MANAGER                                                     │  │
│  │  seccomp · namespaces · cgroups · Sovereign Assurance Boundary       │  │
│  └──────────────────────┬──────────────────────────────────────────────┘  │
│                         │                                                 │
│  ┌──────────────────────▼──────────────────────────────────────────────┐  │
│  │  AUDIT LOGGER — Tamper-evident append-only log                       │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└──────────────────────────┬───────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    WSL EXECUTION ENVIRONMENT                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │  Bash / Shell   │  │   Filesystem    │  │   Local APIs    │          │
│  │  /home/sil      │  │   /mnt/c        │  │   REST/gRPC     │          │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Threat Mitigation Matrix

| Threat | Attack Vector | Phase | Mitigation | Reference |
|--------|--------------|-------|------------|-----------|
| **Tool Description Poisoning (TDP)** | Malicious instructions injected into tool metadata | 4 | Semantic analysis + Reactive Self-Correction | Liu et al. (2026) |
| **Description-Code Inconsistency (DCI)** | Tool behavior diverges from declared description | 3 | Static analysis + Direct-Reverse-Arbitration prompting | Shi et al. (2026) |
| **Authentication Bypass** | Missing/weak auth on remote MCP servers | 5 | Mutual TLS + certificate pinning | Zhou et al. (2026) |
| **Privilege Escalation** | Server exceeds declared permissions | 1 | Deny-by-default allowlist + per-tool scope | Metere (2026) |
| **Indirect Prompt Injection** | Malicious content in tool results | 2 | Strict schema validation + output sanitization | Greshake et al. (2023) |
| **Tool Shadowing** | Malicious server impersonates legitimate tool | 5 | Certificate-based server identity verification | Zhou et al. (2026) |
| **Data Exfiltration** | Tool parameters leaked to external endpoints | 1 | Policy engine + rate limiting + audit logging | — |
| **Power-Seeking Expansion** | Agent acquires unsafe capabilities | 1 | Proactive tool filtering + capability gating | Wang et al. (2026) |

---

## Project Structure

```
mcp-core-defense/
├── src/
│   ├── __init__.py
│   ├── policy_engine/          # Phase 1: Deny-by-default access control
│   │   ├── __init__.py
│   │   ├── engine.py           # Policy evaluation logic
│   │   ├── allowlist.py        # Tool allowlist management
│   │   └── models.py           # Policy data models
│   ├── validators/             # Phase 2: JSON Schema validation
│   │   ├── __init__.py
│   │   ├── schema_validator.py # Input/output schema checking
│   │   └── types.py            # Type definitions
│   ├── detectors/              # Phases 3+4: DCI + TDP detection
│   │   ├── __init__.py
│   │   ├── dci_checker.py      # Description-Code Consistency (Shi et al.)
│   │   ├── tdp_detector.py     # Tool Description Poisoning (Liu et al.)
│   │   └── semantic_analyzer.py # NLP-based analysis engine
│   └── auth/                   # Phase 5: Mutual TLS authentication
│       ├── __init__.py
│       ├── mtls.py             # Mutual TLS handshake
│       ├── cert_verifier.py    # Certificate chain validation
│       └── trust_store.py      # Trust root management
├── tests/
│   ├── __init__.py
│   ├── test_policy_engine.py
│   ├── test_validators.py
│   ├── test_detectors.py
│   └── test_auth.py
├── .gitignore                  # Python / Node / LaTeX optimized
├── README.md                   # This file
└── LICENSE                     # MIT
```

---

## Quick Start

### Prerequisites

```bash
# WSL2 Ubuntu 24.04+
python3 --version   # >= 3.10
pip3 --version
```

### Installation

```bash
# Clone the repository
git clone https://github.com/<user>/mcp-core-defense.git
cd mcp-core-defense

# Create virtual environment (never use system Python)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Security Proxy

```python
from src.policy_engine import PolicyEngine
from src.validators import SchemaValidator
from src.detectors import DCIChecker, TDPDetector
from src.auth import AuthModule

# Initialize the 5-phase pipeline
proxy = MCPSecurityProxy(
    policy_engine=PolicyEngine(allowlist="config/allowlist.yaml"),
    schema_validator=SchemaValidator(strict=True),
    dci_checker=DCIChecker(mode="static+prompt"),
    tdp_detector=TDPDetector(model="local"),
    auth_module=AuthModule(cert_dir="certs/"),
)

# Attach to MCP client
client = MCPClient(proxy=proxy)
client.connect("stdio", "/path/to/mcp-server")
```

### Running Tests

```bash
# Full test suite
python -m pytest tests/ -v

# Specific phase
python -m pytest tests/test_detectors.py -v --tb=short

# With coverage
python -m pytest tests/ --cov=src --cov-report=html
```

---

## Research Basis

This framework is grounded in empirical security research on MCP ecosystems:

- **[Shi et al. (2026)](https://arxiv.org/abs/2606.04769)** — Description-Code Inconsistency in Real-world MCP Servers: Measurement, Detection, and Security Implications
- **[Liu et al. (2026)](https://arxiv.org/abs/2605.24069)** — When the Manual Lies: A Realistic Benchmark to Evaluate MCP Poisoning Attacks for LLM Agents
- **[Zhou et al. (2026)](https://arxiv.org/abs/2605.22333)** — A First Measurement Study on Authentication Security in Real-World Remote MCP Servers
- **[Wang et al. (2026)](https://arxiv.org/abs/2606.01991)** — SafeMCP: Proactive Power Regulation for LLM Agent Defense
- **[Metere (2026)](https://arxiv.org/abs/2605.24248)** — Attested Tool-Server Admission: A Security Extension to MCP
- **[He & Yu (2026)](https://arxiv.org/abs/2606.11632)** — Sovereign Assurance Boundary: Certificate-Bound Admission for Agentic Infrastructure
- **[Greshake et al. (2023)](https://arxiv.org/abs/2302.12173)** — Indirect Prompt Injection in LLM-Integrated Applications

---

## License

MIT License — see [LICENSE](LICENSE) for details.
