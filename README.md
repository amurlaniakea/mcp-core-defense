# MCP Core Defense

A security framework for Model Context Protocol (MCP) agent systems.
Implements a 5-phase verification pipeline to defend against tool poisoning,
description-code inconsistencies, privilege escalation, and authentication attacks.

## Architecture

```
Agent (Hermes/WSL) → MCP-SP (Security Proxy) → WSL Execution Environment
                        │
                        ├── Phase 1: Policy Engine (deny-by-default)
                        ├── Phase 2: Schema Validator (JSON I/O)
                        ├── Phase 3: DCI Checker (description vs. code)
                        ├── Phase 4: TDP Detector (poisoning scan)
                        └── Phase 5: Auth Module (mutual TLS + certificates)
```

## Project Structure

```
mcp-core-defense/
├── src/
│   ├── policy_engine/    # Phase 1: deny-by-default allowlisting
│   ├── validators/       # Phase 2: strict JSON schema validation
│   ├── detectors/        # Phase 3+4: DCI Checker + TDP Detector
│   └── auth/             # Phase 5: mutual TLS + cert verification
├── tests/                # pytest suite
├── .gitignore            # Python/Node/LaTeX optimized
├── README.md             # This file
└── LICENSE               # MIT
```

## Research Basis

- **Shi et al. (2026)** — Description-Code Inconsistency in MCP Servers (9.93% affected)
- **Liu et al. (2026)** — MCP Poisoning Attacks (GPT-4o: ~100% ASR)
- **Zhou et al. (2026)** — Authentication Security in Remote MCP Servers
- **Wang et al. (2026)** — SafeMCP: Proactive Power Regulation
- **Metere (2026)** — Attested Tool-Server Admission
- **He & Yu (2026)** — Sovereign Assurance Boundary

## License

MIT
