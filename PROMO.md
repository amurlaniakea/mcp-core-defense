# MCP Core Defense — Material de Promoción

---

## THREAD PARA X / MASTODON

---

🧵 [1/8] He construido un proxy de seguridad de 7 fases para Model Context Protocol (MCP) — el protocolo que conecta LLMs con herramientas externas.

Es open-source, 115 tests, CI verde en Python 3.10/3.11/3.12.

Por qué importa 👇

🔗 https://github.com/amurlaniakea/mcp-core-defense

---

[2/8] El problema:

MCP tiene 2,200+ servidores públicos. Estudios recientes (Shi et al. 2026) muestran que el 9.93% tienen inconsistencias entre lo que dicen hacer y lo que realmente hacen.

Otro estudio (Liu et al. 2026) demuestra que los modelos sufren ~100% de éxito en ataques de "tool description poisoning".

---

[3/8] MCP Core Defense implementa 7 fases de verificación secuencial (fail-fast):

1️⃣ Policy Engine — Deny-by-default con allowlist y wildcards
2️⃣ Schema Validator — Validación estricta de JSON schema
3️⃣ DCI Checker — Consistencia descripción-código (Python + JS/TS)
4️⃣ TDP Detector — Detección de tool description poisoning
5️⃣ Mutual TLS — Auth con pinning y detección de MITM
6️⃣ Sandbox — Jaula de filesystem con anti path traversal
7️⃣ SDK Adapter — Integración async con clientes MCP

---

[4/8] Rendimiento:

• Policy Engine: < 1ms
• Schema Validator: < 1ms
• DCI Checker: < 5ms
• TDP Detector: < 5ms
• Pipeline completo: < 20ms (avg), < 50ms (p95)
• Throughput: > 100 checks/seg
• Escala a 1,000 herramientas en < 2ms

Overhead mínimo para defensa real.

---

[5/8] DCI Checker multi-lenguaje:

No solo Python. También JavaScript y TypeScript:

• function(), arrow functions, async
• Destructuring {a, b}
• Type annotations de TypeScript
• Auto-detección de lenguaje

La mayoría de implementaciones solo cubren Python. Esto importa porque el ecosistema MCP es poliglota.

---

[6/8] Stack técnico:

• Python 3.12, AGPLv3
• 1,396 LOC producción + tests exhaustivos
• 115 tests (unitarios, integración, performance, escalabilidad)
• CI/CD con GitHub Actions (matrix 3.10/3.11/3.12)
• Makefile con targets por fase
• Pre-commit, ruff, black, mypy

---

[7/8] Basado en investigación real:

• Shi et al. (2026) — Description-Code Inconsistency
• Liu et al. (2026) — Tool Description Poisoning Benchmark
• Zhou et al. (2026) — Authentication Security in MCP
• Wang et al. (2026) — SafeMCP
• Metere (2026) — Attested Tool-Server Admission
• Greshake et al. (2023) — Indirect Prompt Injection

No es un proyecto de eslóganes. Es investigación aplicada.

---

[8/8] El repo:

🔗 https://github.com/amurlaniakea/mcp-core-defense

Instalación:
git clone + make install + make test

Si trabajas con MCP, agentes LLM, o seguridad de AI, esto te interesa.

Issues, PRs y feedback son bienvenidos.

#MCP #AISecurity #LLM #OpenSource #Cybersecurity

---

## POST PARA HACKER NEWS (Show HN)

---

**Title:** Show HN: MCP Core Defense — 7-phase security proxy for AI agent tool calls

**Body:**

MCP (Model Context Protocol) has 2,200+ public servers, but recent research shows 9.93% have description-code inconsistencies and ~100% attack success rates under tool description poisoning.

MCP Core Defense is a defense-in-depth security proxy interposed between the agent and all MCP servers. Seven sequential verification phases with fail-fast:

1. Policy Engine — deny-by-default allowlist with wildcards
2. Schema Validator — strict JSON schema validation
3. DCI Checker — description-code consistency (Python + JS/TS)
4. TDP Detector — tool description poisoning scan
5. Mutual TLS — certificate verification + pinning + MITM detection
6. Sandbox — filesystem jail with path traversal prevention
7. SDK Adapter — async MCP client integration

Performance: < 20ms avg for the full pipeline, > 100 checks/sec throughput.

115 tests passing on Python 3.10/3.11/3.12. AGPLv3.

GitHub: https://github.com/amurlaniakea/mcp-core-defense

---

## TEMPLATE PARA PR/Issue EN REPOS MCP POPULARES

---

**Title:** Suggestion: Integrate MCP Core Defense as security layer

**Body:**

Hi,

I've been working on [MCP Core Defense](https://github.com/amurlaniakea/mcp-core-defense), a 7-phase security proxy for MCP agent systems.

Given the recent research on MCP security vulnerabilities (Shi et al. 2026: 9.93% description-code inconsistency rate; Liu et al. 2026: ~100% poisoning attack success), I think there could be value in integrating a security layer like this into the MCP ecosystem.

The proxy implements:
- Deny-by-default policy engine
- Strict schema validation
- Description-code consistency checking (Python + JS/TS)
- Tool description poisoning detection
- Mutual TLS with certificate pinning
- Filesystem sandbox
- Async SDK adapter

All 115 tests pass on Python 3.10/3.11/3.12. Performance overhead is < 20ms avg.

Would you be open to a discussion about integration? Happy to contribute.

Repo: https://github.com/amurlaniakea/mcp-core-defense
