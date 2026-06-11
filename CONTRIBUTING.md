# Contributing to MCP Core Defense

## Setup

```bash
git clone https://github.com/amurlaniakea/mcp-core-defense.git
cd mcp-core-defense
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running Tests

```bash
pytest tests/ -v
```

All tests must pass before submitting a PR.

## Development Rules

1. **TDD only** — no production code without a failing test first
2. **One behavior per test** — clear descriptive names
3. **Real code, not mocks** — unless truly unavoidable
4. **All 5 phases must pass** — policy → schema → DCI → TDP → auth

## Project Structure

```
src/
├── policy_engine/      # Phase 1: Deny-by-default access control
├── validators/         # Phase 2: Strict JSON schema validation
├── detectors/          # Phase 3+4: DCI Checker + TDP Detector
└── auth/               # Phase 5: Mutual TLS authentication
tests/
├── test_policy_engine.py
├── test_schema_validator.py
├── test_dci_checker.py
├── test_tdp_detector.py
├── test_mtls.py
└── test_integration.py   # Full pipeline integration tests
```

## Adding a New Phase

1. Write failing tests in `tests/test_<phase>.py`
2. Run `pytest tests/test_<phase>.py -v` → confirm RED
3. Implement in `src/<module>/<phase>.py`
4. Run tests → confirm GREEN
5. Add integration test in `test_integration.py`
6. Update this file
