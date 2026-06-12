# Contributing to MCP Core Defense

## Development Setup

```bash
# Clone and setup
git clone https://github.com/amurlaniakea/mcp-core-defense.git
cd mcp-core-defense
python3 -m venv venv
source venv/bin/activate
make install

# Run all checks
make check
```

## Make Targets

| Target | Description |
|--------|-------------|
| `make test` | Run all tests |
| `make test-verbose` | Tests + coverage |
| `make test-phase{N}` | Run Phase N tests only |
| `make lint` | Run ruff linter |
| `make format` | Format with black + ruff |
| `make typecheck` | Run mypy |
| `make check` | lint + typecheck + test |
| `make clean` | Remove artifacts |

## TDD Rules

1. **No production code without a failing test first** (RED → GREEN → REFACTOR)
2. Write the test, confirm it fails, then implement the minimum code to pass
3. All tests must pass before committing
4. Never commit failing tests

## Code Standards

- Python >= 3.10, type hints required on all functions
- Google-style docstrings
- Line length: 100 chars
- Imports sorted with ruff (isort rules)
- All source files must include the SPDX license header

## License

By contributing, you agree that your contributions will be licensed under
AGPL-3.0-or-later.
