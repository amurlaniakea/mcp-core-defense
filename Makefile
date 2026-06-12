# mcp-core-defense Makefile

.PHONY: help install test test-verbose lint format typecheck check clean all

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install package in dev mode with all dev dependencies
	pip install -e ".[dev]"

test: ## Run all tests
	python -m pytest tests/ -v --tb=short

test-verbose: ## Run tests with coverage report
	python -m pytest tests/ -v --tb=long --cov=src --cov-report=term-missing

test-phase1: ## Run Phase 1 tests (Policy Engine)
	python -m pytest tests/test_policy_engine.py -v

test-phase2: ## Run Phase 2 tests (Schema Validator)
	python -m pytest tests/test_schema_validator.py -v

test-phase3: ## Run Phase 3 tests (DCI Checker)
	python -m pytest tests/test_dci_checker.py -v

test-phase4: ## Run Phase 4 tests (TDP Detector)
	python -m pytest tests/test_tdp_detector.py -v

test-phase5: ## Run Phase 5 tests (Mutual TLS)
	python -m pytest tests/test_mtls.py -v

test-pipeline: ## Run Pipeline + Integration tests
	python -m pytest tests/test_pipeline.py tests/test_integration.py -v

test-perf: ## Run Performance tests
	python -m pytest tests/test_performance.py -v

lint: ## Run ruff linter
	ruff check src tests

format: ## Format code with black + ruff
	black src tests
	ruff check --fix src tests

typecheck: ## Run mypy type checker
	mypy src

check: lint typecheck test ## Run all checks (lint + typecheck + test)

clean: ## Remove build artifacts and cache
	rm -rf build/ dist/ *.egg-info .mypy_cache .ruff_cache .pytest_cache
	find src tests -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find src tests -name "*.pyc" -delete 2>/dev/null || true

all: format check ## Format, lint, typecheck, and test
