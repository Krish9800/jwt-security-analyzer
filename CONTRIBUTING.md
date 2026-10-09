# Contributing to JWT Security Analyzer

Thank you for your interest in contributing to `jwt-security-analyzer`.

## Development Guidelines

1. **Coding Style**:
   - Follow PEP 8 guidelines enforced via Ruff (`ruff check` and `ruff format`).
   - Line length strictly limited to 100 characters.

2. **Type Checking**:
   - 100% strict type hints enforced via `mypy`. No untyped definitions allowed.

3. **Testing & Coverage**:
   - All contributions must include automated tests in `tests/`.
   - Maintain minimum test coverage of 90% via `pytest --cov=jwtsec`.

4. **Security Analysis**:
   - Zero high or medium severity defects under `bandit -r src/`.

## Workflow
1. Fork and create a topic branch.
2. Ensure all quality gates pass: `pytest && ruff check . && ruff format --check . && mypy src tests && bandit -r src/`.
3. Submit a pull request with an explanation of changes.
