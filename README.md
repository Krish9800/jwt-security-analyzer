# JWT Security Analyzer (`jwtsec`)

[![CI](https://github.com/krish/jwt-security-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/krish/jwt-security-analyzer/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/mypy-strict-blue.svg)](https://mypy-lang.org/)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

Enterprise-Grade JSON Web Token (JWT) Security Auditor, Cracker, Token Crafter, and Dual-Mode Verification Lab.

---

## Features

- **Automated Vulnerability Detection**:
  - `alg: none` detection including case-manipulation bypasses (`none`, `None`, `NONE`, `nOnE`) and signature stripping (CWE-327).
  - Key confusion vulnerability detection where RSA public keys are accepted as HMAC secrets (CWE-347).
  - Header parameter injection auditing (`kid` traversal, command injection, SQL injection, rogue `jwk`, CWE-22/CWE-89).
  - Temporal claims audit (`exp`, `nbf`, `iat`, clock skew leeway, missing expiration, CWE-613).
  - Plaintext sensitive data disclosure in unencrypted claims (passwords, tokens, API keys, PII, CWE-312).
- **High-Speed HMAC Secret Cracker**:
  - Dictionary attack against HMAC-SHA256/384/512 tokens with built-in high-frequency wordlists.
- **Proof-of-Concept Token Crafter**:
  - Generate test tokens for `none`, custom HMAC, and RSA signatures for security evaluation.
- **Dual-Mode Interactive Verification Lab**:
  - `insecure`: Simulates legacy, vulnerable verification logic.
  - `hardened`: Production-grade zero-trust validation with strict algorithm whitelisting.
- **Multi-Format Reporting**:
  - Rich CLI formatting, JSON, GitHub Flavored Markdown, and OASIS SARIF v2.1.0.
- **Production REST Microservice**:
  - FastAPI service with interactive OpenAPI docs at `/docs` running on port 8082.
- **Containerized & Rootless**:
  - Multi-stage Docker container running as non-privileged user (`UID 10001:10001`).

---

## Installation

```bash
# Clone repository
git clone https://github.com/krish/jwt-security-analyzer.git
cd jwt-security-analyzer

# Setup virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"
```

---

## Quick Start CLI

```bash
# Audit a JWT token
jwtsec audit "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."

# Audit with markdown report output
jwtsec audit "<token>" --format markdown --output report.md

# Crack an HMAC token with dictionary attack
jwtsec crack "<token>"

# Craft an unsigned token
jwtsec craft --alg none --claim sub=admin --claim role=root

# Run the verification lab
jwtsec lab --mode hardened --token "<token>"
```

---

## REST API Microservice

Start the microservice:

```bash
uvicorn jwtsec.api.app:app --host 0.0.0.0 --port 8082
```

Or using Docker:

```bash
docker compose up -d
```

### Endpoints

- `GET /health`: Service health check.
- `GET /api/v1/rules`: List all vulnerability audit rules and CWE classifications.
- `POST /api/v1/audit`: Audit a JWT token.
- `POST /api/v1/crack`: Dictionary attack on HMAC tokens.
- `POST /api/v1/craft`: Craft specialized test tokens.
- `POST /api/v1/verify`: Verify token against insecure or hardened verifiers.

---

## Verification & Quality Gates

Run the comprehensive test and quality assurance suite:

```bash
# Run pytest with 90%+ coverage gate
pytest --cov=jwtsec --cov-report=term-missing --cov-fail-under=90

# Linting and formatting
ruff check .
ruff format --check .

# Static type checking
mypy src tests

# Security AST scanner
bandit -r src/ -c pyproject.toml
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
