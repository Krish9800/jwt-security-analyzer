# JWT Security Analyzer (`jwtsec`)

Enterprise-Grade JSON Web Token (JWT) Security Auditor, Algorithm Confusion Detector, Offline Cracker, and Dual-Mode Practice Lab.

[![CI Pipeline](https://github.com/Krish9800/jwt-security-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Krish9800/jwt-security-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![CLI: Typer](https://img.shields.io/badge/CLI-Typer-green.svg)](https://typer.tiangolo.com/)
[![Standards: RFC 7519](https://img.shields.io/badge/Standards-RFC%207519-orange.svg)](https://datatracker.ietf.org/doc/html/rfc7519)

---

## Overview & Problem Statement

JSON Web Tokens (JWTs) are the ubiquitous authentication mechanism for distributed microservices and modern single-page applications. However, subtle flaws in token verification—such as acceptance of the unauthenticated `none` algorithm, asymmetric-to-symmetric key confusion (CVE-2016-5431 / CVE-2015-9235), weak signing secrets, and missing claim expiration checks—expose systems to unauthorized privilege escalation and account takeover.

**JWT Security Analyzer** is an automated auditing engine and dual-mode practice laboratory. It inspects token structures for cryptographic and syntactic misconfigurations, tests for known implementation vulnerabilities, benchmarks weak HMAC secrets via high-speed dictionary cracking, and provides an interactive vulnerable/hardened target environment for defensive training.

---

## Architecture & Data Flow

```mermaid
flowchart TD
    TokenInput[Raw JWT Token / Authorization Header] --> Parser[JWT Structural Decoder]

    subgraph Inspection & Verification Layer
        Parser --> HeaderCheck[Header Analysis: alg / typ / jku / x5u / kid]
        Parser --> ClaimsCheck[Claims Validator: exp / nbf / iat / iss / aud]
        Parser --> CryptoCheck[Signature Verification Engine]
    end

    subgraph Vulnerability Auditing Engine
        HeaderCheck --> VulnEngine{Vulnerability Evaluator}
        ClaimsCheck --> VulnEngine
        CryptoCheck --> VulnEngine

        VulnEngine --> AlgConfusion[Algorithm Confusion: RS256 as HS256]
        VulnEngine --> NoneAlg[None Algorithm Bypass]
        VulnEngine --> WeakSecret[Weak HMAC Secret Dictionary Cracker]
        VulnEngine --> Injection[SQLi / SSRF in Header Parameters]
    end

    subgraph Dual-Mode Practice Lab
        Lab[FastAPI Interactive Lab] --> VulnerableEndpoint[Vulnerable JWT Validator]
        Lab --> HardenedEndpoint[Strict Cryptographic Validator]
    end

    VulnEngine --> Report[Audit Report: CLI Table / JSON]
```

---

## Verified Features

- **Structural Decoding:** Inspects JOSE headers and claims without signature verification for offline reconnaissance.
- **Cryptographic Vulnerability Audits:**
  - `none` algorithm acceptance and casing bypasses (`None`, `NONE`, `noNe`).
  - Key confusion attacks (verifying RSA public keys against HMAC-SHA256).
  - Null signature acceptance and stripped signature testing.
  - Header parameter abuse (`jku` URI spoofing, `x5u` cert tampering, `kid` directory traversal).
- **Offline HMAC Cracker:** High-throughput dictionary attack engine for cracking weak HS256/HS384/HS512 shared secrets.
- **Token Crafter:** Utility to generate modified JWTs with arbitrary claims, mutated headers, and forged signatures for authorized testing.
- **Dual-Mode Practice Lab:** Embedded FastAPI server hosting both vulnerable endpoints (demonstrating exploitation) and hardened endpoints (demonstrating defensive mitigations).

---

## Technology Stack

- **Runtime:** Python 3.12+
- **Cryptography:** `cryptography` (PyCA) & `pyjwt`
- **CLI Framework:** Typer & Rich
- **API Framework:** FastAPI & Uvicorn
- **Quality Gates:** Pytest, Ruff, Mypy Strict, Bandit

---

## Requirements & Installation

```bash
# Clone the repository
git clone https://github.com/Krish9800/jwt-security-analyzer.git
cd jwt-security-analyzer

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package
pip install -e .
```

---

## Verified Usage Examples

### 1. Command-Line Interface (CLI)

```bash
# Audit a JWT token for vulnerabilities and misconfigurations
jwtsec audit "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Attempt offline dictionary cracking on a weak HMAC secret
jwtsec crack "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --wordlist wordlists/passwords.txt --threads 4

# Craft a forged token with modified claims and 'none' algorithm
jwtsec craft --alg none --payload '{"sub":"admin","role":"superuser"}'

# Launch the interactive dual-mode training lab
jwtsec lab --host 127.0.0.1 --port 8080
```

### 2. REST API Service

```bash
# Start the API service
uvicorn jwtsec.api.app:app --host 127.0.0.1 --port 8000
```

Endpoints available at `http://127.0.0.1:8000/docs`:
- `GET /health` — Service health check
- `POST /api/v1/audit` — Audit JWT token payload and headers
- `POST /api/v1/crack` — Asynchronously crack HMAC signature
- `POST /api/v1/craft` — Construct custom test tokens

---

## Testing & Quality Gates

```bash
# Run complete test suite with coverage
pytest --cov=jwtsec --cov-report=term-missing

# Run vulnerability audit test cases
pytest tests/unit/test_auditor.py

# Linting and static analysis
ruff check .
ruff format --check .
mypy src/jwtsec
```

---

## Security Model & Threat Boundaries

- **Defensive Auditing:** Designed for passive analysis of tokens captured in authorized security assessments.
- **Offline Processing:** Cracking and token analysis execute entirely in memory on the local machine with zero data transmitted externally.
- **Lab Containment:** The dual-mode lab binds to localhost by default and should never be exposed to public networks.

---

## Limitations & Known Issues

- **Hardware Acceleration:** The offline cracker uses pure Python multiprocessing; extreme throughput (millions of guesses/sec) requires GPU-accelerated tools like Hashcat.
- **ES256 / EdDSA Curve Attacks:** Auditing focuses on RSA and HMAC primitives; elliptic curve invalid point attacks are not currently simulated.

---

## License & Responsible Use

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

> [!CAUTION]
> **Responsible-Use Notice:** Use this tool only on authentication tokens and applications that you own or have explicit written permission to assess.
