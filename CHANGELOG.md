# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-09

### Added
- **Core Engine & Architecture**:
  - `JWTParser`: Resilient base64url lexer with padding correction, segment validation, and 16KB DoS guardrails.
  - `JWTAuditEngine`: Central orchestration pipeline aggregating specialized vulnerability analyzers.
- **Vulnerability Scanners**:
  - `AlgNoneScanner`: Detection of `alg: none` case variations (`none`, `None`, `NONE`, `nOnE`) and signature stripping.
  - `KeyConfusionScanner`: Asymmetric-to-symmetric key confusion detector verifying RSA public key PEM HMAC vulnerability.
  - `HeaderInjectionScanner`: Header injection detection for `kid` directory traversal, SQLi, command injection, and rogue `jwk`.
  - `ClaimsAuditor`: Temporal validity validation for `exp`, `nbf`, `iat`, clock skew, and missing expiration.
  - `SensitiveDataScanner`: Unencrypted sensitive data detection in claims (passwords, tokens, API keys, PII).
- **Cracking & Token Generation**:
  - `HMACSecretCracker`: High-throughput HMAC dictionary recovery engine with built-in weak secret lists.
  - `JWTCrafter`: Token crafting utility for generating exploit reproduction tokens and unit test vectors.
- **Verification Lab**:
  - `InsecureVerifier`: Vulnerable verification pipeline demonstrating legacy security defects.
  - `HardenedVerifier`: Zero-trust token verifier with strict algorithm whitelisting and expiration enforcement.
- **Reporting & Interface**:
  - Multi-format report generators supporting Rich Terminal, JSON, Markdown, and SARIF v2.1.0.
  - Typer CLI with `audit`, `crack`, `craft`, and `lab` subcommands.
  - FastAPI REST microservice with OpenAPI documentation at `/docs` and endpoints for audit, cracking, crafting, and verification.
  - Rootless Dockerfile (`UID 10001:10001`) and `docker-compose.yml`.
  - Full CI pipeline with GitHub Actions, mypy, ruff, bandit, and $\ge 90\%$ pytest coverage.
