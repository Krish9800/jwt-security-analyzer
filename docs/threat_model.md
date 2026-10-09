# Threat Model: JWT Security Analyzer (`jwtsec`)

## 1. Overview & Scope

The threat model evaluates the `jwtsec` library, CLI, and REST API microservice against the STRIDE methodology.

## 2. STRIDE Assessment Matrix

| Threat Category | Threat Description | Severity | Countermeasure / Mitigation in `jwtsec` |
|:---|:---|:---|:---|
| **Spoofing** | Adversary crafts an unsigned or rogue token claiming high privilege (`sub: admin`). | Critical | Audit engine flags `ALG_NONE` and `KEY_CONFUSION`. `HardenedVerifier` requires explicit signature matching against configured secrets and rejects unapproved algorithms. |
| **Tampering** | Adversary mutates token header or payload and sets `alg: none` or exploits `kid` path traversal to force a known static key file. | Critical | `HeaderInjectionScanner` audits `kid` against directory traversal and SQLi patterns. `AlgNoneScanner` audits token signatures. |
| **Repudiation** | Lack of traceability for audits and verifications performed by the engine. | Low | Structured audit findings capture timestamps, rule IDs, confidence scores, and token hashes. |
| **Information Disclosure** | Sensitive authentication tokens or unencrypted secrets exposed in claims or logs. | High | `SensitiveDataScanner` inspects payload claims for plaintext passwords, tokens, and PII. CLI and API truncate raw token logging where appropriate. |
| **Denial of Service** | Oversized JWT strings or pathological inputs submitted to parser or cracker. | Medium | Token parser strictly enforces a 16KB size ceiling. Cracker caps candidate iterations and processes candidates in fixed batches. |
| **Elevation of Privilege** | Key confusion attack where server verifies HMAC signature using public key PEM bytes. | Critical | `KeyConfusionScanner` simulates public key signing to detect susceptibility. `HardenedVerifier` enforces disjoint algorithm-to-key mapping. |

## 3. Trust Boundaries

1. **Client / Untrusted Input Boundary**:
   - Raw JWT strings submitted via CLI arguments, environment variables, or HTTP request payloads.
   - Mitigation: All tokens are treated as completely untrusted data. Parsed without signature verification initially, bounded by size checks and strict base64url decoding.

2. **Verification Lab Boundary**:
   - `InsecureVerifier` is strictly isolated for educational and testing demonstrations.
   - `HardenedVerifier` enforces zero-trust validation rules for production deployments.

3. **Microservice Network Boundary**:
   - FastAPI container runs as rootless user (`UID 10001:10001`), read-only root filesystem, tmpfs `/tmp`.
