"""Unit tests for Phase 5 claims auditor and sensitive data exposure scanners."""

import time
from typing import Any

from jwtsec.models.token import DecodedJWT
from jwtsec.scanners.claims import ClaimsAuditor
from jwtsec.scanners.data_leak import SensitiveDataScanner


def _make_token(payload: dict[str, Any]) -> DecodedJWT:
    return DecodedJWT(
        raw_token="header.payload.sig",
        header={"alg": "HS256"},
        payload=payload,
        signature="sig",
        algorithm="HS256",
    )


def test_claims_auditor_missing_exp() -> None:
    token = _make_token({"sub": "user123"})
    findings = ClaimsAuditor.scan(token)
    assert any(f.finding_id == "JWT-VULN-CLAIMS-NO-EXP-01" for f in findings)


def test_claims_auditor_expired_token() -> None:
    past_time = time.time() - 3600
    token = _make_token({"sub": "user123", "exp": past_time, "iat": past_time - 3600})
    findings = ClaimsAuditor.scan(token)
    assert any(f.finding_id == "JWT-VULN-CLAIMS-EXPIRED-02" for f in findings)


def test_claims_auditor_excessive_ttl() -> None:
    now = time.time()
    iat = now
    exp = now + (45 * 86400)  # 45 days
    token = _make_token({"sub": "user123", "iat": iat, "exp": exp})
    findings = ClaimsAuditor.scan(token)
    assert any(f.finding_id == "JWT-VULN-CLAIMS-LONG-TTL-03" for f in findings)


def test_claims_auditor_premature_nbf_and_future_iat() -> None:
    now = time.time()
    token = _make_token(
        {
            "sub": "user123",
            "nbf": now + 500,
            "iat": now + 600,
            "exp": now + 3600,
        }
    )
    findings = ClaimsAuditor.scan(token)
    assert any(f.finding_id == "JWT-VULN-CLAIMS-PREMATURE-NBF-04" for f in findings)
    assert any(f.finding_id == "JWT-VULN-CLAIMS-FUTURE-IAT-05" for f in findings)


def test_claims_auditor_clean_token() -> None:
    now = time.time()
    token = _make_token(
        {
            "sub": "user123",
            "iat": now - 60,
            "exp": now + 1800,
            "nbf": now - 60,
        }
    )
    findings = ClaimsAuditor.scan(token)
    assert len(findings) == 0


def test_sensitive_data_scanner_dangerous_keys() -> None:
    token = _make_token(
        {
            "sub": "user123",
            "password": "Password123!",
            "credentials": {"api_key": "sk_test_12345"},
        }
    )
    findings = SensitiveDataScanner.scan(token)
    assert any(f.finding_id == "JWT-VULN-SENSITIVE-KEY-PASSWORD" for f in findings)
    assert any(f.finding_id == "JWT-VULN-SENSITIVE-KEY-API_KEY" for f in findings)


def test_sensitive_data_scanner_value_patterns() -> None:
    token = _make_token(
        {
            "user_id": "123",
            "aws_token": "AKIAIOSFODNN7EXAMPLE",
            "tax_id": "000-12-3456",
        }
    )
    findings = SensitiveDataScanner.scan(token)
    assert any(f.finding_id == "JWT-VULN-SENSITIVE-VAL-AWS-ACCESS-KEY" for f in findings)
    assert any(f.finding_id == "JWT-VULN-SENSITIVE-VAL-SOCIAL-SECURITY-NUMBER" for f in findings)


def test_sensitive_data_scanner_clean() -> None:
    token = _make_token({"sub": "1234", "name": "Alice Smith", "roles": ["viewer"]})
    findings = SensitiveDataScanner.scan(token)
    assert len(findings) == 0
