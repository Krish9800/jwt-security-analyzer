"""Unit tests for jwtsec domain models and taxonomy schemas."""

import pytest
from pydantic import ValidationError

from jwtsec.models.token import (
    CrackRequest,
    CrackResult,
    CraftRequest,
    CraftResult,
    DecodedJWT,
    JWTAuditResult,
)
from jwtsec.models.vulnerability import (
    ConfidenceLevel,
    DetectionFinding,
    JWTVulnerabilityType,
    SeverityLevel,
)


def test_detection_finding_instantiation() -> None:
    finding = DetectionFinding(
        finding_id="JWT-ALG-NONE-01",
        vulnerability_type=JWTVulnerabilityType.ALG_NONE,
        title="Insecure None Algorithm Accepted",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.CERTAIN,
        cwe_id="CWE-327",
        description="The token uses alg: none which bypasses signature validation.",
        remediation="Strictly whitelist allowed signing algorithms (e.g. HS256, RS256).",
        details={"alg": "none"},
    )
    assert finding.finding_id == "JWT-ALG-NONE-01"
    assert finding.severity == SeverityLevel.CRITICAL
    assert finding.details["alg"] == "none"


def test_decoded_jwt_defaults() -> None:
    decoded = DecodedJWT(raw_token="header.payload.sig")
    assert decoded.raw_token == "header.payload.sig"
    assert decoded.header == {}
    assert decoded.payload == {}
    assert decoded.algorithm == "none"
    assert decoded.is_valid_format is True


def test_jwt_audit_result_score_validation() -> None:
    result = JWTAuditResult(
        token_snippet="eyJhbGciOi...",
        is_vulnerable=True,
        risk_score=85.5,
        risk_level="CRITICAL",
        findings=[],
        header={"alg": "HS256"},
        payload={"sub": "1234"},
        cracked_secret=None,
    )
    assert result.risk_score == 85.5
    assert result.is_vulnerable is True

    # Out of bounds score
    with pytest.raises(ValidationError):
        JWTAuditResult(
            token_snippet="test",
            is_vulnerable=False,
            risk_score=105.0,
        )


def test_crack_and_craft_models() -> None:
    crack_req = CrackRequest(token="header.payload.signature", max_words=500)
    assert crack_req.max_words == 500

    crack_res = CrackResult(cracked=True, secret="secret123", attempts=12, duration_ms=4.5)
    assert crack_res.cracked is True
    assert crack_res.secret == "secret123"

    craft_req = CraftRequest(
        claims={"admin": True},
        algorithm="none",
        secret_or_key=None,
    )
    assert craft_req.algorithm == "none"
    assert craft_req.claims["admin"] is True

    craft_res = CraftResult(
        token="eyJh...eyJh...",
        algorithm="none",
        header={"alg": "none"},
        payload={"admin": True},
    )
    assert craft_res.token.startswith("eyJh")
