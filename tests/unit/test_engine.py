"""Unit tests for Phase 7 consolidated JWTAuditEngine and JWTCrafter."""

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from jwtsec.core.crafter import JWTCrafter
from jwtsec.core.engine import JWTAuditEngine


def _generate_rsa_key_pair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem


def test_crafter_none_token() -> None:
    res = JWTCrafter.craft_none(claims={"sub": "admin", "role": "root"})
    assert res.token.endswith(".")
    assert res.algorithm == "none"
    assert res.header["alg"] == "none"
    assert res.payload["sub"] == "admin"


def test_crafter_hmac_and_rsa() -> None:
    # HMAC
    res_hmac = JWTCrafter.craft_hmac(claims={"user": "alice"}, secret="my_super_secret_key_12345")
    assert len(res_hmac.token.split(".")) == 3
    assert res_hmac.algorithm == "HS256"

    # RSA
    priv_pem, _ = _generate_rsa_key_pair()
    res_rsa = JWTCrafter.craft_rsa(claims={"user": "bob"}, private_key_pem=priv_pem)
    assert len(res_rsa.token.split(".")) == 3
    assert res_rsa.algorithm == "RS256"


def test_crafter_key_confusion() -> None:
    _, pub_pem = _generate_rsa_key_pair()
    res_kc = JWTCrafter.craft_key_confusion(claims={"user": "eve"}, public_key_pem=pub_pem)
    assert len(res_kc.token.split(".")) == 3
    assert res_kc.algorithm == "HS256"


def test_audit_engine_clean_token() -> None:
    now = time.time()
    clean_claims = {
        "sub": "user_123",
        "iss": "auth.corp.internal",
        "aud": "api.corp.internal",
        "iat": now - 30,
        "exp": now + 900,
    }
    # Sign with a secret that is not in the top weak wordlist
    strong_token = JWTCrafter.craft_hmac(clean_claims, secret="zK8#mQ9!vL2$pX5*nB4^").token

    engine = JWTAuditEngine()
    result = engine.audit(strong_token)

    assert result.is_vulnerable is False
    assert result.risk_level == "SAFE"
    assert result.risk_score == 0.0
    assert len(result.findings) == 0
    assert result.cracked_secret is None


def test_audit_engine_alg_none_token() -> None:
    token = JWTCrafter.craft_none({"sub": "admin", "exp": time.time() + 3600}).token
    engine = JWTAuditEngine()
    result = engine.audit(token)

    assert result.is_vulnerable is True
    assert result.risk_level == "CRITICAL"
    assert result.risk_score >= 80.0
    assert any(f.finding_id == "JWT-VULN-ALG-NONE-01" for f in result.findings)


def test_audit_engine_weak_hmac_secret() -> None:
    token = JWTCrafter.craft_hmac(
        {"sub": "admin", "exp": time.time() + 3600},
        secret="password",
    ).token
    engine = JWTAuditEngine()
    result = engine.audit(token)

    assert result.is_vulnerable is True
    assert result.cracked_secret == "password"
    assert any(f.finding_id == "JWT-VULN-WEAK-SECRET-01" for f in result.findings)


def test_audit_engine_malformed_token() -> None:
    engine = JWTAuditEngine()
    result = engine.audit("invalid.structure")

    assert result.is_vulnerable is True
    assert any(f.finding_id == "JWT-VULN-STRUCTURE-01" for f in result.findings)


def test_audit_engine_key_confusion_verified() -> None:
    _, pub_pem = _generate_rsa_key_pair()
    token = JWTCrafter.craft_key_confusion(
        {"sub": "admin", "exp": time.time() + 3600},
        public_key_pem=pub_pem,
    ).token

    engine = JWTAuditEngine()
    result = engine.audit(token, public_key_pem=pub_pem)

    assert result.is_vulnerable is True
    assert any(f.finding_id == "JWT-VULN-KEY-CONFUSION-VERIFIED-02" for f in result.findings)
