"""Adversarial security and edge-case fuzzing tests for jwtsec."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from jwtsec.core.cracker import HMACSecretCracker
from jwtsec.core.crafter import JWTCrafter
from jwtsec.core.engine import JWTAuditEngine
from jwtsec.core.parser import JWTParser
from jwtsec.models.vulnerability import JWTVulnerabilityType


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


@pytest.mark.parametrize(
    "variant",
    ["none", "None", "NONE", "nOnE", "NoNe"],
)
def test_alg_none_case_variations(variant: str) -> None:
    crafted = JWTCrafter.craft_none(claims={"sub": "adversary"}, case_variant=variant)
    engine = JWTAuditEngine()
    result = engine.audit(crafted.token)

    assert result.is_vulnerable is True
    vuln_types = [f.vulnerability_type for f in result.findings]
    assert JWTVulnerabilityType.ALG_NONE in vuln_types


@pytest.mark.parametrize(
    "malformed_token",
    [
        "",
        "single-segment",
        "header.payload",  # only 2 segments
        "a.b.c.d",  # 4 segments
        "a.b.c.d.e.f",  # 6 segments
        "!!!.@@@.###",
        "eyJh.bad_json.sig",
        "Bearer",
        "Bearer ",
    ],
)
def test_parser_adversarial_malformed_tokens(malformed_token: str) -> None:
    parser = JWTParser()
    decoded = parser.parse(malformed_token)
    assert decoded.is_valid_format is False


def test_audit_engine_handles_malformed_tokens_safely() -> None:
    engine = JWTAuditEngine()
    result = engine.audit("invalid.corrupt.token")
    assert result.is_vulnerable is True
    assert any("Malformed Token Structure" in f.title for f in result.findings)
    assert result.findings[0].vulnerability_type == JWTVulnerabilityType.MALFORMED_STRUCTURE


def test_cracker_adversarial_inputs() -> None:
    cracker = HMACSecretCracker()

    # Empty token
    empty_res = cracker.crack("", wordlist=["secret"])
    assert empty_res.cracked is False

    # Alg none token passed to cracker
    none_token = JWTCrafter.craft_none(claims={"sub": "test"}).token
    none_res = cracker.crack(none_token, wordlist=["secret"])
    assert none_res.cracked is False

    # RS256 token passed to cracker
    priv_pem, _ = _generate_rsa_key_pair()
    rsa_token = JWTCrafter.craft_rsa(claims={"sub": "test"}, private_key_pem=priv_pem).token
    rsa_res = cracker.crack(rsa_token, wordlist=["secret"])
    assert rsa_res.cracked is False


def test_header_injection_adversarial_patterns() -> None:
    engine = JWTAuditEngine()

    injections = [
        "../../../../../../etc/passwd",
        "key.pem; rm -rf /",
        "1' OR '1'='1",
        "key%00.pem",
    ]

    for inj in injections:
        token = JWTCrafter.craft_hmac(
            claims={"sub": "attacker"},
            secret="validsecret12345678901234567890",
            header_overrides={"kid": inj},
        ).token
        res = engine.audit(token)
        types = [f.vulnerability_type for f in res.findings]
        assert JWTVulnerabilityType.KID_INJECTION in types
