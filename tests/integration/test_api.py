"""Integration tests for the jwtsec REST API microservice."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from jwtsec.api.app import app
from jwtsec.core.crafter import JWTCrafter

client = TestClient(app)


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


def test_api_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "timestamp" in data


def test_api_list_rules() -> None:
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    data = response.json()
    assert data["total_rules"] == 7
    rule_ids = [r["rule_id"] for r in data["rules"]]
    assert "RULE-JWT-ALG-NONE" in rule_ids
    assert "RULE-JWT-KEY-CONFUSION" in rule_ids


def test_api_audit_token() -> None:
    crafted = JWTCrafter.craft_none(claims={"sub": "admin", "password": "plaintext_pass"})
    response = client.post("/api/v1/audit", json={"token": crafted.token})
    assert response.status_code == 200
    data = response.json()
    assert data["is_vulnerable"] is True
    vuln_types = [f["vulnerability_type"] for f in data["findings"]]
    assert "ALG_NONE" in vuln_types
    assert "SENSITIVE_DATA_EXPOSURE" in vuln_types


def test_api_crack_token() -> None:
    crafted = JWTCrafter.craft_hmac(claims={"sub": "user1"}, secret="supersecret", alg="HS256")
    response = client.post(
        "/api/v1/crack",
        json={"token": crafted.token, "custom_wordlist": ["wrong1", "supersecret", "wrong2"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["cracked"] is True
    assert data["secret"] == "supersecret"


def test_api_craft_none() -> None:
    response = client.post(
        "/api/v1/craft",
        json={"claims": {"sub": "root", "role": "admin"}, "algorithm": "none"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["algorithm"] == "none"
    assert data["token"].endswith(".")


def test_api_craft_hmac() -> None:
    response = client.post(
        "/api/v1/craft",
        json={"claims": {"sub": "root"}, "algorithm": "HS256", "secret": "mysecret123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["algorithm"] == "HS256"


def test_api_craft_hmac_missing_secret() -> None:
    response = client.post(
        "/api/v1/craft",
        json={"claims": {"sub": "root"}, "algorithm": "HS256"},
    )
    assert response.status_code == 400
    assert "Signing secret is required" in response.json()["detail"]


def test_api_craft_rsa_and_errors() -> None:
    priv_pem, _ = _generate_rsa_key_pair()
    response = client.post(
        "/api/v1/craft",
        json={"claims": {"sub": "root"}, "algorithm": "RS256", "private_key_pem": priv_pem},
    )
    assert response.status_code == 200
    assert response.json()["algorithm"] == "RS256"

    # Missing private key
    res_missing = client.post(
        "/api/v1/craft",
        json={"claims": {"sub": "root"}, "algorithm": "RS256"},
    )
    assert res_missing.status_code == 400
    assert "private_key_pem is required" in res_missing.json()["detail"]

    # Invalid private key
    res_invalid = client.post(
        "/api/v1/craft",
        json={"claims": {"sub": "root"}, "algorithm": "RS256", "private_key_pem": "not-a-pem"},
    )
    assert res_invalid.status_code == 400
    assert "Invalid RSA private key" in res_invalid.json()["detail"]

    # Unsupported algorithm
    res_unsupported = client.post(
        "/api/v1/craft",
        json={"claims": {"sub": "root"}, "algorithm": "ES256"},
    )
    assert res_unsupported.status_code == 400
    assert "Unsupported algorithm" in res_unsupported.json()["detail"]


def test_api_verify_flow() -> None:
    _, pub_pem = _generate_rsa_key_pair()
    # Key confusion attack token signed with HMAC using pub_pem as secret
    forged = JWTCrafter.craft_hmac(claims={"sub": "admin"}, secret=pub_pem, alg="HS256")

    # Insecure verifier accepts forged token
    resp_insecure = client.post(
        "/api/v1/verify",
        json={"token": forged.token, "mode": "insecure", "public_key_pem": pub_pem},
    )
    assert resp_insecure.status_code == 200
    assert resp_insecure.json()["authenticated"] is True
    assert resp_insecure.json()["identity"] == "admin"

    # Hardened verifier rejects forged token
    resp_hardened = client.post(
        "/api/v1/verify",
        json={"token": forged.token, "mode": "hardened", "public_key_pem": pub_pem},
    )
    assert resp_hardened.status_code == 200
    assert resp_hardened.json()["authenticated"] is False
