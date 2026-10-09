"""Integration tests contrasting vulnerable vs hardened verification lab behavior."""

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from jwtsec.core.crafter import JWTCrafter
from jwtsec.lab.verifier import HardenedVerifier, InsecureVerifier


def _generate_rsa_keys() -> tuple[str, str]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return priv_pem, pub_pem


def test_lab_alg_none_attack() -> None:
    token = JWTCrafter.craft_none(claims={"sub": "admin_user", "role": "superuser"}).token

    # Insecure verifier allows alg: none bypass
    insecure = InsecureVerifier()
    is_auth, sub, details = insecure.verify(token)
    assert is_auth is True
    assert sub == "admin_user"
    assert details["vulnerability_exploited"] == "ALG_NONE"

    # Hardened verifier rejects alg: none
    hardened = HardenedVerifier(allowed_algorithms=["RS256", "HS256"])
    is_auth_h, sub_h, details_h = hardened.verify(token)
    assert is_auth_h is False
    assert sub_h == "anonymous"
    assert "not permitted" in details_h["error"]


def test_lab_key_confusion_attack() -> None:
    _, pub_pem = _generate_rsa_keys()
    kc_token = JWTCrafter.craft_key_confusion(
        claims={"sub": "impersonated_admin"},
        public_key_pem=pub_pem,
    ).token

    # Insecure verifier is tricked by RSA public key HMAC confusion
    insecure = InsecureVerifier(expected_rsa_public_key=pub_pem)
    is_auth, sub, details = insecure.verify(kc_token)
    assert is_auth is True
    assert sub == "impersonated_admin"
    assert details["vulnerability_exploited"] == "KEY_CONFUSION"

    # Hardened verifier configured for RS256 rejects HS256 token
    hardened = HardenedVerifier(
        allowed_algorithms=["RS256"],
        rsa_public_key_pem=pub_pem,
    )
    is_auth_h, sub_h, details_h = hardened.verify(kc_token)
    assert is_auth_h is False
    assert sub_h == "anonymous"
    assert "not permitted" in details_h["error"]


def test_lab_expired_and_missing_exp_token() -> None:
    secret = "production_super_secret_key_8841"
    now = time.time()

    # Expired token
    expired_token = JWTCrafter.craft_hmac(
        claims={"sub": "charlie", "exp": now - 300},
        secret=secret,
    ).token

    hardened = HardenedVerifier(allowed_algorithms=["HS256"], hmac_secret=secret)
    is_auth, _, details = hardened.verify(expired_token)
    assert is_auth is False
    assert "expired" in details["error"].lower()

    # Missing exp token
    no_exp_token = JWTCrafter.craft_hmac(
        claims={"sub": "charlie"},
        secret=secret,
    ).token
    is_auth_no_exp, _, details_no_exp = hardened.verify(no_exp_token)
    assert is_auth_no_exp is False
    assert "missing" in details_no_exp["error"].lower()


def test_lab_hardened_valid_tokens() -> None:
    hmac_key = "production_hmac_secret_key_2026_enterprise"
    now = time.time()

    # Valid HMAC token
    hmac_token = JWTCrafter.craft_hmac(
        claims={"sub": "alice_valid", "exp": now + 600},
        secret=hmac_key,
    ).token
    hardened_hmac = HardenedVerifier(allowed_algorithms=["HS256"], hmac_secret=hmac_key)
    is_auth, sub, details = hardened_hmac.verify(hmac_token)
    assert is_auth is True
    assert sub == "alice_valid"
    assert details["status"] == "verified"

    # Valid RSA token
    priv_pem, pub_pem = _generate_rsa_keys()
    rsa_token = JWTCrafter.craft_rsa(
        claims={"sub": "bob_rsa_valid", "exp": now + 600},
        private_key_pem=priv_pem,
    ).token
    hardened_rsa = HardenedVerifier(allowed_algorithms=["RS256"], rsa_public_key_pem=pub_pem)
    is_auth_rsa, sub_rsa, details_rsa = hardened_rsa.verify(rsa_token)
    assert is_auth_rsa is True
    assert sub_rsa == "bob_rsa_valid"
    assert details_rsa["status"] == "verified"
