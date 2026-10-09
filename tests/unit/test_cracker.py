"""Unit tests for Phase 6 HMAC secret dictionary cracker."""

import base64
import hashlib
import hmac
import json
from typing import Any

from jwtsec.core.cracker import HMACSecretCracker


def _generate_hmac_jwt(
    secret: str,
    alg: str = "HS256",
    payload: dict[str, Any] | None = None,
) -> str:
    header = {"alg": alg, "typ": "JWT"}
    p = payload or {"sub": "12345", "role": "user"}

    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip("=")
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    h_func = hash_map[alg]

    sig = hmac.new(secret.encode("utf-8"), signing_input, h_func).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return f"{h_b64}.{p_b64}.{sig_b64}"


def test_cracker_hs256_default_wordlist() -> None:
    token = _generate_hmac_jwt(secret="password123", alg="HS256")
    cracker = HMACSecretCracker()
    result = cracker.crack(token)

    assert result.cracked is True
    assert result.secret == "password123"
    assert result.attempts > 0
    assert result.duration_ms >= 0.0


def test_cracker_hs384_and_hs512() -> None:
    cracker = HMACSecretCracker()

    # HS384
    token_384 = _generate_hmac_jwt(secret="secret", alg="HS384")
    res_384 = cracker.crack(token_384)
    assert res_384.cracked is True
    assert res_384.secret == "secret"

    # HS512
    token_512 = _generate_hmac_jwt(secret="admin", alg="HS512")
    res_512 = cracker.crack(token_512)
    assert res_512.cracked is True
    assert res_512.secret == "admin"


def test_cracker_custom_wordlist() -> None:
    custom_secret = "super_unusual_secret_9981"
    token = _generate_hmac_jwt(secret=custom_secret, alg="HS256")
    cracker = HMACSecretCracker()

    # Fails with default list
    res_default = cracker.crack(token)
    assert res_default.cracked is False

    # Succeeds with custom wordlist
    custom_list = ["apple", "banana", custom_secret, "orange"]
    res_custom = cracker.crack(token, wordlist=custom_list)
    assert res_custom.cracked is True
    assert res_custom.secret == custom_secret
    assert res_custom.attempts == 3


def test_cracker_non_hmac_and_unsigned_token() -> None:
    cracker = HMACSecretCracker()

    # Algorithm none
    h_b64 = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(b'{"sub":"admin"}').decode().rstrip("=")
    unsigned = f"{h_b64}.{p_b64}."
    assert cracker.crack(unsigned).cracked is False

    # Algorithm RS256
    h_rsa = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=")
    rsa_token = f"{h_rsa}.{p_b64}.somesig"
    assert cracker.crack(rsa_token).cracked is False


def test_cracker_malformed_token() -> None:
    cracker = HMACSecretCracker()
    assert cracker.crack("not.a.valid.jwt.token").cracked is False
    assert cracker.crack("invalid_token").cracked is False
