"""Unit tests for Phase 4 algorithm and header vulnerability scanners."""

import base64
import hashlib
import hmac
import json
from typing import Any

from jwtsec.models.token import DecodedJWT
from jwtsec.scanners.alg_none import AlgNoneScanner
from jwtsec.scanners.headers import HeaderInjectionScanner
from jwtsec.scanners.key_confusion import KeyConfusionScanner


def _make_decoded(
    header: dict[str, Any], payload: dict[str, Any], signature: str = "sig"
) -> DecodedJWT:
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    raw = f"{h_b64}.{p_b64}.{signature}"
    return DecodedJWT(
        raw_token=raw,
        header=header,
        payload=payload,
        signature=signature,
        algorithm=str(header.get("alg", "none")),
    )


def test_alg_none_scanner_detects_variants() -> None:
    variants = ["none", "None", "NONE", "nOnE"]
    for v in variants:
        decoded = _make_decoded({"alg": v}, {"sub": "admin"}, signature="")
        findings = AlgNoneScanner.scan(decoded)
        assert len(findings) == 1
        assert findings[0].finding_id == "JWT-VULN-ALG-NONE-01"


def test_alg_none_scanner_detects_stripped_signature() -> None:
    decoded = _make_decoded({"alg": "HS256"}, {"sub": "alice"}, signature="")
    findings = AlgNoneScanner.scan(decoded)
    assert any(f.finding_id == "JWT-VULN-STRIPPED-SIG-02" for f in findings)


def test_alg_none_clean_token() -> None:
    decoded = _make_decoded({"alg": "RS256"}, {"sub": "alice"}, signature="valid_signature")
    assert len(AlgNoneScanner.scan(decoded)) == 0


def test_key_confusion_hmac_with_asymmetric_headers() -> None:
    decoded = _make_decoded(
        {"alg": "HS256", "jwk": {"kty": "RSA"}},
        {"sub": "victim"},
        signature="somesig",
    )
    findings = KeyConfusionScanner.scan(decoded)
    assert any(f.finding_id == "JWT-VULN-KEY-CONFUSION-01" for f in findings)


def test_key_confusion_verified_with_public_key() -> None:
    pub_key = (
        "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"
    )
    header = {"alg": "HS256"}
    payload = {"sub": "admin", "role": "superuser"}

    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    sig_bytes = hmac.new(pub_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")

    decoded = DecodedJWT(
        raw_token=f"{h_b64}.{p_b64}.{sig_b64}",
        header=header,
        payload=payload,
        signature=sig_b64,
        algorithm="HS256",
    )

    findings = KeyConfusionScanner.scan(decoded, public_key_pem=pub_key)
    assert any(f.finding_id == "JWT-VULN-KEY-CONFUSION-VERIFIED-02" for f in findings)


def test_header_injection_kid_traversal_and_sqli() -> None:
    # Traversal
    dec_trav = _make_decoded({"alg": "HS256", "kid": "../../../etc/passwd"}, {})
    findings_trav = HeaderInjectionScanner.scan(dec_trav)
    assert any(f.finding_id == "JWT-VULN-KID-TRAVERSAL-01" for f in findings_trav)

    # SQLi
    dec_sqli = _make_decoded({"alg": "HS256", "kid": "key' OR 1=1--"}, {})
    findings_sqli = HeaderInjectionScanner.scan(dec_sqli)
    assert any(f.finding_id == "JWT-VULN-KID-SQLI-02" for f in findings_sqli)

    # Command Injection
    dec_cmdi = _make_decoded({"alg": "HS256", "kid": "key; whoami"}, {})
    findings_cmdi = HeaderInjectionScanner.scan(dec_cmdi)
    assert any(f.finding_id == "JWT-VULN-KID-CMDI-03" for f in findings_cmdi)


def test_header_injection_jwk_and_jku() -> None:
    # Rogue JWK
    dec_jwk = _make_decoded({"alg": "RS256", "jwk": {"kty": "RSA"}}, {})
    findings_jwk = HeaderInjectionScanner.scan(dec_jwk)
    assert any(f.finding_id == "JWT-VULN-ROGUE-JWK-01" for f in findings_jwk)

    # Untrusted & Cleartext JKU
    dec_jku = _make_decoded({"alg": "RS256", "jku": "http://evil.corp/keys.json"}, {})
    findings_jku = HeaderInjectionScanner.scan(dec_jku)
    assert any(f.finding_id == "JWT-VULN-JKU-CLEARTEXT-01" for f in findings_jku)
    assert any(f.finding_id == "JWT-VULN-JKU-UNTRUSTED-02" for f in findings_jku)


def test_header_clean_kid() -> None:
    dec_clean = _make_decoded({"alg": "HS256", "kid": "key-2026-prod-01"}, {})
    findings = HeaderInjectionScanner.scan(dec_clean)
    assert len(findings) == 0
