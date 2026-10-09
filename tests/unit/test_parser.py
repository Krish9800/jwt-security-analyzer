"""Unit tests for JWT lexical parser and base64url decoder."""

import base64
import json
from typing import Any

from jwtsec.core.parser import JWTParser


def _make_jwt(
    header: dict[str, Any],
    payload: dict[str, Any],
    signature: str = "dGVzdHNpZw",
) -> str:
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{signature}"


def test_parser_valid_hs256_token() -> None:
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user123", "admin": False})
    parser = JWTParser()
    decoded = parser.parse(token)

    assert decoded.is_valid_format is True
    assert decoded.algorithm == "HS256"
    assert decoded.header["alg"] == "HS256"
    assert decoded.payload["sub"] == "user123"
    assert decoded.signature == "dGVzdHNpZw"


def test_parser_bearer_prefix_stripping() -> None:
    raw_token = _make_jwt({"alg": "RS256"}, {"user": "alice"})
    bearer_token = f"Bearer {raw_token}"
    parser = JWTParser()
    decoded = parser.parse(bearer_token)

    assert decoded.is_valid_format is True
    assert decoded.algorithm == "RS256"
    assert decoded.payload["user"] == "alice"


def test_parser_unsigned_token() -> None:
    token = _make_jwt({"alg": "none"}, {"sub": "root"}, signature="")
    parser = JWTParser()
    decoded = parser.parse(token)

    assert decoded.is_valid_format is True
    assert decoded.algorithm == "none"
    assert decoded.signature == ""


def test_parser_jwe_five_segments() -> None:
    jwe_token = "seg1.seg2.seg3.seg4.seg5"
    parser = JWTParser()
    decoded = parser.parse(jwe_token)

    assert decoded.is_valid_format is True
    assert decoded.algorithm == "JWE"
    assert decoded.header["enc_type"] == "JWE"


def test_parser_invalid_segment_counts() -> None:
    parser = JWTParser()

    assert parser.parse("single_segment").is_valid_format is False
    assert parser.parse("part1.part2").is_valid_format is False
    assert parser.parse("p1.p2.p3.p4").is_valid_format is False


def test_parser_empty_and_whitespace() -> None:
    parser = JWTParser()
    assert parser.parse("").is_valid_format is False
    assert parser.parse("   ").is_valid_format is False


def test_parser_invalid_characters_and_malformed_json() -> None:
    parser = JWTParser()
    # Invalid characters in base64
    invalid_chars_token = "invalid!@#.payload.sig"
    assert parser.parse(invalid_chars_token).is_valid_format is False

    # Valid base64 but not valid JSON
    not_json_b64 = base64.urlsafe_b64encode(b"not json at all").decode().rstrip("=")
    malformed_token = f"{not_json_b64}.{not_json_b64}.sig"
    decoded = parser.parse(malformed_token)
    assert decoded.is_valid_format is False
    assert "error" in decoded.header


def test_parser_token_length_limit() -> None:
    parser = JWTParser(max_token_length=50)
    long_token = "a" * 100
    decoded = parser.parse(long_token)
    assert decoded.is_valid_format is False
    assert "error" in decoded.header
