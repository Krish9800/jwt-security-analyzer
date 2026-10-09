"""Lexical parser and base64url decoder for JSON Web Tokens without library dependencies."""

import base64
import json
import re
from typing import Any

from jwtsec.config.settings import get_settings
from jwtsec.models.token import DecodedJWT


class JWTFormatError(ValueError):
    """Raised when an inspected token deviates from RFC 7519 structural rules."""


class JWTParser:
    """Decodes and inspects raw JWT strings into structured headers, payloads, and signatures."""

    _BEARER_REGEX = re.compile(r"^Bearer\s+", re.IGNORECASE)
    _BASE64URL_CHARS = re.compile(r"^[A-Za-z0-9_-]*$")

    def __init__(self, max_token_length: int | None = None) -> None:
        settings = get_settings()
        self.max_token_length = max_token_length or settings.max_token_length

    def parse(self, raw_token: str) -> DecodedJWT:
        """Parse raw token into DecodedJWT structure.

        Args:
            raw_token: Raw JWT or Bearer string.

        Returns:
            DecodedJWT populated with header, payload, signature, and validity status.
        """
        cleaned = raw_token.strip()
        if self._BEARER_REGEX.match(cleaned):
            cleaned = self._BEARER_REGEX.sub("", cleaned).strip()

        if not cleaned:
            return DecodedJWT(
                raw_token=raw_token,
                header={},
                payload={},
                signature="",
                algorithm="none",
                is_valid_format=False,
            )

        if len(cleaned) > self.max_token_length:
            return DecodedJWT(
                raw_token=raw_token,
                header={"error": "Token exceeds maximum length limit"},
                payload={},
                signature="",
                algorithm="none",
                is_valid_format=False,
            )

        parts = cleaned.split(".")
        if len(parts) == 5:
            # JWE (JSON Web Encryption) detected
            return DecodedJWT(
                raw_token=cleaned,
                header={"enc_type": "JWE", "segments": 5},
                payload={"error": "Encrypted JWE token; payload is ciphertext"},
                signature="",
                algorithm="JWE",
                is_valid_format=True,
            )

        if len(parts) != 3:
            return DecodedJWT(
                raw_token=cleaned,
                header={"error": f"Invalid segment count: {len(parts)} (expected 3)"},
                payload={},
                signature="",
                algorithm="none",
                is_valid_format=False,
            )

        header_b64, payload_b64, signature_b64 = parts

        header_json, header_valid = self._decode_segment(header_b64)
        payload_json, payload_valid = self._decode_segment(payload_b64)

        algorithm = "none"
        if isinstance(header_json, dict):
            algorithm = str(header_json.get("alg", "none"))

        is_valid = header_valid and payload_valid

        return DecodedJWT(
            raw_token=cleaned,
            header=header_json if isinstance(header_json, dict) else {"raw": header_json},
            payload=payload_json if isinstance(payload_json, dict) else {"raw": payload_json},
            signature=signature_b64,
            algorithm=algorithm,
            is_valid_format=is_valid,
        )

    def _decode_segment(self, segment: str) -> tuple[dict[str, Any] | str, bool]:
        """Decode base64url string and parse JSON object."""
        if not segment:
            return {}, True

        # Validate base64url characters
        if not self._BASE64URL_CHARS.match(segment):
            return {"error": "Invalid base64url characters"}, False

        # Compute missing padding
        padding_needed = (4 - len(segment) % 4) % 4
        padded = segment + ("=" * padding_needed)

        try:
            decoded_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
            decoded_text = decoded_bytes.decode("utf-8")
        except Exception:
            return {"error": "Base64 decoding failed"}, False

        try:
            parsed_json = json.loads(decoded_text)
            if isinstance(parsed_json, dict):
                return parsed_json, True
            return {"raw_value": parsed_json}, True
        except json.JSONDecodeError:
            return {"raw_content": decoded_text, "error": "Malformed JSON structure"}, False
