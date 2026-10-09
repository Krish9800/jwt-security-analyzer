"""Dual-mode JWT verification lab contrasting vulnerable vs zero-trust hardened verifiers."""

import time
from typing import Any

import jwt

from jwtsec.core.parser import JWTParser
from jwtsec.scanners.key_confusion import KeyConfusionScanner


class InsecureVerifier:
    """Intentionally vulnerable JWT verifier demonstrating common real-world auth flaws."""

    def __init__(self, expected_rsa_public_key: str | bytes | None = None) -> None:
        self.parser = JWTParser()
        self.expected_rsa_public_key = expected_rsa_public_key

    def verify(self, token: str) -> tuple[bool, str, dict[str, Any]]:
        """Verify token with vulnerable algorithm acceptance and key confusion flaws.

        Returns:
            Tuple of (is_authenticated, subject_identity, diagnostic_metadata).
        """
        decoded = self.parser.parse(token)
        if not decoded.is_valid_format:
            return False, "anonymous", {"error": "Malformed token structure"}

        alg = decoded.algorithm.lower()

        # VULNERABILITY 1: Acceptance of alg: none without signature
        if alg == "none":
            sub = str(decoded.payload.get("sub", decoded.payload.get("user", "authenticated_user")))
            return (
                True,
                sub,
                {
                    "mode": "insecure",
                    "vulnerability_exploited": "ALG_NONE",
                    "explanation": "Accepted unsigned token due to alg: none parameter.",
                },
            )

        # VULNERABILITY 2: Key Confusion (verifying HS256 using RSA public key as HMAC secret)
        if (
            decoded.algorithm.upper() == "HS256"
            and self.expected_rsa_public_key
            and KeyConfusionScanner._verify_hmac_with_public_key(
                decoded, self.expected_rsa_public_key, "HS256"
            )
        ):
            sub = str(decoded.payload.get("sub", decoded.payload.get("user", "authenticated_user")))
            return (
                True,
                sub,
                {
                    "mode": "insecure",
                    "vulnerability_exploited": "KEY_CONFUSION",
                    "explanation": "Verified HMAC token using RSA public key string as shared secret.",
                },
            )

        # VULNERABILITY 3: Missing expiration enforcement
        # If standard HS256 matches a dummy default secret
        if decoded.algorithm.upper() == "HS256":
            import base64
            import hashlib
            import hmac

            signing_input = f"{token.split('.')[0]}.{token.split('.')[1]}".encode("ascii")
            test_sig = hmac.new(b"secret", signing_input, hashlib.sha256).digest()
            test_b64 = base64.urlsafe_b64encode(test_sig).decode("ascii").rstrip("=")
            if hmac.compare_digest(test_b64, decoded.signature):
                sub = str(decoded.payload.get("sub", "authenticated_user"))
                return (
                    True,
                    sub,
                    {
                        "mode": "insecure",
                        "vulnerability_exploited": "WEAK_DEFAULT_SECRET",
                        "explanation": "Verified using default weak secret 'secret'.",
                    },
                )

        return False, "anonymous", {"error": "Signature mismatch or unhandled algorithm"}


class HardenedVerifier:
    """Zero-Trust, cryptographically hardened JWT verification engine."""

    def __init__(
        self,
        allowed_algorithms: list[str],
        hmac_secret: str | None = None,
        rsa_public_key_pem: str | bytes | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        leeway_seconds: int = 60,
    ) -> None:
        self.allowed_algorithms = [a.upper() for a in allowed_algorithms]
        self.hmac_secret = hmac_secret
        self.rsa_public_key_pem = rsa_public_key_pem
        self.issuer = issuer
        self.audience = audience
        self.leeway_seconds = leeway_seconds
        self.parser = JWTParser()

    def verify(self, token: str) -> tuple[bool, str, dict[str, Any]]:
        """Verify token under strict cryptographic zero-trust validation rules.

        Returns:
            Tuple of (is_authenticated, subject_identity, diagnostic_metadata).
        """
        decoded = self.parser.parse(token)
        if not decoded.is_valid_format:
            return False, "anonymous", {"error": "Malformed token structure"}

        alg = decoded.algorithm.upper()

        # DEFENSE 1: Strict algorithm whitelisting and unconditional rejection of 'none'
        if alg not in self.allowed_algorithms or alg == "NONE":
            return (
                False,
                "anonymous",
                {
                    "mode": "hardened",
                    "error": f"Algorithm '{decoded.algorithm}' is not permitted by server policy.",
                },
            )

        # DEFENSE 2: Rejection of stripped signatures
        if not decoded.signature:
            return (
                False,
                "anonymous",
                {"mode": "hardened", "error": "Token lacks required cryptographic signature."},
            )

        # DEFENSE 3: Strict claim validation (exp, iat, nbf)
        payload = decoded.payload
        now = time.time()

        if "exp" not in payload:
            return (
                False,
                "anonymous",
                {"mode": "hardened", "error": "Token missing mandatory 'exp' expiration claim."},
            )

        exp_val = payload.get("exp")
        if not isinstance(exp_val, (int, float)) or now > (exp_val + self.leeway_seconds):
            return (
                False,
                "anonymous",
                {"mode": "hardened", "error": f"Token has expired at timestamp {exp_val}."},
            )

        nbf_val = payload.get("nbf")
        if isinstance(nbf_val, (int, float)) and now < (nbf_val - self.leeway_seconds):
            return (
                False,
                "anonymous",
                {"mode": "hardened", "error": f"Token not yet valid (nbf: {nbf_val})."},
            )

        # DEFENSE 4: Cryptographic verification isolating algorithm families
        if alg in ("HS256", "HS384", "HS512"):
            if not self.hmac_secret:
                return (
                    False,
                    "anonymous",
                    {"mode": "hardened", "error": "Server not configured for HMAC verification."},
                )
            try:
                verified_payload = jwt.decode(
                    token,
                    self.hmac_secret,
                    algorithms=[alg],
                    leeway=self.leeway_seconds,
                    options={"verify_signature": True, "verify_exp": True},
                )
                sub = str(verified_payload.get("sub", "authenticated_user"))
                return True, sub, {"mode": "hardened", "status": "verified", "alg": alg}
            except Exception as exc:
                return (
                    False,
                    "anonymous",
                    {"mode": "hardened", "error": f"Cryptographic verification failed: {exc}"},
                )

        if alg in ("RS256", "RS384", "RS512"):
            if not self.rsa_public_key_pem:
                return (
                    False,
                    "anonymous",
                    {"mode": "hardened", "error": "Server not configured for RSA verification."},
                )
            try:
                verified_payload = jwt.decode(
                    token,
                    self.rsa_public_key_pem,
                    algorithms=[alg],
                    leeway=self.leeway_seconds,
                    options={"verify_signature": True, "verify_exp": True},
                )
                sub = str(verified_payload.get("sub", "authenticated_user"))
                return True, sub, {"mode": "hardened", "status": "verified", "alg": alg}
            except Exception as exc:
                return (
                    False,
                    "anonymous",
                    {"mode": "hardened", "error": f"Cryptographic verification failed: {exc}"},
                )

        return (
            False,
            "anonymous",
            {"mode": "hardened", "error": f"Unsupported algorithm '{alg}'."},
        )
