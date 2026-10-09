"""Scanner evaluating Asymmetric-to-Symmetric Key Confusion (CVE-2016-5431)."""

import hashlib
import hmac
from typing import ClassVar

from jwtsec.models.token import DecodedJWT
from jwtsec.models.vulnerability import (
    ConfidenceLevel,
    DetectionFinding,
    JWTVulnerabilityType,
    SeverityLevel,
)


class KeyConfusionScanner:
    """Detects susceptibility to RS256/HS256 public key confusion attacks."""

    ASYMMETRIC_ALGS: ClassVar[set[str]] = {
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
    }
    HMAC_ALGS: ClassVar[set[str]] = {"HS256", "HS384", "HS512"}

    @classmethod
    def scan(
        cls,
        decoded: DecodedJWT,
        public_key_pem: str | bytes | None = None,
    ) -> list[DetectionFinding]:
        """Inspect token for key confusion vulnerabilities."""
        findings: list[DetectionFinding] = []
        declared_alg = str(decoded.header.get("alg", "")).upper()

        # Check for mixed indicators: HMAC algorithm with asymmetric headers (x5c, x5u, jwk)
        has_asymmetric_headers = any(h in decoded.header for h in ("x5c", "x5u", "jwk"))
        if declared_alg in cls.HMAC_ALGS and has_asymmetric_headers:
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-KEY-CONFUSION-01",
                    vulnerability_type=JWTVulnerabilityType.KEY_CONFUSION,
                    title="Key Confusion Anomaly: HMAC Declared with Asymmetric Header",
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    cwe_id="CWE-347",
                    description=(
                        f"The token declared symmetric algorithm '{declared_alg}' but contains "
                        "asymmetric certificate or key headers (x5c/x5u/jwk). This pattern is "
                        "frequently associated with public key confusion attacks."
                    ),
                    remediation=(
                        "Ensure the server strictly separates symmetric secret verifiers from "
                        "asymmetric public key verifiers based on pre-configured server policy."
                    ),
                    details={"alg": declared_alg},
                )
            )

        # Check if public key is provided and verifies the HMAC signature
        if (
            public_key_pem
            and declared_alg in cls.HMAC_ALGS
            and decoded.signature
            and cls._verify_hmac_with_public_key(decoded, public_key_pem, declared_alg)
        ):
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-KEY-CONFUSION-VERIFIED-02",
                    vulnerability_type=JWTVulnerabilityType.KEY_CONFUSION,
                    title="Critical Key Confusion Confirmed (CVE-2016-5431)",
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.CERTAIN,
                    cwe_id="CWE-347",
                    description=(
                        "The token was successfully verified using HMAC with the RSA/EC "
                        "public key as the HMAC secret. This proves the token was forged "
                        "using an asymmetric-to-symmetric key confusion attack."
                    ),
                    remediation=(
                        "Do not permit client-specified 'alg' headers to determine whether an "
                        "asymmetric or symmetric verification function is called."
                    ),
                    details={"alg": declared_alg},
                )
            )

        return findings

    @classmethod
    def _verify_hmac_with_public_key(
        cls,
        decoded: DecodedJWT,
        public_key: str | bytes,
        alg: str,
    ) -> bool:
        """Test if HMAC signature matches when computed over public key bytes."""
        key_bytes = public_key.encode("utf-8") if isinstance(public_key, str) else public_key
        parts = decoded.raw_token.split(".")
        if len(parts) != 3:
            return False

        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

        hash_func = hashlib.sha256
        if alg == "HS384":
            hash_func = hashlib.sha384
        elif alg == "HS512":
            hash_func = hashlib.sha512

        computed_sig = hmac.new(key_bytes, signing_input, hash_func).digest()

        # Base64url encode without padding
        import base64

        computed_b64 = base64.urlsafe_b64encode(computed_sig).decode("ascii").rstrip("=")
        return hmac.compare_digest(computed_b64, decoded.signature)
