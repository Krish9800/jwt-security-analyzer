"""Scanner detecting sensitive data exposure in JWT payload claims."""

import re
from typing import Any, ClassVar

from jwtsec.models.token import DecodedJWT
from jwtsec.models.vulnerability import (
    ConfidenceLevel,
    DetectionFinding,
    JWTVulnerabilityType,
    SeverityLevel,
)


class SensitiveDataScanner:
    """Detects credentials, private keys, API secrets, and PII in unencrypted JWT claims."""

    DANGEROUS_KEYS: ClassVar[set[str]] = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "secret_key",
        "api_key",
        "apikey",
        "access_token",
        "private_key",
        "privkey",
        "ssn",
        "social_security",
        "credit_card",
    }

    PATTERNS: ClassVar[list[tuple[str, re.Pattern[str]]]] = [
        ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        (
            "Private Key",
            re.compile(
                r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED)? ?PRIVATE KEY",
                re.IGNORECASE,
            ),
        ),
        ("Social Security Number", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        (
            "Bcrypt Password Hash",
            re.compile(r"^\$2[aby]?\$\d{1,2}\$[./0-9A-Za-z]{53}$"),
        ),
    ]

    @classmethod
    def scan(cls, decoded: DecodedJWT) -> list[DetectionFinding]:
        """Traverse payload claims identifying sensitive credentials or exposed data."""
        findings: list[DetectionFinding] = []
        cls._traverse_payload(decoded.payload, findings)
        return findings

    @classmethod
    def _traverse_payload(
        cls,
        obj: Any,
        findings: list[DetectionFinding],
        path: str = "",
    ) -> None:
        """Recursively scan dict or list structures for sensitive keys and values."""
        if isinstance(obj, dict):
            for key, val in obj.items():
                current_path = f"{path}.{key}" if path else key
                # Check dangerous key name
                if key.lower().strip() in cls.DANGEROUS_KEYS:
                    findings.append(
                        DetectionFinding(
                            finding_id=f"JWT-VULN-SENSITIVE-KEY-{key.upper()}",
                            vulnerability_type=JWTVulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                            title=f"Sensitive Data Exposure: '{key}' Field in Claims",
                            severity=SeverityLevel.HIGH,
                            confidence=ConfidenceLevel.HIGH,
                            cwe_id="CWE-312",
                            description=(
                                f"Payload claim '{current_path}' appears to store credentials "
                                "or secret material. JWT payloads are merely base64url encoded "
                                "and readable by any client, intermediary, or log observer."
                            ),
                            remediation=(
                                "Never store passwords, private keys, or high-privilege API secrets "
                                "in standard JWTs. Use JSON Web Encryption (JWE) if confidentiality is required."
                            ),
                            details={"claim_path": current_path},
                        )
                    )
                cls._traverse_payload(val, findings, current_path)

        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                cls._traverse_payload(item, findings, f"{path}[{idx}]")

        elif isinstance(obj, str):
            for label, pattern in cls.PATTERNS:
                if pattern.search(obj):
                    findings.append(
                        DetectionFinding(
                            finding_id=f"JWT-VULN-SENSITIVE-VAL-{label.upper().replace(' ', '-')}",
                            vulnerability_type=JWTVulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                            title=f"Sensitive Secret Pattern Detected: {label}",
                            severity=SeverityLevel.HIGH,
                            confidence=ConfidenceLevel.HIGH,
                            cwe_id="CWE-312",
                            description=(
                                f"Claim '{path}' contains a value matching a {label} pattern. "
                                "Transmitting unencrypted secrets inside JWT claims exposes them "
                                "to unauthorized disclosure."
                            ),
                            remediation=(
                                "Remove sensitive patterns from token claims and encrypt tokens "
                                "using JWE when transporting confidential data."
                            ),
                            details={"claim_path": path, "pattern_label": label},
                        )
                    )
