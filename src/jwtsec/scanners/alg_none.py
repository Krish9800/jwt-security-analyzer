"""Scanner identifying 'none' algorithm bypasses and signature stripping attacks."""

from jwtsec.models.token import DecodedJWT
from jwtsec.models.vulnerability import (
    ConfidenceLevel,
    DetectionFinding,
    JWTVulnerabilityType,
    SeverityLevel,
)


class AlgNoneScanner:
    """Detects algorithm confusion resulting from unverified 'none' or stripped signatures."""

    @classmethod
    def scan(cls, decoded: DecodedJWT) -> list[DetectionFinding]:
        """Inspect token header and signature for 'none' algorithm vulnerabilities."""
        findings: list[DetectionFinding] = []
        raw_alg = str(decoded.header.get("alg", "")).strip()

        # Check for case variants of 'none'
        if raw_alg.lower() == "none":
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-ALG-NONE-01",
                    vulnerability_type=JWTVulnerabilityType.ALG_NONE,
                    title="Insecure 'none' Algorithm Declared (CVE-2015-9235)",
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.CERTAIN,
                    cwe_id="CWE-327",
                    description=(
                        f"The token explicitly declares algorithm '{raw_alg}'. "
                        "Many vulnerable verifiers accept 'none' tokens without checking "
                        "signatures, allowing attackers to forge arbitrary administrative claims."
                    ),
                    remediation=(
                        "Configure the JWT verifier with an explicit whitelist of allowed "
                        "algorithms (e.g. ['RS256'] or ['HS256']) and explicitly reject 'none'."
                    ),
                    details={"declared_alg": raw_alg, "has_signature": bool(decoded.signature)},
                )
            )

        # Check for stripped signature when an algorithm is declared
        if raw_alg and raw_alg.lower() != "none" and not decoded.signature:
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-STRIPPED-SIG-02",
                    vulnerability_type=JWTVulnerabilityType.UNVERIFIED_SIGNATURE,
                    title="Stripped Token Signature",
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.CERTAIN,
                    cwe_id="CWE-347",
                    description=(
                        f"The token declares signed algorithm '{raw_alg}' but possesses an empty "
                        "or stripped signature component."
                    ),
                    remediation="Reject any token lacking a non-empty cryptographic signature.",
                    details={"declared_alg": raw_alg},
                )
            )

        return findings
