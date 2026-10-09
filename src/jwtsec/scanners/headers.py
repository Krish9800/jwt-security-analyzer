"""Scanner detecting header injection vulnerabilities (kid traversal, rogue jwk, untrusted jku)."""

import re

from jwtsec.models.token import DecodedJWT
from jwtsec.models.vulnerability import (
    ConfidenceLevel,
    DetectionFinding,
    JWTVulnerabilityType,
    SeverityLevel,
)


class HeaderInjectionScanner:
    """Audits JWT header parameters for injection payloads and dangerous configurations."""

    _PATH_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|/etc/|/dev/null|C:\\)")
    _SQL_INJECTION = re.compile(r"('|\bOR\b|\bUNION\b|\bSELECT\b|--|#|/\*)", re.IGNORECASE)
    _COMMAND_INJECTION = re.compile(r"(;|\||`|\$\()", re.IGNORECASE)

    @classmethod
    def scan(cls, decoded: DecodedJWT) -> list[DetectionFinding]:
        """Audit token header parameters for dangerous parameters."""
        findings: list[DetectionFinding] = []
        header = decoded.header

        # 1. Audit Key ID (kid) parameter
        kid = header.get("kid")
        if isinstance(kid, str):
            findings.extend(cls._audit_kid(kid))

        # 2. Audit Embedded JSON Web Key (jwk)
        if "jwk" in header:
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-ROGUE-JWK-01",
                    vulnerability_type=JWTVulnerabilityType.ROGUE_JWK,
                    title="Embedded Self-Signed JSON Web Key (jwk) in Header",
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    cwe_id="CWE-347",
                    description=(
                        "The token header contains an embedded 'jwk' object. If the verifying "
                        "application uses the client-supplied public key from the header instead "
                        "of a trusted server key, the attacker can sign arbitrary tokens."
                    ),
                    remediation=(
                        "Never trust keys supplied in the token header. Validate signatures "
                        "exclusively against a trusted, pre-configured server keystore."
                    ),
                    details={"jwk_present": True},
                )
            )

        # 3. Audit Remote JWK Set URL (jku)
        jku = header.get("jku")
        if isinstance(jku, str):
            findings.extend(cls._audit_jku(jku))

        return findings

    @classmethod
    def _audit_kid(cls, kid: str) -> list[DetectionFinding]:
        """Inspect kid value for traversal, SQLi, and command injection patterns."""
        findings: list[DetectionFinding] = []

        if cls._PATH_TRAVERSAL.search(kid):
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-KID-TRAVERSAL-01",
                    vulnerability_type=JWTVulnerabilityType.KID_INJECTION,
                    title="Path Traversal Pattern Detected in 'kid' Header",
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    cwe_id="CWE-22",
                    description=(
                        f"The 'kid' parameter '{kid}' contains directory traversal sequences. "
                        "Attackers exploit this to point the key lookup to known files "
                        "(e.g. /dev/null or static assets) with predictable contents."
                    ),
                    remediation=(
                        "Sanitize 'kid' by resolving against a strict whitelist or database ID "
                        "rather than dynamically constructing file paths."
                    ),
                    details={"kid": kid},
                )
            )

        if cls._SQL_INJECTION.search(kid):
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-KID-SQLI-02",
                    vulnerability_type=JWTVulnerabilityType.KID_INJECTION,
                    title="SQL Injection Syntax in 'kid' Header",
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    cwe_id="CWE-89",
                    description=(
                        f"The 'kid' parameter '{kid}' contains SQL injection metacharacters. "
                        "If the server queries keys from a database using string concatenation, "
                        "an attacker could inject arbitrary SQL to control the returned secret."
                    ),
                    remediation="Use parameterized queries when looking up keys by 'kid'.",
                    details={"kid": kid},
                )
            )

        if cls._COMMAND_INJECTION.search(kid):
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-KID-CMDI-03",
                    vulnerability_type=JWTVulnerabilityType.KID_INJECTION,
                    title="Command Injection Pattern in 'kid' Header",
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.HIGH,
                    cwe_id="CWE-78",
                    description=(
                        f"The 'kid' parameter '{kid}' contains shell metacharacters. If key "
                        "lookup delegates to a system command or shell script, arbitrary OS "
                        "execution may result."
                    ),
                    remediation="Never pass unsanitized 'kid' values to shell execution functions.",
                    details={"kid": kid},
                )
            )

        return findings

    @classmethod
    def _audit_jku(cls, jku: str) -> list[DetectionFinding]:
        """Inspect jku URL for unencrypted protocol or untrusted origins."""
        findings: list[DetectionFinding] = []
        lower_jku = jku.strip().lower()

        if lower_jku.startswith("http://"):
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-JKU-CLEARTEXT-01",
                    vulnerability_type=JWTVulnerabilityType.UNTRUSTED_JKU,
                    title="Cleartext HTTP URL in 'jku' Header",
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.CERTAIN,
                    cwe_id="CWE-319",
                    description=(
                        f"The 'jku' parameter '{jku}' uses unencrypted HTTP. A man-in-the-middle "
                        "adversary could tamper with the returned JWK set to compromise validation."
                    ),
                    remediation="Enforce HTTPS for all 'jku' URLs.",
                    details={"jku": jku},
                )
            )

        findings.append(
            DetectionFinding(
                finding_id="JWT-VULN-JKU-UNTRUSTED-02",
                vulnerability_type=JWTVulnerabilityType.UNTRUSTED_JKU,
                title="Untrusted Remote JWK Set URL (jku) Present",
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.MEDIUM,
                cwe_id="CWE-918",
                description=(
                    f"The token references a remote JWK Set URL '{jku}'. Servers fetching this "
                    "URL are vulnerable to SSRF (Server-Side Request Forgery) and rogue key sets."
                ),
                remediation=(
                    "Strictly validate 'jku' against an explicit whitelist of trusted domains "
                    "or disable dynamic 'jku' key resolution entirely."
                ),
                details={"jku": jku},
            )
        )

        return findings
