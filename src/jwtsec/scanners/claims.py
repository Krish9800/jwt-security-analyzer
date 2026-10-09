"""Scanner auditing standard RFC 7519 claims (exp, nbf, iat, iss, aud)."""

import time

from jwtsec.config.settings import get_settings
from jwtsec.models.token import DecodedJWT
from jwtsec.models.vulnerability import (
    ConfidenceLevel,
    DetectionFinding,
    JWTVulnerabilityType,
    SeverityLevel,
)


class ClaimsAuditor:
    """Audits RFC 7519 registered claims for timestamp anomalies and missing expiration."""

    MAX_REASONABLE_LIFETIME_SECONDS = 30 * 86400  # 30 days

    @classmethod
    def scan(
        cls,
        decoded: DecodedJWT,
        current_time: float | None = None,
        leeway_seconds: int | None = None,
    ) -> list[DetectionFinding]:
        """Audit payload claims against standard timestamp constraints and freshness rules."""
        findings: list[DetectionFinding] = []
        payload = decoded.payload
        settings = get_settings()

        now = current_time if current_time is not None else time.time()
        leeway = (
            leeway_seconds if leeway_seconds is not None else settings.clock_skew_leeway_seconds
        )

        exp = payload.get("exp")
        nbf = payload.get("nbf")
        iat = payload.get("iat")

        # 1. Missing Expiration (exp)
        if exp is None:
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-CLAIMS-NO-EXP-01",
                    vulnerability_type=JWTVulnerabilityType.MISSING_EXPIRATION,
                    title="Missing Expiration (exp) Claim",
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.CERTAIN,
                    cwe_id="CWE-613",
                    description=(
                        "The token lacks an 'exp' (Expiration Time) claim. Without an expiration, "
                        "the token is perpetual and remains valid indefinitely if intercepted."
                    ),
                    remediation="Always include an 'exp' claim with an appropriate short TTL.",
                    details={"exp_present": False},
                )
            )
        elif isinstance(exp, (int, float)):
            # Expired token
            if now > (exp + leeway):
                findings.append(
                    DetectionFinding(
                        finding_id="JWT-VULN-CLAIMS-EXPIRED-02",
                        vulnerability_type=JWTVulnerabilityType.EXPIRED_TOKEN,
                        title="Expired Token (exp in Past)",
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.CERTAIN,
                        cwe_id="CWE-613",
                        description=(
                            f"The token expired at timestamp {exp} (current time: {int(now)}). "
                            "Accepting expired tokens permits replay and stale credential attacks."
                        ),
                        remediation="Reject any token whose 'exp' timestamp has elapsed.",
                        details={"exp": exp, "current_time": int(now)},
                    )
                )

            # Excessive TTL
            if isinstance(iat, (int, float)) and (exp - iat) > cls.MAX_REASONABLE_LIFETIME_SECONDS:
                findings.append(
                    DetectionFinding(
                        finding_id="JWT-VULN-CLAIMS-LONG-TTL-03",
                        vulnerability_type=JWTVulnerabilityType.MISSING_EXPIRATION,
                        title="Excessive Token Lifetime (TTL > 30 Days)",
                        severity=SeverityLevel.LOW,
                        confidence=ConfidenceLevel.HIGH,
                        cwe_id="CWE-613",
                        description=(
                            f"The token lifetime ({int(exp - iat)} seconds) exceeds 30 days. "
                            "Long-lived access tokens increase the attack window if leaked."
                        ),
                        remediation="Issue short-lived access tokens (e.g. 15-60 min) with refresh tokens.",
                        details={"ttl_seconds": int(exp - iat)},
                    )
                )

        # 2. Premature Not-Before (nbf)
        if isinstance(nbf, (int, float)) and now < (nbf - leeway):
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-CLAIMS-PREMATURE-NBF-04",
                    vulnerability_type=JWTVulnerabilityType.PREMATURE_NBF,
                    title="Token Not Yet Valid (nbf in Future)",
                    severity=SeverityLevel.LOW,
                    confidence=ConfidenceLevel.CERTAIN,
                    cwe_id="CWE-613",
                    description=(
                        f"The token 'nbf' timestamp {nbf} is in the future (current: {int(now)})."
                    ),
                    remediation="Reject tokens evaluated before their specified 'nbf' activation.",
                    details={"nbf": nbf, "current_time": int(now)},
                )
            )

        # 3. Future Issued-At (iat)
        if isinstance(iat, (int, float)) and iat > (now + leeway):
            findings.append(
                DetectionFinding(
                    finding_id="JWT-VULN-CLAIMS-FUTURE-IAT-05",
                    vulnerability_type=JWTVulnerabilityType.FUTURE_IAT,
                    title="Token Issued in Future (iat > now + leeway)",
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    cwe_id="CWE-613",
                    description=(
                        f"The token 'iat' timestamp {iat} is ahead of current time {int(now)} "
                        "beyond clock skew leeway. This may indicate clock desynchronization or forgery."
                    ),
                    remediation="Ensure client and server systems synchronize clocks via NTP.",
                    details={"iat": iat, "current_time": int(now)},
                )
            )

        return findings
