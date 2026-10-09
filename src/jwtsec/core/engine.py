"""Consolidated JWT audit engine orchestrating all vulnerability scanners and cracker."""

from collections.abc import Sequence

from jwtsec.config.settings import Settings, get_settings
from jwtsec.core.cracker import HMACSecretCracker
from jwtsec.core.parser import JWTParser
from jwtsec.models.token import JWTAuditResult
from jwtsec.models.vulnerability import (
    ConfidenceLevel,
    DetectionFinding,
    JWTVulnerabilityType,
    SeverityLevel,
)
from jwtsec.scanners.alg_none import AlgNoneScanner
from jwtsec.scanners.claims import ClaimsAuditor
from jwtsec.scanners.data_leak import SensitiveDataScanner
from jwtsec.scanners.headers import HeaderInjectionScanner
from jwtsec.scanners.key_confusion import KeyConfusionScanner


class JWTAuditEngine:
    """Core security evaluation engine coordinating all vulnerability detection scanners."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.parser = JWTParser(max_token_length=self.settings.max_token_length)
        self.cracker = HMACSecretCracker(parser=self.parser)

    def audit(
        self,
        token: str,
        public_key_pem: str | bytes | None = None,
        check_weak_secrets: bool = True,
    ) -> JWTAuditResult:
        """Perform comprehensive security assessment on target token.

        Args:
            token: Raw JWT or Bearer string to evaluate.
            public_key_pem: Optional RSA/EC public key to verify against key confusion.
            check_weak_secrets: Whether to run dictionary cracking on HMAC tokens.

        Returns:
            JWTAuditResult containing risk score, qualitative verdict, and findings.
        """
        decoded = self.parser.parse(token)
        snippet = self._make_snippet(decoded.raw_token)

        # 1. Structural Check
        if not decoded.is_valid_format:
            findings = [
                DetectionFinding(
                    finding_id="JWT-VULN-STRUCTURE-01",
                    vulnerability_type=JWTVulnerabilityType.MALFORMED_STRUCTURE,
                    title="Malformed Token Structure",
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.CERTAIN,
                    cwe_id="CWE-20",
                    description=(
                        "The token fails RFC 7519 formatting requirements. Header or payload "
                        "segments contain invalid base64url characters or invalid JSON."
                    ),
                    remediation="Ensure tokens follow strict header.payload.signature format.",
                    details=decoded.header,
                )
            ]
            return JWTAuditResult(
                token_snippet=snippet,
                is_vulnerable=True,
                risk_score=75.0,
                risk_level="VULNERABLE",
                findings=findings,
                header=decoded.header,
                payload=decoded.payload,
            )

        all_findings: list[DetectionFinding] = []

        # 2. Algorithm Scanners
        all_findings.extend(AlgNoneScanner.scan(decoded))

        # 3. Key Confusion Scanner
        all_findings.extend(KeyConfusionScanner.scan(decoded, public_key_pem=public_key_pem))

        # 4. Header Injection Scanner
        all_findings.extend(HeaderInjectionScanner.scan(decoded))

        # 5. Claims & Freshness Auditor
        all_findings.extend(ClaimsAuditor.scan(decoded))

        # 6. Sensitive Data Scanner
        all_findings.extend(SensitiveDataScanner.scan(decoded))

        # 7. Weak HMAC Secret Cracker
        cracked_secret: str | None = None
        if check_weak_secrets and self.settings.enable_bruteforce:
            alg_upper = decoded.algorithm.upper()
            if alg_upper in ("HS256", "HS384", "HS512") and decoded.signature:
                crack_res = self.cracker.crack(decoded.raw_token)
                if crack_res.cracked and crack_res.secret:
                    cracked_secret = crack_res.secret
                    all_findings.append(
                        DetectionFinding(
                            finding_id="JWT-VULN-WEAK-SECRET-01",
                            vulnerability_type=JWTVulnerabilityType.WEAK_HMAC_SECRET,
                            title="Trivial / Dictionary HMAC Secret Recovered",
                            severity=SeverityLevel.CRITICAL,
                            confidence=ConfidenceLevel.CERTAIN,
                            cwe_id="CWE-522",
                            description=(
                                f"The token was successfully cracked with dictionary secret: "
                                f"'{crack_res.secret}'. Trivial secrets allow attackers to forge "
                                "tokens for any identity or privilege level."
                            ),
                            remediation=(
                                "Generate cryptographically secure secrets with at least 256 bits "
                                "of high entropy (e.g. `openssl rand -base64 32`)."
                            ),
                            details={
                                "recovered_secret": crack_res.secret,
                                "attempts": crack_res.attempts,
                            },
                        )
                    )

        unique_findings = self._deduplicate_findings(all_findings)
        risk_score = self._compute_risk_score(unique_findings)
        risk_level = self._categorize_risk_level(risk_score)
        is_vulnerable = risk_score >= 50.0

        return JWTAuditResult(
            token_snippet=snippet,
            is_vulnerable=is_vulnerable,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=unique_findings,
            header=decoded.header,
            payload=decoded.payload,
            cracked_secret=cracked_secret,
        )

    def _compute_risk_score(self, findings: Sequence[DetectionFinding]) -> float:
        """Compute composite risk score 0.0 to 100.0 from detected vulnerabilities."""
        if not findings:
            return 0.0

        severity_weights = {
            SeverityLevel.CRITICAL: 40.0,
            SeverityLevel.HIGH: 25.0,
            SeverityLevel.MEDIUM: 15.0,
            SeverityLevel.LOW: 8.0,
            SeverityLevel.INFORMATIONAL: 2.0,
        }

        score = 0.0
        has_critical = False
        has_high = False

        for f in findings:
            score += severity_weights.get(f.severity, 10.0)
            if f.severity == SeverityLevel.CRITICAL:
                has_critical = True
            elif f.severity == SeverityLevel.HIGH:
                has_high = True

        if has_critical:
            score = max(score, 80.0)
        elif has_high:
            score = max(score, 60.0)

        return round(min(100.0, max(0.0, score)), 1)

    def _categorize_risk_level(self, score: float) -> str:
        """Classify numeric risk score into standard risk tier."""
        if score >= 80.0:
            return "CRITICAL"
        if score >= 50.0:
            return "VULNERABLE"
        if score >= 20.0:
            return "SUSPICIOUS"
        return "SAFE"

    @staticmethod
    def _make_snippet(token: str) -> str:
        """Create a safe truncated snippet of the token for logging."""
        if not token:
            return "<empty>"
        if len(token) <= 24:
            return token
        return f"{token[:12]}...{token[-8:]}"

    @staticmethod
    def _deduplicate_findings(findings: Sequence[DetectionFinding]) -> list[DetectionFinding]:
        """Eliminate duplicate findings with identical finding_id preserving order."""
        seen: set[str] = set()
        deduped: list[DetectionFinding] = []
        for f in findings:
            if f.finding_id not in seen:
                seen.add(f.finding_id)
                deduped.append(f)
        return deduped
