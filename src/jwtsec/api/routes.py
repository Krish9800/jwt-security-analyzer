"""API route handlers for jwtsec token auditing, cracking, and verification."""

from fastapi import APIRouter, HTTPException, status

from jwtsec.api.schemas import (
    AuditRequest,
    CrackAPIRequest,
    CraftAPIRequest,
    HealthResponse,
    RuleDetail,
    RulesListResponse,
    VerifyRequest,
    VerifyResponse,
)
from jwtsec.config.settings import get_settings
from jwtsec.core.cracker import HMACSecretCracker
from jwtsec.core.crafter import JWTCrafter
from jwtsec.core.engine import JWTAuditEngine
from jwtsec.lab.verifier import HardenedVerifier, InsecureVerifier
from jwtsec.models.token import CrackResult, CraftResult, JWTAuditResult
from jwtsec.models.vulnerability import JWTVulnerabilityType

router = APIRouter()
_engine = JWTAuditEngine()
_cracker = HMACSecretCracker()


@router.get("/health", response_model=HealthResponse, tags=["System"])
def get_health() -> HealthResponse:
    """Return microservice health status and application version."""
    settings = get_settings()
    return HealthResponse(status="healthy", version=settings.version)


@router.post(
    "/api/v1/audit",
    response_model=JWTAuditResult,
    status_code=status.HTTP_200_OK,
    tags=["Assessment"],
)
def audit_token(payload: AuditRequest) -> JWTAuditResult:
    """Perform comprehensive security assessment on target token."""
    return _engine.audit(
        token=payload.token,
        public_key_pem=payload.public_key_pem,
        check_weak_secrets=payload.check_weak_secrets,
    )


@router.post(
    "/api/v1/crack",
    response_model=CrackResult,
    status_code=status.HTTP_200_OK,
    tags=["Cracking"],
)
def crack_token(payload: CrackAPIRequest) -> CrackResult:
    """Execute dictionary attack to recover HMAC signing secrets."""
    return _cracker.crack(
        token=payload.token,
        wordlist=payload.custom_wordlist,
        max_words=payload.max_words,
    )


@router.post(
    "/api/v1/craft",
    response_model=CraftResult,
    status_code=status.HTTP_200_OK,
    tags=["Crafting"],
)
def craft_token(payload: CraftAPIRequest) -> CraftResult:
    """Craft a specialized JWT for vulnerability reproduction or testing."""
    alg_lower = payload.algorithm.lower().strip()
    if alg_lower == "none":
        return JWTCrafter.craft_none(claims=payload.claims, case_variant=payload.algorithm)
    if alg_lower in ("hs256", "hs384", "hs512"):
        if not payload.secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signing secret is required for HMAC algorithms.",
            )
        return JWTCrafter.craft_hmac(
            claims=payload.claims, secret=payload.secret, alg=payload.algorithm.upper()
        )
    if alg_lower in ("rs256", "rs384", "rs512"):
        if not payload.private_key_pem:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="RSA private_key_pem is required for RSA algorithms.",
            )
        try:
            return JWTCrafter.craft_rsa(
                claims=payload.claims,
                private_key_pem=payload.private_key_pem,
                alg=payload.algorithm.upper(),
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid RSA private key: {exc}",
            ) from exc

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unsupported algorithm '{payload.algorithm}'. Supported: none, HS256, HS384, HS512, RS256.",
    )


@router.post(
    "/api/v1/verify",
    response_model=VerifyResponse,
    status_code=status.HTTP_200_OK,
    tags=["Verification Lab"],
)
def verify_token(payload: VerifyRequest) -> VerifyResponse:
    """Simulate token verification in vulnerable or zero-trust hardened mode."""
    is_hardened = payload.mode.lower() == "hardened"

    if is_hardened:
        allowed = ["RS256"] if payload.public_key_pem else ["HS256"]
        verifier = HardenedVerifier(
            allowed_algorithms=allowed,
            hmac_secret=payload.hmac_secret,
            rsa_public_key_pem=payload.public_key_pem,
        )
        is_auth, sub, details = verifier.verify(payload.token)
    else:
        insecure = InsecureVerifier(expected_rsa_public_key=payload.public_key_pem)
        is_auth, sub, details = insecure.verify(payload.token)

    return VerifyResponse(authenticated=is_auth, identity=sub, details=details)


@router.get(
    "/api/v1/rules",
    response_model=RulesListResponse,
    tags=["Taxonomy"],
)
def list_rules() -> RulesListResponse:
    """List all registered vulnerability detection categories and CWE mapping."""
    rules = [
        RuleDetail(
            rule_id="RULE-JWT-ALG-NONE",
            vulnerability_type=JWTVulnerabilityType.ALG_NONE.value,
            title="Algorithm Confusion (none / unsigned bypass)",
            severity="CRITICAL",
            cwe_id="CWE-327",
            description="Detects tokens explicitly declaring 'none' or stripping signatures.",
            remediation="Strictly whitelist allowed algorithms and reject 'none'.",
        ),
        RuleDetail(
            rule_id="RULE-JWT-KEY-CONFUSION",
            vulnerability_type=JWTVulnerabilityType.KEY_CONFUSION.value,
            title="Asymmetric-to-Symmetric Key Confusion",
            severity="CRITICAL",
            cwe_id="CWE-347",
            description="Detects HMAC tokens using RSA/EC public key bytes as HMAC secrets.",
            remediation="Never allow token headers to select between asymmetric and symmetric verification.",
        ),
        RuleDetail(
            rule_id="RULE-JWT-WEAK-SECRET",
            vulnerability_type=JWTVulnerabilityType.WEAK_HMAC_SECRET.value,
            title="Weak / Dictionary HMAC Secret",
            severity="CRITICAL",
            cwe_id="CWE-522",
            description="Recovers trivial or dictionary-based HMAC signing secrets.",
            remediation="Use high-entropy keys with at least 256 bits of cryptographically random entropy.",
        ),
        RuleDetail(
            rule_id="RULE-JWT-KID-INJECTION",
            vulnerability_type=JWTVulnerabilityType.KID_INJECTION.value,
            title="Header Parameter Injection (kid)",
            severity="HIGH",
            cwe_id="CWE-22",
            description="Detects path traversal, SQLi, or command injection sequences in 'kid'.",
            remediation="Sanitize 'kid' lookups against an immutable whitelist.",
        ),
        RuleDetail(
            rule_id="RULE-JWT-ROGUE-JWK",
            vulnerability_type=JWTVulnerabilityType.ROGUE_JWK.value,
            title="Embedded Self-Signed Key (jwk)",
            severity="HIGH",
            cwe_id="CWE-347",
            description="Detects client-supplied public keys embedded in token headers.",
            remediation="Validate signatures strictly against server-managed keystores.",
        ),
        RuleDetail(
            rule_id="RULE-JWT-EXPIRED",
            vulnerability_type=JWTVulnerabilityType.EXPIRED_TOKEN.value,
            title="Expired Token Evaluation",
            severity="HIGH",
            cwe_id="CWE-613",
            description="Detects expired or stale tokens.",
            remediation="Strictly enforce 'exp' expiration timestamps with minimal clock skew.",
        ),
        RuleDetail(
            rule_id="RULE-JWT-SENSITIVE-DATA",
            vulnerability_type=JWTVulnerabilityType.SENSITIVE_DATA_EXPOSURE.value,
            title="Sensitive Data Exposure in Claims",
            severity="HIGH",
            cwe_id="CWE-312",
            description="Detects credentials, API keys, passwords, and PII in unencrypted claims.",
            remediation="Never store confidential secrets in standard unencrypted JWT payloads.",
        ),
    ]
    return RulesListResponse(total_rules=len(rules), rules=rules)
