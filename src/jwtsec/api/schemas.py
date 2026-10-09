"""Pydantic schemas for the jwtsec REST API microservice."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from jwtsec.models.token import CraftResult, JWTAuditResult


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="healthy", description="Service operational status")
    version: str = Field(..., description="Application version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Current server UTC timestamp",
    )


class AuditRequest(BaseModel):
    """Request payload to audit a JWT token."""

    token: str = Field(..., min_length=5, description="Raw JWT string or Bearer token to audit")
    public_key_pem: str | None = Field(
        default=None, description="Optional RSA public key PEM for key confusion analysis"
    )
    check_weak_secrets: bool = Field(
        default=True, description="Whether to execute dictionary secret cracking on HMAC tokens"
    )


class CrackAPIRequest(BaseModel):
    """Request payload to crack HMAC signed token."""

    token: str = Field(..., min_length=5, description="Target HMAC JWT token to crack")
    custom_wordlist: list[str] | None = Field(
        default=None, description="Optional custom password candidates"
    )
    max_words: int = Field(default=10000, description="Maximum candidate words to evaluate")


class CraftAPIRequest(BaseModel):
    """Request payload to generate a specialized testing JWT."""

    claims: dict[str, Any] = Field(default_factory=dict, description="Payload claims dictionary")
    algorithm: str = Field(
        default="none", description="Algorithm to set in header (none, HS256, RS256)"
    )
    secret: str | None = Field(default=None, description="HMAC signing secret (for HS256)")
    private_key_pem: str | None = Field(default=None, description="RSA private key PEM (for RS256)")


class VerifyRequest(BaseModel):
    """Request payload to simulate token verification."""

    token: str = Field(..., min_length=5, description="Token to verify")
    mode: str = Field(default="insecure", description="Verification mode: 'insecure' or 'hardened'")
    hmac_secret: str | None = Field(default=None, description="Secret for hardened HMAC check")
    public_key_pem: str | None = Field(default=None, description="Public key PEM for RSA check")


class VerifyResponse(BaseModel):
    """Result of token verification simulation."""

    authenticated: bool = Field(..., description="True if token was accepted")
    identity: str = Field(..., description="Subject identity extracted from token")
    details: dict[str, Any] = Field(default_factory=dict, description="Diagnostic audit details")


class RuleDetail(BaseModel):
    """Metadata describing a vulnerability check rule."""

    rule_id: str
    vulnerability_type: str
    title: str
    severity: str
    cwe_id: str
    description: str
    remediation: str


class RulesListResponse(BaseModel):
    """Response containing all registered vulnerability checks."""

    total_rules: int
    rules: list[RuleDetail]


__all__ = [
    "AuditRequest",
    "CrackAPIRequest",
    "CraftAPIRequest",
    "CraftResult",
    "HealthResponse",
    "JWTAuditResult",
    "RuleDetail",
    "RulesListResponse",
    "VerifyRequest",
    "VerifyResponse",
]
