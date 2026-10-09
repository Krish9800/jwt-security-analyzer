"""Domain models representing decoded tokens, audit results, and lab requests."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from jwtsec.models.vulnerability import DetectionFinding


class DecodedJWT(BaseModel):
    """Normalized components of a decoded JSON Web Token."""

    raw_token: str = Field(..., description="Original raw token string")
    header: dict[str, Any] = Field(default_factory=dict, description="Parsed header JSON")
    payload: dict[str, Any] = Field(default_factory=dict, description="Parsed payload claims JSON")
    signature: str = Field(default="", description="Base64URL encoded signature segment")
    algorithm: str = Field(default="none", description="Declared algorithm from header")
    is_valid_format: bool = Field(
        default=True, description="True if token conforms to 3 segment structure"
    )


class JWTAuditResult(BaseModel):
    """Comprehensive security evaluation verdict for a target JWT."""

    token_snippet: str = Field(..., description="Truncated token string for safe logging")
    is_vulnerable: bool = Field(..., description="True if token exhibits security defects")
    risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Calculated risk score from 0.0 to 100.0"
    )
    risk_level: str = Field(
        default="SAFE", description="Classification: SAFE, SUSPICIOUS, VULNERABLE, CRITICAL"
    )
    findings: list[DetectionFinding] = Field(
        default_factory=list, description="List of detected vulnerability findings"
    )
    header: dict[str, Any] = Field(default_factory=dict, description="Inspected header claims")
    payload: dict[str, Any] = Field(default_factory=dict, description="Inspected payload claims")
    cracked_secret: str | None = Field(
        default=None, description="Recovered HMAC signing secret if cracked"
    )
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when audit was performed",
    )


class CrackRequest(BaseModel):
    """Request payload to brute-force recover HMAC signing secrets."""

    token: str = Field(..., min_length=10, description="Target JWT token")
    wordlist: list[str] | None = Field(
        default=None, description="Optional custom candidate password list"
    )
    max_words: int = Field(default=10000, description="Maximum word candidates to test")


class CrackResult(BaseModel):
    """Result of an HMAC secret cracking attempt."""

    cracked: bool = Field(..., description="True if matching secret was found")
    secret: str | None = Field(default=None, description="Recovered signing secret")
    attempts: int = Field(default=0, description="Total candidates evaluated")
    duration_ms: float = Field(default=0.0, description="Execution time in milliseconds")


class CraftRequest(BaseModel):
    """Request to generate specialized JWT payloads for security testing."""

    claims: dict[str, Any] = Field(default_factory=dict, description="Payload claims to include")
    algorithm: str = Field(default="none", description="Algorithm to set in header")
    secret_or_key: str | None = Field(
        default=None, description="Secret or private key for signature calculation"
    )
    header_overrides: dict[str, Any] | None = Field(
        default=None, description="Custom header fields (e.g. kid, jku, jwk)"
    )


class CraftResult(BaseModel):
    """Result of JWT crafting operation."""

    token: str = Field(..., description="Generated JWT string")
    algorithm: str = Field(..., description="Active signing algorithm")
    header: dict[str, Any] = Field(..., description="Generated header structure")
    payload: dict[str, Any] = Field(..., description="Generated payload structure")
