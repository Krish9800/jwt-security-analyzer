"""High-speed HMAC dictionary secret cracker for HS256, HS384, and HS512 tokens."""

import base64
import hashlib
import hmac
import time
from typing import Any, ClassVar

from jwtsec.config.settings import get_settings
from jwtsec.core.parser import JWTParser
from jwtsec.models.token import CrackResult


class HMACSecretCracker:
    """Dictionary-based HMAC signing secret recovery engine."""

    DEFAULT_WORDLIST: ClassVar[list[str]] = [
        "secret",
        "password",
        "123456",
        "12345678",
        "admin",
        "administrator",
        "root",
        "jwt",
        "jwtsecret",
        "jwt_secret",
        "mysecret",
        "supersecret",
        "test",
        "testing",
        "token",
        "auth",
        "dev",
        "development",
        "prod",
        "production",
        "staging",
        "default",
        "changeme",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "login",
        "key",
        "private",
        "public",
        "access",
        "app",
        "api",
        "apisecret",
        "secret123",
        "password123",
        "admin123",
        "pass",
        "qwerty",
        "letmein",
        "security",
        "secure",
        "secretkey",
        "your-secret-key",
        "my-secret-key",
        "shared-secret",
        "super-secret-key",
        "company",
        "internal",
        "demo",
        "guest",
        "user",
        "database",
        "oracle",
        "cisco",
        "server",
        "client",
        "session",
        "cookie",
    ]

    _HASH_MAP: ClassVar[dict[str, Any]] = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    def __init__(self, parser: JWTParser | None = None) -> None:
        self.parser = parser or JWTParser()
        self.settings = get_settings()

    def crack(
        self,
        token: str,
        wordlist: list[str] | None = None,
        max_words: int | None = None,
    ) -> CrackResult:
        """Attempt to crack the HMAC secret of a given token against a dictionary.

        Args:
            token: Raw JWT string.
            wordlist: Optional custom candidate wordlist.
            max_words: Limit on candidates evaluated.

        Returns:
            CrackResult containing status, secret (if found), attempts count, and runtime.
        """
        start_time = time.perf_counter()
        decoded = self.parser.parse(token)

        alg = decoded.algorithm.upper()
        hash_func = self._HASH_MAP.get(alg)
        if not hash_func or not decoded.signature:
            return CrackResult(
                cracked=False,
                secret=None,
                attempts=0,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        parts = decoded.raw_token.split(".")
        if len(parts) != 3:
            return CrackResult(
                cracked=False,
                secret=None,
                attempts=0,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

        # Decode target signature bytes
        padding_needed = (4 - len(decoded.signature) % 4) % 4
        padded_sig = decoded.signature + ("=" * padding_needed)
        try:
            target_sig_bytes = base64.urlsafe_b64decode(padded_sig.encode("ascii"))
        except Exception:
            return CrackResult(
                cracked=False,
                secret=None,
                attempts=0,
                duration_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        candidates = wordlist if wordlist is not None else self.DEFAULT_WORDLIST
        limit = max_words or self.settings.max_crack_words

        attempts = 0
        for word in candidates:
            if attempts >= limit:
                break
            attempts += 1

            candidate_bytes = word.encode("utf-8")
            computed = hmac.new(candidate_bytes, signing_input, hash_func).digest()

            if hmac.compare_digest(computed, target_sig_bytes):
                duration_ms = (time.perf_counter() - start_time) * 1000
                return CrackResult(
                    cracked=True,
                    secret=word,
                    attempts=attempts,
                    duration_ms=round(duration_ms, 2),
                )

        duration_ms = (time.perf_counter() - start_time) * 1000
        return CrackResult(
            cracked=False,
            secret=None,
            attempts=attempts,
            duration_ms=round(duration_ms, 2),
        )
