"""Abstract base class interface for jwtsec security audit reporters."""

from abc import ABC, abstractmethod

from jwtsec.models.token import JWTAuditResult


class BaseReporter(ABC):
    """Abstract reporter producing formatted audit output."""

    @abstractmethod
    def generate(self, result: JWTAuditResult) -> str:
        """Render a single JWTAuditResult into the designated output format string."""

    @abstractmethod
    def generate_batch(self, results: list[JWTAuditResult]) -> str:
        """Render a collection of JWTAuditResults into the designated output format string."""
