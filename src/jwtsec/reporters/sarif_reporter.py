"""SARIF (OASIS Static Analysis Results Interchange Format v2.1.0) reporter for jwtsec."""

import json
from typing import Any

from jwtsec.models.token import JWTAuditResult
from jwtsec.models.vulnerability import DetectionFinding, SeverityLevel
from jwtsec.reporters.base import BaseReporter


class SARIFReporter(BaseReporter):
    """Produces OASIS SARIF v2.1.0 schema reports for GitHub Code Scanning."""

    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def generate(self, result: JWTAuditResult) -> str:
        """Render a single JWTAuditResult as a SARIF v2.1.0 JSON string."""
        return self.generate_batch([result])

    def generate_batch(self, results: list[JWTAuditResult]) -> str:
        """Render multiple JWTAuditResults into a unified SARIF v2.1.0 report."""
        rules_map: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        for result in results:
            for finding in result.findings:
                if finding.finding_id not in rules_map:
                    rules_map[finding.finding_id] = self._create_sarif_rule(finding)

                sarif_results.append(self._create_sarif_result(finding, result.token_snippet))

        sarif_document = {
            "$schema": self.SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "jwtsec",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/cybersecurity-portfolio/jwt-security-analyzer",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        return json.dumps(sarif_document, indent=2)

    def _create_sarif_rule(self, finding: DetectionFinding) -> dict[str, Any]:
        """Convert a detection finding into a SARIF rule definition."""
        level = self._map_severity_to_sarif_level(finding.severity)
        return {
            "id": finding.finding_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "defaultConfiguration": {"level": level},
            "help": {
                "text": f"Remediation: {finding.remediation}",
                "markdown": f"### Remediation\n\n{finding.remediation}",
            },
            "properties": {
                "category": finding.vulnerability_type.value,
                "cwe": finding.cwe_id,
            },
        }

    def _create_sarif_result(
        self,
        finding: DetectionFinding,
        token_snippet: str,
    ) -> dict[str, Any]:
        """Convert a detection finding match into a SARIF result item."""
        level = self._map_severity_to_sarif_level(finding.severity)
        return {
            "ruleId": finding.finding_id,
            "level": level,
            "message": {
                "text": (f"JWT Security Defect: {finding.description} (Token: {token_snippet})")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "token_input.jwt"},
                        "region": {
                            "startLine": 1,
                            "snippet": {"text": token_snippet},
                        },
                    }
                }
            ],
        }

    def _map_severity_to_sarif_level(self, severity: SeverityLevel) -> str:
        """Map vulnerability severity to SARIF level."""
        if severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
            return "error"
        if severity == SeverityLevel.MEDIUM:
            return "warning"
        return "note"
