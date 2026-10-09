"""Markdown report generator for jwtsec security audit results."""

import json

from jwtsec.models.token import JWTAuditResult
from jwtsec.reporters.base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Produces GitHub Flavored Markdown security audit reports."""

    def generate(self, result: JWTAuditResult) -> str:
        """Render a single audit result to a formatted Markdown report."""
        badge = (
            "🔴 **CRITICAL VULNERABILITY**"
            if result.risk_level == "CRITICAL"
            else (
                "🟠 **VULNERABLE**"
                if result.is_vulnerable
                else (
                    "🟡 **SUSPICIOUS**"
                    if result.risk_level == "SUSPICIOUS"
                    else "🟢 **SAFE / COMPLIANT**"
                )
            )
        )

        md_lines = [
            "# JWT Security Assessment Report",
            "",
            f"**Audit Verdict:** {badge}  ",
            f"**Risk Score:** `{result.risk_score:.1f}/100.0` ({result.risk_level})  ",
            f"**Token Snippet:** `{result.token_snippet}`  ",
            f"**Analyzed At:** `{result.analyzed_at.isoformat()}`  ",
            "",
        ]

        if result.cracked_secret:
            md_lines.extend(
                [
                    "## ⚠️ Recovered Signing Secret",
                    f"> **CRACKED SECRET:** `{result.cracked_secret}`",
                    "",
                ]
            )

        md_lines.extend(
            [
                "## Decoded Token Components",
                "### Header",
                "```json",
                json.dumps(result.header, indent=2),
                "```",
                "",
                "### Payload Claims",
                "```json",
                json.dumps(result.payload, indent=2),
                "```",
                "",
                "## Findings Summary",
            ]
        )

        if not result.findings:
            md_lines.extend(
                [
                    "",
                    "> No algorithm flaws, weak secrets, injection patterns, or claim anomalies detected.",
                    "",
                ]
            )
        else:
            md_lines.extend(
                [
                    "",
                    "| ID | Title | Severity | Confidence | CWE |",
                    "| :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for f in result.findings:
                md_lines.append(
                    f"| `{f.finding_id}` | {f.title} | `{f.severity.value}` "
                    f"| `{f.confidence.value}` | `{f.cwe_id}` |"
                )

            md_lines.extend(
                [
                    "",
                    "## Technical Explanations & Remediation Guidance",
                    "",
                ]
            )
            for f in result.findings:
                md_lines.extend(
                    [
                        f"### {f.title} (`{f.finding_id}`)",
                        f"- **Severity:** `{f.severity.value}` | **Confidence:** `{f.confidence.value}` | **CWE:** `{f.cwe_id}`",
                        f"- **Description:** {f.description}",
                        f"- **Remediation:** {f.remediation}",
                        "",
                    ]
                )

        md_lines.extend(
            [
                "---",
                "*Generated automatically by JWT-Security-Analyzer Security Engine.*",
            ]
        )
        return "\n".join(md_lines)

    def generate_batch(self, results: list[JWTAuditResult]) -> str:
        """Render multiple audit results into a consolidated Markdown document."""
        md_lines = [
            "# Batch JWT Security Audit Report",
            "",
            f"**Total Tokens Audited:** `{len(results)}`  ",
            f"**Vulnerable Tokens Detected:** `{sum(1 for r in results if r.is_vulnerable)}`  ",
            "",
            "| # | Snippet | Verdict | Risk Score | Findings | Cracked Secret |",
            "| :- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for i, r in enumerate(results, 1):
            status_icon = (
                "🔴"
                if r.risk_level == "CRITICAL"
                else ("🟠" if r.is_vulnerable else ("🟡" if r.risk_level == "SUSPICIOUS" else "🟢"))
            )
            cracked = f"`{r.cracked_secret}`" if r.cracked_secret else "-"
            md_lines.append(
                f"| {i} | `{r.token_snippet}` | {status_icon} `{r.risk_level}` "
                f"| `{r.risk_score:.1f}` | `{len(r.findings)}` | {cracked} |"
            )

        md_lines.extend(
            [
                "",
                "---",
                "*Generated automatically by JWT-Security-Analyzer Security Engine.*",
            ]
        )
        return "\n".join(md_lines)
