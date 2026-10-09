"""Unit tests for jwtsec reporting subsystem (JSON, Markdown, SARIF, Factory)."""

import json
import time

import pytest

from jwtsec.core.crafter import JWTCrafter
from jwtsec.core.engine import JWTAuditEngine
from jwtsec.models.token import JWTAuditResult
from jwtsec.reporters.factory import ReporterFactory
from jwtsec.reporters.json_reporter import JSONReporter
from jwtsec.reporters.markdown_reporter import MarkdownReporter
from jwtsec.reporters.sarif_reporter import SARIFReporter


@pytest.fixture
def sample_vulnerable_result() -> JWTAuditResult:
    token = JWTCrafter.craft_none(claims={"sub": "admin", "role": "root"}).token
    engine = JWTAuditEngine()
    return engine.audit(token)


@pytest.fixture
def sample_clean_result() -> JWTAuditResult:
    now = time.time()
    token = JWTCrafter.craft_hmac(
        claims={"sub": "user123", "iat": now - 30, "exp": now + 1200},
        secret="complex_random_secret_44920491",
    ).token
    engine = JWTAuditEngine()
    return engine.audit(token)


def test_json_reporter_single(sample_vulnerable_result: JWTAuditResult) -> None:
    reporter = JSONReporter()
    output = reporter.generate(sample_vulnerable_result)
    data = json.loads(output)

    assert data["is_vulnerable"] is True
    assert data["risk_score"] >= 80.0
    assert len(data["findings"]) > 0
    assert "token_snippet" in data


def test_json_reporter_batch(
    sample_vulnerable_result: JWTAuditResult,
    sample_clean_result: JWTAuditResult,
) -> None:
    reporter = JSONReporter()
    output = reporter.generate_batch([sample_vulnerable_result, sample_clean_result])
    data = json.loads(output)

    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["is_vulnerable"] is True
    assert data[1]["is_vulnerable"] is False


def test_markdown_reporter_single_vulnerable(
    sample_vulnerable_result: JWTAuditResult,
) -> None:
    reporter = MarkdownReporter()
    output = reporter.generate(sample_vulnerable_result)

    assert "# JWT Security Assessment Report" in output
    assert "CRITICAL VULNERABILITY" in output
    assert "## Decoded Token Components" in output
    assert "| ID | Title | Severity | Confidence | CWE |" in output


def test_markdown_reporter_single_clean(sample_clean_result: JWTAuditResult) -> None:
    reporter = MarkdownReporter()
    output = reporter.generate(sample_clean_result)

    assert "# JWT Security Assessment Report" in output
    assert "SAFE / COMPLIANT" in output
    assert "No algorithm flaws" in output


def test_markdown_reporter_batch(
    sample_vulnerable_result: JWTAuditResult,
    sample_clean_result: JWTAuditResult,
) -> None:
    reporter = MarkdownReporter()
    output = reporter.generate_batch([sample_vulnerable_result, sample_clean_result])

    assert "# Batch JWT Security Audit Report" in output
    assert "**Total Tokens Audited:** `2`" in output
    assert "**Vulnerable Tokens Detected:** `1`" in output
    assert "| 1 |" in output
    assert "| 2 |" in output


def test_sarif_reporter_single(sample_vulnerable_result: JWTAuditResult) -> None:
    reporter = SARIFReporter()
    output = reporter.generate(sample_vulnerable_result)
    data = json.loads(output)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "jwtsec"
    assert len(run["results"]) > 0


def test_sarif_reporter_batch(
    sample_vulnerable_result: JWTAuditResult,
    sample_clean_result: JWTAuditResult,
) -> None:
    reporter = SARIFReporter()
    output = reporter.generate_batch([sample_vulnerable_result, sample_clean_result])
    data = json.loads(output)

    assert len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) >= 1


def test_reporter_factory() -> None:
    assert isinstance(ReporterFactory.create_reporter("json"), JSONReporter)
    assert isinstance(ReporterFactory.create_reporter("markdown"), MarkdownReporter)
    assert isinstance(ReporterFactory.create_reporter("md"), MarkdownReporter)
    assert isinstance(ReporterFactory.create_reporter("sarif"), SARIFReporter)

    with pytest.raises(ValueError, match="Unsupported report format 'xml'"):
        ReporterFactory.create_reporter("xml")
