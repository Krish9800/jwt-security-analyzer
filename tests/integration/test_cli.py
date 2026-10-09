"""Integration tests for jwtsec Typer CLI commands."""

import json
import time
from pathlib import Path

from typer.testing import CliRunner

from jwtsec.cli.main import app
from jwtsec.core.crafter import JWTCrafter

runner = CliRunner(env={"COLUMNS": "160"})


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output
    assert "System Information" in result.output


def test_cli_audit_vulnerable_token() -> None:
    none_token = JWTCrafter.craft_none(claims={"sub": "admin"}).token
    result = runner.invoke(app, ["audit", none_token])
    assert result.exit_code == 1
    assert "CRITICAL VULNERABILITY" in result.output
    assert "JWT-VULN-ALG-NONE-01" in result.output


def test_cli_audit_clean_token() -> None:
    now = time.time()
    clean_token = JWTCrafter.craft_hmac(
        claims={"sub": "alice", "iat": now - 30, "exp": now + 600},
        secret="extremely_secure_key_1928401",
    ).token
    result = runner.invoke(app, ["audit", clean_token])
    assert result.exit_code == 0
    assert "SAFE / COMPLIANT" in result.output


def test_cli_audit_json_format() -> None:
    token = JWTCrafter.craft_none(claims={"sub": "admin"}).token
    result = runner.invoke(app, ["audit", token, "--format", "json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["is_vulnerable"] is True
    assert data["risk_score"] >= 80.0


def test_cli_audit_invalid_format() -> None:
    token = JWTCrafter.craft_none(claims={"sub": "admin"}).token
    result = runner.invoke(app, ["audit", token, "--format", "yaml"])
    assert result.exit_code == 2
    assert "Unsupported report format" in result.output


def test_cli_audit_file_output(tmp_path: Path) -> None:
    token = JWTCrafter.craft_none(claims={"sub": "admin"}).token
    out_file = tmp_path / "audit_report.json"
    result = runner.invoke(app, ["audit", token, "--format", "json", "--output", str(out_file)])
    assert result.exit_code == 1
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "token_snippet" in data


def test_cli_crack_success_and_failure() -> None:
    # Success
    weak_token = JWTCrafter.craft_hmac(claims={"sub": "user"}, secret="password123").token
    res_success = runner.invoke(app, ["crack", weak_token])
    assert res_success.exit_code == 0
    assert "CRACK SUCCESSFUL" in res_success.output
    assert "password123" in res_success.output

    # Failure
    strong_token = JWTCrafter.craft_hmac(
        claims={"sub": "user"}, secret="not_in_dict_secret_99"
    ).token
    res_fail = runner.invoke(app, ["crack", strong_token])
    assert res_fail.exit_code == 1
    assert "CRACK FAILED" in res_fail.output


def test_cli_craft_commands() -> None:
    # Craft none
    res_none = runner.invoke(app, ["craft", "--alg", "none", "--claims", '{"user":"root"}'])
    assert res_none.exit_code == 0
    assert "Crafted Token" in res_none.output

    # Craft HMAC
    res_hmac = runner.invoke(
        app,
        ["craft", "--alg", "HS256", "--claims", '{"user":"test"}', "--secret", "mysecret"],
    )
    assert res_hmac.exit_code == 0
    assert "HS256" in res_hmac.output

    # Craft invalid alg
    res_invalid = runner.invoke(app, ["craft", "--alg", "invalid_alg"])
    assert res_invalid.exit_code == 2


def test_cli_lab_commands() -> None:
    none_token = JWTCrafter.craft_none(claims={"sub": "admin"}).token

    # Insecure mode authenticates
    res_insecure = runner.invoke(app, ["lab", none_token, "--mode", "insecure"])
    assert res_insecure.exit_code == 0
    assert "AUTHENTICATED" in res_insecure.output

    # Hardened mode rejects
    res_hardened = runner.invoke(app, ["lab", none_token, "--mode", "hardened"])
    assert res_hardened.exit_code == 1
    assert "REJECTED" in res_hardened.output
