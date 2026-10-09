"""Command Line Interface for jwtsec token security auditor and lab."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from jwtsec.config.settings import get_settings
from jwtsec.core.cracker import HMACSecretCracker
from jwtsec.core.crafter import JWTCrafter
from jwtsec.core.engine import JWTAuditEngine
from jwtsec.lab.verifier import HardenedVerifier, InsecureVerifier
from jwtsec.models.token import JWTAuditResult
from jwtsec.reporters.factory import ReporterFactory

app = typer.Typer(
    name="jwtsec",
    help="Enterprise-Grade JSON Web Token (JWT) Security Auditor and Dual-Mode Lab CLI.",
    add_completion=False,
)
console = Console()


def _render_table_audit(result: JWTAuditResult) -> None:
    """Render a single JWTAuditResult as rich terminal tables and panels."""
    badge = (
        "[bold red]CRITICAL VULNERABILITY[/]"
        if result.risk_level == "CRITICAL"
        else (
            "[bold red]VULNERABLE[/]"
            if result.is_vulnerable
            else (
                "[bold yellow]SUSPICIOUS[/]"
                if result.risk_level == "SUSPICIOUS"
                else "[bold green]SAFE / COMPLIANT[/]"
            )
        )
    )

    info_lines = [
        f"[bold]Verdict:[/] {badge}",
        f"[bold]Risk Score:[/] {result.risk_score:.1f}/100.0 ({result.risk_level})",
        f"[bold]Token Snippet:[/] [cyan]{result.token_snippet}[/]",
        f"[bold]Analyzed At:[/] {result.analyzed_at.isoformat()}",
    ]
    if result.cracked_secret:
        info_lines.append(f"[bold red]CRACKED SIGNING SECRET:[/] [white]{result.cracked_secret}[/]")

    console.print(
        Panel("\n".join(info_lines), title="JWT Security Assessment", border_style="blue")
    )

    # Display decoded header & payload
    console.print(
        Panel(
            json.dumps(result.header, indent=2),
            title="Decoded Header",
            border_style="cyan",
        )
    )
    console.print(
        Panel(
            json.dumps(result.payload, indent=2),
            title="Decoded Payload Claims",
            border_style="magenta",
        )
    )

    if result.findings:
        table = Table(title="Detected Vulnerability Findings", border_style="red")
        table.add_column("Finding ID", style="cyan", no_wrap=True)
        table.add_column("Title", style="white")
        table.add_column("Severity", style="bold red")
        table.add_column("Confidence", style="yellow")
        table.add_column("CWE", style="magenta")

        for f in result.findings:
            table.add_row(
                f.finding_id,
                f.title,
                f.severity.value,
                f.confidence.value,
                f.cwe_id,
            )
        console.print(table)
    else:
        console.print("[green]✔ No algorithm flaws, weak secrets, or claim anomalies detected.[/]")


@app.command(name="audit")
def audit(
    token: Annotated[
        str,
        typer.Argument(help="Raw JWT or Bearer token string to audit"),
    ],
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, json, markdown, sarif"),
    ] = "table",
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional file path to write results"),
    ] = None,
    public_key_file: Annotated[
        Path | None,
        typer.Option("--public-key", "-k", help="Public key PEM file for key confusion check"),
    ] = None,
    no_crack: Annotated[
        bool,
        typer.Option("--no-crack", help="Skip dictionary cracking for HMAC tokens"),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", "-s", help="Exit code 1 on SUSPICIOUS as well as VULNERABLE"),
    ] = False,
) -> None:
    """Audit a JWT token for algorithm confusion, weak secrets, and claim flaws."""
    pub_key_content: str | None = None
    if public_key_file:
        if not public_key_file.exists():
            console.print(f"[bold red]Error:[/] Public key file '{public_key_file}' not found.")
            raise typer.Exit(code=2)
        pub_key_content = public_key_file.read_text(encoding="utf-8")

    engine = JWTAuditEngine()
    result = engine.audit(
        token=token,
        public_key_pem=pub_key_content,
        check_weak_secrets=not no_crack,
    )

    if output_format.lower() == "table":
        _render_table_audit(result)
    else:
        try:
            reporter = ReporterFactory.create_reporter(output_format)
            rendered = reporter.generate(result)
            if output_file:
                output_file.write_text(rendered, encoding="utf-8")
                console.print(f"[bold green]Report saved to:[/] {output_file}")
            else:
                typer.echo(rendered)
        except ValueError as err:
            console.print(f"[bold red]Error:[/] {err}")
            raise typer.Exit(code=2) from err

    if result.is_vulnerable or (strict and result.risk_level == "SUSPICIOUS"):
        raise typer.Exit(code=1)


@app.command(name="crack")
def crack(
    token: Annotated[
        str,
        typer.Argument(help="Target HMAC JWT token to crack"),
    ],
    wordlist_file: Annotated[
        Path | None,
        typer.Option("--wordlist", "-w", help="Custom password dictionary text file"),
    ] = None,
    max_words: Annotated[
        int,
        typer.Option("--max-words", "-m", help="Maximum words to evaluate"),
    ] = 10000,
) -> None:
    """Perform dictionary cracking against HMAC signed tokens (HS256/384/512)."""
    words: list[str] | None = None
    if wordlist_file:
        if not wordlist_file.exists():
            console.print(f"[bold red]Error:[/] Wordlist file '{wordlist_file}' not found.")
            raise typer.Exit(code=2)
        words = [
            line.strip()
            for line in wordlist_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    cracker = HMACSecretCracker()
    result = cracker.crack(token, wordlist=words, max_words=max_words)

    if result.cracked:
        console.print(
            Panel(
                f"[bold green]CRACK SUCCESSFUL![/]\n\n"
                f"[bold]Recovered Secret:[/] [bold yellow]{result.secret}[/]\n"
                f"[bold]Candidates Evaluated:[/] {result.attempts}\n"
                f"[bold]Cracking Latency:[/] {result.duration_ms:.2f} ms",
                title="HMAC Secret Recovery",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]CRACK FAILED[/]\n\n"
                f"[bold]Candidates Evaluated:[/] {result.attempts}\n"
                f"[bold]Search Latency:[/] {result.duration_ms:.2f} ms\n"
                f"Secret not found in candidate dictionary.",
                title="HMAC Secret Recovery",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)


@app.command(name="craft")
def craft(
    algorithm: Annotated[
        str,
        typer.Option("--alg", "-a", help="Algorithm: none, HS256, RS256"),
    ] = "none",
    claims_json: Annotated[
        str,
        typer.Option("--claims", "-c", help="JSON string containing payload claims"),
    ] = '{"sub":"admin"}',
    secret: Annotated[
        str | None,
        typer.Option("--secret", "-s", help="HMAC signing secret (for HS256)"),
    ] = None,
    private_key_file: Annotated[
        Path | None,
        typer.Option("--key-file", "-k", help="RSA private key file (for RS256)"),
    ] = None,
) -> None:
    """Craft a specialized JWT token for security testing and exploit demonstration."""
    try:
        claims = json.loads(claims_json)
    except json.JSONDecodeError as err:
        console.print(f"[bold red]Error:[/] Invalid claims JSON: {err}")
        raise typer.Exit(code=2) from err

    alg_lower = algorithm.lower().strip()
    if alg_lower == "none":
        res = JWTCrafter.craft_none(claims=claims, case_variant=algorithm)
    elif alg_lower in ("hs256", "hs384", "hs512"):
        if not secret:
            console.print("[bold red]Error:[/] --secret is required for HMAC algorithms.")
            raise typer.Exit(code=2)
        res = JWTCrafter.craft_hmac(claims=claims, secret=secret, alg=algorithm.upper())
    elif alg_lower in ("rs256", "rs384", "rs512"):
        if not private_key_file or not private_key_file.exists():
            console.print("[bold red]Error:[/] Valid --key-file is required for RSA algorithms.")
            raise typer.Exit(code=2)
        key_content = private_key_file.read_text(encoding="utf-8")
        res = JWTCrafter.craft_rsa(
            claims=claims, private_key_pem=key_content, alg=algorithm.upper()
        )
    else:
        console.print(f"[bold red]Error:[/] Unsupported crafting algorithm '{algorithm}'.")
        raise typer.Exit(code=2)

    console.print(
        Panel(
            f"[bold]Algorithm:[/] {res.algorithm}\n\n"
            f"[bold]Crafted Token:[/] \n[cyan]{res.token}[/]",
            title="JWT Crafting Result",
            border_style="green",
        )
    )


@app.command(name="lab")
def lab(
    token: Annotated[
        str,
        typer.Argument(help="JWT token to test in verification lab"),
    ],
    mode: Annotated[
        str,
        typer.Option("--mode", "-m", help="Verification mode: insecure or hardened"),
    ] = "insecure",
    public_key_file: Annotated[
        Path | None,
        typer.Option("--public-key", "-k", help="Public key PEM file for RSA / key confusion"),
    ] = None,
    hmac_secret: Annotated[
        str | None,
        typer.Option("--secret", "-s", help="HMAC shared secret for hardened verification"),
    ] = None,
) -> None:
    """Test token authentication against vulnerable and hardened verifiers."""
    pub_key_pem: str | None = None
    if public_key_file and public_key_file.exists():
        pub_key_pem = public_key_file.read_text(encoding="utf-8")

    is_hardened = mode.lower() == "hardened"

    if is_hardened:
        allowed = ["RS256"] if pub_key_pem else ["HS256"]
        verifier = HardenedVerifier(
            allowed_algorithms=allowed,
            hmac_secret=hmac_secret,
            rsa_public_key_pem=pub_key_pem,
        )
        is_auth, sub, details = verifier.verify(token)
    else:
        insecure_verifier = InsecureVerifier(expected_rsa_public_key=pub_key_pem)
        is_auth, sub, details = insecure_verifier.verify(token)

    badge = "[bold green]AUTHENTICATED[/]" if is_auth else "[bold red]REJECTED[/]"
    console.print(
        Panel(
            f"[bold]Verifier Mode:[/] {mode.upper()}\n"
            f"[bold]Auth Status:[/] {badge}\n"
            f"[bold]Identity Subject:[/] [cyan]{sub}[/]\n\n"
            f"[bold]Diagnostic Details:[/] \n{json.dumps(details, indent=2)}",
            title="Verification Lab Result",
            border_style="green" if is_auth else "red",
        )
    )

    if not is_auth:
        raise typer.Exit(code=1)


@app.command(name="version")
def version() -> None:
    """Display jwtsec version and configuration details."""
    settings = get_settings()
    console.print(
        Panel(
            f"[bold cyan]jwtsec[/] JSON Web Token Security Analyzer\n"
            f"[bold]Version:[/] {settings.version}\n"
            f"[bold]Environment:[/] {settings.environment}\n"
            f"[bold]Bruteforce Enabled:[/] {settings.enable_bruteforce}\n"
            f"[bold]Clock Skew Leeway:[/] {settings.clock_skew_leeway_seconds}s",
            title="System Information",
            border_style="blue",
        )
    )


if __name__ == "__main__":
    app()
