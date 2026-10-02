"""Command-line entry point. Thin layer: parse arguments, delegate, set exit code."""

import sys
from pathlib import Path

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from leakprobe import __version__
from leakprobe.collectors import routes
from leakprobe.doctor import run_checks
from leakprobe.models import Report, exit_code, make_report
from leakprobe.report import OutputFormat, render
from leakprobe.report.jsonout import from_json
from leakprobe.tests_impl.route_audit import audit_routes
from leakprobe.util.net import parse_endpoint
from leakprobe.util.sh import ShError

app = typer.Typer(no_args_is_help=True, add_completion=False)
err = Console(stderr=True)

FORMAT = typer.Option(OutputFormat.TERM, "--format", "-f", help="Output format.")
OUTPUT = typer.Option(None, "--output", "-o", help="Write to file.")
STRICT = typer.Option(False, "--strict", help="Treat WARN as failure.")
ALLOW_LAN = typer.Option(False, "--allow-lan", help="Allow traffic to local LAN prefixes.")


def _emit(rep: Report, fmt: OutputFormat, output: Path | None, strict: bool) -> None:
    """Render, write to stdout or a file, and exit with the report's exit code."""
    text = render(rep, fmt, color=output is None and sys.stdout.isatty())
    if output is None:
        sys.stdout.write(text)
    else:
        output.write_text(text)
    raise typer.Exit(exit_code(rep.findings, strict))


def _fail(message: str) -> typer.Exit:
    err.print(f"[red]error:[/] {message}")
    return typer.Exit(2)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"leakprobe {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version."
    ),
) -> None:
    """LeakProbe: measure whether a VPN tunnel actually protects traffic."""


@app.command()
def doctor() -> None:
    """Check root, required tools, kernel module and namespace support."""
    table = Table(title="leakprobe doctor")
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Detail")
    checks = run_checks()
    for c in checks:
        if c.ok:
            result = "[green]ok[/]"
        else:
            result = "[red]missing[/]" if c.required else "[yellow]optional[/]"
        table.add_row(c.name, result, c.detail)
    Console().print(table)
    if not all(c.ok for c in checks if c.required):
        raise typer.Exit(2)


@app.command()
def report(
    results: Path = typer.Argument(..., exists=True, dir_okay=False, help="Saved JSON report."),
    fmt: OutputFormat = FORMAT,
    output: Path | None = OUTPUT,
    strict: bool = STRICT,
) -> None:
    """Re-render a saved JSON report as term, json or md."""
    try:
        rep = from_json(results.read_text())
    except ValidationError as exc:
        raise _fail(f"invalid report {results}: {exc.error_count()} validation error(s)") from exc
    _emit(rep, fmt, output, strict)


@app.command("audit-routes")
def audit_routes_cmd(
    from_file: Path | None = typer.Option(
        None, "--from-file", exists=True, dir_okay=False, help="Saved routing state (no root)."
    ),
    save: Path | None = typer.Option(None, "--save", help="Also save the routing state here."),
    tunnel: list[str] = typer.Option(["wg0"], "--tunnel", "-t", help="Tunnel interface(s)."),
    endpoint: list[str] = typer.Option(
        [], "--endpoint", "-e", help="VPN endpoint IP[:PORT] whose host route is allowed."
    ),
    allow_lan: bool = ALLOW_LAN,
    fmt: OutputFormat = FORMAT,
    output: Path | None = OUTPUT,
    strict: bool = STRICT,
) -> None:
    """LP-ROUTE-01: predict egress for test destinations and look for bypass routes."""
    try:
        endpoints = [parse_endpoint(e)[0] for e in endpoint]
        state = routes.load(from_file) if from_file else routes.collect()
    except (ValueError, KeyError, ShError) as exc:
        raise _fail(str(exc)) from exc
    if save:
        routes.save(state, save)
    finding = audit_routes(state, tunnel, endpoints, allow_lan)
    env = {"tunnel": ",".join(tunnel), "source": str(from_file) if from_file else "live"}
    _emit(make_report([finding], environment=env), fmt, output, strict)
