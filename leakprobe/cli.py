"""Command-line entry point. Thin layer: parse arguments, delegate, set exit code."""

import sys
from pathlib import Path

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from leakprobe import __version__
from leakprobe.doctor import run_checks
from leakprobe.models import exit_code
from leakprobe.report import OutputFormat, render
from leakprobe.report.jsonout import from_json

app = typer.Typer(no_args_is_help=True, add_completion=False)
err = Console(stderr=True)


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
    fmt: OutputFormat = typer.Option(OutputFormat.TERM, "--format", "-f", help="Output format."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write to file."),
    strict: bool = typer.Option(False, "--strict", help="Treat WARN as failure."),
) -> None:
    """Re-render a saved JSON report as term, json or md."""
    try:
        rep = from_json(results.read_text())
    except ValidationError as exc:
        err.print(f"[red]invalid report {results}:[/] {exc.error_count()} validation error(s)")
        raise typer.Exit(2) from exc

    text = render(rep, fmt, color=output is None and sys.stdout.isatty())
    if output is None:
        sys.stdout.write(text)
    else:
        output.write_text(text)
    raise typer.Exit(exit_code(rep.findings, strict))
