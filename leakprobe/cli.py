"""Command-line entry point. Thin layer: parse arguments, delegate, set exit code."""

import typer

from leakprobe import __version__

app = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)


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
