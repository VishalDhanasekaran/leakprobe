"""Command-line entry point. Thin layer: parse arguments, delegate, set exit code."""

import ipaddress
import sys
from pathlib import Path

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from leakprobe import __version__
from leakprobe.analyzers.packet_classifier import DEFAULT_LAN, ClassifierContext
from leakprobe.collectors import routes
from leakprobe.doctor import run_checks
from leakprobe.faults.injector import METHODS
from leakprobe.lab import builder
from leakprobe.lab.profile import list_profiles, load_profile
from leakprobe.models import Report, exit_code, make_report
from leakprobe.report import OutputFormat, render
from leakprobe.report.jsonout import from_json
from leakprobe.tests_impl.context import RunContext
from leakprobe.tests_impl.egress import audit_egress
from leakprobe.tests_impl.killswitch import run_killswitch
from leakprobe.tests_impl.route_audit import audit_routes
from leakprobe.util.net import parse_endpoint
from leakprobe.util.sh import ShError

app = typer.Typer(no_args_is_help=True, add_completion=False)
lab_app = typer.Typer(no_args_is_help=True, help="Build and inspect the namespace lab (root).")
app.add_typer(lab_app, name="lab")
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


@app.command()
def analyze(
    capture: Path = typer.Argument(..., exists=True, dir_okay=False, help="pcap/pcapng file."),
    endpoint: str = typer.Option(..., "--endpoint", "-e", help="VPN endpoint IP:PORT."),
    allow_lan: bool = ALLOW_LAN,
    lan_prefix: list[str] = typer.Option(
        [], "--lan-prefix", help="LAN prefix for --allow-lan (default: private ranges)."
    ),
    iface: str = typer.Option("", "--iface", help="Interface the capture was taken on."),
    fmt: OutputFormat = FORMAT,
    output: Path | None = OUTPUT,
    strict: bool = STRICT,
) -> None:
    """LP-EGRESS-01 on a saved capture of the physical interface (no root needed)."""
    from leakprobe.capture.pcap import parse_pcap  # scapy is slow to import

    try:
        ip, port = parse_endpoint(endpoint)
        prefixes = tuple(ipaddress.ip_network(p, strict=False) for p in lan_prefix) or DEFAULT_LAN
        packets = parse_pcap(capture, iface)
    except (ValueError, OSError) as exc:
        raise _fail(str(exc)) from exc
    ctx = ClassifierContext(ip, port, allow_lan, prefixes)
    env = {"capture": str(capture), "endpoint": endpoint, "physical": iface or "unknown"}
    _emit(make_report([audit_egress(packets, ctx)], environment=env), fmt, output, strict)


def _print_status(status: builder.LabStatus) -> None:
    table = Table(title=f"leakprobe lab: {'UP' if status.up else 'DOWN'}")
    table.add_column("Item")
    table.add_column("State")
    table.add_row("profile", status.state.profile if status.state else "-")
    table.add_row("namespaces", ", ".join(status.namespaces) or "-")
    services = status.state.services if status.state else {}
    for name, svc in services.items():
        ok = status.services_alive.get(name, False)
        state = f"{'[green]running[/]' if ok else '[red]dead[/]'} {svc.ns} {svc.proto}/{svc.port}"
        table.add_row(f"service: {name}", state)
    age = status.handshake_age_s
    table.add_row("wg handshake", f"{age:.0f}s ago" if age is not None else "none yet")
    Console().print(table)


@lab_app.command("up")
def lab_up(
    profile: str = typer.Option(
        ..., "--profile", "-p", help=f"One of: {', '.join(list_profiles())}"
    ),
) -> None:
    """Build the lab for a profile (idempotent)."""
    try:
        builder.up(load_profile(profile))
    except (ValueError, builder.LabError, ShError, OSError) as exc:
        raise _fail(str(exc)) from exc
    _print_status(builder.status())


@lab_app.command("down")
def lab_down() -> None:
    """Remove every lp-* namespace, service and config file, even after a crash."""
    try:
        builder.require_root()
    except builder.LabError as exc:
        raise _fail(str(exc)) from exc
    removed = builder.down()
    typer.echo(f"removed: {', '.join(removed)}" if removed else "nothing to remove")


@lab_app.command("status")
def lab_status() -> None:
    """Show the lab state. Exit 0 when the lab is up, 1 otherwise."""
    status = builder.status()
    _print_status(status)
    raise typer.Exit(0 if status.up else 1)


@app.command("drop-test")
def drop_test(
    method: str = typer.Option("link-down", "--method", "-m", help=" | ".join(METHODS)),
    trials: int = typer.Option(20, "--trials", "-n", min=1, help="Number of fault trials."),
    pre: float = typer.Option(2.0, "--pre", help="Seconds of steady probing before the fault."),
    post: float = typer.Option(3.0, "--post", help="Seconds observed after the fault."),
    rate: float = typer.Option(100.0, "--rate", help="Probe packets per second."),
    fmt: OutputFormat = FORMAT,
    output: Path | None = OUTPUT,
    strict: bool = STRICT,
) -> None:
    """LP-KILL-01 against the running lab: inject a tunnel fault N times, measure leaks."""
    if method not in METHODS:
        raise _fail(f"unknown method {method!r}; choose from {', '.join(METHODS)}")
    try:
        builder.require_root()
    except builder.LabError as exc:
        raise _fail(str(exc)) from exc
    status = builder.status()
    if not status.up or status.state is None:
        raise _fail("the lab is not up; run `leakprobe lab up --profile NAME` first")
    ctx = RunContext.from_lab(status.state)
    finding = run_killswitch(ctx, method, trials, pre, post, rate)
    env = {"profile": status.state.profile, "tunnel": ctx.tunnel, "physical": ctx.physical}
    _emit(make_report([finding], mode="lab", environment=env), fmt, output, strict)
