"""Rich terminal rendering of reports."""

from io import StringIO

from rich.console import Console
from rich.table import Table

from leakprobe.models import Report, Status

STATUS_STYLE = {
    Status.PASS: "bold green",
    Status.FAIL: "bold red",
    Status.WARN: "bold yellow",
    Status.SKIP: "dim",
    Status.ERROR: "bold magenta",
}


def _status(status: Status) -> str:
    return f"[{STATUS_STYLE[status]}]{status.value.upper()}[/]"


def to_terminal(report: Report, color: bool = True, width: int = 100) -> str:
    """Render a report as text for a terminal; ANSI colours only when ``color``."""
    console = Console(file=StringIO(), force_terminal=color, no_color=not color, width=width)

    table = Table(title=f"LeakProbe ({report.mode} mode)", show_lines=False)
    table.add_column("Test", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Summary")
    for f in report.findings:
        table.add_row(f.test_id, _status(f.status), f.severity.value, f.summary)
    console.print(table)

    for f in report.findings:
        if not (f.evidence or f.metrics or f.remediation):
            continue
        console.print(f"\n[bold]{f.test_id}[/] {f.title}")
        for line in f.evidence:
            console.print(f"  • {line}", markup=False, highlight=False)
        for key, value in f.metrics.items():
            console.print(f"  {key}: {value}", markup=False, highlight=False)
        if f.remediation:
            console.print("  Remediation:", style="bold")
            console.print(f.remediation, markup=False, highlight=False)

    console.print(f"\nOverall: {_status(report.overall)}")
    out = console.file
    assert isinstance(out, StringIO)
    return out.getvalue()
