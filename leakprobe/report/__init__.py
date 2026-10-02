"""Report rendering: terminal, JSON, Markdown and remediation text."""

from enum import StrEnum

from leakprobe.models import Report
from leakprobe.report.jsonout import to_json
from leakprobe.report.markdown import to_markdown
from leakprobe.report.terminal import to_terminal


class OutputFormat(StrEnum):
    """Supported report formats."""

    TERM = "term"
    JSON = "json"
    MD = "md"


def render(report: Report, fmt: OutputFormat, color: bool = True) -> str:
    """Render ``report`` in the requested format."""
    if fmt is OutputFormat.JSON:
        return to_json(report) + "\n"
    if fmt is OutputFormat.MD:
        return to_markdown(report)
    return to_terminal(report, color=color)
