"""Markdown rendering of reports."""

from leakprobe.models import Report


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(report: Report) -> str:
    """Render a report as a Markdown document."""
    lines = [
        "# LeakProbe report",
        "",
        f"- **Overall:** {report.overall.value.upper()}",
        f"- **Mode:** {report.mode}",
        f"- **Started:** {report.started_at.isoformat()}",
        f"- **Tool version:** {report.tool_version}",
    ]
    if report.environment:
        lines += ["", "## Environment", "", "| Key | Value |", "|---|---|"]
        lines += [f"| {_cell(k)} | {_cell(v)} |" for k, v in report.environment.items()]

    lines += ["", "## Summary", "", "| Test | Title | Status | Severity | Summary |"]
    lines.append("|---|---|---|---|---|")
    for f in report.findings:
        lines.append(
            f"| {f.test_id} | {_cell(f.title)} | {f.status.value.upper()} "
            f"| {f.severity.value} | {_cell(f.summary)} |"
        )

    for f in report.findings:
        lines += ["", f"## {f.test_id}: {f.title} ({f.status.value.upper()})", "", f.summary]
        if f.evidence:
            lines += ["", "**Evidence**", ""]
            lines += [f"- {e}" for e in f.evidence]
        if f.metrics:
            lines += ["", "| Metric | Value |", "|---|---|"]
            lines += [f"| {_cell(k)} | {v} |" for k, v in f.metrics.items()]
        if f.remediation:
            lines += ["", "**Remediation**", "", "```", f.remediation, "```"]
    return "\n".join(lines) + "\n"
