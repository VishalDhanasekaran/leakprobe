"""Report rendering from hand-built findings."""

from leakprobe.models import Report
from leakprobe.report import OutputFormat, render
from leakprobe.report.jsonout import from_json, to_json
from leakprobe.report.markdown import to_markdown
from leakprobe.report.terminal import to_terminal


def test_json_round_trip(report: Report) -> None:
    assert from_json(to_json(report)) == report


def test_markdown(report: Report) -> None:
    md = to_markdown(report)
    assert md.startswith("# LeakProbe report\n")
    assert "- **Overall:** FAIL" in md
    assert "| LP-KILL-01 | Kill switch | FAIL | critical |" in md
    assert "Leaked in 18/20 trials \\| link-down" in md  # pipes escaped in tables
    assert "## LP-KILL-01: Kill switch (FAIL)" in md
    assert "- udp 192.168.100.2:40000 -> 198.51.100.10:9000 after fault" in md
    assert "| leak_window_ms_p95 | 412.5 |" in md
    assert "**Remediation**" in md


def test_terminal_plain(report: Report) -> None:
    text = to_terminal(report, color=False)
    assert "\x1b[" not in text
    for test_id in ("LP-ROUTE-01", "LP-KILL-01", "LP-SPLIT-01"):
        assert test_id in text
    assert "Overall: FAIL" in text
    assert "leaked_trials: 18" in text


def test_terminal_color(report: Report) -> None:
    assert "\x1b[" in to_terminal(report, color=True)


def test_render_dispatch(report: Report) -> None:
    assert from_json(render(report, OutputFormat.JSON)) == report
    assert render(report, OutputFormat.MD) == to_markdown(report)
    assert "LP-KILL-01" in render(report, OutputFormat.TERM, color=False)
