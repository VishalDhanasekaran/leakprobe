"""CLI: version, report re-rendering, doctor."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from leakprobe import __version__, cli
from leakprobe.doctor import Check
from leakprobe.models import Finding, Report
from leakprobe.report.jsonout import from_json, to_json
from tests.unit.conftest import make_report

runner = CliRunner()


def _save(report: Report, tmp_path: Path) -> Path:
    path = tmp_path / "results.json"
    path.write_text(to_json(report))
    return path


def test_version() -> None:
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_report_markdown(report: Report, tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["report", str(_save(report, tmp_path)), "--format", "md"])
    assert result.exit_code == 1  # report contains a FAIL
    assert result.output.startswith("# LeakProbe report")


def test_report_json_to_file(report: Report, tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    args = ["report", str(_save(report, tmp_path)), "-f", "json", "-o", str(out)]
    runner.invoke(cli.app, args)
    assert from_json(out.read_text()) == report


def test_report_term_default(report: Report, tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["report", str(_save(report, tmp_path))])
    assert "LP-KILL-01" in result.output
    assert "\x1b[" not in result.output  # no colour when not a tty


def test_report_strict(findings: list[Finding], tmp_path: Path) -> None:
    path = _save(make_report([f for f in findings if f.test_id != "LP-KILL-01"]), tmp_path)
    assert runner.invoke(cli.app, ["report", str(path)]).exit_code == 0
    assert runner.invoke(cli.app, ["report", str(path), "--strict"]).exit_code == 1


def test_report_invalid(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"mode": "lab"}')
    assert runner.invoke(cli.app, ["report", str(path)]).exit_code == 2


def test_doctor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "run_checks", lambda: [Check("root", True, "euid 0")])
    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0
    assert "root" in result.output


def test_doctor_missing_required(monkeypatch: pytest.MonkeyPatch) -> None:
    checks = [Check("tool: wg", False, "not installed"), Check("tool: openvpn", False, "-", False)]
    monkeypatch.setattr(cli, "run_checks", lambda: checks)
    assert runner.invoke(cli.app, ["doctor"]).exit_code == 2
