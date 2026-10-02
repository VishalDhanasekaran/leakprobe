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


ROUTES = Path(__file__).parent.parent / "fixtures" / "routes"


def test_audit_routes_from_file() -> None:
    result = runner.invoke(
        cli.app, ["audit-routes", "--from-file", str(ROUTES / "tunnelvision.json"), "-f", "json"]
    )
    assert result.exit_code == 1
    rep = from_json(result.output)
    assert rep.findings[0].test_id == "LP-ROUTE-01"
    assert "CVE-2024-3661" in rep.findings[0].summary


def test_audit_routes_pass_and_save(tmp_path: Path) -> None:
    saved = tmp_path / "state.json"
    args = ["audit-routes", "--from-file", str(ROUTES / "openvpn_def1.json"), "-t", "tun0",
            "-e", "203.0.113.10:1194", "--save", str(saved)]
    assert runner.invoke(cli.app, args).exit_code == 0
    assert saved.exists()


def test_audit_routes_bad_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert runner.invoke(cli.app, ["audit-routes", "--from-file", str(bad)]).exit_code == 2


def test_analyze_pcap(tmp_path: Path) -> None:
    from scapy.utils import wrpcap

    from tests.unit.packets import PACKETS

    path = tmp_path / "c.pcap"
    wrpcap(str(path), [PACKETS["endpoint_out"], PACKETS["arp"], PACKETS["dns_leak"]])
    result = runner.invoke(
        cli.app, ["analyze", str(path), "--endpoint", "203.0.113.10:51820", "-f", "json"]
    )
    assert result.exit_code == 1
    finding = from_json(result.output).findings[0]
    assert finding.test_id == "LP-EGRESS-01" and finding.metrics["leak_dns"] == 1

    wrpcap(str(path), [PACKETS["endpoint_out"], PACKETS["lan_ssh"]])
    args = ["analyze", str(path), "-e", "203.0.113.10:51820", "--allow-lan"]
    assert runner.invoke(cli.app, args).exit_code == 0


def test_analyze_bad_endpoint(tmp_path: Path) -> None:
    path = tmp_path / "c.pcap"
    path.write_bytes(b"")
    assert runner.invoke(cli.app, ["analyze", str(path), "-e", "nope"]).exit_code == 2
