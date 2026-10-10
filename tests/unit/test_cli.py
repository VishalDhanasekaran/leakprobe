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


def test_drop_test_rejects_unknown_method() -> None:
    assert runner.invoke(cli.app, ["drop-test", "--method", "unplug"]).exit_code == 2


def test_drop_test_needs_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.builder.os, "geteuid", lambda: 1000)
    result = runner.invoke(cli.app, ["drop-test"])
    assert result.exit_code == 2


def _stub_run(monkeypatch: pytest.MonkeyPatch, report: Report) -> list[object]:
    """No root, no lab: capture the context passed to the orchestrator."""
    seen: list[object] = []
    monkeypatch.setattr(cli.builder, "require_root", lambda: None)

    def fake_run(ctx: object, opts: object, *args: object, **kw: object) -> Report:
        seen.append(ctx)
        return report

    monkeypatch.setattr(cli.orchestrator, "run", fake_run)
    return seen


def test_run_real_needs_yes(monkeypatch: pytest.MonkeyPatch, report: Report) -> None:
    _stub_run(monkeypatch, report)
    args = ["run", "--mode", "real", "--physical", "eth0", "--endpoint", "203.0.113.10:51820"]
    result = runner.invoke(cli.app, args)
    assert result.exit_code == 2
    assert "sends probe traffic" in result.output
    assert runner.invoke(cli.app, [*args, "--yes"]).exit_code == 1  # report contains a FAIL


def test_run_real_passes_context(monkeypatch: pytest.MonkeyPatch, report: Report) -> None:
    seen = _stub_run(monkeypatch, report)
    args = ["run", "--mode", "real", "--yes", "--physical", "eth0", "--tunnel", "wg1",
            "--endpoint", "203.0.113.10:51820", "--beacon", "192.0.2.50", "-f", "json"]
    result = runner.invoke(cli.app, args)
    assert from_json(result.stdout) == report
    ctx = seen[0]
    assert (ctx.tunnel, ctx.physical, ctx.beacon) == ("wg1", "eth0", "192.0.2.50")  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "args",
    [
        ["run", "--mode", "lab"],  # no profile
        ["run", "--mode", "lab", "--profile", "nope"],
        ["run", "--mode", "moon"],
        ["run", "--tests", "LP-FOO-01", "--profile", "wg-hardened"],
        ["run", "--method", "unplug", "--profile", "wg-hardened"],
        ["run", "--mode", "real", "--yes", "--endpoint", "203.0.113.10"],  # no physical
    ],
)
def test_run_usage_errors(
    monkeypatch: pytest.MonkeyPatch, report: Report, args: list[str]
) -> None:
    _stub_run(monkeypatch, report)
    assert runner.invoke(cli.app, args).exit_code == 2


def test_run_needs_root(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny() -> None:
        raise cli.builder.LabError("the lab needs root")

    monkeypatch.setattr(cli.builder, "require_root", deny)
    result = runner.invoke(cli.app, ["run", "--profile", "wg-hardened"])
    assert result.exit_code == 2 and "root" in result.output
