"""Hand-built findings and reports shared by unit tests."""

from datetime import UTC, datetime

import pytest

from leakprobe.models import Finding, Report, Severity, Status, overall_status


def make_report(findings: list[Finding]) -> Report:
    return Report(
        tool_version="0.1.0",
        started_at=datetime(2026, 10, 2, 12, 0, tzinfo=UTC),
        mode="lab",
        environment={"kernel": "6.18", "tunnel": "wg0", "physical": "c-phys"},
        findings=findings,
        overall=overall_status(findings),
    )


@pytest.fixture
def findings() -> list[Finding]:
    return [
        Finding(
            test_id="LP-ROUTE-01",
            title="Route audit",
            status=Status.PASS,
            severity=Severity.HIGH,
            summary="All test destinations egress via wg0",
        ),
        Finding(
            test_id="LP-KILL-01",
            title="Kill switch",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            summary="Leaked in 18/20 trials | link-down",
            evidence=["udp 192.168.100.2:40000 -> 198.51.100.10:9000 after fault"],
            metrics={"leak_window_ms_p95": 412.5, "leaked_trials": 18, "method": "link-down"},
            remediation="table inet leakprobe_killswitch { ... }",
        ),
        Finding(
            test_id="LP-SPLIT-01",
            title="Split-tunnel audit",
            status=Status.WARN,
            severity=Severity.LOW,
            summary="1 socket bound to the physical address",
        ),
    ]


@pytest.fixture
def report(findings: list[Finding]) -> Report:
    return make_report(findings)
