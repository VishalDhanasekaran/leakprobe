"""Core data models shared by collectors, analyzers, tests and reports."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Status(StrEnum):
    """Outcome of a single test."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


class Severity(StrEnum):
    """How bad a failing test is."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PacketRecord(BaseModel):
    """One captured packet, reduced to the fields the classifier needs."""

    ts: float
    iface: str
    l2: str
    l3: str | None = None
    proto: str | None = None
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    size: int
    icmp6_type: int | None = None


class Finding(BaseModel):
    """Result of one test, with evidence and an optional fix."""

    test_id: str
    title: str
    status: Status
    severity: Severity
    summary: str
    evidence: list[str] = Field(default_factory=list)
    metrics: dict[str, float | int | str] = Field(default_factory=dict)
    remediation: str | None = None


class Report(BaseModel):
    """A full LeakProbe run."""

    tool_version: str
    started_at: datetime
    mode: Literal["lab", "real"]
    environment: dict[str, str] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    overall: Status


def overall_status(findings: list[Finding]) -> Status:
    """Worst status across findings: ERROR > FAIL > WARN > PASS; SKIP if nothing ran."""
    statuses = {f.status for f in findings}
    for status in (Status.ERROR, Status.FAIL, Status.WARN, Status.PASS):
        if status in statuses:
            return status
    return Status.SKIP


def exit_code(findings: list[Finding], strict: bool = False) -> int:
    """Process exit code: 0 ok, 1 at least one FAIL (or WARN with strict), 2 tool error."""
    overall = overall_status(findings)
    if overall is Status.ERROR:
        return 2
    if overall is Status.FAIL or (strict and overall is Status.WARN):
        return 1
    return 0


def make_report(
    findings: list[Finding],
    mode: Literal["lab", "real"] = "real",
    environment: dict[str, str] | None = None,
    started_at: datetime | None = None,
) -> Report:
    """Assemble a Report and compute its overall status."""
    from leakprobe import __version__

    return Report(
        tool_version=__version__,
        started_at=started_at or datetime.now(UTC),
        mode=mode,
        environment=environment or {},
        findings=findings,
        overall=overall_status(findings),
    )
