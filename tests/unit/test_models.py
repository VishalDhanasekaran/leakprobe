"""Overall status and exit-code rules."""

import pytest

from leakprobe.models import Finding, Severity, Status, exit_code, overall_status


def _f(status: Status) -> Finding:
    return Finding(test_id="T", title="t", status=status, severity=Severity.LOW, summary="s")


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], Status.SKIP),
        ([Status.SKIP], Status.SKIP),
        ([Status.PASS, Status.SKIP], Status.PASS),
        ([Status.PASS, Status.WARN], Status.WARN),
        ([Status.WARN, Status.FAIL], Status.FAIL),
        ([Status.FAIL, Status.ERROR], Status.ERROR),
    ],
)
def test_overall_status(statuses: list[Status], expected: Status) -> None:
    assert overall_status([_f(s) for s in statuses]) is expected


@pytest.mark.parametrize(
    ("statuses", "strict", "code"),
    [
        ([Status.PASS], False, 0),
        ([Status.PASS, Status.WARN], False, 0),
        ([Status.PASS, Status.WARN], True, 1),
        ([Status.FAIL], False, 1),
        ([Status.FAIL, Status.ERROR], False, 2),
    ],
)
def test_exit_code(statuses: list[Status], strict: bool, code: int) -> None:
    assert exit_code([_f(s) for s in statuses], strict) == code


def test_finding_defaults_are_independent() -> None:
    a, b = _f(Status.PASS), _f(Status.PASS)
    a.evidence.append("x")
    assert b.evidence == []
