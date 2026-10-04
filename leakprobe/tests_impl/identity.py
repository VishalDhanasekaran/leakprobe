"""LP-IDENT-01: the beacon must see our expected VPN exit address."""

from collections.abc import Sequence

from leakprobe.models import Finding, Severity, Status
from leakprobe.probes.runner import run_probe
from leakprobe.tests_impl.context import RunContext

TEST_ID = "LP-IDENT-01"
TITLE = "Egress identity"


def evaluate_identity(
    observed: str | None, expected: Sequence[str], error: str | None = None
) -> Finding:
    """PASS only when the observed source IP is one of the expected exits."""
    evidence = [f"expected exit: {', '.join(expected) or 'none given'}"]
    evidence.append(f"beacon saw: {observed}" if observed else f"beacon unreachable: {error}")
    metrics: dict[str, float | int | str] = {"observed": observed or "none"}
    if observed is None:
        status, summary = Status.WARN, "Beacon unreachable; egress identity unknown"
    elif not expected:
        status, summary = Status.WARN, f"Beacon saw {observed}; no expected exit to compare"
    elif observed in expected:
        status, summary = Status.PASS, f"Beacon saw the VPN exit {observed}"
    else:
        status, summary = Status.FAIL, f"Beacon saw {observed}, not the VPN exit"
    return Finding(
        test_id=TEST_ID, title=TITLE, status=status, severity=Severity.HIGH,
        summary=summary, evidence=evidence, metrics=metrics,
    )


def run_identity(ctx: RunContext) -> Finding:
    """Connect to the beacon from the client and compare what it reports."""
    result = run_probe(ctx.client_ns, "ident", "--host", ctx.beacon, "--port", str(ctx.beacon_port))
    return evaluate_identity(result.get("observed"), ctx.expected_exits, result.get("error"))
