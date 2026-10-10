"""Run orchestration: test selection, ordering, the egress window and error handling."""

from collections.abc import Callable

import pytest

from leakprobe import orchestrator
from leakprobe.lab.profile import TEST_IDS
from leakprobe.models import Finding, Severity, Status
from leakprobe.orchestrator import RunOptions, run, run_tests, select_tests
from leakprobe.tests_impl.context import RunContext

CTX = RunContext(
    mode="lab", client_ns="lp-client", physical="c-phys", tunnel="wg0",
    endpoint_ip="203.0.113.10", endpoint_port=51820, tunnel_dns="10.66.0.1",
)


def _finding(test_id: str, status: Status = Status.PASS) -> Finding:
    return Finding(
        test_id=test_id, title=test_id, status=status, severity=Severity.HIGH, summary="ok"
    )


class Recorder:
    """Stub runners that log the order of events."""

    def __init__(self, statuses: dict[str, Status] | None = None) -> None:
        self.log: list[str] = []
        self.statuses = statuses or {}

    def runner(self, test_id: str) -> Callable[[RunContext], Finding]:
        def fn(ctx: RunContext) -> Finding:
            self.log.append(test_id)
            return _finding(test_id, self.statuses.get(test_id, Status.PASS))
        return fn

    def runners(self) -> dict[str, Callable[[RunContext], Finding]]:
        return {t: self.runner(t) for t in TEST_IDS if t != orchestrator.EGRESS}

    def egress(self, ctx: RunContext, during: Callable[[], None]) -> Finding:
        self.log.append("egress-start")
        during()
        self.log.append("egress-stop")
        return _finding(orchestrator.EGRESS, self.statuses.get(orchestrator.EGRESS, Status.PASS))


def test_select_all_and_subset() -> None:
    assert select_tests("all") == TEST_IDS
    assert select_tests("lp-kill-01, LP-DNS-01") == ("LP-DNS-01", "LP-KILL-01")


@pytest.mark.parametrize("spec", ["LP-FOO-01", "", " , "])
def test_select_rejects_unknown(spec: str) -> None:
    with pytest.raises(ValueError, match="unknown test id"):
        select_tests(spec)


def test_disruptive_tests_run_after_the_egress_window() -> None:
    rec = Recorder()
    findings = run_tests(CTX, RunOptions(), rec.runners(), rec.egress)
    assert rec.log == [
        "egress-start", "LP-ROUTE-01", "LP-V6-01", "LP-DNS-01", "LP-SPLIT-01", "LP-IDENT-01",
        "egress-stop", "LP-START-01", "LP-KILL-01",
    ]
    assert [f.test_id for f in findings] == list(TEST_IDS)


def test_subset_without_egress_has_no_capture_window() -> None:
    rec = Recorder()
    opts = RunOptions(tests=select_tests("LP-KILL-01,LP-DNS-01"))
    findings = run_tests(CTX, opts, rec.runners(), rec.egress)
    assert rec.log == ["LP-DNS-01", "LP-KILL-01"]
    assert [f.test_id for f in findings] == ["LP-DNS-01", "LP-KILL-01"]


def test_crashing_test_becomes_error_and_others_still_run() -> None:
    rec = Recorder()
    runners = rec.runners()

    def boom(ctx: RunContext) -> Finding:
        raise RuntimeError("tcpdump vanished")

    runners["LP-DNS-01"] = boom
    findings = {f.test_id: f for f in run_tests(CTX, RunOptions(), runners, rec.egress)}
    assert findings["LP-DNS-01"].status is Status.ERROR
    assert "tcpdump vanished" in findings["LP-DNS-01"].summary
    assert findings["LP-DNS-01"].severity is Severity.HIGH
    assert findings["LP-KILL-01"].status is Status.PASS
    assert len(findings) == len(TEST_IDS)


def test_progress_callback_sees_every_test() -> None:
    rec, seen = Recorder(), []
    run_tests(CTX, RunOptions(), rec.runners(), rec.egress, seen.append)
    assert sorted(seen) == sorted(TEST_IDS)


def test_run_builds_report_with_remediation() -> None:
    rec = Recorder({"LP-KILL-01": Status.FAIL, "LP-SPLIT-01": Status.WARN})
    rep = run(CTX, RunOptions(trials=3), {"profile": "p"}, runners=rec.runners(),
              egress=rec.egress)
    assert rep.mode == "lab" and rep.overall is Status.FAIL
    assert rep.environment["profile"] == "p"
    assert rep.environment["fault"] == "link-down x 3 trials"
    assert rep.environment["endpoint"] == "203.0.113.10:51820"
    by_id = {f.test_id: f for f in rep.findings}
    assert "leakprobe_killswitch" in (by_id["LP-KILL-01"].remediation or "")
    assert by_id["LP-SPLIT-01"].remediation
    assert by_id["LP-ROUTE-01"].remediation is None


def test_from_real_context() -> None:
    ctx = RunContext.from_real("wg0", "eth0", "[2001:db8::1]:51820", "192.0.2.50", ["192.0.2.9"])
    assert (ctx.mode, ctx.client_ns, ctx.endpoint_ip, ctx.endpoint_port) == (
        "real", None, "2001:db8::1", 51820
    )
    assert ctx.beacon == ctx.canary == "192.0.2.50"
    assert ctx.expected_exits == ("192.0.2.9",)
    with pytest.raises(ValueError):
        RunContext.from_real("wg0", "eth0", "203.0.113.10", "not-an-ip")
