"""``leakprobe run``: run the selected tests in a safe order and assemble the report.

Non-disruptive tests run first, inside one LP-EGRESS-01 capture window, so the egress audit
reflects normal operation. LP-START-01 and LP-KILL-01 tear the tunnel down on purpose and
run afterwards, outside that window.
"""

import platform
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from leakprobe.lab.profile import TEST_IDS
from leakprobe.models import Finding, Report, Severity, Status, make_report
from leakprobe.report.remediation import FixContext, with_remediation
from leakprobe.tests_impl.context import RunContext
from leakprobe.tests_impl.dns_leak import run_dns
from leakprobe.tests_impl.egress import run_egress
from leakprobe.tests_impl.identity import run_identity
from leakprobe.tests_impl.ipv6_leak import run_ipv6
from leakprobe.tests_impl.killswitch import run_killswitch
from leakprobe.tests_impl.route_audit import run_route
from leakprobe.tests_impl.split import run_split
from leakprobe.tests_impl.startup import run_startup

EGRESS = "LP-EGRESS-01"
DISRUPTIVE = ("LP-START-01", "LP-KILL-01")  # run last, in this order
SEVERITY = {
    "LP-ROUTE-01": Severity.HIGH, "LP-V6-01": Severity.HIGH, "LP-DNS-01": Severity.HIGH,
    "LP-KILL-01": Severity.CRITICAL, "LP-START-01": Severity.MEDIUM, "LP-SPLIT-01": Severity.LOW,
    "LP-EGRESS-01": Severity.HIGH, "LP-IDENT-01": Severity.HIGH,
}

Runner = Callable[[RunContext], Finding]
EgressRunner = Callable[[RunContext, Callable[[], None]], Finding]


@dataclass(frozen=True)
class RunOptions:
    """Which tests to run and how hard to push the disruptive ones."""

    tests: tuple[str, ...] = TEST_IDS
    trials: int = 20
    method: str = "link-down"
    pre_s: float = 2.0
    post_s: float = 3.0
    rate: float = 100.0


def select_tests(spec: str) -> tuple[str, ...]:
    """Parse ``all`` or a comma-separated list of test IDs into catalogue order."""
    if spec.strip().lower() == "all":
        return TEST_IDS
    wanted = {s.strip().upper() for s in spec.split(",") if s.strip()}
    unknown = wanted - set(TEST_IDS)
    if unknown or not wanted:
        bad = ", ".join(sorted(unknown)) or "none given"
        raise ValueError(f"unknown test id(s): {bad}; choose from all, {', '.join(TEST_IDS)}")
    return tuple(t for t in TEST_IDS if t in wanted)


def default_runners(opts: RunOptions) -> dict[str, Runner]:
    """The live implementation of every test except LP-EGRESS-01 (which wraps the others)."""
    return {
        "LP-ROUTE-01": run_route,
        "LP-V6-01": run_ipv6,
        "LP-DNS-01": run_dns,
        "LP-SPLIT-01": run_split,
        "LP-IDENT-01": run_identity,
        "LP-START-01": lambda ctx: run_startup(ctx, rate=opts.rate),
        "LP-KILL-01": lambda ctx: run_killswitch(
            ctx, opts.method, opts.trials, opts.pre_s, opts.post_s, opts.rate
        ),
    }


def error_finding(test_id: str, exc: BaseException) -> Finding:
    """A test that crashed becomes an ERROR finding instead of aborting the run."""
    return Finding(
        test_id=test_id, title=test_id, status=Status.ERROR,
        severity=SEVERITY.get(test_id, Severity.INFO),
        summary=f"Test crashed: {type(exc).__name__}: {exc}",
    )


def run_tests(
    ctx: RunContext,
    opts: RunOptions,
    runners: Mapping[str, Runner] | None = None,
    egress: EgressRunner = run_egress,
    on_start: Callable[[str], None] = lambda test_id: None,
) -> list[Finding]:
    """Run ``opts.tests``; return findings in catalogue order."""
    runners = runners if runners is not None else default_runners(opts)
    results: dict[str, Finding] = {}

    def run_one(test_id: str) -> None:
        on_start(test_id)
        try:
            results[test_id] = egress(ctx, passive) if test_id == EGRESS else runners[test_id](ctx)
        except Exception as exc:  # one broken test must not lose the others' results
            results[test_id] = error_finding(test_id, exc)

    def passive() -> None:
        for test_id in opts.tests:
            if test_id != EGRESS and test_id not in DISRUPTIVE:
                run_one(test_id)

    if EGRESS in opts.tests:
        run_one(EGRESS)
    else:
        passive()
    for test_id in DISRUPTIVE:
        if test_id in opts.tests:
            run_one(test_id)
    return [results[t] for t in TEST_IDS if t in results]


def fix_context(ctx: RunContext) -> FixContext:
    """Names the remediation snippets need, taken from the run context."""
    return FixContext(ctx.tunnel, ctx.physical, ctx.endpoint_ip, ctx.endpoint_port, ctx.tunnel_dns)


def environment(ctx: RunContext, opts: RunOptions, extra: Mapping[str, str]) -> dict[str, str]:
    """Report environment block."""
    env = {
        "kernel": platform.release(),
        "vpn": "wireguard",
        "tunnel": ctx.tunnel,
        "physical": ctx.physical,
        "endpoint": f"{ctx.endpoint_ip}:{ctx.endpoint_port}" if ctx.endpoint_port
        else ctx.endpoint_ip,
        "tests": ",".join(opts.tests),
    }
    if any(t in opts.tests for t in DISRUPTIVE):
        env["fault"] = f"{opts.method} x {opts.trials} trials"
    return {**env, **extra}


def run(
    ctx: RunContext,
    opts: RunOptions,
    extra_env: Mapping[str, str] | None = None,
    on_start: Callable[[str], None] = lambda test_id: None,
    runners: Mapping[str, Runner] | None = None,
    egress: EgressRunner = run_egress,
) -> Report:
    """Run the tests, attach remediation and build the report."""
    findings = run_tests(ctx, opts, runners, egress, on_start)
    findings = with_remediation(findings, fix_context(ctx))
    return make_report(findings, ctx.mode, environment(ctx, opts, extra_env or {}))

