"""LP-KILL-01: inject a tunnel failure under steady probe traffic and measure the leak window."""

import json
import time
from collections.abc import Sequence

from leakprobe.analyzers.leak_window import TrialResult, analyze_trial, summarize_trials
from leakprobe.capture.pcap import Capture, parse_pcap
from leakprobe.faults.injector import Fault, NoFault, make_fault, tunnel_exists
from leakprobe.models import Finding, Severity, Status
from leakprobe.probes.runner import spawn_probe
from leakprobe.tests_impl.context import RunContext
from leakprobe.util import sh

TEST_ID = "LP-KILL-01"
TITLE = "Kill switch"
MAX_TRIAL_LINES = 5


def evaluate_killswitch(
    trials: Sequence[TrialResult], method: str, observe_s: float, notes: Sequence[str] = ()
) -> Finding:
    """FAIL if any completed trial leaked; ERROR if no trial completed."""
    metrics = summarize_trials(trials)
    metrics["method"] = method
    done = int(metrics["trials"])
    leaked = int(metrics["leaked_trials"])
    evidence = [
        *notes,
        f"method {method}, {len(trials)} trials, observed {observe_s * 1000:.0f} ms after "
        "each fault (leak windows cannot exceed this)",
    ]
    for i, t in enumerate(trials, 1):
        if t.error:
            evidence.append(f"trial {i}: error: {t.error}")
    shown = [(i, t) for i, t in enumerate(trials, 1) if t.leaked][:MAX_TRIAL_LINES]
    evidence += [
        f"trial {i}: {t.leak_packets} probe packets leaked, first after "
        f"{t.time_to_first_leak_ms:.1f} ms, last after {t.leak_window_ms:.1f} ms"
        for i, t in shown
    ]
    if done == 0 or metrics["probe_sent"] == 0:
        status, summary = Status.ERROR, "No trial completed with probe traffic"
    elif leaked:
        status = Status.FAIL
        summary = (
            f"Leaked in {leaked}/{done} trials after {method}: median "
            f"{metrics['leak_packets_median']:.0f} packets, p95 window "
            f"{metrics['leak_window_ms_p95']:.0f} ms"
        )
    else:
        status, summary = Status.PASS, f"No probe packet leaked in {done} trials after {method}"
    return Finding(
        test_id=TEST_ID, title=TITLE, status=status, severity=Severity.CRITICAL,
        summary=summary, evidence=evidence, metrics=metrics,
    )


def run_trial(
    ctx: RunContext, fault: Fault, index: int, pre_s: float, post_s: float, rate: float
) -> TrialResult:
    """One trial: capture + steady probe, fault, keep probing, stop, restore, analyze."""
    ctx.workdir.mkdir(parents=True, exist_ok=True)
    pcap = ctx.workdir / f"kill-{index}.pcap"
    out = ctx.workdir / f"kill-{index}.json"
    out.unlink(missing_ok=True)
    capture = Capture(ctx.physical, pcap, ctx.client_ns)
    capture.start()
    proc = None
    try:
        proc = spawn_probe(
            ctx.client_ns, "--out", str(out), "stream", "--dst", ctx.canary,
            "--port", str(ctx.canary_port), "--rate", str(rate), "--duration", str(pre_s + post_s),
        )
        time.sleep(pre_s)
        fault.inject()
        t_fault = time.time()  # PLAN.md 6.4: right after the fault command returns
        proc.wait(timeout=post_s + 15)
        time.sleep(0.2)  # let the last packets reach the capture
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
        capture.stop()
        fault.restore()
    probe = json.loads(out.read_text()) if out.exists() else {"sent": 0, "errors": 0}
    return analyze_trial(
        parse_pcap(pcap, ctx.physical), t_fault, ctx.classifier(), ctx.canary, ctx.canary_port,
        probe["sent"], probe["errors"],
    )


def run_killswitch(
    ctx: RunContext,
    method: str = "link-down",
    trials: int = 20,
    pre_s: float = 2.0,
    post_s: float = 3.0,
    rate: float = 100.0,
    settle_s: float = 1.0,
) -> Finding:
    """Repeat ``run_trial`` and summarize (PLAN.md 6.4)."""
    notes: list[str] = []
    fault: Fault
    if method != "endpoint-block" and not tunnel_exists(ctx.client_ns, ctx.tunnel):
        fault = NoFault()
        notes.append(f"tunnel {ctx.tunnel} does not exist; measuring traffic with no fault")
    else:
        fault = make_fault(method, ctx.client_ns, ctx.tunnel, ctx.fault_ns, ctx.endpoint_ip)
    results: list[TrialResult] = []
    for i in range(1, trials + 1):
        try:
            results.append(run_trial(ctx, fault, i, pre_s, post_s, rate))
        except (sh.ShError, RuntimeError, OSError, ValueError) as exc:
            results.append(TrialResult(error=str(exc)))
        time.sleep(settle_s)  # let the restored tunnel handshake again
    return evaluate_killswitch(results, method, post_s, notes)
