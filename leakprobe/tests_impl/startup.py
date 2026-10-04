"""LP-START-01: no probe packet may leak while the tunnel is still coming up."""

import json
import subprocess
import time
from collections.abc import Sequence

from leakprobe.analyzers.leak_window import probe_leaks
from leakprobe.capture.pcap import Capture, parse_pcap
from leakprobe.faults.injector import (
    restore_tunnel,
    run_in,
    snapshot_tunnel,
    tunnel_exists,
)
from leakprobe.models import Finding, PacketRecord, Severity, Status
from leakprobe.probes.runner import spawn_probe
from leakprobe.tests_impl.context import RunContext

TEST_ID = "LP-START-01"
TITLE = "Startup race"


def evaluate_startup(
    leaks: Sequence[PacketRecord],
    t_bringup: float | None,
    t_ready: float | None,
    probe_sent: int,
    notes: Sequence[str] = (),
) -> Finding:
    """FAIL if any probe packet leaked before the tunnel was ready."""
    evidence = list(notes)
    metrics: dict[str, float | int | str] = {"leak_packets": len(leaks), "probe_sent": probe_sent}
    if t_bringup is not None and t_ready is not None:
        metrics["time_to_ready_ms"] = round((t_ready - t_bringup) * 1000, 1)
        evidence.append(f"tunnel ready {metrics['time_to_ready_ms']} ms after bring-up started")
    else:
        evidence.append("tunnel never became ready; every leaked probe packet counts")
    if leaks:
        span = (leaks[-1].ts - leaks[0].ts) * 1000
        metrics["leak_span_ms"] = round(span, 1)
        evidence.append(f"{len(leaks)} probe packets left on the physical interface over "
                        f"{span:.0f} ms before the tunnel was ready")
        if t_bringup is not None:
            before = sum(p.ts < t_bringup for p in leaks)
            evidence.append(f"{before} before bring-up started, {len(leaks) - before} during it")
    if probe_sent == 0:
        status, summary = Status.ERROR, "The probe sent no traffic"
    elif leaks:
        status, summary = Status.FAIL, f"{len(leaks)} probe packets leaked before the tunnel was up"
    else:
        status, summary = Status.PASS, "No probe packet leaked while the tunnel came up"
    return Finding(
        test_id=TEST_ID, title=TITLE, status=status, severity=Severity.MEDIUM,
        summary=summary, evidence=evidence, metrics=metrics,
    )


def wait_for_handshake(ns: str | None, tunnel: str, timeout: float) -> float | None:
    """Poll ``wg show <tun> latest-handshakes``; time.time() when one appears, or None."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = run_in(ns, ["wg", "show", tunnel, "latest-handshakes"], check=False).stdout
        if any(int(f[1]) > 0 for f in (line.split() for line in out.splitlines()) if len(f) == 2):
            return time.time()
        time.sleep(0.01)
    return None


def run_startup(
    ctx: RunContext,
    pre_s: float = 1.0,
    post_s: float = 1.0,
    rate: float = 100.0,
    ready_timeout: float = 10.0,
) -> Finding:
    """Tear the tunnel down, probe, bring it back up, and count leaks before the handshake."""
    notes: list[str] = []
    snap = None
    if tunnel_exists(ctx.client_ns, ctx.tunnel):
        snap = snapshot_tunnel(ctx.client_ns, ctx.tunnel)
        run_in(ctx.client_ns, ["ip", "link", "del", ctx.tunnel])
    else:
        notes.append(f"tunnel {ctx.tunnel} does not exist; there is nothing to bring up")

    ctx.workdir.mkdir(parents=True, exist_ok=True)
    pcap, out = ctx.workdir / "start.pcap", ctx.workdir / "start.json"
    out.unlink(missing_ok=True)
    capture = Capture(ctx.physical, pcap, ctx.client_ns)
    proc: subprocess.Popen[str] | None = None
    t_bringup = t_ready = None
    try:
        capture.start()
        proc = spawn_probe(
            ctx.client_ns, "--out", str(out), "stream", "--dst", ctx.canary,
            "--port", str(ctx.canary_port), "--rate", str(rate),
            "--duration", str(pre_s + ready_timeout + post_s + 5),
        )
        time.sleep(pre_s)
        if snap is not None:
            t_bringup = time.time()
            restore_tunnel(ctx.client_ns, ctx.tunnel, snap)  # the profile's bring-up
            t_ready = wait_for_handshake(ctx.client_ns, ctx.tunnel, ready_timeout)
        time.sleep(post_s)
    finally:
        if proc is not None:
            proc.terminate()  # the stream probe stops cleanly and writes its counters
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        time.sleep(0.2)
        capture.stop()
        if snap is not None:
            restore_tunnel(ctx.client_ns, ctx.tunnel, snap)  # no-op when already up
    sent = json.loads(out.read_text())["sent"] if out.exists() else 0
    end = t_ready if t_ready is not None else float("inf")
    leaks = probe_leaks(
        parse_pcap(pcap, ctx.physical), ctx.classifier(), ctx.canary, ctx.canary_port, end=end
    )
    return evaluate_startup(leaks, t_bringup, t_ready, sent, notes)
