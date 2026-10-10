"""LP-EGRESS-01: every packet on the physical interface must be endpoint or housekeeping."""

from collections import Counter
from collections.abc import Callable, Sequence
from contextlib import suppress

from leakprobe.analyzers.packet_classifier import (
    ClassifierContext,
    LeakReason,
    PacketClass,
    classify,
)
from leakprobe.capture.pcap import capture_while
from leakprobe.models import Finding, PacketRecord, Severity, Status
from leakprobe.probes.runner import run_probe
from leakprobe.tests_impl.context import RunContext
from leakprobe.util import sh

TEST_ID = "LP-EGRESS-01"
TITLE = "Allowlist audit"
MAX_FLOWS = 10


def _flow(pkt: PacketRecord, reason: LeakReason | None) -> str:
    dst = f"[{pkt.dst}]" if pkt.l3 == "ipv6" and pkt.dport is not None else pkt.dst
    dport = f":{pkt.dport}" if pkt.dport is not None else ""
    proto = pkt.proto or pkt.l3 or pkt.l2
    return f"{reason}: {proto} {pkt.src} -> {dst}{dport}"


def audit_egress(packets: Sequence[PacketRecord], ctx: ClassifierContext) -> Finding:
    """Classify all captured packets and FAIL on any LEAK."""
    classes: Counter[PacketClass] = Counter()
    reasons: Counter[LeakReason] = Counter()
    flows: Counter[str] = Counter()
    for pkt in packets:
        result = classify(pkt, ctx)
        classes[result.cls] += 1
        if result.cls is PacketClass.LEAK and result.reason is not None:
            reasons[result.reason] += 1
            flows[_flow(pkt, result.reason)] += 1

    metrics: dict[str, float | int | str] = {"packets": len(packets)}
    metrics |= {c.value: classes[c] for c in PacketClass}
    metrics |= {f"leak_{r.value}": reasons[r] for r in LeakReason}
    top = flows.most_common(MAX_FLOWS)
    evidence = [f"{flow} ({n} pkt{'s' if n > 1 else ''})" for flow, n in top]
    if len(flows) > MAX_FLOWS:
        evidence.append(f"... {len(flows) - MAX_FLOWS} more leaking flows")

    leaks = classes[PacketClass.LEAK]
    if not packets:
        status, summary = Status.WARN, "No packets captured on the physical interface"
    elif leaks:
        kinds = ", ".join(f"{r.value} {n}" for r, n in reasons.most_common())
        status, summary = Status.FAIL, f"{leaks} of {len(packets)} packets leaked ({kinds})"
    else:
        status = Status.PASS
        summary = f"All {len(packets)} packets were endpoint or housekeeping traffic"
    return Finding(
        test_id=TEST_ID, title=TITLE, status=status, severity=Severity.HIGH,
        summary=summary, evidence=evidence, metrics=metrics,
    )


def run_egress(ctx: RunContext, during: Callable[[], None] = lambda: None) -> Finding:
    """Capture the physical interface while ``during`` runs plus a short baseline probe.

    The orchestrator passes the non-disruptive tests as ``during``, so the finding covers
    normal operation; fault-injection tests run outside this window.
    """
    def work() -> None:
        for dst in (ctx.canary, ctx.canary6):
            # Baseline traffic only; an unreachable family must not abort the capture.
            with suppress(sh.ShError, ValueError):
                run_probe(ctx.client_ns, "udp", "--dst", dst, "--port", str(ctx.canary_port),
                          "--count", "3")
        during()

    _, packets = capture_while(ctx.physical, ctx.workdir / "egress.pcap", work, ctx.client_ns)
    return audit_egress(packets, ctx.classifier())
