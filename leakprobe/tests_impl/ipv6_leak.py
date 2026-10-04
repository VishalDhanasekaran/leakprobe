"""LP-V6-01: IPv6 must be tunneled (or disabled); none may leave on the physical interface."""

from collections.abc import Sequence

from leakprobe.analyzers.packet_classifier import (
    ClassifierContext,
    LeakReason,
    PacketClass,
    classify,
)
from leakprobe.analyzers.route_predictor import RouteDecision, predict_egress
from leakprobe.capture.pcap import capture_while
from leakprobe.collectors import routes, sysctl
from leakprobe.models import Finding, PacketRecord, Severity, Status
from leakprobe.probes.runner import run_probe
from leakprobe.tests_impl.context import RunContext

TEST_ID = "LP-V6-01"
TITLE = "IPv6 leak"


def evaluate_ipv6(
    decision: RouteDecision,
    tunnel: str,
    ipv6_disabled: bool,
    packets: Sequence[PacketRecord],
    classifier: ClassifierContext,
) -> Finding:
    """Static check (route / sysctl) plus the dynamic capture."""
    leaks = [
        p for p in packets
        if p.l3 == "ipv6" and classify(p, classifier).cls is PacketClass.LEAK
    ]
    dns_leaks = sum(classify(p, classifier).reason is LeakReason.DNS for p in leaks)
    static_ok = ipv6_disabled or decision.dev == tunnel or decision.blocked
    evidence = [
        f"route: {decision.dst} -> {decision.dev or 'blocked'} ({decision.reason})",
        f"IPv6 disabled on physical interface: {'yes' if ipv6_disabled else 'no'}",
        f"IPv6 packets leaked on physical interface: {len(leaks)}",
    ]
    evidence += [f"leak: {p.proto} {p.src} -> [{p.dst}]:{p.dport}" for p in leaks[:5]]
    metrics: dict[str, float | int | str] = {
        "ipv6_leak_packets": len(leaks),
        "ipv6_dns_leaks": dns_leaks,
        "static": "ok" if static_ok else "not tunneled",
    }
    if leaks:
        status, summary = Status.FAIL, f"{len(leaks)} IPv6 packets left outside the tunnel"
    elif not static_ok:
        status = Status.WARN
        summary = "IPv6 is routed outside the tunnel, but no probe leaked (blocked elsewhere?)"
    else:
        status, summary = Status.PASS, "IPv6 is tunneled or disabled; no IPv6 leaked"
    return Finding(
        test_id=TEST_ID, title=TITLE, status=status, severity=Severity.HIGH,
        summary=summary, evidence=evidence, metrics=metrics,
    )


def run_ipv6(ctx: RunContext, count: int = 5) -> Finding:
    """Predict the IPv6 route, then send UDP to the IPv6 canary while capturing."""
    decision = predict_egress(ctx.canary6, routes.collect(ctx.client_ns))
    disabled = sysctl.ipv6_disabled(ctx.physical, ctx.client_ns)
    probe = ["udp", "--dst", ctx.canary6, "--port", str(ctx.canary_port), "--count", str(count)]
    _, packets = capture_while(
        ctx.physical, ctx.workdir / "v6.pcap", lambda: run_probe(ctx.client_ns, *probe),
        netns=ctx.client_ns,
    )
    return evaluate_ipv6(decision, ctx.tunnel, disabled, packets, ctx.classifier())
