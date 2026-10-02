"""LP-ROUTE-01: every external destination must egress via the tunnel; no bypass routes."""

import ipaddress
from collections.abc import Sequence

from leakprobe.analyzers.route_predictor import RouteDecision, predict_egress
from leakprobe.collectors.routes import Route, RoutingState
from leakprobe.models import Finding, Severity, Status
from leakprobe.util.net import LINK_SCOPE_NETS, PRIVATE_NETS, within

TEST_ID = "LP-ROUTE-01"
TITLE = "Route audit"
LAB_CANARY = "198.51.100.10"
DEFAULT_DESTINATIONS = ("1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111", LAB_CANARY)
TUNNELVISION = "more-specific route bypasses tunnel, TunnelVision-style, see CVE-2024-3661"
LAN_BYPASS = "routed LAN prefix bypasses tunnel (pass --allow-lan if intended)"


def _describe(d: RouteDecision) -> str:
    target = d.dev or "blocked"
    via = f" via {d.via}" if d.via else ""
    return f"{d.dst} -> {target}{via} ({d.reason})"


def _route_str(r: Route) -> str:
    via = f" via {r.gateway}" if r.gateway else ""
    return f"{r.dst}{via} dev {r.dev} (table {r.table})"


def tunnel_carries_ipv6(state: RoutingState, tunnels: Sequence[str], dests: Sequence[str]) -> bool:
    """True when some tunnel route covers an IPv6 test destination.

    A v4-only tunnel leaves IPv6 to LP-V6-01; LP-ROUTE-01 then audits IPv4 only.
    """
    v6 = [ipaddress.ip_address(d) for d in dests if ipaddress.ip_address(d).version == 6]
    return any(
        r.family == 6 and r.dev in tunnels and any(a in r.dst for a in v6) for r in state.routes
    )


def _exempt(route: Route, endpoints: Sequence[str], allow_lan: bool) -> bool:
    """Non-tunnel routes that are allowed: endpoint host route, link scope, local LAN."""
    net = route.dst
    if net.prefixlen == net.max_prefixlen and str(net.network_address) in endpoints:
        return True
    if within(net, LINK_SCOPE_NETS):
        return True
    # The directly connected private subnet is always needed; routed LAN prefixes need --allow-lan.
    return within(net, PRIVATE_NETS) and (route.gateway is None or allow_lan)


def find_bypasses(
    state: RoutingState,
    tunnels: Sequence[str],
    endpoints: Sequence[str] = (),
    allow_lan: bool = False,
    families: Sequence[int] = (4, 6),
) -> list[Route]:
    """Non-tunnel routes more specific than a default route that actually win a lookup."""
    bypasses = []
    for route in state.routes:
        if (
            route.type != "unicast"
            or route.family not in families
            or route.dev is None
            or route.dev in tunnels
            or route.dst.prefixlen == 0
            or _exempt(route, endpoints, allow_lan)
        ):
            continue
        net = route.dst
        sample = net.network_address + (1 if net.num_addresses > 1 else 0)
        if predict_egress(str(sample), state).route == route:
            bypasses.append(route)
    return bypasses


def audit_routes(
    state: RoutingState,
    tunnels: Sequence[str],
    endpoints: Sequence[str] = (),
    allow_lan: bool = False,
    destinations: Sequence[str] = DEFAULT_DESTINATIONS,
) -> Finding:
    """Run LP-ROUTE-01 against a routing state."""
    if not state.routes or not state.rules:
        return Finding(
            test_id=TEST_ID, title=TITLE, status=Status.ERROR, severity=Severity.HIGH,
            summary="No routing data collected",
        )

    families = [4, 6] if tunnel_carries_ipv6(state, tunnels, destinations) else [4]
    evidence: list[str] = []
    outside: list[RouteDecision] = []
    audited = [d for d in destinations if ipaddress.ip_address(d).version in families]
    for dst in destinations:
        decision = predict_egress(dst, state)
        if dst not in audited:
            evidence.append(f"{_describe(decision)} [IPv6 not tunneled; see LP-V6-01]")
            continue
        evidence.append(_describe(decision))
        if not decision.blocked and decision.dev not in tunnels:
            outside.append(decision)

    bypasses = find_bypasses(state, tunnels, endpoints, allow_lan, families)
    evidence += [f"bypass: {_route_str(r)}" for r in bypasses]

    audited_count = len(audited)
    metrics: dict[str, float | int | str] = {
        "destinations": audited_count,
        "outside_tunnel": len(outside),
        "bypass_routes": len(bypasses),
        "ipv6_audited": "yes" if 6 in families else "no",
    }
    if bypasses:
        lan_only = all(within(r.dst, PRIVATE_NETS) for r in bypasses)
        status, summary = Status.FAIL, LAN_BYPASS if lan_only else TUNNELVISION
    elif outside:
        devs = ", ".join(sorted({d.dev or "" for d in outside}))
        summary = f"{len(outside)} of {audited_count} test destinations egress via {devs}"
        status = Status.FAIL
    else:
        status = Status.PASS
        summary = f"All {audited_count} test destinations egress via {', '.join(tunnels)}"
    return Finding(
        test_id=TEST_ID, title=TITLE, status=status, severity=Severity.HIGH,
        summary=summary, evidence=evidence, metrics=metrics,
    )
