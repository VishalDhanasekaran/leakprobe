"""Predict the egress interface for a destination: policy rules, then longest prefix match."""

import ipaddress
from dataclasses import dataclass

from leakprobe.collectors.routes import Route, RoutingState, Rule
from leakprobe.util.net import IPAddress

BLOCKING = ("unreachable", "blackhole", "prohibit")


@dataclass(frozen=True)
class RouteDecision:
    """Where a packet to ``dst`` would go. ``dev`` is None when blocked or unroutable."""

    dst: str
    dev: str | None
    via: str | None = None
    table: str | None = None
    prefix: str | None = None
    rule_priority: int | None = None
    route: Route | None = None
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.dev is None


def _rule_matches(rule: Rule, dst: IPAddress, src: IPAddress | None, fwmark: int) -> bool:
    # Locally generated traffic has iif lo; selectors we cannot evaluate never match.
    if rule.unmodelled or (rule.iif is not None and rule.iif != "lo"):
        return False
    match = (
        (rule.src is None or (src is not None and src in rule.src))
        and (rule.dst is None or dst in rule.dst)
        and (rule.fwmark is None or (fwmark & rule.fwmask) == (rule.fwmark & rule.fwmask))
    )
    return match != rule.invert


def lookup(state: RoutingState, table: str, dst: IPAddress) -> Route | None:
    """Longest matching prefix in ``table``; ties broken by lowest metric."""
    candidates = [
        r
        for r in state.routes
        if r.table == table and r.family == dst.version and dst in r.dst and "dead" not in r.flags
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda r: (-r.dst.prefixlen, r.metric))


def predict_egress(
    dst: str, state: RoutingState, src: str | None = None, fwmark: int = 0
) -> RouteDecision:
    """Walk ``ip rule`` in priority order and resolve ``dst`` like the kernel would."""
    addr = ipaddress.ip_address(dst)
    src_addr = ipaddress.ip_address(src) if src else None
    rules = sorted((r for r in state.rules if r.family == addr.version), key=lambda r: r.priority)
    for rule in rules:
        if not _rule_matches(rule, addr, src_addr, fwmark):
            continue
        if rule.action in BLOCKING:
            reason = f"rule {rule.priority}: {rule.action}"
            return RouteDecision(dst, None, rule_priority=rule.priority, reason=reason)
        if rule.action != "lookup" or rule.table is None:
            continue
        route = lookup(state, rule.table, addr)
        if route is None or route.type == "throw":
            continue
        if rule.suppress_prefixlen is not None and route.dst.prefixlen <= rule.suppress_prefixlen:
            continue
        where = f"table {route.table}, {route.dst}, rule {rule.priority}"
        if route.type in BLOCKING:
            return RouteDecision(
                dst, None, table=route.table, prefix=str(route.dst), rule_priority=rule.priority,
                route=route, reason=f"{route.type} ({where})",
            )
        return RouteDecision(
            dst, route.dev, via=route.gateway, table=route.table, prefix=str(route.dst),
            rule_priority=rule.priority, route=route, reason=where,
        )
    return RouteDecision(dst, None, reason="no matching route")
