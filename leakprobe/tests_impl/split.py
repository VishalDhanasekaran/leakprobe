"""LP-SPLIT-01: sockets and policy rules that let traffic bypass the tunnel. WARN only."""

import ipaddress
from collections.abc import Sequence

from leakprobe.collectors import routes, sockets
from leakprobe.collectors.routes import Rule
from leakprobe.collectors.sockets import Socket
from leakprobe.faults.injector import run_in
from leakprobe.models import Finding, Severity, Status
from leakprobe.tests_impl.context import RunContext
from leakprobe.util.net import LINK_SCOPE_NETS, IPAddress, IPInterface

TEST_ID = "LP-SPLIT-01"
TITLE = "Split-tunnel audit"
LIMITATION = (
    "limitation: only sockets bound to a physical address, or whose device binding ss "
    "reports (%iface), are visible; per-socket SO_MARK and other per-app routing are not"
)
WILDCARDS = {"*", "0.0.0.0", "::"}


def _addr(text: str) -> str:
    return text.removeprefix("::ffff:")


def _ip(text: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None


def _link_scope(text: str) -> bool:
    ip = _ip(text)
    return ip is not None and any(ip in n for n in LINK_SCOPE_NETS)


def _is_lan(peer: str, physical: Sequence[IPInterface]) -> bool:
    ip = _ip(peer)
    return ip is not None and (any(ip in i.network for i in physical) or _link_scope(peer))


def bypass_sockets(
    socks: Sequence[Socket], physical: Sequence[IPInterface], physical_dev: str, endpoint_ip: str
) -> list[Socket]:
    """Sockets pinned to the physical side whose peer is neither the endpoint nor the LAN."""
    own_ips = {str(i.ip) for i in physical}
    flagged = []
    for s in socks:
        local = _addr(s.local_addr)
        pinned = local in own_ips or s.iface == physical_dev
        # Listeners only accept inbound; link-local sockets (e.g. DHCPv6) cannot leave the link.
        if not pinned or s.state == "LISTEN" or _link_scope(local):
            continue
        peer = _addr(s.peer_addr)
        if peer == endpoint_ip or (peer not in WILDCARDS and _is_lan(peer, physical)):
            continue
        flagged.append(s)
    return flagged


def bypass_rules(rules: Sequence[Rule], vpn_fwmark: int | None) -> list[Rule]:
    """``ip rule`` entries with a uidrange, or an fwmark that is not the VPN client's."""
    return [
        r for r in rules
        if "uid_start" in r.unmodelled or (r.fwmark is not None and r.fwmark != vpn_fwmark)
    ]


def _socket_str(s: Socket) -> str:
    who = f" ({s.process}, pid {s.pid})" if s.process else ""
    dev = f"%{s.iface}" if s.iface else ""
    return f"{s.proto} {s.local_addr}{dev}:{s.local_port} -> {s.peer_addr}:{s.peer_port}{who}"


def _rule_str(r: Rule) -> str:
    parts = [f"{r.priority}:", "not" if r.invert else ""]
    if r.fwmark is not None:
        parts.append(f"fwmark {r.fwmark:#x}")
    if "uid_start" in r.unmodelled:
        parts.append("uidrange")
    parts.append(f"lookup {r.table}" if r.table else r.action)
    return f"rule IPv{r.family} " + " ".join(p for p in parts if p)


def evaluate_split(
    socks: Sequence[Socket],
    physical: Sequence[IPInterface],
    physical_dev: str,
    endpoint_ip: str,
    rules: Sequence[Rule],
    vpn_fwmark: int | None,
) -> Finding:
    """WARN when bypass sockets or rules exist; never FAIL (visibility is partial)."""
    bad_socks = bypass_sockets(socks, physical, physical_dev, endpoint_ip)
    bad_rules = bypass_rules(rules, vpn_fwmark)
    evidence = [f"socket: {_socket_str(s)}" for s in bad_socks]
    evidence += [_rule_str(r) for r in bad_rules]
    evidence.append(LIMITATION)
    metrics: dict[str, float | int | str] = {
        "bypass_sockets": len(bad_socks), "bypass_rules": len(bad_rules),
    }
    if bad_socks or bad_rules:
        status = Status.WARN
        summary = (f"{len(bad_socks)} socket(s) and {len(bad_rules)} rule(s) can send traffic "
                   "outside the tunnel")
    else:
        status, summary = Status.PASS, "No sockets or rules that bypass the tunnel were found"
    return Finding(
        test_id=TEST_ID, title=TITLE, status=status, severity=Severity.LOW,
        summary=summary, evidence=evidence, metrics=metrics,
    )


def vpn_fwmark(ns: str | None, tunnel: str) -> int | None:
    """The fwmark the VPN client sets on its own packets (``wg show <tun> fwmark``)."""
    out = run_in(ns, ["wg", "show", tunnel, "fwmark"], check=False).stdout.strip()
    return int(out, 16) if out.startswith("0x") else None


def run_split(ctx: RunContext) -> Finding:
    """Collect sockets, physical addresses and rules in the client namespace."""
    return evaluate_split(
        sockets.collect(ctx.client_ns),
        routes.interface_addresses(ctx.physical, ctx.client_ns),
        ctx.physical,
        ctx.endpoint_ip,
        routes.collect(ctx.client_ns).rules,
        vpn_fwmark(ctx.client_ns, ctx.tunnel),
    )
