"""Fix snippets for failing or warning findings (PLAN.md section 9). Pure functions."""

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from leakprobe.lab.builder import killswitch_ruleset
from leakprobe.models import Finding, Status

BYPASS_LINE = re.compile(r"^bypass: (\S+)(?: via (\S+))? dev (\S+) \(table (\S+)\)$")
NEEDS_FIX = (Status.FAIL, Status.WARN)


@dataclass(frozen=True)
class FixContext:
    """Names to substitute into the snippets."""

    tunnel: str
    physical: str
    endpoint_ip: str
    endpoint_port: int | None = None
    tunnel_dns: str | None = None  # the resolver inside the tunnel, if known

    @property
    def dns(self) -> str:
        return self.tunnel_dns or "<tunnel resolver IP>"


def killswitch(ctx: FixContext) -> str:
    """nftables kill switch: only loopback, the tunnel and the endpoint may leave."""
    return (
        "# nftables kill switch (load with `nft -f`; keep it loaded before the tunnel starts)\n"
        + killswitch_ruleset("inet", ctx.tunnel, ctx.endpoint_ip, ctx.endpoint_port)
    )


def allowed_ips() -> str:
    """Full-tunnel WireGuard routing for both families."""
    return (
        "# WireGuard [Peer]: send every IPv4 and IPv6 destination through the tunnel\n"
        "AllowedIPs = 0.0.0.0/0, ::/0"
    )


def pin_dns(ctx: FixContext) -> str:
    """Use only the tunnel's resolver."""
    return (
        "# WireGuard [Interface] (wg-quick): use only the tunnel resolver\n"
        f"DNS = {ctx.dns}\n"
        "# with systemd-resolved: route every lookup to the tunnel link\n"
        f"resolvectl dns {ctx.tunnel} {ctx.dns}\n"
        f"resolvectl domain {ctx.tunnel} '~.'\n"
        f"resolvectl default-route {ctx.physical} false"
    )


def disable_ipv6(ctx: FixContext) -> str:
    """Turn IPv6 off on the physical interface when the tunnel cannot carry it."""
    return (
        "# or, if the VPN has no IPv6: disable IPv6 on the physical interface\n"
        f"sysctl -w net.ipv6.conf.{ctx.physical}.disable_ipv6=1"
    )


def delete_routes(evidence: Sequence[str]) -> str:
    """``ip route del`` for every ``bypass:`` line in LP-ROUTE-01's evidence."""
    cmds = []
    for line in evidence:
        m = BYPASS_LINE.match(line)
        if m is None:
            continue
        dst, via, dev, table = m.groups()
        family = "-6 " if ":" in dst else ""
        gateway = f" via {via}" if via else ""
        cmds.append(f"ip {family}route del {dst}{gateway} dev {dev} table {table}")
    return "\n".join(cmds)


def _route(f: Finding, ctx: FixContext) -> str:
    deletes = delete_routes(f.evidence)
    if not deletes:
        return allowed_ips() + "\n\n" + killswitch(ctx)
    return (
        "# remove the routes that bypass the tunnel\n" + deletes + "\n\n"
        "# stop DHCP from installing them again (DHCP option 121, TunnelVision)\n"
        f"nmcli connection modify <connection on {ctx.physical}> ipv4.ignore-auto-routes yes\n"
        "# dhclient: drop classless-static-routes from the `request` line in dhclient.conf\n\n"
        "# a kill switch turns any remaining bypass into dropped packets\n" + killswitch(ctx)
    )


def _ipv6(f: Finding, ctx: FixContext) -> str:
    return allowed_ips() + "\n\n" + disable_ipv6(ctx) + "\n\n" + killswitch(ctx)


def _dns(f: Finding, ctx: FixContext) -> str:
    return pin_dns(ctx) + "\n\n" + killswitch(ctx)


def _kill(f: Finding, ctx: FixContext) -> str:
    return killswitch(ctx)


def _start(f: Finding, ctx: FixContext) -> str:
    return (
        killswitch(ctx) + "\n"
        "# load it at boot, before the VPN client, e.g. enable nftables.service with this\n"
        "# ruleset in /etc/nftables.conf, or in wg-quick:\n"
        "PreUp = nft -f /etc/nftables.d/leakprobe-killswitch.nft"
    )


def _egress(f: Finding, ctx: FixContext) -> str:
    parts = [killswitch(ctx)]
    if f.metrics.get("leak_dns"):
        parts.append(pin_dns(ctx))
    if f.metrics.get("leak_ipv6"):
        parts += [allowed_ips(), disable_ipv6(ctx)]
    return "\n\n".join(parts)


def _ident(f: Finding, ctx: FixContext) -> str:
    return (
        "# traffic reaches the internet without the VPN exit: route it all via the tunnel\n"
        + allowed_ips() + "\n\n"
        "# and check LP-ROUTE-01 for more-specific routes that bypass it\n" + killswitch(ctx)
    )


def _split(f: Finding, ctx: FixContext) -> str:
    return (
        "# review each socket and rule listed above; if it is not intended:\n"
        "#  - stop the process, or configure it to bind to the tunnel address instead of the\n"
        f"#    {ctx.physical} address\n"
        "#  - delete the rule: ip rule del priority <N>   (ip -6 rule del ... for IPv6)\n"
        "# a kill switch still drops anything that tries to leave outside the tunnel\n"
        + killswitch(ctx)
    )


SNIPPETS: dict[str, Callable[[Finding, FixContext], str]] = {
    "LP-ROUTE-01": _route,
    "LP-V6-01": _ipv6,
    "LP-DNS-01": _dns,
    "LP-KILL-01": _kill,
    "LP-START-01": _start,
    "LP-SPLIT-01": _split,
    "LP-EGRESS-01": _egress,
    "LP-IDENT-01": _ident,
}


def remediation_for(finding: Finding, ctx: FixContext) -> str | None:
    """The fix snippet for a FAIL or WARN finding; None otherwise or for unknown tests."""
    snippet = SNIPPETS.get(finding.test_id)
    if finding.status not in NEEDS_FIX or snippet is None:
        return None
    return snippet(finding, ctx)


def with_remediation(findings: Sequence[Finding], ctx: FixContext) -> list[Finding]:
    """Copies of ``findings`` with remediation attached where one applies (kept if already set)."""
    return [
        f if f.remediation else f.model_copy(update={"remediation": remediation_for(f, ctx)})
        for f in findings
    ]
