"""Fault injection for LP-KILL-01 / LP-START-01 (PLAN.md section 7). Needs root.

Every fault has ``inject()`` and ``restore()``; callers must call ``restore()`` in ``finally``.
Faults that destroy tunnel state snapshot it first (``wg showconf``, addresses, routes) and
rebuild it on restore. The snapshot, which holds the private key, lives only in memory.
"""

import json
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from leakprobe.util import netns, sh

METHODS = ("link-down", "delete-iface", "endpoint-block")


def _run(ns: str | None, argv: Sequence[str], **kw: Any) -> sh.ShResult:
    return netns.run(ns, argv, **kw) if ns else sh.run(argv, **kw)


def tunnel_exists(ns: str | None, tunnel: str) -> bool:
    """True when the tunnel interface exists in ``ns``."""
    return _run(ns, ["ip", "link", "show", "dev", tunnel], check=False).ok


@dataclass
class TunnelSnapshot:
    """Enough of a WireGuard interface to recreate it."""

    conf: str
    addresses: list[list[str]] = field(default_factory=list)  # ip args, e.g. ["-6", "addr", ...]
    routes: list[list[str]] = field(default_factory=list)  # ip args, e.g. ["-4", "route", ...]


def address_commands(addr_json: list[dict[str, Any]], tunnel: str) -> list[list[str]]:
    """``ip addr add`` argument lists from ``ip -j addr show dev <tunnel>``."""
    cmds = []
    for link in addr_json:
        for a in link.get("addr_info", []):
            if a.get("scope") == "link":
                continue
            fam = "-6" if a["family"] == "inet6" else "-4"
            extra = ["nodad"] if fam == "-6" else []
            cmds.append([fam, "addr", "add", f"{a['local']}/{a['prefixlen']}", "dev", tunnel,
                         *extra])
    return cmds


def route_commands(route_json: list[dict[str, Any]], family: int, tunnel: str) -> list[list[str]]:
    """``ip route add`` lists for non-kernel unicast routes from ``ip -j route show ... dev``."""
    cmds = []
    for r in route_json:
        table = str(r.get("table", "main"))
        if "type" in r or r.get("protocol") == "kernel" or table == "local":
            continue
        cmd = [f"-{family}", "route", "add", r["dst"], "dev", tunnel]
        if table != "main":
            cmd += ["table", table]
        if "metric" in r:
            cmd += ["metric", str(r["metric"])]
        cmds.append(cmd)
    return cmds


def snapshot_tunnel(ns: str | None, tunnel: str) -> TunnelSnapshot:
    """Capture config, addresses and routes of ``tunnel``."""
    conf = _run(ns, ["wg", "showconf", tunnel]).stdout
    addrs = json.loads(_run(ns, ["ip", "-j", "addr", "show", "dev", tunnel]).stdout or "[]")
    routes: list[list[str]] = []
    for fam in (4, 6):
        out = _run(ns, ["ip", "-j", f"-{fam}", "route", "show", "table", "all", "dev", tunnel])
        routes += route_commands(json.loads(out.stdout or "[]"), fam, tunnel)
    return TunnelSnapshot(conf, address_commands(addrs, tunnel), routes)


def restore_tunnel(ns: str | None, tunnel: str, snap: TunnelSnapshot) -> None:
    """Recreate ``tunnel`` from a snapshot; steps that already hold are skipped quietly."""
    if not tunnel_exists(ns, tunnel):
        _run(ns, ["ip", "link", "add", tunnel, "type", "wireguard"])
        _run(ns, ["wg", "setconf", tunnel, "/dev/stdin"], input_text=snap.conf)
    _run(ns, ["ip", "link", "set", tunnel, "up"])
    for cmd in snap.addresses + snap.routes:
        _run(ns, ["ip", *cmd], check=False)  # "File exists" is fine


class Fault(ABC):
    """A reversible failure."""

    name: str

    @abstractmethod
    def inject(self) -> None:
        """Break something."""

    @abstractmethod
    def restore(self) -> None:
        """Undo ``inject``; safe to call even if ``inject`` failed or never ran."""


class NoFault(Fault):
    """Used when there is no tunnel to break: measures the baseline instead."""

    name = "none"

    def inject(self) -> None:
        pass

    def restore(self) -> None:
        pass


class _TunnelFault(Fault):
    def __init__(self, ns: str | None, tunnel: str) -> None:
        self.ns, self.tunnel = ns, tunnel
        self._snap: TunnelSnapshot | None = None

    def inject(self) -> None:
        self._snap = snapshot_tunnel(self.ns, self.tunnel)
        self._break()

    @abstractmethod
    def _break(self) -> None: ...

    def restore(self) -> None:
        if self._snap is not None:
            restore_tunnel(self.ns, self.tunnel, self._snap)
            self._snap = None


class LinkDown(_TunnelFault):
    """``ip link set <tun> down``: client crash or manual disconnect."""

    name = "link-down"

    def _break(self) -> None:
        _run(self.ns, ["ip", "link", "set", self.tunnel, "down"])


class DeleteIface(_TunnelFault):
    """``ip link del <tun>``: tunnel torn down and its routes removed."""

    name = "delete-iface"

    def _break(self) -> None:
        _run(self.ns, ["ip", "link", "del", self.tunnel])


def block_ruleset(endpoint_ip: str) -> str:
    """nftables table that drops all traffic to and from the endpoint."""
    fam = "ip6" if ":" in endpoint_ip else "ip"
    return (
        "table inet leakprobe_fault {\n"
        "  chain forward { type filter hook forward priority -10; policy accept;\n"
        f"    {fam} daddr {endpoint_ip} drop\n    {fam} saddr {endpoint_ip} drop\n  }}\n"
        "  chain output { type filter hook output priority -10; policy accept;\n"
        f"    {fam} daddr {endpoint_ip} drop\n  }}\n"
        "}\n"
    )


class EndpointBlock(Fault):
    """Drop endpoint traffic upstream (the ISP in the lab): server gone, interface still up."""

    name = "endpoint-block"

    def __init__(self, ns: str | None, endpoint_ip: str) -> None:
        self.ns, self.endpoint_ip = ns, endpoint_ip

    def inject(self) -> None:
        _run(self.ns, ["nft", "-f", "-"], input_text=block_ruleset(self.endpoint_ip))

    def restore(self) -> None:
        _run(self.ns, ["nft", "delete", "table", "inet", "leakprobe_fault"], check=False)


def make_fault(
    method: str, client_ns: str | None, tunnel: str, block_ns: str | None, endpoint_ip: str
) -> Fault:
    """Build the injector for ``method`` (one of METHODS)."""
    if method == "link-down":
        return LinkDown(client_ns, tunnel)
    if method == "delete-iface":
        return DeleteIface(client_ns, tunnel)
    if method == "endpoint-block":
        return EndpointBlock(block_ns, endpoint_ip)
    raise ValueError(f"unknown fault method {method!r}; choose from {', '.join(METHODS)}")
