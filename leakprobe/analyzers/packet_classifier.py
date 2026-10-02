"""Allowlist classifier: anything on the physical interface that is not endpoint or
housekeeping traffic (or LAN with --allow-lan) is a leak."""

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

from leakprobe.models import PacketRecord
from leakprobe.util.net import PRIVATE_NETS, IPNetwork

# NDP (133-137) plus MLD (130-132, 143): link-local IPv6 control the kernel sends by itself.
HOUSEKEEPING_ICMP6 = frozenset({130, 131, 132, 133, 134, 135, 136, 137, 143})
DHCP_PORTS = ({67, 68}, {546, 547})
DNS_PORTS = frozenset({53, 853})
DEFAULT_LAN = PRIVATE_NETS + tuple(
    ipaddress.ip_network(n) for n in ("169.254.0.0/16", "fe80::/10")
)
LAN_GROUPS = tuple(
    ipaddress.ip_network(n) for n in ("224.0.0.0/4", "255.255.255.255/32", "ff00::/8")
)


class PacketClass(StrEnum):
    """Allowlist class of a packet."""

    ENDPOINT = "endpoint"
    HOUSEKEEPING = "housekeeping"
    LAN = "lan"
    LEAK = "leak"


class LeakReason(StrEnum):
    """Why a LEAK packet matters."""

    DNS = "dns"
    IPV6 = "ipv6"
    OTHER = "other"


@dataclass(frozen=True)
class ClassifierContext:
    """What is allowed on the physical interface. ``endpoint_port`` None means any port."""

    endpoint_ip: str
    endpoint_port: int | None = None
    allow_lan: bool = False
    local_prefixes: tuple[IPNetwork, ...] = DEFAULT_LAN


@dataclass(frozen=True)
class Classification:
    """Class of a packet, with a reason for leaks."""

    cls: PacketClass
    reason: LeakReason | None = None


def _in(addr: str | None, nets: tuple[IPNetwork, ...]) -> bool:
    if addr is None:
        return False
    ip = ipaddress.ip_address(addr)
    return any(ip in n for n in nets)


def _is_endpoint(pkt: PacketRecord, ctx: ClassifierContext) -> bool:
    if pkt.proto not in ("udp", "tcp"):
        return False
    port_ok = ctx.endpoint_port is None
    return (pkt.dst == ctx.endpoint_ip and (port_ok or pkt.dport == ctx.endpoint_port)) or (
        pkt.src == ctx.endpoint_ip and (port_ok or pkt.sport == ctx.endpoint_port)
    )


def _is_housekeeping(pkt: PacketRecord) -> bool:
    if pkt.l3 == "arp":
        return True
    if pkt.proto == "icmp6" and pkt.icmp6_type in HOUSEKEEPING_ICMP6:
        return True
    return pkt.proto == "udp" and any({pkt.sport, pkt.dport} == ports for ports in DHCP_PORTS)


def _is_lan(pkt: PacketRecord, ctx: ClassifierContext) -> bool:
    return _in(pkt.src, ctx.local_prefixes) and (
        _in(pkt.dst, ctx.local_prefixes) or _in(pkt.dst, LAN_GROUPS)
    )


def classify(pkt: PacketRecord, ctx: ClassifierContext) -> Classification:
    """Classify one packet seen on the physical interface."""
    if _is_endpoint(pkt, ctx):
        return Classification(PacketClass.ENDPOINT)
    if _is_housekeeping(pkt):
        return Classification(PacketClass.HOUSEKEEPING)
    if ctx.allow_lan and _is_lan(pkt, ctx):
        return Classification(PacketClass.LAN)
    if pkt.proto in ("udp", "tcp") and DNS_PORTS & {pkt.sport, pkt.dport}:
        return Classification(PacketClass.LEAK, LeakReason.DNS)
    if pkt.l3 == "ipv6":
        return Classification(PacketClass.LEAK, LeakReason.IPV6)
    return Classification(PacketClass.LEAK, LeakReason.OTHER)
