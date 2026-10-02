"""Address helpers shared by the route audit and the packet classifier."""

import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network

PRIVATE_NETS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
LINK_SCOPE_NETS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in ("169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fe80::/10", "ff00::/8")
)


def within(net: IPNetwork, parents: tuple[IPNetwork, ...]) -> bool:
    """True when ``net`` lies entirely inside one of ``parents`` (same family)."""
    return any(net.version == p.version and net.subnet_of(p) for p in parents)  # type: ignore[arg-type]


def parse_endpoint(text: str) -> tuple[str, int | None]:
    """Parse ``IP``, ``IP:PORT`` or ``[IPv6]:PORT`` into (normalised ip, port)."""
    host, port = text, None
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else None
    elif text.count(":") == 1:
        host, _, p = text.partition(":")
        port = int(p)
    return str(ipaddress.ip_address(host)), port
