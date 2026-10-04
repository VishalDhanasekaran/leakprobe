"""Read sysctls that matter for leaks: IPv6 disable flags and rp_filter."""

from leakprobe.util import netns, sh


def read(key: str, ns: str | None = None) -> str | None:
    """Value of ``key`` (e.g. ``net.ipv6.conf.eth0.disable_ipv6``), or None if unreadable."""
    argv = ["sysctl", "-n", key]
    result = netns.run(ns, argv, check=False) if ns else sh.run(argv, check=False)
    return result.stdout.strip() if result.ok else None


def ipv6_disabled(iface: str, ns: str | None = None) -> bool:
    """True when IPv6 is disabled on ``iface`` (or globally)."""
    keys = (f"net.ipv6.conf.{iface}.disable_ipv6", "net.ipv6.conf.all.disable_ipv6")
    return any(read(k, ns) == "1" for k in keys)


def rp_filter(iface: str, ns: str | None = None) -> int | None:
    """Effective reverse-path filter mode: the max of ``all`` and the interface value."""
    values = [read(f"net.ipv4.conf.{name}.rp_filter", ns) for name in ("all", iface)]
    known = [int(v) for v in values if v is not None and v.isdigit()]
    return max(known) if known else None
