"""Collect and parse routes and policy rules (IPv4 + IPv6, all tables) from ``ip -j``."""

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from leakprobe.util import sh
from leakprobe.util.net import IPInterface, IPNetwork

# Rule selectors the predictor cannot evaluate for generic traffic.
UNMODELLED_SELECTORS = ("uid_start", "oif", "ipproto", "sport", "dport", "tos", "dsfield", "l3mdev")
RAW_KEYS = ("routes4", "routes6", "rules4", "rules6")


@dataclass(frozen=True)
class Route:
    """One route from ``ip -j route show table all``."""

    family: int
    table: str
    dst: IPNetwork
    type: str = "unicast"
    dev: str | None = None
    gateway: str | None = None
    metric: int = 0
    protocol: str | None = None
    flags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    """One policy rule from ``ip -j rule``."""

    family: int
    priority: int
    action: str = "lookup"  # "lookup" or unreachable/blackhole/prohibit/goto/nop
    table: str | None = None
    invert: bool = False
    src: IPNetwork | None = None
    dst: IPNetwork | None = None
    fwmark: int | None = None
    fwmask: int = 0xFFFFFFFF
    iif: str | None = None
    suppress_prefixlen: int | None = None
    unmodelled: tuple[str, ...] = ()


@dataclass
class RoutingState:
    """All routes and rules of one host or namespace, plus the raw ``ip -j`` data."""

    routes: list[Route] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    raw: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def _network(value: str, family: int, length: int | None = None) -> IPNetwork:
    if value in ("default", "all"):
        return ipaddress.ip_network("0.0.0.0/0" if family == 4 else "::/0")
    if length is not None and "/" not in value:
        value = f"{value}/{length}"
    return ipaddress.ip_network(value, strict=False)


def parse_route(obj: dict[str, Any], family: int) -> Route:
    """Convert one ``ip -j route`` object. Routes without ``table`` live in ``main``."""
    dev = obj.get("dev")
    gateway = obj.get("gateway")
    if dev is None and obj.get("nexthops"):  # multipath: use the first hop
        hop = obj["nexthops"][0]
        dev, gateway = hop.get("dev"), hop.get("gateway")
    return Route(
        family=family,
        table=str(obj.get("table", "main")),
        dst=_network(obj["dst"], family),
        type=obj.get("type", "unicast"),
        dev=dev,
        gateway=gateway,
        metric=int(obj.get("metric", 0)),
        protocol=obj.get("protocol"),
        flags=tuple(obj.get("flags", ())),
    )


def parse_rule(obj: dict[str, Any], family: int) -> Rule:
    """Convert one ``ip -j rule`` object."""
    src = obj.get("src", "all")
    dst = obj.get("dst")
    return Rule(
        family=family,
        priority=int(obj["priority"]),
        action=obj.get("action", "lookup") if "table" not in obj else "lookup",
        table=obj.get("table"),
        invert="not" in obj,
        src=None if src == "all" else _network(src, family, obj.get("srclen")),
        dst=None if dst in (None, "all") else _network(dst, family, obj.get("dstlen")),
        fwmark=int(obj["fwmark"], 16) if "fwmark" in obj else None,
        fwmask=int(obj["fwmask"], 16) if "fwmask" in obj else 0xFFFFFFFF,
        iif=obj.get("iif"),
        suppress_prefixlen=obj.get("suppress_prefixlen"),
        unmodelled=tuple(k for k in UNMODELLED_SELECTORS if k in obj),
    )


def parse_state(raw: dict[str, list[dict[str, Any]]]) -> RoutingState:
    """Build a RoutingState from ``{"routes4", "routes6", "rules4", "rules6"}`` lists."""
    missing = [k for k in RAW_KEYS if k not in raw]
    if missing:
        raise ValueError(f"routing data missing keys: {', '.join(missing)}")
    routes = [parse_route(o, 4) for o in raw["routes4"]] + [
        parse_route(o, 6) for o in raw["routes6"]
    ]
    rules = [parse_rule(o, 4) for o in raw["rules4"]] + [parse_rule(o, 6) for o in raw["rules6"]]
    return RoutingState(routes=routes, rules=rules, raw=raw)


def collect_raw(ns: str | None = None) -> dict[str, list[dict[str, Any]]]:
    """Run ``ip -j`` for routes and rules in both families (in ``ns`` if given)."""
    prefix = ["ip", "-n", ns] if ns else ["ip"]

    def ip_json(*args: str) -> list[dict[str, Any]]:
        data: list[dict[str, Any]] = json.loads(sh.run([*prefix, "-j", *args]).stdout or "[]")
        return data

    return {
        "routes4": ip_json("-4", "route", "show", "table", "all"),
        "routes6": ip_json("-6", "route", "show", "table", "all"),
        "rules4": ip_json("-4", "rule"),
        "rules6": ip_json("-6", "rule"),
    }


def collect(ns: str | None = None) -> RoutingState:
    """Collect the live routing state of the current namespace, or of ``ns``."""
    return parse_state(collect_raw(ns))


def load(path: Path) -> RoutingState:
    """Load routing state saved with ``save`` (or by tests/fixtures/routes/generate.sh)."""
    return parse_state(json.loads(path.read_text()))


def save(state: RoutingState, path: Path) -> None:
    """Write the raw ``ip -j`` data so it can be audited later without root."""
    path.write_text(json.dumps(state.raw, indent=1) + "\n")


def parse_addresses(addr_json: list[dict[str, Any]]) -> list[IPInterface]:
    """Addresses (with prefix) from ``ip -j addr show``."""
    return [
        ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}")
        for link in addr_json
        for a in link.get("addr_info", [])
    ]


def interface_addresses(iface: str, ns: str | None = None) -> list[IPInterface]:
    """Addresses configured on ``iface`` (in ``ns`` if given); empty if it does not exist."""
    argv = ["ip", *(["-n", ns] if ns else []), "-j", "addr", "show", "dev", iface]
    result = sh.run(argv, check=False)
    return parse_addresses(json.loads(result.stdout or "[]")) if result.ok else []
