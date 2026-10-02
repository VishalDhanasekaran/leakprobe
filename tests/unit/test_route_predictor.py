"""Policy-rule walk and longest-prefix match."""

import ipaddress
from pathlib import Path
from typing import Any

import pytest

from leakprobe.analyzers.route_predictor import lookup, predict_egress
from leakprobe.collectors import routes
from leakprobe.collectors.routes import RoutingState

FIXTURES = Path(__file__).parent.parent / "fixtures" / "routes"
MAIN = {"priority": 32766, "src": "all", "table": "main"}


def state(routes4: list[dict[str, Any]], rules4: list[dict[str, Any]]) -> RoutingState:
    return routes.parse_state({"routes4": routes4, "routes6": [], "rules4": rules4, "rules6": []})


def fixture(name: str) -> RoutingState:
    return routes.load(FIXTURES / f"{name}.json")


def test_longest_prefix_wins() -> None:
    s = state(
        [
            {"dst": "default", "dev": "eth0"},
            {"dst": "10.0.0.0/8", "dev": "eth1"},
            {"dst": "10.1.0.0/16", "dev": "eth2"},
        ],
        [MAIN],
    )
    assert predict_egress("10.1.2.3", s).dev == "eth2"
    assert predict_egress("10.9.9.9", s).dev == "eth1"
    assert predict_egress("1.1.1.1", s).dev == "eth0"


def test_metric_tie_break() -> None:
    s = state(
        [{"dst": "default", "dev": "slow", "metric": 600}, {"dst": "default", "dev": "fast",
          "metric": 100}],
        [MAIN],
    )
    assert predict_egress("1.1.1.1", s).dev == "fast"


def test_wg_quick_suppress_prefixlength() -> None:
    s = fixture("wg_quick_full")
    d = predict_egress("1.1.1.1", s)
    # rule 32764 (main, suppress_prefixlength 0) finds only the /0 and is skipped.
    assert (d.dev, d.table, d.rule_priority) == ("wg0", "51820", 32765)
    # The connected subnet is longer than /0, so suppression does not apply to it.
    lan = predict_egress("192.168.100.1", s)
    assert (lan.dev, lan.rule_priority) == ("c-phys", 32764)


def test_wg_fwmark_traffic_uses_main() -> None:
    d = predict_egress("203.0.113.10", fixture("wg_quick_full"), fwmark=0xCA6C)
    assert (d.dev, d.via, d.rule_priority) == ("c-phys", "192.168.100.1", 32766)


def test_suppress_larger_threshold() -> None:
    s = state(
        [{"dst": "10.0.0.0/8", "dev": "phys"}, {"dst": "default", "dev": "tun", "table": "7"}],
        [
            {"priority": 10, "src": "all", "table": "main", "suppress_prefixlen": 8},
            {"priority": 20, "src": "all", "table": "7"},
        ],
    )
    assert predict_egress("10.1.1.1", s).dev == "tun"


def test_ipv6_prediction() -> None:
    assert predict_egress("2606:4700:4700::1111", fixture("wg_quick_full")).dev == "wg0"
    d = predict_egress("2606:4700:4700::1111", fixture("wg_quick_v4only"))
    assert (d.dev, d.via) == ("c-phys", "fd00:100::1")


def test_blocking_rule_and_route() -> None:
    s = state(
        [{"dst": "default", "dev": "eth0"}, {"type": "blackhole", "dst": "9.9.9.0/24"}],
        [{"priority": 5, "src": "all", "dst": "8.8.8.0", "dstlen": 24, "action": "unreachable"},
         MAIN],
    )
    unreachable = predict_egress("8.8.8.8", s)
    assert unreachable.blocked and "unreachable" in unreachable.reason
    blackhole = predict_egress("9.9.9.9", s)
    assert blackhole.blocked and "blackhole" in blackhole.reason
    assert predict_egress("1.1.1.1", s).dev == "eth0"


def test_throw_falls_through() -> None:
    s = state(
        [{"type": "throw", "dst": "default", "table": "7"}, {"dst": "default", "dev": "eth0"}],
        [{"priority": 10, "src": "all", "table": "7"}, MAIN],
    )
    assert predict_egress("1.1.1.1", s).dev == "eth0"


@pytest.mark.parametrize(
    ("rule", "src", "uses_table_7"),
    [
        ({"src": "10.9.0.0", "srclen": 16}, None, False),  # unbound socket has no source yet
        ({"src": "10.9.0.0", "srclen": 16}, "10.9.1.1", True),
        ({"src": "all", "uid_start": 1000, "uid_end": 1000}, None, False),  # not modelled
        ({"src": "all", "iif": "lo"}, None, True),
        ({"src": "all", "iif": "eth0"}, None, False),
    ],
)
def test_rule_selectors(rule: dict[str, Any], src: str | None, uses_table_7: bool) -> None:
    s = state(
        [{"dst": "default", "dev": "tun", "table": "7"}, {"dst": "default", "dev": "eth0"}],
        [{"priority": 10, "table": "7", **rule}, MAIN],
    )
    assert (predict_egress("1.1.1.1", s, src=src).dev == "tun") is uses_table_7


def test_no_route() -> None:
    d = predict_egress("1.1.1.1", state([], [MAIN]))
    assert d.blocked and d.reason == "no matching route"


def test_lookup_ignores_other_tables_and_families() -> None:
    s = fixture("wg_quick_full")
    assert lookup(s, "local", ipaddress.ip_address("1.1.1.1")) is None
    assert lookup(s, "main", ipaddress.ip_address("fd00:100::9")).family == 6  # type: ignore[union-attr]
