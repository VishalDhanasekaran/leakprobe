"""Parsers for routes, rules, resolvers and sockets."""

import ipaddress
import json
from pathlib import Path

import pytest

from leakprobe.collectors import resolvers, routes, sockets

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parse_route_defaults_and_tables() -> None:
    r = routes.parse_route({"dst": "default", "gateway": "192.168.100.1", "dev": "c-phys"}, 4)
    assert r.table == "main" and r.type == "unicast" and r.metric == 0
    assert r.dst == ipaddress.ip_network("0.0.0.0/0")
    host = routes.parse_route({"type": "local", "dst": "10.66.0.2", "table": "local"}, 4)
    assert host.dst.prefixlen == 32 and host.type == "local"
    assert routes.parse_route({"dst": "default", "dev": "wg0"}, 6).dst.prefixlen == 0


def test_parse_route_multipath() -> None:
    obj = {"dst": "default", "nexthops": [{"gateway": "192.168.1.1", "dev": "eth0"}]}
    r = routes.parse_route(obj, 4)
    assert (r.dev, r.gateway) == ("eth0", "192.168.1.1")


def test_parse_rules_from_real_output() -> None:
    raw = [
        {"priority": 100, "src": "10.9.0.0", "srclen": 16, "dst": "1.2.3.0", "dstlen": 24,
         "uid_start": 0, "uid_end": 0, "table": "100"},
        {"priority": 200, "src": "all", "fwmark": "0x10", "fwmask": "0xff",
         "action": "unreachable"},
        {"priority": 32764, "src": "all", "table": "main", "suppress_prefixlen": 0},
        {"priority": 32765, "not": None, "src": "all", "fwmark": "0xca6c", "table": "51820"},
    ]
    uid, unreach, suppress, wg = (routes.parse_rule(o, 4) for o in raw)
    assert uid.src == ipaddress.ip_network("10.9.0.0/16")
    assert uid.dst == ipaddress.ip_network("1.2.3.0/24")
    assert uid.unmodelled == ("uid_start",)
    assert unreach.action == "unreachable" and unreach.fwmark == 0x10 and unreach.fwmask == 0xFF
    assert suppress.suppress_prefixlen == 0 and suppress.table == "main"
    assert wg.invert and wg.fwmark == 0xCA6C and wg.action == "lookup"


def test_load_fixture_has_both_families() -> None:
    state = routes.load(FIXTURES / "routes" / "wg_quick_full.json")
    assert {r.family for r in state.routes} == {4, 6}
    assert {r.family for r in state.rules} == {4, 6}


def test_save_round_trip(tmp_path: Path) -> None:
    state = routes.load(FIXTURES / "routes" / "tunnelvision.json")
    routes.save(state, tmp_path / "s.json")
    assert routes.load(tmp_path / "s.json").routes == state.routes


def test_parse_state_rejects_incomplete() -> None:
    with pytest.raises(ValueError, match="rules6"):
        routes.parse_state({"routes4": [], "routes6": [], "rules4": []})


def test_collect_raw_uses_explicit_families(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str]) -> routes.sh.ShResult:
        calls.append(list(args))
        return routes.sh.ShResult(tuple(args), 0, json.dumps([]), "")

    monkeypatch.setattr(routes.sh, "run", fake_run)
    routes.collect_raw()
    assert ["ip", "-j", "-4", "route", "show", "table", "all"] in calls
    assert ["ip", "-j", "-6", "rule"] in calls


def test_parse_resolv_conf() -> None:
    text = "# generated\nsearch lan\nnameserver 192.168.1.1\nnameserver fe80::1%wlan0 # v6\n"
    assert resolvers.parse_resolv_conf(text) == ["192.168.1.1", "fe80::1%wlan0"]


def test_parse_resolvectl() -> None:
    parsed = resolvers.parse_resolvectl((FIXTURES / "resolvectl_status.txt").read_text())
    assert parsed == {
        "global": ["10.66.0.1", "1.1.1.1"],
        "c-phys": ["192.168.100.1", "fd00:100::1", "fe80::1%c-phys"],
        "wg0": ["10.66.0.1"],
    }


def test_resolver_collect_without_resolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 10.66.0.1\n")
    failed = resolvers.sh.ShResult(("resolvectl",), 1, "", "Failed to connect")
    monkeypatch.setattr(resolvers.sh, "run", lambda *a, **k: failed)
    info = resolvers.collect(conf)
    assert info.resolv_conf == ["10.66.0.1"] and info.resolved == {}
    assert info.all_servers() == ["10.66.0.1"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("192.168.1.6%wlan0:68", ("192.168.1.6", "wlan0", 68)),
        ("[fe80::1]%wlan0:546", ("fe80::1", "wlan0", 546)),
        ("[::]:*", ("::", None, None)),
        ("*:22", ("*", None, 22)),
        ("[::ffff:1.2.3.4]:443", ("::ffff:1.2.3.4", None, 443)),
    ],
)
def test_split_addr(text: str, expected: tuple[str, str | None, int | None]) -> None:
    assert sockets.split_addr(text) == expected


def test_parse_ss() -> None:
    socks = sockets.parse_ss((FIXTURES / "ss_tunap.txt").read_text())
    assert len(socks) == 7
    dhcp = socks[0]
    assert (dhcp.proto, dhcp.state, dhcp.iface, dhcp.local_port, dhcp.peer_port) == (
        "udp", "ESTAB", "c-phys", 68, 67,
    )
    leaky = socks[4]
    assert (leaky.local_addr, leaky.peer_addr, leaky.process, leaky.pid) == (
        "192.168.100.2", "198.51.100.10", "leaky-app", 777,
    )
    assert socks[1].process is None
