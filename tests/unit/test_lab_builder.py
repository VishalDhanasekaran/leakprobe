"""Pure parts of the lab builder: rulesets, wg-quick routing, resolv.conf, state file."""

from pathlib import Path

import pytest

from leakprobe.lab import builder
from leakprobe.lab.profile import load_profile


def test_killswitch_matches_plan() -> None:
    rules = builder.killswitch_ruleset("inet", "wg0", "203.0.113.10", 51820)
    assert rules.startswith("table inet leakprobe_killswitch {")
    for line in (
        "type filter hook output priority 0; policy drop;",
        'oifname "lo" accept',
        'oifname "wg0" accept',
        "ip daddr 203.0.113.10 udp dport 51820 accept",
        "udp sport 68 udp dport 67 accept",
        "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept",
    ):
        assert line in rules


def test_killswitch_v4_only_has_no_icmpv6() -> None:
    rules = builder.killswitch_ruleset("ip", "wg0", "203.0.113.10", 51820)
    assert rules.startswith("table ip ") and "icmpv6" not in rules


def test_nat_ruleset() -> None:
    assert 'oifname != "i-c" masquerade' in builder.nat_ruleset('!= "i-c"')


def test_wg_routes_full_tunnel_both_families() -> None:
    cmds = builder.wg_route_commands(["0.0.0.0/0", "::/0"])
    assert ["-4", "route", "add", "0.0.0.0/0", "dev", "wg0", "table", "51820"] in cmds
    assert ["-6", "route", "add", "::/0", "dev", "wg0", "table", "51820"] in cmds
    assert ["-4", "rule", "add", "not", "fwmark", "0xca6c", "table", "51820"] in cmds
    assert ["-6", "rule", "add", "table", "main", "suppress_prefixlength", "0"] in cmds
    assert len(cmds) == 6


def test_wg_routes_v4_only_and_split() -> None:
    assert all(c[0] == "-4" for c in builder.wg_route_commands(["0.0.0.0/0"]))
    split = builder.wg_route_commands(["10.0.0.0/8"])
    assert split == [["-4", "route", "add", "10.0.0.0/8", "dev", "wg0"]]


@pytest.mark.parametrize(
    ("name", "server"),
    [("wg-hardened", "10.66.0.1"), ("wg-default-leaky", "192.168.100.1"),
     ("control-broken", "192.168.100.1")],
)
def test_resolv_conf(name: str, server: str) -> None:
    assert builder.resolv_conf(load_profile(name)).endswith(f"nameserver {server}\n")


def test_state_round_trip(tmp_path: Path) -> None:
    state = builder.LabState("wg-hardened", 1.5, {"beacon": builder.Service("lp-inet", 42,
                             "tcp", 8080)}, {"isp": "/run/leakprobe/isp-dns.log"})
    state.save(tmp_path / "lab.json")
    assert builder.LabState.load(tmp_path / "lab.json") == state
    assert builder.LabState.load(tmp_path / "missing.json") is None


def test_up_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builder.os, "geteuid", lambda: 1000)
    with pytest.raises(builder.LabError, match="root"):
        builder.up(load_profile("wg-hardened"))
