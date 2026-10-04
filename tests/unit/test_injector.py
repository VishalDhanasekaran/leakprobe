"""Fault injector command building and snapshot/restore, with a fake command runner."""

import json
from typing import Any

import pytest

from leakprobe.faults import injector
from leakprobe.util import sh

ADDR_JSON = [{"ifname": "wg0", "addr_info": [
    {"family": "inet", "local": "10.66.0.2", "prefixlen": 24, "scope": "global"},
    {"family": "inet6", "local": "fd66::2", "prefixlen": 64, "scope": "global"},
    {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"},
]}]
ROUTES4 = [
    {"dst": "default", "dev": "wg0", "table": "51820", "scope": "link", "flags": []},
    {"dst": "10.66.0.0/24", "dev": "wg0", "protocol": "kernel", "scope": "link", "flags": []},
    {"type": "local", "dst": "10.66.0.2", "dev": "wg0", "table": "local", "flags": []},
]
ROUTES6 = [
    {"dst": "default", "dev": "wg0", "table": "51820", "metric": 1024, "flags": []},
    {"type": "multicast", "dst": "ff00::/8", "dev": "wg0", "table": "local", "flags": []},
]


def test_address_commands_skip_link_scope() -> None:
    assert injector.address_commands(ADDR_JSON, "wg0") == [
        ["-4", "addr", "add", "10.66.0.2/24", "dev", "wg0"],
        ["-6", "addr", "add", "fd66::2/64", "dev", "wg0", "nodad"],
    ]


def test_route_commands_keep_only_configured_routes() -> None:
    assert injector.route_commands(ROUTES4, 4, "wg0") == [
        ["-4", "route", "add", "default", "dev", "wg0", "table", "51820"],
    ]
    assert injector.route_commands(ROUTES6, 6, "wg0") == [
        ["-6", "route", "add", "default", "dev", "wg0", "table", "51820", "metric", "1024"],
    ]


def test_block_ruleset() -> None:
    rules = injector.block_ruleset("203.0.113.10")
    assert "ip daddr 203.0.113.10 drop" in rules and "ip saddr 203.0.113.10 drop" in rules
    assert "hook forward" in rules and "hook output" in rules
    assert "ip6 daddr 2001:db8::1 drop" in injector.block_ruleset("2001:db8::1")


class FakeRunner:
    """Records commands; answers the read-only ones with canned output."""

    def __init__(self, link_exists: bool = True) -> None:
        self.calls: list[list[str]] = []
        self.inputs: list[str | None] = []
        self.link_exists = link_exists

    def __call__(self, ns: str | None, argv: list[str], **kw: Any) -> sh.ShResult:
        argv = list(argv)
        self.calls.append(argv)
        self.inputs.append(kw.get("input_text"))
        out, rc = "", 0
        if argv[:2] == ["wg", "showconf"]:
            out = "[Interface]\nPrivateKey = secret\n"
        elif argv[:4] == ["ip", "-j", "addr", "show"]:
            out = json.dumps(ADDR_JSON)
        elif argv[:3] == ["ip", "-j", "-4"]:
            out = json.dumps(ROUTES4)
        elif argv[:3] == ["ip", "-j", "-6"]:
            out = json.dumps(ROUTES6)
        elif argv[:3] == ["ip", "link", "show"]:
            rc = 0 if self.link_exists else 1
        elif argv[:3] == ["ip", "link", "del"]:
            self.link_exists = False
        elif argv[:3] == ["ip", "link", "add"]:
            self.link_exists = True
        return sh.ShResult(tuple(argv), rc, out, "")


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    runner = FakeRunner()
    monkeypatch.setattr(injector, "run_in", runner)
    return runner


def test_link_down_restores_routes(fake: FakeRunner) -> None:
    fault = injector.make_fault("link-down", "lp-client", "wg0", "lp-isp", "203.0.113.10")
    fault.inject()
    assert ["ip", "link", "set", "wg0", "down"] in fake.calls
    fake.calls.clear()
    fault.restore()
    assert ["ip", "link", "add", "wg0", "type", "wireguard"] not in fake.calls  # still exists
    assert fake.calls[1] == ["ip", "link", "set", "wg0", "up"]
    assert ["ip", "-4", "route", "add", "default", "dev", "wg0", "table", "51820"] in fake.calls
    assert ["ip", "-6", "addr", "add", "fd66::2/64", "dev", "wg0", "nodad"] in fake.calls


def test_delete_iface_recreates_from_snapshot(fake: FakeRunner) -> None:
    fault = injector.make_fault("delete-iface", "lp-client", "wg0", "lp-isp", "203.0.113.10")
    fault.inject()
    assert ["ip", "link", "del", "wg0"] in fake.calls
    fault.restore()
    assert ["ip", "link", "add", "wg0", "type", "wireguard"] in fake.calls
    i = fake.calls.index(["wg", "setconf", "wg0", "/dev/stdin"])
    assert fake.inputs[i] == "[Interface]\nPrivateKey = secret\n"  # key passed on stdin only


def test_restore_without_inject_is_noop(fake: FakeRunner) -> None:
    injector.make_fault("link-down", "lp-client", "wg0", None, "203.0.113.10").restore()
    assert fake.calls == []


def test_endpoint_block(fake: FakeRunner) -> None:
    fault = injector.make_fault("endpoint-block", "lp-client", "wg0", "lp-isp", "203.0.113.10")
    fault.inject()
    fault.restore()
    assert fake.calls == [["nft", "-f", "-"], ["nft", "delete", "table", "inet", "leakprobe_fault"]]


def test_unknown_method() -> None:
    with pytest.raises(ValueError, match="unknown fault method"):
        injector.make_fault("unplug", None, "wg0", None, "203.0.113.10")
