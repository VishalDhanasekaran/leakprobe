"""LP-START-01 and LP-SPLIT-01 decision logic (no root)."""

import ipaddress
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from leakprobe.collectors import routes
from leakprobe.collectors.sockets import Socket, parse_ss
from leakprobe.models import PacketRecord, Status
from leakprobe.tests_impl import startup
from leakprobe.tests_impl.split import bypass_rules, bypass_sockets, evaluate_split
from leakprobe.util import sh

FIXTURES = Path(__file__).parent.parent / "fixtures"
PHYS = [ipaddress.ip_interface("192.168.100.2/24"), ipaddress.ip_interface("fd00:100::2/64")]
ENDPOINT = "203.0.113.10"


def probe(ts: float) -> PacketRecord:
    return PacketRecord(ts=ts, iface="c-phys", l2="ether", l3="ipv4", proto="udp",
                        src="192.168.100.2", dst="198.51.100.10", sport=4000, dport=9000, size=60)


# ----- LP-START-01 -----------------------------------------------------------------------------


def test_startup_fail_with_timing() -> None:
    leaks = [probe(99.5), probe(100.004), probe(100.0)]
    f = startup.evaluate_startup(sorted(leaks, key=lambda p: p.ts), 100.0, 100.025, 200)
    assert f.status is Status.FAIL and f.severity.value == "medium"
    assert f.metrics["time_to_ready_ms"] == 25.0 and f.metrics["leak_packets"] == 3
    assert "1 before bring-up started, 2 during it" in f.evidence


def test_startup_pass_and_never_ready() -> None:
    assert startup.evaluate_startup([], 100.0, 100.02, 100).status is Status.PASS
    f = startup.evaluate_startup([probe(1.0)], None, None, 100, ["tunnel wg0 does not exist"])
    assert f.status is Status.FAIL and f.evidence[0] == "tunnel wg0 does not exist"
    assert any("never became ready" in e for e in f.evidence)
    assert startup.evaluate_startup([], None, None, 0).status is Status.ERROR


def test_wait_for_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    outputs = iter(["peerkey\t0\n", "peerkey\t0\n", "peerkey\t1791125052\n"])
    monkeypatch.setattr(
        startup, "run_in", lambda ns, argv, **kw: sh.ShResult(tuple(argv), 0, next(outputs), "")
    )
    assert startup.wait_for_handshake("lp-client", "wg0", timeout=2) is not None


def test_wait_for_handshake_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        startup, "run_in", lambda ns, argv, **kw: sh.ShResult(tuple(argv), 0, "peerkey\t0\n", "")
    )
    assert startup.wait_for_handshake("lp-client", "wg0", timeout=0.05) is None


def test_stream_probe_stops_cleanly_on_sigterm(tmp_path: Path) -> None:
    out = tmp_path / "s.json"
    proc = subprocess.Popen([sys.executable, "-m", "leakprobe.probes", "--out", str(out),
                             "stream", "--dst", "127.0.0.1", "--port", "9", "--duration", "30"])
    time.sleep(1.0)
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=5) == 0
    assert '"sent"' in out.read_text()


# ----- LP-SPLIT-01 -----------------------------------------------------------------------------


def sock(local: str, peer: str, port: int = 443, state: str = "ESTAB", iface: str | None = None,
         proto: str = "tcp") -> Socket:
    return Socket(proto, state, local, 40000, peer, port, iface, "app", 7)


@pytest.mark.parametrize(
    ("s", "flagged"),
    [
        (sock("192.168.100.2", "198.51.100.10"), True),            # pinned to physical IP
        (sock("10.66.0.2", "198.51.100.10"), False),               # tunnel address: fine
        (sock("0.0.0.0", "198.51.100.10"), False),                 # unbound: follows routes
        (sock("192.168.100.2", ENDPOINT, 51820, proto="udp"), False),  # the VPN endpoint
        (sock("192.168.100.2", "192.168.100.1", 67, proto="udp"), False),  # LAN peer
        (sock("192.168.100.2", "*", 0, "LISTEN"), False),          # inbound listener
        (sock("192.168.100.2", "*", 0, "UNCONN", proto="udp"), True),  # can send anywhere
        (sock("0.0.0.0", "198.51.100.10", iface="c-phys"), True),  # SO_BINDTODEVICE seen by ss
        (sock("::ffff:192.168.100.2", "198.51.100.10"), True),     # v4-mapped
        (sock("fe80::2", "fe80::1", iface="c-phys"), False),       # link-local peer
        (sock("fe80::2", "::", 0, "UNCONN", "c-phys", "udp"), False),  # DHCPv6 client
    ],
)
def test_bypass_sockets(s: Socket, flagged: bool) -> None:
    assert (bypass_sockets([s], PHYS, "c-phys", ENDPOINT) == [s]) is flagged


def test_bypass_sockets_from_ss_fixture() -> None:
    socks = parse_ss((FIXTURES / "ss_tunap.txt").read_text())
    flagged = bypass_sockets(socks, PHYS, "c-phys", ENDPOINT)
    assert [s.process for s in flagged] == ["leaky-app"]


def rules(*objs: dict[str, object]) -> list[routes.Rule]:
    return [routes.parse_rule(dict(o), 4) for o in objs]


def test_bypass_rules() -> None:
    rs = rules(
        {"priority": 0, "src": "all", "table": "local"},
        {"priority": 32764, "src": "all", "table": "main", "suppress_prefixlen": 0},
        {"priority": 32765, "not": None, "src": "all", "fwmark": "0xca6c", "table": "51820"},
        {"priority": 100, "src": "all", "uid_start": 1000, "uid_end": 1000, "table": "main"},
        {"priority": 200, "src": "all", "fwmark": "0x1", "table": "main"},
    )
    assert sorted(r.priority for r in bypass_rules(rs, 0xCA6C)) == [100, 200]
    assert sorted(r.priority for r in bypass_rules(rs, None)) == [100, 200, 32765]


def test_evaluate_split() -> None:
    clean = evaluate_split([], PHYS, "c-phys", ENDPOINT, [], 0xCA6C)
    assert clean.status is Status.PASS and clean.evidence[-1].startswith("limitation")
    bad = evaluate_split(
        [sock("192.168.100.2", "198.51.100.10")], PHYS, "c-phys", ENDPOINT,
        rules({"priority": 100, "src": "all", "uid_start": 0, "uid_end": 0, "table": "main"}),
        0xCA6C,
    )
    assert bad.status is Status.WARN and bad.severity.value == "low"
    assert bad.metrics == {"bypass_sockets": 1, "bypass_rules": 1}
    assert "socket: tcp 192.168.100.2:40000 -> 198.51.100.10:443 (app, pid 7)" in bad.evidence
    assert "rule IPv4 100: uidrange lookup main" in bad.evidence


def test_parse_addresses() -> None:
    addr_json = [{"addr_info": [{"local": "192.168.100.2", "prefixlen": 24},
                                {"local": "fd00:100::2", "prefixlen": 64}]}]
    assert routes.parse_addresses(addr_json) == PHYS
