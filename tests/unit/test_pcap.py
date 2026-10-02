"""pcap parsing (scapy-generated captures) and the tcpdump wrapper."""

import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import CookedLinux
from scapy.utils import wrpcap, wrpcapng

from leakprobe.capture import pcap
from leakprobe.util import sh
from tests.unit.packets import PACKETS


def _write(tmp_path: Path, pkts: list[Any], ng: bool = False) -> Path:
    path = tmp_path / ("c.pcapng" if ng else "c.pcap")
    (wrpcapng if ng else wrpcap)(str(path), pkts)
    return path


def test_to_record_udp() -> None:
    r = pcap.to_record(PACKETS["endpoint_out"], "c-phys")
    assert (r.iface, r.l2, r.l3, r.proto) == ("c-phys", "ether", "ipv4", "udp")
    assert (r.src, r.dst, r.sport, r.dport) == ("192.168.100.2", "203.0.113.10", 40000, 51820)
    assert r.size == len(PACKETS["endpoint_out"])


def test_to_record_arp() -> None:
    r = pcap.to_record(PACKETS["arp"])
    assert (r.l3, r.proto, r.src, r.dst) == ("arp", None, "192.168.100.2", "192.168.100.1")


@pytest.mark.parametrize(("name", "icmp6_type"), [("ndp_ns", 135), ("ndp_rs", 133),
                                                   ("mld_report", 143)])
def test_to_record_icmp6_through_ext_headers(name: str, icmp6_type: int) -> None:
    r = pcap.to_record(PACKETS[name])
    assert (r.l3, r.proto, r.icmp6_type) == ("ipv6", "icmp6", icmp6_type)


def test_to_record_ipv6_udp() -> None:
    r = pcap.to_record(PACKETS["ipv6_leak"])
    assert (r.l3, r.proto, r.dst, r.dport, r.icmp6_type) == (
        "ipv6", "udp", "2001:db8:198::10", 9000, None,
    )


@pytest.mark.parametrize("ng", [False, True])
def test_parse_pcap_round_trip(tmp_path: Path, ng: bool) -> None:
    pkts = list(PACKETS.values())
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000.0 + i * 0.01
    records = pcap.parse_pcap(_write(tmp_path, pkts, ng), "c-phys")
    assert len(records) == len(pkts)
    assert records[3].ts == pytest.approx(1_700_000_000.03)
    assert [r.l3 for r in records[:4]] == ["ipv4", "ipv4", "ipv4", "arp"]


def test_parse_cooked_capture(tmp_path: Path) -> None:
    pkt = CookedLinux() / IP(src="192.168.100.2", dst="1.1.1.1") / UDP(sport=1, dport=53)
    (r,) = pcap.parse_pcap(_write(tmp_path, [pkt]))
    assert (r.l2, r.proto, r.dport) == ("sll", "udp", 53)


def test_capture_argv_in_netns(tmp_path: Path) -> None:
    argv = pcap.Capture("c-phys", tmp_path / "x.pcap", netns="lp-client").argv()
    assert argv[:5] == ["ip", "netns", "exec", "lp-client", "tcpdump"]
    assert argv[argv.index("-i") + 1] == "c-phys"
    assert "--immediate-mode" in argv


FAKE_TCPDUMP = textwrap.dedent(
    """
    import signal, sys, time
    def stop(*_):
        sys.stderr.write("12 packets captured\\n14 packets received by filter\\n"
                         "0 packets dropped by kernel\\n")
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)
    sys.stderr.write("tcpdump: listening on c-phys, link-type EN10MB\\n")
    sys.stderr.flush()
    time.sleep(30)
    """
)


def test_capture_start_stop_with_fake_tcpdump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "fake_tcpdump.py"
    script.write_text(FAKE_TCPDUMP)
    real_spawn = sh.spawn
    monkeypatch.setattr(sh, "spawn", lambda argv: real_spawn([sys.executable, str(script)]))
    with pcap.Capture("c-phys", tmp_path / "x.pcap") as cap:
        assert cap._proc is not None and cap._proc.poll() is None
    assert cap._proc is None
    cap2 = pcap.Capture("c-phys", tmp_path / "y.pcap")
    cap2.start()
    assert cap2.stop() == pcap.CaptureStats(captured=12, dropped_by_kernel=0)


def test_capture_reports_early_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_spawn = sh.spawn
    code = "import sys; sys.stderr.write('tcpdump: c-phys: No such device\\n'); sys.exit(1)"
    monkeypatch.setattr(sh, "spawn", lambda argv: real_spawn([sys.executable, "-c", code]))
    with pytest.raises(RuntimeError, match="No such device"):
        pcap.Capture("c-phys", tmp_path / "x.pcap").start()
