"""LP-EGRESS-01 from captured packet records."""

from scapy.layers.inet import IP, UDP

from leakprobe.analyzers.packet_classifier import ClassifierContext
from leakprobe.capture.pcap import to_record
from leakprobe.models import Status
from leakprobe.tests_impl.egress import MAX_FLOWS, audit_egress
from tests.unit.packets import ENDPOINT, PACKETS, eth

CTX = ClassifierContext(ENDPOINT, 51820)
CLEAN = ["endpoint_out", "endpoint_in", "arp", "ndp_ns", "mld_report", "dhcp4", "dhcp6"]


def test_clean_capture_passes() -> None:
    f = audit_egress([to_record(PACKETS[n]) for n in CLEAN], CTX)
    assert f.status is Status.PASS
    assert f.metrics["endpoint"] == 2 and f.metrics["housekeeping"] == 5 and f.metrics["leak"] == 0
    assert f.evidence == []


def test_leaks_fail_with_breakdown() -> None:
    names = [*CLEAN, "dns_leak", "dns_leak", "ipv6_leak", "unknown_v4"]
    f = audit_egress([to_record(PACKETS[n]) for n in names], CTX)
    assert f.status is Status.FAIL
    assert f.summary == "4 of 11 packets leaked (dns 2, ipv6 1, other 1)"
    assert (f.metrics["leak_dns"], f.metrics["leak_ipv6"], f.metrics["leak_other"]) == (2, 1, 1)
    assert f.evidence[0] == "dns: udp 192.168.100.2 -> 192.168.100.1:53 (2 pkts)"
    assert "ipv6: udp fd00:100::2 -> [2001:db8:198::10]:9000 (1 pkt)" in f.evidence


def test_empty_capture_warns() -> None:
    assert audit_egress([], CTX).status is Status.WARN


def test_evidence_is_capped() -> None:
    pkts = [
        to_record(eth() / IP(src="192.168.100.2", dst=f"198.51.100.{i}") / UDP(dport=9000))
        for i in range(MAX_FLOWS + 3)
    ]
    f = audit_egress(pkts, CTX)
    assert len(f.evidence) == MAX_FLOWS + 1
    assert f.evidence[-1] == "... 3 more leaking flows"
