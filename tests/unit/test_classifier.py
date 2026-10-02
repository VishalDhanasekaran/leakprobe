"""Allowlist classifier over scapy-built packets."""

import ipaddress

import pytest

from leakprobe.analyzers.packet_classifier import (
    ClassifierContext,
    LeakReason,
    PacketClass,
    classify,
)
from leakprobe.capture.pcap import to_record
from tests.unit.packets import ENDPOINT, PACKETS

CTX = ClassifierContext(ENDPOINT, 51820)
E, H, LAN, LEAK = PacketClass
DNS, V6, OTHER = LeakReason


@pytest.mark.parametrize(
    ("name", "cls", "reason"),
    [
        ("endpoint_out", E, None),
        ("endpoint_in", E, None),
        ("endpoint_wrong_port", LEAK, OTHER),
        ("arp", H, None),
        ("ndp_ns", H, None),
        ("ndp_rs", H, None),
        ("mld_report", H, None),
        ("dhcp4", H, None),
        ("dhcp6", H, None),
        ("dns_leak", LEAK, DNS),
        ("dns_tcp", LEAK, DNS),
        ("dot_leak", LEAK, DNS),
        ("dns6_leak", LEAK, DNS),
        ("ipv6_leak", LEAK, V6),
        ("unknown_v4", LEAK, OTHER),
        ("lan_ssh", LEAK, OTHER),
        ("lan_mdns", LEAK, OTHER),
    ],
)
def test_classify(name: str, cls: PacketClass, reason: LeakReason | None) -> None:
    result = classify(to_record(PACKETS[name]), CTX)
    assert (result.cls, result.reason) == (cls, reason)


@pytest.mark.parametrize("name", ["lan_ssh", "lan_mdns"])
def test_allow_lan(name: str) -> None:
    ctx = ClassifierContext(ENDPOINT, 51820, allow_lan=True)
    assert classify(to_record(PACKETS[name]), ctx).cls is LAN


def test_allow_lan_does_not_cover_internet_or_dns_to_internet() -> None:
    ctx = ClassifierContext(ENDPOINT, 51820, allow_lan=True)
    assert classify(to_record(PACKETS["unknown_v4"]), ctx).cls is LEAK
    assert classify(to_record(PACKETS["dot_leak"]), ctx).reason is DNS


def test_allow_lan_custom_prefixes() -> None:
    ctx = ClassifierContext(
        ENDPOINT, 51820, allow_lan=True, local_prefixes=(ipaddress.ip_network("10.0.0.0/8"),)
    )
    assert classify(to_record(PACKETS["lan_ssh"]), ctx).cls is LEAK


def test_endpoint_any_port() -> None:
    ctx = ClassifierContext(ENDPOINT)
    assert classify(to_record(PACKETS["endpoint_wrong_port"]), ctx).cls is E
