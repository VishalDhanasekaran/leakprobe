"""Scapy packet builders for classifier and pcap tests (lab addressing)."""

from typing import Any

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import DHCP6_Solicit
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import (
    ICMPv6MLReport2,
    ICMPv6ND_NS,
    ICMPv6ND_RS,
    IPv6,
    IPv6ExtHdrHopByHop,
)
from scapy.layers.l2 import ARP, Ether

CLIENT = "192.168.100.2"
GATEWAY = "192.168.100.1"
ENDPOINT = "203.0.113.10"
CANARY = "198.51.100.10"
CLIENT6 = "fd00:100::2"
CANARY6 = "2001:db8:198::10"


def eth() -> Any:
    return Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")


PACKETS: dict[str, Any] = {
    "endpoint_out": eth() / IP(src=CLIENT, dst=ENDPOINT) / UDP(sport=40000, dport=51820),
    "endpoint_in": eth() / IP(src=ENDPOINT, dst=CLIENT) / UDP(sport=51820, dport=40000),
    "endpoint_wrong_port": eth() / IP(src=CLIENT, dst=ENDPOINT) / UDP(sport=40000, dport=9999),
    "arp": eth() / ARP(psrc=CLIENT, pdst=GATEWAY),
    "ndp_ns": eth() / IPv6(src=CLIENT6, dst="ff02::1:ff00:1") / ICMPv6ND_NS(tgt="fd00:100::1"),
    "ndp_rs": eth() / IPv6(src="fe80::2", dst="ff02::2") / ICMPv6ND_RS(),
    "mld_report": eth()
    / IPv6(src="fe80::2", dst="ff02::16")
    / IPv6ExtHdrHopByHop()
    / ICMPv6MLReport2(),
    "dhcp4": eth()
    / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(sport=68, dport=67)
    / BOOTP()
    / DHCP(options=[("message-type", "discover"), "end"]),
    "dhcp6": eth() / IPv6(src="fe80::2", dst="ff02::1:2") / UDP(sport=546, dport=547)
    / DHCP6_Solicit(),
    "dns_leak": eth()
    / IP(src=CLIENT, dst=GATEWAY)
    / UDP(sport=33333, dport=53)
    / DNS(qd=DNSQR(qname="lp-1a2b3c4d.leakprobe.test")),
    "dns_tcp": eth() / IP(src=CLIENT, dst=GATEWAY) / TCP(sport=33334, dport=53),
    "dot_leak": eth() / IP(src=CLIENT, dst="9.9.9.9") / TCP(sport=33335, dport=853),
    "dns6_leak": eth() / IPv6(src=CLIENT6, dst="fd00:100::1") / UDP(sport=33336, dport=53),
    "ipv6_leak": eth() / IPv6(src=CLIENT6, dst=CANARY6) / UDP(sport=40001, dport=9000),
    "unknown_v4": eth() / IP(src=CLIENT, dst=CANARY) / TCP(sport=40002, dport=8080),
    "lan_ssh": eth() / IP(src=CLIENT, dst="192.168.100.50") / TCP(sport=40003, dport=22),
    "lan_mdns": eth() / IP(src=CLIENT, dst="224.0.0.251") / UDP(sport=5353, dport=5353),
}
