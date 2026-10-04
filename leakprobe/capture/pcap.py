"""Run tcpdump on the physical interface and parse pcap files into PacketRecords."""

import logging
import re
import select
import signal
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, TypeVar

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6, _IPv6ExtHdr  # noqa: E402
from scapy.layers.l2 import ARP, CookedLinux, CookedLinuxV2, Ether  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

from leakprobe.models import PacketRecord  # noqa: E402
from leakprobe.util import sh  # noqa: E402

T = TypeVar("T")
IP_PROTOS = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmp6", 132: "sctp"}
_STAT = re.compile(r"(\d+) packets? (captured|dropped by kernel)")


@dataclass(frozen=True)
class CaptureStats:
    """tcpdump's own counters, printed when it exits."""

    captured: int | None = None
    dropped_by_kernel: int | None = None


class Capture:
    """tcpdump writing raw packets on ``iface`` to ``path``; usable as a context manager."""

    def __init__(self, iface: str, path: Path, netns: str | None = None) -> None:
        self.iface = iface
        self.path = path
        self.netns = netns
        self._proc: subprocess.Popen[str] | None = None

    def argv(self) -> list[str]:
        """The tcpdump command line (inside ``ip netns exec`` when a namespace is set)."""
        prefix = ["ip", "netns", "exec", self.netns] if self.netns else []
        return [
            *prefix, "tcpdump", "-i", self.iface, "-w", str(self.path),
            "-n", "-U", "--immediate-mode", "-s", "0", "-Z", "root",
        ]

    def start(self, ready_timeout: float = 5.0) -> None:
        """Start tcpdump and wait until it reports it is listening."""
        self._proc = sh.spawn(self.argv())
        assert self._proc.stderr is not None
        deadline = time.monotonic() + ready_timeout
        seen = ""
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"tcpdump exited early: {seen}{self._proc.stderr.read()}")
            ready, _, _ = select.select([self._proc.stderr], [], [], 0.1)
            if ready:
                seen += self._proc.stderr.readline()
                if "listening on" in seen:
                    return
        self.stop()
        raise RuntimeError(f"tcpdump not ready after {ready_timeout}s: {seen}")

    def stop(self, timeout: float = 5.0) -> CaptureStats:
        """Stop tcpdump with SIGINT so it flushes the file; return its counters."""
        proc, self._proc = self._proc, None
        if proc is None:
            return CaptureStats()
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        stderr = proc.stderr.read() if proc.stderr else ""
        counts = {kind: int(n) for n, kind in _STAT.findall(stderr)}
        return CaptureStats(counts.get("captured"), counts.get("dropped by kernel"))

    def __enter__(self) -> "Capture":
        self.start()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()


def _l2_name(pkt: Any) -> str:
    if isinstance(pkt, Ether):
        return "ether"
    if isinstance(pkt, CookedLinux | CookedLinuxV2):
        return "sll"
    return str(pkt.name).lower()


def to_record(pkt: Any, iface: str = "") -> PacketRecord:
    """Reduce one scapy packet to a PacketRecord (kernel timestamp kept)."""
    fields: dict[str, Any] = {}
    if ARP in pkt:
        arp = pkt[ARP]
        fields = {"l3": "arp", "src": arp.psrc, "dst": arp.pdst}
    elif IP in pkt:
        ip = pkt[IP]
        fields = {"l3": "ipv4", "src": ip.src, "dst": ip.dst,
                  "proto": IP_PROTOS.get(ip.proto, str(ip.proto))}
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        layer, nh = ip6.payload, ip6.nh
        while isinstance(layer, _IPv6ExtHdr):  # hop-by-hop (MLD), routing, fragment, ...
            nh, layer = layer.nh, layer.payload
        fields = {"l3": "ipv6", "src": ip6.src, "dst": ip6.dst,
                  "proto": IP_PROTOS.get(nh, str(nh))}
        raw = bytes(layer)
        if nh == 58 and raw:
            fields["icmp6_type"] = raw[0]
    for l4 in (UDP, TCP):
        if l4 in pkt:
            fields["sport"], fields["dport"] = int(pkt[l4].sport), int(pkt[l4].dport)
            break
    return PacketRecord(
        ts=float(pkt.time),
        iface=iface,
        l2=_l2_name(pkt),
        size=int(getattr(pkt, "wirelen", None) or len(pkt)),
        **fields,
    )


def parse_pcap(path: Path, iface: str = "") -> list[PacketRecord]:
    """Read a pcap or pcapng file into PacketRecords, in capture order."""
    with PcapReader(str(path)) as reader:
        return [to_record(pkt, iface) for pkt in reader]


def capture_while(
    iface: str, path: Path, action: Callable[[], T], netns: str | None = None,
    settle: float = 0.3,
) -> tuple[T, list[PacketRecord]]:
    """Capture on ``iface`` while ``action`` runs; return its result and the packets seen."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with Capture(iface, path, netns):
        result = action()
        time.sleep(settle)  # let in-flight packets reach the capture
    return result, parse_pcap(path, iface)
