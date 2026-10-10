"""Everything a test needs to know about the system under test, in lab or real mode."""

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from leakprobe.analyzers.packet_classifier import ClassifierContext
from leakprobe.lab import topology as t
from leakprobe.lab.builder import LabState
from leakprobe.util.net import parse_endpoint


@dataclass(frozen=True)
class RunContext:
    """Where probes run, what to capture, and what counts as correct."""

    mode: Literal["lab", "real"]
    client_ns: str | None  # namespace the probes run in; None = this host
    physical: str
    tunnel: str
    endpoint_ip: str
    endpoint_port: int | None
    canary: str = t.CANARY_IP
    canary6: str = t.CANARY_IP6
    canary_port: int = t.CANARY_UDP_PORT
    beacon: str = t.CANARY_IP
    beacon_port: int = t.BEACON_PORT
    expected_exits: tuple[str, ...] = ()
    dns_logs: dict[str, Path] = field(default_factory=dict)  # resolver name -> query log
    fault_ns: str | None = None  # where endpoint-block drops endpoint traffic (lab: the ISP)
    workdir: Path = Path(t.STATE_DIR) / "captures"
    allow_lan: bool = False
    tunnel_dns: str | None = None  # the resolver inside the tunnel, for remediation text

    def classifier(self) -> ClassifierContext:
        """Allowlist for packets on the physical interface."""
        return ClassifierContext(self.endpoint_ip, self.endpoint_port, self.allow_lan)

    @classmethod
    def from_lab(cls, state: LabState) -> "RunContext":
        """Context for the running lab described by ``state``."""
        return cls(
            mode="lab",
            client_ns=t.CLIENT,
            physical=t.PHYSICAL,
            tunnel=t.TUNNEL,
            endpoint_ip=t.ENDPOINT_IP,
            endpoint_port=t.ENDPOINT_PORT,
            expected_exits=(t.EXIT_VIA_VPN,),
            dns_logs={name: Path(p) for name, p in state.dns_logs.items()},
            fault_ns=t.ISP,
            tunnel_dns=t.VPN_RESOLVER,
        )

    @classmethod
    def from_real(
        cls,
        tunnel: str,
        physical: str,
        endpoint: str,
        beacon: str | None = None,
        expected_exits: Sequence[str] = (),
        allow_lan: bool = False,
    ) -> "RunContext":
        """Context for this host. Without a beacon, probes target the (unrouted) lab canary."""
        ip, port = parse_endpoint(endpoint)
        target = str(ipaddress.ip_address(beacon)) if beacon else t.CANARY_IP
        return cls(
            mode="real", client_ns=None, physical=physical, tunnel=tunnel, endpoint_ip=ip,
            endpoint_port=port, canary=target, beacon=target,
            expected_exits=tuple(expected_exits), allow_lan=allow_lan,
        )
