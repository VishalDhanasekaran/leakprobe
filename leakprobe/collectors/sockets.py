"""Collect and parse sockets from ``ss -tunapH``."""

import re
from dataclasses import dataclass

from leakprobe.util import netns, sh

_PROCESS = re.compile(r'\("(?P<name>[^"]*)",pid=(?P<pid>\d+)')


@dataclass(frozen=True)
class Socket:
    """One socket line from ``ss``. ``*`` addresses mean any."""

    proto: str
    state: str
    local_addr: str
    local_port: int | None
    peer_addr: str
    peer_port: int | None
    iface: str | None = None
    process: str | None = None
    pid: int | None = None


def split_addr(text: str) -> tuple[str, str | None, int | None]:
    """Split ``[fe80::1]%wlan0:546`` / ``1.2.3.4:53`` / ``*:*`` into (addr, iface, port)."""
    host, _, port = text.rpartition(":")
    host, _, iface = host.partition("%")
    host = host.strip("[]")
    return host, iface or None, None if port == "*" else int(port)


def parse_ss(text: str) -> list[Socket]:
    """Parse ``ss -tunapH`` output (netid state recv-q send-q local peer [process])."""
    sockets = []
    for line in text.splitlines():
        cols = line.split(maxsplit=6)
        if len(cols) < 6:
            continue
        local, local_iface, local_port = split_addr(cols[4])
        peer, _, peer_port = split_addr(cols[5])
        proc = _PROCESS.search(cols[6]) if len(cols) > 6 else None
        sockets.append(
            Socket(
                proto=cols[0],
                state=cols[1],
                local_addr=local,
                local_port=local_port,
                peer_addr=peer,
                peer_port=peer_port,
                iface=local_iface,
                process=proc["name"] if proc else None,
                pid=int(proc["pid"]) if proc else None,
            )
        )
    return sockets


def collect(ns: str | None = None) -> list[Socket]:
    """Sockets of this namespace or ``ns``. Process names need root for others' sockets."""
    argv = ["ss", "-tunapH"]
    return parse_ss((netns.run(ns, argv) if ns else sh.run(argv)).stdout)
