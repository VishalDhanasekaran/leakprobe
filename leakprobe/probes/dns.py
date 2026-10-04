"""Unique-label DNS probes: system resolution plus direct queries to each nameserver."""

import random
import socket
import struct
import uuid

DOMAIN = "leakprobe.test"


def new_label() -> str:
    """A fresh ``lp-<uuid8>.leakprobe.test`` name."""
    return f"lp-{uuid.uuid4().hex[:8]}.{DOMAIN}"


def build_query(name: str, qid: int | None = None) -> bytes:
    """A recursive A query for ``name``."""
    qid = random.randrange(1 << 16) if qid is None else qid
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def system_resolve(name: str) -> dict[str, object]:
    """Resolve through the system resolver (getaddrinfo / resolv.conf)."""
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "addresses": sorted({str(i[4][0]) for i in infos})}


def direct_query(server: str, name: str, timeout: float = 1.0) -> dict[str, object]:
    """Send one UDP query straight to ``server``; report whether an answer came back."""
    host = server.split("%", 1)[0]
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(build_query(name), (server, 53))
            sock.recv(512)
        except OSError as exc:
            return {"server": server, "ok": False, "error": str(exc)}
    return {"server": server, "ok": True}
