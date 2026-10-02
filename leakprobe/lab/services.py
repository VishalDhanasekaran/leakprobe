"""Lab services, each run inside a namespace as ``python -m leakprobe.lab.services <kind>``.

- beacon: TCP server that replies with the source IP it observed (LP-IDENT-01).
- canary: UDP sink for probe traffic.
- dns:    minimal UDP resolver that logs every qname with the client IP (LP-DNS-01).
"""

import argparse
import socket
import struct
import sys
import time
from collections.abc import Sequence
from pathlib import Path

QTYPE_A = 1


def observed_ip(peer: str) -> str:
    """Strip the IPv4-mapped prefix that dual-stack sockets report."""
    return peer.removeprefix("::ffff:")


def parse_query(data: bytes) -> tuple[int, str, int, int]:
    """Return (id, qname, qtype, end of question) for a single-question DNS query."""
    if len(data) < 12:
        raise ValueError("short DNS packet")
    qid = struct.unpack("!H", data[:2])[0]
    labels, pos = [], 12
    while True:
        if pos >= len(data):
            raise ValueError("truncated qname")
        length = data[pos]
        pos += 1
        if length == 0:
            break
        labels.append(data[pos : pos + length].decode("ascii", "replace"))
        pos += length
    if pos + 4 > len(data):
        raise ValueError("truncated question")
    qtype = struct.unpack("!H", data[pos : pos + 2])[0]
    return qid, ".".join(labels).lower(), qtype, pos + 4


def build_response(query: bytes, answer_ip: str) -> bytes:
    """NOERROR reply echoing the question; one A record for A queries, empty otherwise."""
    qid, _, qtype, end = parse_query(query)
    answers = 1 if qtype == QTYPE_A else 0
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, answers, 0, 0)
    body = query[12:end]
    if answers:
        rdata = socket.inet_aton(answer_ip)
        body += struct.pack("!HHHIH", 0xC00C, QTYPE_A, 1, 30, len(rdata)) + rdata
    return header + body


def _dual_stack(kind: int, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET6, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    return sock


def serve_beacon(port: int) -> None:
    """Reply ``<observed source ip>\\n`` to every TCP connection."""
    srv = _dual_stack(socket.SOCK_STREAM, port)
    srv.listen(64)
    while True:
        conn, peer = srv.accept()
        with conn:
            conn.sendall(observed_ip(peer[0]).encode() + b"\n")


def serve_canary(port: int) -> None:
    """Swallow UDP probes (avoids ICMP port-unreachable noise in captures)."""
    sock = _dual_stack(socket.SOCK_DGRAM, port)
    while True:
        sock.recvfrom(2048)


def serve_dns(bind: str, port: int, log: Path, answer_ip: str) -> None:
    """Answer queries on ``bind:port`` and append ``ts<TAB>client<TAB>qname`` to ``log``."""
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    with log.open("a", buffering=1) as out:
        while True:
            data, peer = sock.recvfrom(4096)
            try:
                _, qname, _, _ = parse_query(data)
                reply = build_response(data, answer_ip)
            except ValueError:
                continue
            out.write(f"{time.time():.6f}\t{peer[0]}\t{qname}\n")
            sock.sendto(reply, peer)


def read_dns_log(log: Path) -> list[tuple[float, str, str]]:
    """Parse a resolver log into (ts, client, qname) tuples."""
    if not log.exists():
        return []
    entries = []
    for line in log.read_text().splitlines():
        ts, client, qname = line.split("\t")
        entries.append((float(ts), client, qname))
    return entries


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point for ``python -m leakprobe.lab.services``."""
    parser = argparse.ArgumentParser(prog="leakprobe.lab.services")
    sub = parser.add_subparsers(dest="kind", required=True)
    sub.add_parser("beacon").add_argument("--port", type=int, default=8080)
    sub.add_parser("canary").add_argument("--port", type=int, default=9000)
    dns = sub.add_parser("dns")
    dns.add_argument("--bind", required=True)
    dns.add_argument("--port", type=int, default=53)
    dns.add_argument("--log", type=Path, required=True)
    dns.add_argument("--answer", default="198.51.100.10")
    args = parser.parse_args(argv)
    if args.kind == "beacon":
        serve_beacon(args.port)
    elif args.kind == "canary":
        serve_canary(args.port)
    else:
        serve_dns(args.bind, args.port, args.log, args.answer)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
