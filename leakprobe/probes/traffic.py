"""UDP probe senders: a short burst, or a steady sequence-numbered stream."""

import socket
import time

PAYLOAD_PREFIX = b"LEAKPROBE"


def payload(seq: int) -> bytes:
    """Probe payload carrying a sequence number."""
    return PAYLOAD_PREFIX + seq.to_bytes(4, "big")


def _socket(dst: str) -> socket.socket:
    return socket.socket(socket.AF_INET6 if ":" in dst else socket.AF_INET, socket.SOCK_DGRAM)


def send_udp(dst: str, port: int, count: int = 5, interval: float = 0.05) -> dict[str, int]:
    """Send ``count`` probes; send errors (unreachable, firewall EPERM) are counted, not raised."""
    sent = errors = 0
    with _socket(dst) as sock:
        for seq in range(count):
            try:
                sock.sendto(payload(seq), (dst, port))
                sent += 1
            except OSError:
                errors += 1
            time.sleep(interval)
    return {"sent": sent, "errors": errors}


def stream_udp(dst: str, port: int, rate: float, duration: float) -> dict[str, int]:
    """Send ``rate`` packets/s for ``duration`` seconds on a fixed schedule (no drift)."""
    sent = errors = 0
    interval = 1.0 / rate
    start = time.monotonic()
    seq = 0
    with _socket(dst) as sock:
        while (now := time.monotonic()) - start < duration:
            try:
                sock.sendto(payload(seq), (dst, port))
                sent += 1
            except OSError:
                errors += 1
            seq += 1
            time.sleep(max(0.0, start + seq * interval - now))
    return {"sent": sent, "errors": errors}
