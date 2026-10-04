"""Ask the beacon which source IP it sees for our connection."""

import socket


def query_beacon(host: str, port: int, timeout: float = 2.0) -> dict[str, str | None]:
    """Return ``{"observed": ip}`` or ``{"observed": None, "error": ...}``."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            observed = conn.recv(128).decode().strip()
    except OSError as exc:
        return {"observed": None, "error": str(exc)}
    return {"observed": observed or None}
