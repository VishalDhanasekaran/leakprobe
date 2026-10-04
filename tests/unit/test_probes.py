"""Probe senders, DNS query format and the probe entry point (localhost only, no root)."""

import json
import socket
import threading
import time
from pathlib import Path

import pytest

from leakprobe.lab import services
from leakprobe.probes import __main__ as probe_main
from leakprobe.probes import dns, identity, traffic


def test_new_label_format() -> None:
    label = dns.new_label()
    assert label.startswith("lp-") and label.endswith(".leakprobe.test")
    assert len(label.split(".")[0]) == 3 + 8 and dns.new_label() != label


def test_build_query_round_trips_through_lab_resolver() -> None:
    query = dns.build_query("lp-1a2b3c4d.leakprobe.test", qid=7)
    assert services.parse_query(query)[:3] == (7, "lp-1a2b3c4d.leakprobe.test", 1)


@pytest.fixture
def udp_sink() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(1)
    return sock, int(sock.getsockname()[1])


def test_send_udp_sequence_numbers(udp_sink: tuple[socket.socket, int]) -> None:
    sock, port = udp_sink
    assert traffic.send_udp("127.0.0.1", port, count=3, interval=0) == {"sent": 3, "errors": 0}
    assert [sock.recv(64) for _ in range(3)] == [traffic.payload(i) for i in range(3)]


def test_send_udp_never_raises() -> None:
    # Whether ::1 works here or not, failures are counted rather than raised.
    result = traffic.send_udp("::1", 9, count=2, interval=0)
    assert result["sent"] + result["errors"] == 2


def test_stream_rate(udp_sink: tuple[socket.socket, int]) -> None:
    _, port = udp_sink
    start = time.monotonic()
    result = traffic.stream_udp("127.0.0.1", port, rate=200, duration=0.5)
    assert 0.45 < time.monotonic() - start < 0.7
    assert 80 <= result["sent"] <= 101 and result["errors"] == 0


def test_lab_resolver_logs_probe_query(tmp_path: Path) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
    threading.Thread(
        target=services.serve_dns, args=("127.0.0.1", port, tmp_path / "d.log", "198.51.100.10"),
        daemon=True,
    ).start()
    time.sleep(0.1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
        c.settimeout(1)
        c.sendto(dns.build_query("lp-x.leakprobe.test"), ("127.0.0.1", port))
        assert c.recv(512)
    assert services.read_dns_log(tmp_path / "d.log")[0][2] == "lp-x.leakprobe.test"


def test_direct_query_without_server() -> None:
    result = dns.direct_query("127.0.0.1", "lp-x.leakprobe.test", timeout=0.2)  # nothing on :53
    assert result == {"server": "127.0.0.1", "ok": False, "error": result["error"]}


def test_query_beacon_unreachable() -> None:
    result = identity.query_beacon("127.0.0.1", 1, timeout=0.5)
    assert result["observed"] is None and result["error"]


def test_entry_point_writes_json(tmp_path: Path, udp_sink: tuple[socket.socket, int]) -> None:
    _, port = udp_sink
    out = tmp_path / "r.json"
    probe_main.main(["--out", str(out), "udp", "--dst", "127.0.0.1", "--port", str(port),
                     "--count", "2", "--interval", "0"])
    assert json.loads(out.read_text()) == {"sent": 2, "errors": 0}
