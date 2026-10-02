"""Lab services: DNS wire format and a real beacon on localhost."""

import socket
import struct
import threading
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR

from leakprobe.lab import services


def query(name: str, qtype: str = "A") -> bytes:
    return bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname=name, qtype=qtype)))


def test_parse_query() -> None:
    qid, qname, qtype, _ = services.parse_query(query("LP-1a2b3c4d.LeakProbe.test"))
    assert (qid, qname, qtype) == (0x1234, "lp-1a2b3c4d.leakprobe.test", 1)


@pytest.mark.parametrize("data", [b"", b"\x00" * 11, b"\x00" * 12 + b"\x05ab"])
def test_parse_query_rejects_garbage(data: bytes) -> None:
    with pytest.raises(ValueError):
        services.parse_query(data)


def test_build_response_a_record() -> None:
    reply = DNS(services.build_response(query("lp-x.leakprobe.test"), "198.51.100.10"))
    assert reply.id == 0x1234 and reply.qr == 1 and reply.rcode == 0 and reply.ancount == 1
    assert reply.an[0].rdata == "198.51.100.10"


def test_build_response_aaaa_is_empty() -> None:
    reply = DNS(services.build_response(query("lp-x.leakprobe.test", "AAAA"), "198.51.100.10"))
    assert reply.ancount == 0 and reply.rcode == 0


def test_observed_ip() -> None:
    assert services.observed_ip("::ffff:192.0.2.2") == "192.0.2.2"
    assert services.observed_ip("2001:db8:192::2") == "2001:db8:192::2"


def test_read_dns_log(tmp_path: Path) -> None:
    log = tmp_path / "isp-dns.log"
    log.write_text("1.5\t192.168.100.2\tlp-a.leakprobe.test\n2.0\t10.66.0.2\tlp-b.leakprobe.test\n")
    assert services.read_dns_log(log) == [
        (1.5, "192.168.100.2", "lp-a.leakprobe.test"), (2.0, "10.66.0.2", "lp-b.leakprobe.test"),
    ]
    assert services.read_dns_log(tmp_path / "missing.log") == []


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_beacon_reports_source_ip() -> None:
    port = _free_port()
    threading.Thread(target=services.serve_beacon, args=(port,), daemon=True).start()
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as c:
                assert c.recv(64) == b"127.0.0.1\n"
                return
        except ConnectionRefusedError:
            threading.Event().wait(0.02)
    pytest.fail("beacon did not start")


def test_dns_server_logs_and_answers(tmp_path: Path) -> None:
    port, log = _free_port(), tmp_path / "dns.log"
    threading.Thread(
        target=services.serve_dns, args=("127.0.0.1", port, log, "198.51.100.10"), daemon=True
    ).start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
        c.settimeout(0.2)
        for _ in range(25):
            c.sendto(query("lp-deadbeef.leakprobe.test"), ("127.0.0.1", port))
            try:
                reply = c.recv(512)
                break
            except TimeoutError:
                continue
        else:
            pytest.fail("dns service did not answer")
    assert struct.unpack("!H", reply[6:8])[0] == 1
    assert services.read_dns_log(log)[0][1:] == ("127.0.0.1", "lp-deadbeef.leakprobe.test")
