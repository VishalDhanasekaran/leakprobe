"""Decision logic of LP-DNS-01, LP-V6-01 and LP-IDENT-01."""

from leakprobe.analyzers.packet_classifier import ClassifierContext
from leakprobe.analyzers.route_predictor import RouteDecision
from leakprobe.capture.pcap import to_record
from leakprobe.models import Status
from leakprobe.tests_impl.dns_leak import evaluate_dns
from leakprobe.tests_impl.identity import evaluate_identity
from leakprobe.tests_impl.ipv6_leak import evaluate_ipv6
from tests.unit.packets import ENDPOINT, PACKETS

LABEL = "lp-1a2b3c4d.leakprobe.test"
CTX = ClassifierContext(ENDPOINT, 51820)
TUNNELED = RouteDecision("2001:db8:198::10", "wg0", reason="table 51820")
PHYSICAL = RouteDecision("2001:db8:198::10", "c-phys", via="fd00:100::1", reason="table main")


def test_dns_pass_only_vpn() -> None:
    f = evaluate_dns(LABEL, {"isp": [], "vpn": ["10.66.0.2", "10.66.0.2"]}, ["10.66.0.1"])
    assert f.status is Status.PASS and f.metrics == {"isp_queries": 0, "vpn_queries": 2}
    assert f"label {LABEL}" in f.evidence


def test_dns_fail_when_isp_sees_label() -> None:
    f = evaluate_dns(LABEL, {"isp": ["192.168.100.2"], "vpn": ["10.66.0.2"]}, ["192.168.100.1"])
    assert f.status is Status.FAIL and "isp" in f.summary
    assert "isp resolver: 192.168.100.2" in f.evidence


def test_dns_inconclusive() -> None:
    probe = {"system": {"ok": False}}
    f = evaluate_dns(LABEL, {"isp": [], "vpn": []}, [], probe)
    assert f.status is Status.WARN and "system resolution: failed" in f.evidence


def test_ipv6_pass_when_tunneled_and_quiet() -> None:
    pkts = [to_record(PACKETS[n]) for n in ("endpoint_out", "ndp_ns", "mld_report")]
    f = evaluate_ipv6(TUNNELED, "wg0", False, pkts, CTX)
    assert f.status is Status.PASS and f.metrics["ipv6_leak_packets"] == 0


def test_ipv6_fail_on_leaked_packets() -> None:
    pkts = [to_record(PACKETS[n]) for n in ("ipv6_leak", "ipv6_leak", "dns6_leak", "dns_leak")]
    f = evaluate_ipv6(PHYSICAL, "wg0", False, pkts, CTX)
    assert f.status is Status.FAIL
    assert f.metrics["ipv6_leak_packets"] == 3 and f.metrics["ipv6_dns_leaks"] == 1


def test_ipv6_warn_when_routed_out_but_nothing_leaked() -> None:
    assert evaluate_ipv6(PHYSICAL, "wg0", False, [], CTX).status is Status.WARN


def test_ipv6_disabled_is_fine() -> None:
    f = evaluate_ipv6(PHYSICAL, "wg0", True, [], CTX)
    assert f.status is Status.PASS and f.metrics["static"] == "ok"


def test_identity() -> None:
    assert evaluate_identity("192.0.2.2", ["192.0.2.2"]).status is Status.PASS
    fail = evaluate_identity("198.51.100.1", ["192.0.2.2"])
    assert fail.status is Status.FAIL and "198.51.100.1" in fail.summary
    assert evaluate_identity(None, ["192.0.2.2"], "timed out").status is Status.WARN
    assert evaluate_identity("192.0.2.2", []).status is Status.WARN
