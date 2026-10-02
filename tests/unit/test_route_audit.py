"""LP-ROUTE-01 against real `ip -j` fixtures (tests/fixtures/routes/generate.sh)."""

from pathlib import Path

import pytest

from leakprobe.collectors import routes
from leakprobe.models import Status
from leakprobe.tests_impl.route_audit import LAN_BYPASS, TUNNELVISION, audit_routes

FIXTURES = Path(__file__).parent.parent / "fixtures" / "routes"



def test_normal_tunnel_passes() -> None:
    f = audit_routes(routes.load(FIXTURES / "wg_quick_full.json"), ["wg0"])
    assert f.status is Status.PASS
    assert f.metrics["ipv6_audited"] == "yes" and f.metrics["destinations"] == 5


def test_tunnelvision_fails_with_cve_message() -> None:
    f = audit_routes(routes.load(FIXTURES / "tunnelvision.json"), ["wg0"])
    assert f.status is Status.FAIL
    assert f.summary == TUNNELVISION and "CVE-2024-3661" in f.summary
    assert "bypass: 0.0.0.0/1 via 192.168.100.1 dev c-phys (table main)" in f.evidence
    assert "bypass: 128.0.0.0/1 via 192.168.100.1 dev c-phys (table main)" in f.evidence
    assert f.metrics["bypass_routes"] == 2


def test_tunnelvision_ipv6() -> None:
    f = audit_routes(routes.load(FIXTURES / "tunnelvision_v6.json"), ["wg0"])
    assert f.status is Status.FAIL and f.summary == TUNNELVISION
    assert any(e.startswith("bypass: ::/1") for e in f.evidence)


def test_v4_only_tunnel_defers_ipv6() -> None:
    f = audit_routes(routes.load(FIXTURES / "wg_quick_v4only.json"), ["wg0"])
    assert f.status is Status.PASS
    assert f.metrics["ipv6_audited"] == "no"
    assert any("see LP-V6-01" in e for e in f.evidence)


def test_openvpn_def1_with_endpoint_route_passes() -> None:
    f = audit_routes(routes.load(FIXTURES / "openvpn_def1.json"), ["tun0"], ["203.0.113.10"])
    assert f.status is Status.PASS


def test_endpoint_host_route_needs_endpoint() -> None:
    f = audit_routes(routes.load(FIXTURES / "openvpn_def1.json"), ["tun0"])
    assert f.status is Status.FAIL
    assert "bypass: 203.0.113.10/32 via 192.168.100.1 dev c-phys (table main)" in f.evidence


def test_no_tunnel_fails_without_tunnelvision_message() -> None:
    f = audit_routes(routes.load(FIXTURES / "no_tunnel.json"), ["wg0"])
    assert f.status is Status.FAIL
    assert f.summary == "4 of 4 test destinations egress via c-phys"


@pytest.mark.parametrize(("allow_lan", "status"), [(False, Status.FAIL), (True, Status.PASS)])
def test_routed_lan_prefix(allow_lan: bool, status: Status) -> None:
    f = audit_routes(routes.load(FIXTURES / "lan_route.json"), ["wg0"], allow_lan=allow_lan)
    assert f.status is status
    if status is Status.FAIL:
        assert f.summary == LAN_BYPASS


def test_empty_state_is_error() -> None:
    f = audit_routes(routes.RoutingState(), ["wg0"])
    assert f.status is Status.ERROR
