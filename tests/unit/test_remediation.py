"""Remediation snippets attached to FAIL/WARN findings."""

import pytest

from leakprobe.lab.profile import TEST_IDS
from leakprobe.models import Finding, Severity, Status
from leakprobe.report.remediation import (
    FixContext,
    delete_routes,
    killswitch,
    remediation_for,
    with_remediation,
)

CTX = FixContext("wg0", "c-phys", "203.0.113.10", 51820, "10.66.0.1")


def _finding(test_id: str, status: Status = Status.FAIL, **kw: object) -> Finding:
    return Finding(
        test_id=test_id, title=test_id, status=status, severity=Severity.HIGH, summary="x",
        **kw,  # type: ignore[arg-type]
    )


def test_killswitch_substitutes_names() -> None:
    text = killswitch(CTX)
    assert "table inet leakprobe_killswitch" in text
    assert 'oifname "wg0" accept' in text
    assert "ip daddr 203.0.113.10 udp dport 51820 accept" in text


def test_killswitch_ipv6_endpoint_without_port() -> None:
    text = killswitch(FixContext("wg1", "eth0", "2001:db8::1"))
    assert "ip6 daddr 2001:db8::1 accept" in text


@pytest.mark.parametrize("test_id", TEST_IDS)
@pytest.mark.parametrize("status", [Status.FAIL, Status.WARN])
def test_every_test_has_a_snippet(test_id: str, status: Status) -> None:
    assert remediation_for(_finding(test_id, status), CTX)


@pytest.mark.parametrize("status", [Status.PASS, Status.SKIP, Status.ERROR])
def test_no_snippet_unless_fail_or_warn(status: Status) -> None:
    assert remediation_for(_finding("LP-KILL-01", status), CTX) is None


def test_unknown_test_has_no_snippet() -> None:
    assert remediation_for(_finding("LP-NOPE-01"), CTX) is None


def test_dns_pins_tunnel_resolver() -> None:
    text = remediation_for(_finding("LP-DNS-01"), CTX) or ""
    assert "DNS = 10.66.0.1" in text
    assert "resolvectl default-route c-phys false" in text
    unknown = remediation_for(_finding("LP-DNS-01"), FixContext("wg0", "eth0", "1.2.3.4"))
    assert "<tunnel resolver IP>" in (unknown or "")


def test_ipv6_offers_allowed_ips_and_sysctl() -> None:
    text = remediation_for(_finding("LP-V6-01"), CTX) or ""
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in text
    assert "net.ipv6.conf.c-phys.disable_ipv6=1" in text


def test_route_deletes_bypass_routes() -> None:
    evidence = [
        "1.1.1.1 -> c-phys via 192.168.100.1 (table main, 0.0.0.0/1)",
        "bypass: 0.0.0.0/1 via 192.168.100.1 dev c-phys (table main)",
        "bypass: 128.0.0.0/1 via 192.168.100.1 dev c-phys (table main)",
        "bypass: 2000::/3 dev c-phys (table main)",
    ]
    assert delete_routes(evidence).splitlines() == [
        "ip route del 0.0.0.0/1 via 192.168.100.1 dev c-phys table main",
        "ip route del 128.0.0.0/1 via 192.168.100.1 dev c-phys table main",
        "ip -6 route del 2000::/3 dev c-phys table main",
    ]
    text = remediation_for(_finding("LP-ROUTE-01", evidence=evidence), CTX) or ""
    assert "option 121" in text and "leakprobe_killswitch" in text


def test_route_without_bypass_suggests_full_tunnel() -> None:
    text = remediation_for(_finding("LP-ROUTE-01"), CTX) or ""
    assert "AllowedIPs" in text and "route del" not in text


def test_egress_snippet_follows_leak_reasons() -> None:
    plain = remediation_for(_finding("LP-EGRESS-01", metrics={"leak_other": 3}), CTX) or ""
    assert "leakprobe_killswitch" in plain and "DNS =" not in plain and "AllowedIPs" not in plain
    both = _finding("LP-EGRESS-01", metrics={"leak_dns": 1, "leak_ipv6": 2})
    text = remediation_for(both, CTX) or ""
    assert "DNS = 10.66.0.1" in text and "AllowedIPs" in text


def test_with_remediation_keeps_existing_and_skips_pass() -> None:
    findings = [
        _finding("LP-KILL-01"),
        _finding("LP-DNS-01", Status.PASS),
        _finding("LP-V6-01", remediation="custom"),
    ]
    out = with_remediation(findings, CTX)
    assert out[0].remediation and "leakprobe_killswitch" in out[0].remediation
    assert out[1].remediation is None
    assert out[2].remediation == "custom"
    assert findings[0].remediation is None  # originals untouched
