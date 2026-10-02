"""Address helpers."""

import ipaddress

import pytest

from leakprobe.util.net import LINK_SCOPE_NETS, PRIVATE_NETS, parse_endpoint, within


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("203.0.113.10:51820", ("203.0.113.10", 51820)),
        ("203.0.113.10", ("203.0.113.10", None)),
        ("[2001:db8::1]:51820", ("2001:db8::1", 51820)),
        ("2001:DB8::1", ("2001:db8::1", None)),
    ],
)
def test_parse_endpoint(text: str, expected: tuple[str, int | None]) -> None:
    assert parse_endpoint(text) == expected


def test_parse_endpoint_invalid() -> None:
    with pytest.raises(ValueError):
        parse_endpoint("not-an-ip:1")


def test_within() -> None:
    assert within(ipaddress.ip_network("192.168.100.0/24"), PRIVATE_NETS)
    assert not within(ipaddress.ip_network("0.0.0.0/1"), PRIVATE_NETS)
    assert within(ipaddress.ip_network("fe80::/64"), LINK_SCOPE_NETS)
    assert not within(ipaddress.ip_network("198.51.100.0/24"), PRIVATE_NETS + LINK_SCOPE_NETS)
