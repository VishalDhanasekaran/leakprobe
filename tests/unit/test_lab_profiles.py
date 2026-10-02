"""Shipped lab profiles parse and carry complete ground truth."""

import pytest
from pydantic import ValidationError

from leakprobe.lab.profile import TEST_IDS, Profile, list_profiles, load_profile

SHIPPED = [
    "control-broken", "wg-default-leaky", "wg-dns-leak", "wg-hardened",
    "wg-ipv6-leak", "wg-no-killswitch", "wg-tunnelvision",
]


def test_all_shipped_profiles_present() -> None:
    assert list_profiles() == SHIPPED


@pytest.mark.parametrize("name", SHIPPED)
def test_profile_has_full_expected_map(name: str) -> None:
    profile = load_profile(name)
    # LP-SPLIT-01 only ever WARNs, so it is not part of the ground truth.
    assert set(profile.expected) == set(TEST_IDS) - {"LP-SPLIT-01"}


def test_plan_example_profile() -> None:
    p = load_profile("wg-default-leaky")
    assert p.wireguard is not None and p.wireguard.allowed_ips == ["0.0.0.0/0"]
    assert p.wireguard.dns is None and p.firewall == "none"
    assert p.expected["LP-V6-01"] == "fail" and p.expected["LP-IDENT-01"] == "pass"


def test_hardened_passes_everything() -> None:
    assert set(load_profile("wg-hardened").expected.values()) == {"pass"}


def test_control_broken_fails_everything() -> None:
    p = load_profile("control-broken")
    assert p.wireguard is None and set(p.expected.values()) == {"fail"}


def test_unknown_profile() -> None:
    with pytest.raises(ValueError, match="unknown profile"):
        load_profile("nope")


def test_rejects_bad_test_id_and_network() -> None:
    base = {"name": "x", "description": "x", "wireguard": None}
    with pytest.raises(ValidationError, match="unknown test ids"):
        Profile.model_validate({**base, "expected": {"LP-BOGUS-01": "pass"}})
    with pytest.raises(ValidationError):
        Profile.model_validate({**base, "wireguard": {"allowed_ips": ["not-a-net"]}})
    with pytest.raises(ValidationError):
        Profile.model_validate({**base, "firewall": "iptables"})
