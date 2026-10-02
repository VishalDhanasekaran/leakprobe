"""Lab lifecycle and data paths. Needs root + LEAKPROBE_LAB=1 (or scripts/sandbox.sh)."""

import sys
from pathlib import Path

import pytest

from leakprobe.lab import builder
from leakprobe.lab import topology as t
from leakprobe.lab.profile import list_profiles, load_profile
from leakprobe.util import netns

pytestmark = pytest.mark.root

BEACON_QUERY = """
import socket, sys
host, mark = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
if mark:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
s.settimeout(2)
s.connect((host, 8080))
print(s.recv(64).decode().strip())
"""


def beacon_sees(host: str = t.CANARY_IP, mark: int = 0) -> str:
    """Source IP the beacon observes for a connection from the client."""
    out = netns.run(t.CLIENT, [sys.executable, "-c", BEACON_QUERY, host, str(mark)], check=False)
    return out.stdout.strip() or "unreachable"


def ping(host: str, mark: int = 0) -> bool:
    args = ["ping", "-c1", "-W2", *(["-m", str(mark)] if mark else []), host]
    return netns.run(t.CLIENT, args, check=False).ok


def no_lab_left() -> bool:
    etc = Path(t.NETNS_ETC)
    return builder.lab_namespaces() == [] and not (etc.is_dir() and any(etc.glob("lp-*")))


def test_ping_canary_through_tunnel_and_directly() -> None:
    with builder.running_lab(load_profile("wg-default-leaky")):
        assert ping(t.CANARY_IP)
        assert beacon_sees() == t.EXIT_VIA_VPN
        # wg's fwmark sends traffic through the main table: the direct ISP path.
        assert ping(t.CANARY_IP, mark=t.WG_FWMARK)
        assert beacon_sees(mark=t.WG_FWMARK) == t.EXIT_VIA_ISP
    assert no_lab_left()


def test_kill_switch_blocks_direct_path() -> None:
    with builder.running_lab(load_profile("wg-hardened")):
        assert beacon_sees() == t.EXIT_VIA_VPN
        assert beacon_sees(t.CANARY_IP6) == t.EXIT_VIA_VPN6
        assert not ping(t.CANARY_IP, mark=t.WG_FWMARK)


@pytest.mark.parametrize("name", list_profiles())
def test_profile_builds(name: str) -> None:
    profile = load_profile(name)
    with builder.running_lab(profile):
        status = builder.status()
        assert status.up and status.state is not None and status.state.profile == name
        resolv = netns.run(t.CLIENT, ["cat", "/etc/resolv.conf"]).stdout
        assert f"nameserver {builder.resolv_conf(profile).split()[-1]}" in resolv
        bypassed = profile.wireguard is None or bool(profile.extra_routes)
        assert beacon_sees() == (t.EXIT_VIA_ISP if bypassed else t.EXIT_VIA_VPN)
    assert no_lab_left()


def test_up_is_idempotent() -> None:
    profile = load_profile("wg-no-killswitch")
    with builder.running_lab(profile) as first:
        again = builder.up(profile)
        assert again.started_at == first.started_at
        assert builder.status().up


def test_up_replaces_other_profile() -> None:
    with builder.running_lab(load_profile("wg-no-killswitch")):
        state = builder.up(load_profile("control-broken"))
        assert state.profile == "control-broken" and builder.status().up


def test_cleanup_after_failure() -> None:
    profile = load_profile("wg-hardened")
    with pytest.raises(RuntimeError, match="boom"), builder.running_lab(profile):
        raise RuntimeError("boom")
    assert no_lab_left()


def test_down_after_crash() -> None:
    builder.up(load_profile("wg-hardened"))
    builder.STATE_FILE.unlink()  # simulate a crash that lost the state file
    assert sorted(builder.down()) == sorted(t.NAMESPACES)
    assert no_lab_left()
