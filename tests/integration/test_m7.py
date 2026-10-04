"""LP-START-01 and LP-SPLIT-01 against the lab (root + lab)."""

import sys
import time

import pytest

from leakprobe.lab import topology as t
from leakprobe.lab.builder import running_lab
from leakprobe.lab.profile import load_profile
from leakprobe.models import Status
from leakprobe.tests_impl.context import RunContext
from leakprobe.tests_impl.split import run_split
from leakprobe.tests_impl.startup import run_startup
from leakprobe.util import netns

pytestmark = pytest.mark.root

BOUND_SOCKET = (
    "import socket, time\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    f"s.bind(('{t.CLIENT_IP}', 0)); s.connect(('{t.CANARY_IP}', 9000))\n"
    "time.sleep(60)\n"
)


@pytest.mark.parametrize(
    ("profile", "status"), [("wg-default-leaky", Status.FAIL), ("wg-hardened", Status.PASS)]
)
def test_startup_race(profile: str, status: Status) -> None:
    with running_lab(load_profile(profile)) as state:
        f = run_startup(RunContext.from_lab(state))
        assert f.status is status, f.evidence
        assert "time_to_ready_ms" in f.metrics
        assert netns.run(t.CLIENT, ["ping", "-c1", "-W2", t.CANARY_IP], check=False).ok


def test_split_tunnel_warns_on_bound_socket() -> None:
    with running_lab(load_profile("wg-hardened")) as state:
        ctx = RunContext.from_lab(state)
        assert run_split(ctx).status is Status.PASS
        proc = netns.spawn(t.CLIENT, [sys.executable, "-c", BOUND_SOCKET])
        try:
            time.sleep(0.5)
            f = run_split(ctx)
        finally:
            proc.kill()
        assert f.status is Status.WARN and f.metrics["bypass_sockets"] == 1
        assert any(e.startswith(f"socket: udp {t.CLIENT_IP}:") for e in f.evidence)


def test_split_tunnel_warns_on_uidrange_rule() -> None:
    with running_lab(load_profile("wg-hardened")) as state:
        netns.ip(t.CLIENT, "rule", "add", "uidrange", "0-0", "lookup", "main", "priority", "100")
        f = run_split(RunContext.from_lab(state))
    assert f.status is Status.WARN and f.metrics["bypass_rules"] == 1
