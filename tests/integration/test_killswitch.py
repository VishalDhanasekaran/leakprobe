"""LP-KILL-01 against the lab with short trials (root + lab).

The full PLAN.md acceptance run (20 trials, 2 s + 3 s) is
`sudo leakprobe drop-test --trials 20` on wg-hardened and wg-no-killswitch.
"""

import json

import pytest
from typer.testing import CliRunner

from leakprobe.cli import app
from leakprobe.lab import topology as t
from leakprobe.lab.builder import running_lab
from leakprobe.lab.profile import load_profile
from leakprobe.models import Status
from leakprobe.tests_impl.context import RunContext
from leakprobe.tests_impl.killswitch import run_killswitch
from leakprobe.util import netns

pytestmark = pytest.mark.root
SHORT = {"pre_s": 1.0, "post_s": 1.5, "settle_s": 0.5}


def tunnel_works() -> bool:
    return netns.run(t.CLIENT, ["ping", "-c1", "-W2", t.CANARY_IP], check=False).ok


@pytest.mark.parametrize(
    ("profile", "method", "status"),
    [
        ("wg-hardened", "link-down", Status.PASS),
        ("wg-hardened", "delete-iface", Status.PASS),
        ("wg-no-killswitch", "link-down", Status.FAIL),
        ("wg-no-killswitch", "delete-iface", Status.FAIL),
        ("wg-no-killswitch", "endpoint-block", Status.PASS),  # blackholed, not leaked
    ],
)
def test_fault_methods(profile: str, method: str, status: Status) -> None:
    with running_lab(load_profile(profile)) as state:
        f = run_killswitch(RunContext.from_lab(state), method, trials=2, **SHORT)
        assert f.status is status, f.evidence
        assert f.metrics["trials"] == 2 and f.metrics["failed_trials"] == 0
        if status is Status.FAIL:
            assert f.metrics["leaked_trials"] == 2 and float(f.metrics["leak_packets_max"]) > 0
        assert tunnel_works()  # restore() brought the tunnel back


def test_no_tunnel_always_leaks() -> None:
    with running_lab(load_profile("control-broken")) as state:
        f = run_killswitch(RunContext.from_lab(state), "link-down", trials=1, **SHORT)
    assert f.status is Status.FAIL and "does not exist" in f.evidence[0]


def test_drop_test_cli() -> None:
    with running_lab(load_profile("wg-no-killswitch")):
        args = ["drop-test", "-n", "1", "--pre", "1", "--post", "1", "-f", "json"]
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 1, result.output
    finding = json.loads(result.output)["findings"][0]
    assert finding["test_id"] == "LP-KILL-01" and finding["metrics"]["leaked_trials"] == 1
