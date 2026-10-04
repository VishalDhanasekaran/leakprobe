"""LP-V6-01, LP-DNS-01 and LP-IDENT-01 match each profile's ground truth (root + lab)."""

import pytest

from leakprobe.lab.builder import running_lab
from leakprobe.lab.profile import list_profiles, load_profile
from leakprobe.tests_impl.context import RunContext
from leakprobe.tests_impl.dns_leak import run_dns
from leakprobe.tests_impl.identity import run_identity
from leakprobe.tests_impl.ipv6_leak import run_ipv6

pytestmark = pytest.mark.root


@pytest.mark.parametrize("name", list_profiles())
def test_results_match_expected(name: str) -> None:
    profile = load_profile(name)
    with running_lab(profile) as state:
        ctx = RunContext.from_lab(state)
        findings = [run_ipv6(ctx), run_dns(ctx), run_identity(ctx)]
    got = {f.test_id: f.status.value for f in findings}
    assert got == {k: profile.expected[k] for k in got}, [f.summary for f in findings]
