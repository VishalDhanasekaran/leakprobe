"""`leakprobe run` against lab profiles: complete report, fix snippets, exit codes (root + lab)."""

import pytest
from typer.testing import CliRunner

from leakprobe import cli
from leakprobe.lab import builder
from leakprobe.lab.profile import TEST_IDS, load_profile
from leakprobe.report.jsonout import from_json

pytestmark = pytest.mark.root


@pytest.mark.parametrize(("name", "code"), [("wg-default-leaky", 1), ("wg-hardened", 0)])
def test_run_lab_profile(name: str, code: int) -> None:
    args = ["run", "--mode", "lab", "--profile", name, "--trials", "3", "-f", "json"]
    result = CliRunner().invoke(cli.app, args)
    assert not builder.lab_namespaces()  # the temporary lab was torn down
    rep = from_json(result.stdout)
    assert result.exit_code == code, [f.summary for f in rep.findings]
    assert [f.test_id for f in rep.findings] == list(TEST_IDS)
    expected = load_profile(name).expected
    got = {f.test_id: f.status.value for f in rep.findings}
    assert got == {**got, **expected}, got
    for f in rep.findings:
        assert (f.remediation is not None) == (f.status.value in ("fail", "warn")), f.test_id


def test_run_reuses_running_lab() -> None:
    with builder.running_lab(load_profile("wg-hardened")):
        result = CliRunner().invoke(
            cli.app, ["run", "--profile", "wg-hardened", "--tests", "LP-IDENT-01", "-f", "json"]
        )
        assert result.exit_code == 0, result.output
        assert builder.status().up  # left running
    assert [f.test_id for f in from_json(result.stdout).findings] == ["LP-IDENT-01"]
