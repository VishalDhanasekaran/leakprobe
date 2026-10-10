"""`leakprobe matrix` against real lab profiles (root + lab)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from leakprobe import cli
from leakprobe.lab import builder

pytestmark = pytest.mark.root

PROFILES = "wg-hardened,wg-tunnelvision"


def test_matrix_two_profiles(tmp_path: Path) -> None:
    out, saved = tmp_path / "matrix.md", tmp_path / "reports"
    args = ["matrix", "--profiles", PROFILES, "--trials", "2",
            "--save-dir", str(saved), "-o", str(out)]
    result = CliRunner().invoke(cli.app, args)
    md = out.read_text()
    print(md)
    assert result.exit_code == 0, md
    assert "| wg-tunnelvision | FAIL ✓ |" in md  # LP-ROUTE-01 column
    assert "(100%)" in md
    assert sorted(p.name for p in saved.iterdir()) == ["wg-hardened.json", "wg-tunnelvision.json"]
    assert not builder.lab_namespaces()
    rescored = CliRunner().invoke(
        cli.app, ["matrix", "--profiles", PROFILES, "--from-dir", str(saved)]
    )
    assert rescored.exit_code == 0 and rescored.stdout == md
