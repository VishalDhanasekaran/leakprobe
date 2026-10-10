"""Validation matrix: scoring, Markdown output, saved reports and the CLI."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from leakprobe import cli
from leakprobe.lab.profile import Profile, load_profile
from leakprobe.matrix import Cell, Matrix, build, from_dir, score, to_markdown
from leakprobe.models import Finding, Report, Severity, Status, make_report


def _report(statuses: dict[str, str]) -> Report:
    return make_report(
        [
            Finding(test_id=t, title=t, status=Status(s), severity=Severity.HIGH, summary="-")
            for t, s in statuses.items()
        ],
        mode="lab",
    )


def _profile(name: str, expected: dict[str, str]) -> Profile:
    return Profile.model_validate(
        {"name": name, "description": "-", "wireguard": None, "expected": expected}
    )


def test_score_counts_fail_as_positive() -> None:
    cells = [
        Cell("fail", "fail"),  # TP
        Cell("fail", "pass"),  # FP
        Cell("pass", "fail"),  # FN
        Cell("error", "fail"),  # FN
        Cell("pass", "pass"),  # TN
        Cell("warn", "pass"),  # TN, but disagrees
        Cell("warn", None),  # no ground truth: ignored
    ]
    s = score(cells)
    assert (s.tp, s.fp, s.fn, s.tn, s.agree, s.judged) == (1, 1, 2, 2, 2, 6)
    assert s.precision == 0.5 and s.recall == pytest.approx(1 / 3)
    assert s.agreement == pytest.approx(2 / 6)


def test_score_without_positives_is_undefined() -> None:
    s = score([Cell("pass", "pass")])
    assert s.precision is None and s.recall is None and s.agreement == 1.0


def test_markdown_marks_disagreements() -> None:
    m = Matrix(tests=("LP-DNS-01", "LP-SPLIT-01"))
    m.add("a", {"LP-DNS-01": "fail"}, _report({"LP-DNS-01": "fail", "LP-SPLIT-01": "warn"}))
    m.add("b", {"LP-DNS-01": "fail"}, _report({"LP-DNS-01": "pass"}))
    md = to_markdown(m)
    assert "| Profile | LP-DNS-01 | LP-SPLIT-01 |" in md
    assert "| a | FAIL ✓ | WARN · |" in md
    assert "| b | **PASS** ✗ (exp FAIL) | NOT RUN · |" in md
    assert "**Agreement:** 1/2 (50%)" in md
    assert "**Precision (FAIL):** 100%" in md and "**Recall (FAIL):** 50%" in md
    assert "| LP-DNS-01 | 1/2 | 100% | 50% | 1 | 0 | 1 |" in md
    assert "LP-SPLIT-01 | 0/0" not in md  # no ground truth, no per-test row
    assert "- b LP-DNS-01: measured PASS, expected FAIL" in md
    assert m.disagreements() == [("b", "LP-DNS-01", Cell("pass", "fail"))]


def test_markdown_all_agree() -> None:
    m = Matrix()
    m.add("p", {"LP-KILL-01": "pass"}, _report({"LP-KILL-01": "pass"}))
    md = to_markdown(m)
    assert "## Disagreements\n\nNone." in md and "Precision (FAIL):** n/a" in md


def test_build_saves_and_from_dir_rescores(tmp_path: Path) -> None:
    profs = [_profile("x", {"LP-V6-01": "fail"}), _profile("y", {"LP-V6-01": "pass"})]
    reports = {"x": _report({"LP-V6-01": "fail"}), "y": _report({"LP-V6-01": "fail"})}
    seen: list[str] = []
    m = build(profs, lambda p: reports[p.name], tmp_path, seen.append)
    assert seen == ["x", "y"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["x.json", "y.json"]
    again = from_dir(profs, tmp_path)
    assert again.rows == m.rows
    assert again.disagreements() == [("y", "LP-V6-01", Cell("fail", "pass"))]


def test_from_dir_missing_report(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="no saved report for x"):
        from_dir([_profile("x", {})], tmp_path)


def _save_expected(tmp_path: Path, name: str, flip: str | None = None) -> None:
    expected = dict(load_profile(name).expected)
    if flip:
        expected[flip] = "pass" if expected[flip] == "fail" else "fail"
    (tmp_path / f"{name}.json").write_text(_report(expected).model_dump_json())


def test_cli_from_dir(tmp_path: Path) -> None:
    _save_expected(tmp_path, "wg-hardened")
    _save_expected(tmp_path, "wg-dns-leak")
    out = tmp_path / "matrix.md"
    args = ["matrix", "--profiles", "wg-hardened,wg-dns-leak", "--from-dir", str(tmp_path),
            "-o", str(out)]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    assert "(100%)" in out.read_text()

    _save_expected(tmp_path, "wg-dns-leak", flip="LP-DNS-01")
    assert CliRunner().invoke(cli.app, args).exit_code == 1


def test_cli_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    assert runner.invoke(cli.app, ["matrix", "--profiles", "nope", "--from-dir",
                                   str(tmp_path)]).exit_code == 2
    assert runner.invoke(cli.app, ["matrix", "--from-dir", str(tmp_path)]).exit_code == 2

    def deny() -> None:
        raise cli.builder.LabError("needs root")

    monkeypatch.setattr(cli.builder, "require_root", deny)
    assert runner.invoke(cli.app, ["matrix"]).exit_code == 2
