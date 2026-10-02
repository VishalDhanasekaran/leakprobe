"""Doctor checks run without root and report every tool."""

from leakprobe.doctor import LAB_TOOLS, run_checks


def test_run_checks_lists_everything() -> None:
    names = {c.name for c in run_checks()}
    assert "root" in names
    assert {f"tool: {t}" for t in LAB_TOOLS} <= names
    assert "kernel: netns" in names
