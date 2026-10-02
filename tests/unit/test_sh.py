"""The subprocess wrapper."""

import sys

import pytest

from leakprobe.util import sh


def test_run_captures_output() -> None:
    result = sh.run([sys.executable, "-c", "print('hi')"])
    assert result.ok
    assert result.stdout == "hi\n"


def test_no_shell_interpretation() -> None:
    result = sh.run([sys.executable, "-c", "import sys; print(sys.argv[1])", "a; echo b"])
    assert result.stdout == "a; echo b\n"


def test_check_raises_on_failure() -> None:
    with pytest.raises(sh.ShError, match="exited 3"):
        sh.run([sys.executable, "-c", "import sys; sys.exit(3)"])


def test_unchecked_failure_returns_result() -> None:
    result = sh.run([sys.executable, "-c", "import sys; sys.exit(3)"], check=False)
    assert result.returncode == 3 and not result.ok


def test_missing_command() -> None:
    result = sh.run(["leakprobe-no-such-tool"], check=False)
    assert result.returncode == 127
    with pytest.raises(sh.ShError):
        sh.run(["leakprobe-no-such-tool"])


def test_empty_command() -> None:
    with pytest.raises(ValueError):
        sh.run([])


def test_input_text() -> None:
    result = sh.run([sys.executable, "-c", "print(input()[::-1])"], input_text="abc\n")
    assert result.stdout == "cba\n"
