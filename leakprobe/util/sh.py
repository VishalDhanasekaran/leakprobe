"""The only subprocess wrapper in LeakProbe. Argument lists only, never a shell."""

import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ShResult:
    """Outcome of an external command."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class ShError(RuntimeError):
    """Raised when a checked command fails or cannot be started."""

    def __init__(self, result: ShResult) -> None:
        self.result = result
        detail = result.stderr.strip() or result.stdout.strip()
        super().__init__(f"{' '.join(result.args)} exited {result.returncode}: {detail}")


def run(
    args: Sequence[str],
    *,
    check: bool = True,
    timeout: float | None = 30.0,
    input_text: str | None = None,
) -> ShResult:
    """Run ``args`` and capture text output. Raise ShError on failure when ``check``."""
    argv = tuple(args)
    if not argv:
        raise ValueError("empty command")
    try:
        proc = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        result = ShResult(argv, 127, "", f"command not found: {argv[0]}")
    else:
        result = ShResult(argv, proc.returncode, proc.stdout, proc.stderr)
    if check and not result.ok:
        raise ShError(result)
    return result


def which(tool: str) -> str | None:
    """Absolute path of ``tool`` on PATH, or None."""
    return shutil.which(tool)


def spawn(args: Sequence[str], *, log: Path | None = None) -> "subprocess.Popen[str]":
    """Start a long-running command; stdout is discarded.

    Without ``log`` stderr is piped to the caller (e.g. tcpdump). With ``log`` the process is
    detached into its own session and stderr goes to that file, so it outlives the caller.
    """
    argv = tuple(args)
    if not argv:
        raise ValueError("empty command")
    if log is None:
        return subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True,
        )
    with log.open("a") as err:
        return subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err, text=True,
            start_new_session=True,
        )
