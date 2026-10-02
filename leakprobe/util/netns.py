"""Run commands inside a named network namespace (through util/sh.py)."""

import subprocess
from collections.abc import Sequence
from pathlib import Path

from leakprobe.util import sh


def exec_argv(ns: str, args: Sequence[str]) -> list[str]:
    """``ip netns exec <ns> <args...>``."""
    return ["ip", "netns", "exec", ns, *args]


def run(
    ns: str, args: Sequence[str], *, check: bool = True, input_text: str | None = None,
    timeout: float | None = 30.0,
) -> sh.ShResult:
    """Run ``args`` inside ``ns``."""
    return sh.run(exec_argv(ns, args), check=check, input_text=input_text, timeout=timeout)


def spawn(ns: str, args: Sequence[str], *, log: Path | None = None) -> "subprocess.Popen[str]":
    """Start a long-running process inside ``ns`` (detached when ``log`` is given)."""
    return sh.spawn(exec_argv(ns, args), log=log)


def ip(ns: str, *args: str, check: bool = True) -> sh.ShResult:
    """``ip -n <ns> ...`` (cheaper than ``ip netns exec`` for iproute2 itself)."""
    return sh.run(["ip", "-n", ns, *args], check=check)


def list_namespaces() -> list[str]:
    """Names from ``ip netns list`` (may include an ``(id: N)`` suffix, stripped)."""
    out = sh.run(["ip", "netns", "list"], check=False).stdout
    return [line.split()[0] for line in out.splitlines() if line.strip()]


def pids(ns: str) -> list[int]:
    """PIDs of processes running in ``ns``."""
    out = sh.run(["ip", "netns", "pids", ns], check=False).stdout
    return [int(p) for p in out.split()]
