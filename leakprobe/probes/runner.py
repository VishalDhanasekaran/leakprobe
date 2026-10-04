"""Run probes as subprocesses inside the client namespace (or locally in real mode)."""

import json
import subprocess
import sys
from typing import Any

from leakprobe.util import netns, sh


def probe_argv(*args: str) -> list[str]:
    """Command line for ``python -m leakprobe.probes``."""
    return [sys.executable, "-m", "leakprobe.probes", *args]


def run_probe(ns: str | None, *args: str, timeout: float = 30.0) -> dict[str, Any]:
    """Run one probe to completion and return its JSON result."""
    argv = probe_argv(*args)
    result = netns.run(ns, argv, timeout=timeout) if ns else sh.run(argv, timeout=timeout)
    data: dict[str, Any] = json.loads(result.stdout)
    return data


def spawn_probe(ns: str | None, *args: str) -> "subprocess.Popen[str]":
    """Start a long-running probe (e.g. ``stream ... --out FILE``) in the background."""
    argv = probe_argv(*args)
    return netns.spawn(ns, argv) if ns else sh.spawn(argv)
