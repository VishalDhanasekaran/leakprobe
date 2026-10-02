"""Environment checks for ``leakprobe doctor``: root, tools, kernel support."""

import os
from dataclasses import dataclass
from pathlib import Path

from leakprobe.util import sh

LAB_TOOLS = ("ip", "wg", "nft", "tcpdump")
OPTIONAL_TOOLS = ("openvpn",)


@dataclass(frozen=True)
class Check:
    """One doctor check."""

    name: str
    ok: bool
    detail: str
    required: bool = True


def _wireguard_module() -> Check:
    if Path("/sys/module/wireguard").exists():
        return Check("kernel: wireguard", True, "loaded")
    found = sh.run(["modinfo", "wireguard"], check=False).ok
    return Check("kernel: wireguard", found, "available" if found else "module not found")


def run_checks() -> list[Check]:
    """Collect all doctor checks. Read-only; safe to run without root."""
    is_root = os.geteuid() == 0
    checks = [Check("root", is_root, "euid 0" if is_root else "run with sudo for lab/capture")]
    for tool in LAB_TOOLS:
        path = sh.which(tool)
        checks.append(Check(f"tool: {tool}", path is not None, path or "not installed"))
    for tool in OPTIONAL_TOOLS:
        path = sh.which(tool)
        checks.append(Check(f"tool: {tool}", path is not None, path or "not installed", False))
    checks.append(_wireguard_module())
    netns = Path("/proc/self/ns/net").exists()
    checks.append(Check("kernel: netns", netns, "supported" if netns else "unsupported"))
    return checks
