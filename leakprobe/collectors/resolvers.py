"""Collect configured DNS resolvers from resolv.conf and ``resolvectl status``."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from leakprobe.util import sh

_KEY_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z .]*?):\s+(.*)$")
_LINK_HEADER = re.compile(r"^Link \d+ \((?P<iface>[^)]+)\)")


@dataclass
class ResolverInfo:
    """Resolvers per source: resolv.conf, plus systemd-resolved scopes (global or per link)."""

    resolv_conf: list[str] = field(default_factory=list)
    resolved: dict[str, list[str]] = field(default_factory=dict)

    def all_servers(self) -> list[str]:
        """Every distinct nameserver, resolv.conf first."""
        seen: dict[str, None] = dict.fromkeys(self.resolv_conf)
        for servers in self.resolved.values():
            seen.update(dict.fromkeys(servers))
        return list(seen)


def parse_resolv_conf(text: str) -> list[str]:
    """``nameserver`` entries in order (scope ids like ``%wlan0`` kept)."""
    servers = []
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1])
    return servers


def _clean_server(token: str) -> str:
    return token.split("#", 1)[0]  # drop DoT server name: 1.1.1.1#cloudflare-dns.com


def parse_resolvectl(text: str) -> dict[str, list[str]]:
    """``DNS Servers`` per scope from ``resolvectl status``; scope is "global" or an iface."""
    result: dict[str, list[str]] = {}
    scope: str | None = None
    in_servers = False
    for line in text.splitlines():
        if not line.strip():
            in_servers = False
            continue
        if line.startswith("Global"):
            scope, in_servers = "global", False
            continue
        header = _LINK_HEADER.match(line)
        if header:
            scope, in_servers = header["iface"], False
            continue
        key_line = _KEY_LINE.match(line)
        if key_line:
            in_servers = key_line[1].strip() == "DNS Servers"
            if in_servers and scope:
                result.setdefault(scope, []).extend(map(_clean_server, key_line[2].split()))
        elif in_servers and scope:  # continuation line of DNS Servers
            result.setdefault(scope, []).extend(map(_clean_server, line.split()))
    return result


def collect(resolv_conf: Path = Path("/etc/resolv.conf")) -> ResolverInfo:
    """Read resolv.conf and, if systemd-resolved is running, its per-link servers."""
    conf = parse_resolv_conf(resolv_conf.read_text()) if resolv_conf.exists() else []
    status = sh.run(["resolvectl", "status", "--no-pager"], check=False)
    return ResolverInfo(conf, parse_resolvectl(status.stdout) if status.ok else {})
