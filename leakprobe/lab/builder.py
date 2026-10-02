"""Create, inspect and destroy the namespace lab. Needs root (CAP_NET_ADMIN)."""

import atexit
import ipaddress
import json
import os
import shutil
import signal
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path

from leakprobe.lab import topology as t
from leakprobe.lab.profile import Profile
from leakprobe.util import netns, sh

STATE_FILE = Path(t.STATE_DIR) / "lab.json"


class LabError(RuntimeError):
    """The lab could not be built or inspected."""


@dataclass
class Service:
    """A lab service process."""

    ns: str
    pid: int
    proto: str
    port: int


@dataclass
class LabState:
    """What ``lab up`` built; saved to /run/leakprobe/lab.json."""

    profile: str
    started_at: float
    services: dict[str, Service] = field(default_factory=dict)
    dns_logs: dict[str, str] = field(default_factory=dict)

    def save(self, path: Path = STATE_FILE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=1) + "\n")

    @classmethod
    def load(cls, path: Path = STATE_FILE) -> "LabState | None":
        if not path.exists():
            return None
        raw = json.loads(path.read_text())
        services = {k: Service(**v) for k, v in raw.pop("services").items()}
        return cls(services=services, **raw)


@dataclass
class LabStatus:
    """Result of ``lab status``."""

    state: LabState | None
    namespaces: list[str]
    services_alive: dict[str, bool]
    handshake_age_s: float | None

    @property
    def up(self) -> bool:
        return (
            self.state is not None
            and set(t.NAMESPACES) <= set(self.namespaces)
            and all(self.services_alive.values())
        )


def require_root() -> None:
    """Raise LabError unless running as root."""
    if os.geteuid() != 0:
        raise LabError("the lab needs root (CAP_NET_ADMIN); run with sudo")


# ----- pure helpers (unit-tested) -------------------------------------------------------------


def nat_ruleset(oif_match: str) -> str:
    """Masquerade everything leaving through interfaces matched by ``oif_match``."""
    return (
        "table inet lp_nat {\n"
        "  chain postrouting {\n"
        "    type nat hook postrouting priority srcnat; policy accept;\n"
        f"    oifname {oif_match} masquerade\n"
        "  }\n"
        "}\n"
    )


def killswitch_ruleset(family: str, tunnel: str, endpoint_ip: str, endpoint_port: int) -> str:
    """The PLAN.md section 9 kill switch; ``family`` "inet" (v4+v6) or "ip" (v4 only)."""
    lines = [
        f"table {family} leakprobe_killswitch {{",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        '    oifname "lo" accept',
        f'    oifname "{tunnel}" accept',
        f"    ip daddr {endpoint_ip} udp dport {endpoint_port} accept",
        "    udp sport 68 udp dport 67 accept",
    ]
    if family == "inet":
        lines.append(
            "    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept"
        )
    return "\n".join([*lines, "  }", "}"]) + "\n"


def wg_route_commands(allowed_ips: list[str]) -> list[list[str]]:
    """wg-quick style routing for the client: ``ip`` argument lists, per address family.

    A family with a /0 gets its routes in table 51820 plus ``not fwmark`` and
    ``suppress_prefixlength 0`` rules; otherwise routes go straight into main.
    """
    cmds: list[list[str]] = []
    for fam in (4, 6):
        nets = [ipaddress.ip_network(n) for n in allowed_ips]
        nets = [n for n in nets if n.version == fam]
        if not nets:
            continue
        flag = f"-{fam}"
        full = any(n.prefixlen == 0 for n in nets)
        for n in nets:
            table = ["table", t.WG_TABLE] if full else []
            cmds.append([flag, "route", "add", str(n), "dev", t.TUNNEL, *table])
        if full:
            mark = hex(t.WG_FWMARK)
            cmds.append([flag, "rule", "add", "not", "fwmark", mark, "table", t.WG_TABLE])
            cmds.append([flag, "rule", "add", "table", "main", "suppress_prefixlength", "0"])
    return cmds


def resolv_conf(profile: Profile) -> str:
    """Client resolv.conf: the tunnel resolver if the profile pins one, else the ISP's."""
    dns = profile.wireguard.dns if profile.wireguard and profile.wireguard.dns else t.ISP_RESOLVER
    return f"# written by leakprobe lab ({profile.name})\nnameserver {dns}\n"


# ----- build steps ----------------------------------------------------------------------------


def _nft(ns: str, ruleset: str) -> None:
    netns.run(ns, ["nft", "-f", "-"], input_text=ruleset)


def _sysctl(ns: str, *settings: str) -> None:
    netns.run(ns, ["sysctl", "-qw", *settings])


def _build_topology() -> None:
    for ns in t.NAMESPACES:
        sh.run(["ip", "netns", "add", ns])
        netns.ip(ns, "link", "set", "lo", "up")
    for ns_a, dev_a, addrs_a, ns_b, dev_b, addrs_b in t.LINKS:
        sh.run(["ip", "link", "add", dev_a, "netns", ns_a, "type", "veth",
                "peer", "name", dev_b, "netns", ns_b])
        for ns, dev, addrs in ((ns_a, dev_a, addrs_a), (ns_b, dev_b, addrs_b)):
            for addr in addrs:
                extra = ["nodad"] if ":" in addr else []
                netns.ip(ns, "addr", "add", addr, "dev", dev, *extra)
            netns.ip(ns, "link", "set", dev, "up")

    netns.ip(t.INET, "addr", "add", f"{t.CANARY_IP}/32", "dev", "lo")
    netns.ip(t.INET, "addr", "add", f"{t.CANARY_IP6}/128", "dev", "lo")

    netns.ip(t.CLIENT, "route", "add", "default", "via", t.ISP_GW, "dev", t.PHYSICAL)
    netns.ip(t.CLIENT, "-6", "route", "add", "default", "via", t.ISP_GW6, "dev", t.PHYSICAL)
    netns.ip(t.ISP, "route", "add", "default", "via", "198.51.100.254")
    netns.ip(t.ISP, "-6", "route", "add", "default", "via", "2001:db8:51::254")
    netns.ip(t.VPN, "route", "add", "default", "via", "192.0.2.254")
    netns.ip(t.VPN, "-6", "route", "add", "default", "via", "2001:db8:192::254")

    for ns in (t.ISP, t.VPN):
        _sysctl(ns, "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
    _nft(t.ISP, nat_ruleset('!= "i-c"'))  # ISP NATs the client toward the VPN and the internet
    _nft(t.VPN, nat_ruleset('"v-n"'))  # VPN exit NAT: tunneled traffic appears as 192.0.2.2


def _wg_keypair() -> tuple[str, str]:
    private = sh.run(["wg", "genkey"]).stdout.strip()
    public = sh.run(["wg", "pubkey"], input_text=private + "\n").stdout.strip()
    return private, public


def _build_wireguard(profile: Profile) -> None:
    assert profile.wireguard is not None
    client_priv, client_pub = _wg_keypair()
    server_priv, server_pub = _wg_keypair()
    v6 = any(ipaddress.ip_network(n).version == 6 for n in profile.wireguard.allowed_ips)

    netns.ip(t.VPN, "link", "add", t.TUNNEL, "type", "wireguard")
    netns.run(t.VPN, ["wg", "set", t.TUNNEL, "private-key", "/dev/stdin",
                      "listen-port", str(t.ENDPOINT_PORT), "peer", client_pub,
                      "allowed-ips", "10.66.0.2/32,fd66::2/128"], input_text=server_priv + "\n")
    for addr in t.WG_SERVER:
        netns.ip(t.VPN, "addr", "add", addr, "dev", t.TUNNEL, *(["nodad"] if ":" in addr else []))
    netns.ip(t.VPN, "link", "set", t.TUNNEL, "up")

    netns.ip(t.CLIENT, "link", "add", t.TUNNEL, "type", "wireguard")
    netns.run(t.CLIENT, ["wg", "set", t.TUNNEL, "private-key", "/dev/stdin",
                         "fwmark", hex(t.WG_FWMARK), "peer", server_pub,
                         "endpoint", f"{t.ENDPOINT_IP}:{t.ENDPOINT_PORT}",
                         "allowed-ips", ",".join(profile.wireguard.allowed_ips),
                         "persistent-keepalive", "25"], input_text=client_priv + "\n")
    netns.ip(t.CLIENT, "addr", "add", t.WG_CLIENT[0], "dev", t.TUNNEL)
    if v6:
        netns.ip(t.CLIENT, "addr", "add", t.WG_CLIENT[1], "dev", t.TUNNEL, "nodad")
    netns.ip(t.CLIENT, "link", "set", t.TUNNEL, "up")
    _sysctl(t.CLIENT, "net.ipv4.conf.all.src_valid_mark=1")
    for cmd in wg_route_commands(profile.wireguard.allowed_ips):
        netns.ip(t.CLIENT, *cmd)


def _build_client_policy(profile: Profile) -> None:
    etc = Path(t.NETNS_ETC) / t.CLIENT
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "resolv.conf").write_text(resolv_conf(profile))
    if profile.firewall != "none":
        family = "inet" if profile.firewall == "killswitch" else "ip"
        _nft(t.CLIENT, killswitch_ruleset(family, t.TUNNEL, t.ENDPOINT_IP, t.ENDPOINT_PORT))
    for route in profile.extra_routes:
        netns.ip(t.CLIENT, "route", "add", route.dst, "via", route.via, "dev", t.PHYSICAL,
                 "proto", "dhcp")


def _listening(ns: str, proto: str, port: int) -> bool:
    flag = "-Hlnu" if proto == "udp" else "-Hlnt"
    return bool(netns.run(ns, ["ss", flag, "sport", "=", f":{port}"], check=False).stdout.strip())


def _start_service(name: str, ns: str, proto: str, port: int, args: list[str]) -> Service:
    log = Path(t.STATE_DIR) / f"{name}.stderr"
    proc = netns.spawn(ns, [sys.executable, "-m", "leakprobe.lab.services", *args], log=log)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise LabError(f"service {name} exited: {log.read_text().strip()}")
        if _listening(ns, proto, port):
            return Service(ns, proc.pid, proto, port)
        time.sleep(0.05)
    raise LabError(f"service {name} not listening on {proto}/{port}")


def _start_services(state: LabState, tunnel: bool) -> None:
    logs = Path(t.STATE_DIR)
    state.services["beacon"] = _start_service(
        "beacon", t.INET, "tcp", t.BEACON_PORT, ["beacon", "--port", str(t.BEACON_PORT)])
    state.services["canary"] = _start_service(
        "canary", t.INET, "udp", t.CANARY_UDP_PORT, ["canary", "--port", str(t.CANARY_UDP_PORT)])
    resolvers = [("isp", t.ISP, t.ISP_RESOLVER)]
    if tunnel:
        resolvers.append(("vpn", t.VPN, t.VPN_RESOLVER))
    for name, ns, ip in resolvers:
        log = logs / f"{name}-dns.log"
        state.dns_logs[name] = str(log)
        state.services[f"{name}-dns"] = _start_service(
            f"{name}-dns", ns, "udp", 53,
            ["dns", "--bind", ip, "--log", str(log), "--answer", t.CANARY_IP])


# ----- lifecycle ------------------------------------------------------------------------------


def lab_namespaces() -> list[str]:
    """Existing namespaces with the lab prefix."""
    return [ns for ns in netns.list_namespaces() if ns.startswith(t.PREFIX)]


def _alive(pid: int) -> bool:
    return Path(f"/proc/{pid}").exists()


def status() -> LabStatus:
    """Inspect the lab without changing it."""
    state = LabState.load()
    present = lab_namespaces()
    alive = {name: _alive(s.pid) for name, s in state.services.items()} if state else {}
    age = None
    if t.CLIENT in present:
        out = netns.run(t.CLIENT, ["wg", "show", t.TUNNEL, "latest-handshakes"], check=False)
        stamps = [int(line.split()[1]) for line in out.stdout.splitlines() if line.strip()]
        if stamps and max(stamps) > 0:
            age = time.time() - max(stamps)
    return LabStatus(state, present, alive, age)


def down() -> list[str]:
    """Remove everything with the ``lp-`` prefix, even after a crash. Returns removed names."""
    removed = lab_namespaces()
    for ns in removed:
        for pid in netns.pids(ns):
            with suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        sh.run(["ip", "netns", "del", ns], check=False)
    etc = Path(t.NETNS_ETC)
    if etc.is_dir():
        for d in etc.glob(f"{t.PREFIX}*"):
            shutil.rmtree(d, ignore_errors=True)
    STATE_FILE.unlink(missing_ok=True)
    return removed


def up(profile: Profile) -> LabState:
    """Build the lab for ``profile``. Idempotent: a healthy lab for the same profile is kept."""
    require_root()
    current = status()
    if current.up and current.state is not None and current.state.profile == profile.name:
        return current.state
    down()
    Path(t.STATE_DIR).mkdir(parents=True, exist_ok=True)
    for old in Path(t.STATE_DIR).glob("*.log"):
        old.unlink()
    state = LabState(profile=profile.name, started_at=time.time())
    try:
        _build_topology()
        _build_client_policy(profile)  # kill switch is in place before the tunnel exists
        if profile.wireguard is not None:
            _build_wireguard(profile)
        _start_services(state, tunnel=profile.wireguard is not None)
        state.save()
    except (sh.ShError, LabError, OSError):
        down()
        raise
    return state


@contextmanager
def running_lab(profile: Profile) -> Iterator[LabState]:
    """Build the lab and always tear it down, also on exceptions and interpreter exit."""
    atexit.register(down)
    try:
        yield up(profile)
    finally:
        down()
        atexit.unregister(down)
