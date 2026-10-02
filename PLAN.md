# LeakProbe — Implementation Plan

> A Linux CLI that measures whether a VPN tunnel actually protects traffic: DNS leaks, IPv6 leaks, route bypasses, kill-switch failures, startup races, and split-tunnel surprises. It runs against a deterministic network-namespace lab (default) or a real machine.

This file is the single source of truth for building the project with Claude Code. Read it fully before writing code, then implement the milestones in order.

---

## 0. Working agreements for Claude Code

1. Implement one milestone at a time (section 10). Each milestone has acceptance criteria. Do not start the next until the current one passes its tests.
2. Run `pytest -q`, `ruff check .` and `mypy leakprobe` after every milestone and fix failures before moving on.
3. Keep **capture** (needs root) separate from **analysis** (pure functions over data). Analysis must be unit-testable with fixtures and no root.
4. Never use `shell=True`. Call external tools with argument lists through the single wrapper in `leakprobe/util/sh.py`.
5. Do not add dependencies beyond section 3 without asking.
6. Every module gets type hints and a short docstring. Prefer small pure functions and dataclasses/pydantic models.
7. If something in this spec is ambiguous or contradicts what you find on the machine, stop and ask instead of guessing.
8. Commit after each milestone with a message like `M3: pcap analyzer and allowlist classifier`.

---

## 1. Goals and non-goals

### Goals
- Turn "I think my VPN protects me" into measured evidence with a clear PASS / FAIL / WARN per test.
- Provide a **lab mode** built from Linux network namespaces so results are reproducible with no real VPN account.
- Quantify the kill-switch **leak window** (packets and milliseconds) over many trials.
- Produce terminal, JSON, and Markdown reports with remediation text.
- Validate the tool itself against deliberately leaky configurations (seeded faults) and report precision/recall.

### Non-goals
- No browser-level checks (WebRTC, DoH inside apps).
- No Windows or macOS support. Linux only.
- No proof that *no* leak exists; only evidence that a leak does.
- No testing of networks or hosts you do not own.
- No GUI.

---

## 2. Core idea

If the VPN is working, the **physical interface** should carry only:

1. Encrypted packets to and from the VPN endpoint (IP + port), and
2. Local housekeeping (ARP, IPv6 NDP, DHCP), optionally LAN traffic with `--allow-lan`.

Anything else leaving the physical interface is a **leak**. Almost every test reduces to:

```
run scenario -> capture on physical interface -> classify each packet -> findings
```

---

## 3. Tech stack

| Item | Choice |
|---|---|
| Language | Python 3.11+ |
| CLI | `typer` + `rich` |
| Models | `pydantic` v2 |
| Packets | `scapy` (pcap parsing, probe crafting) |
| Config | `pyyaml` (lab profiles) |
| Tests | `pytest`, `pytest-cov` |
| Quality | `ruff`, `mypy` |
| System tools (lab mode) | `iproute2`, `wireguard-tools`, `nftables`, `tcpdump`; `openvpn` optional |

Packaging: `pyproject.toml`, console script `leakprobe`. Lab and capture commands need root (`CAP_NET_ADMIN`); `analyze`, `audit-routes` on saved data, and `report` must not.

---

## 4. Repository layout

```
leakprobe/
  PLAN.md
  README.md
  pyproject.toml
  leakprobe/
    __init__.py
    cli.py                  # typer app, thin; no logic
    models.py               # Finding, Report, PacketRecord, Trial, etc.
    util/
      sh.py                 # the only subprocess wrapper
      netns.py              # run commands inside a namespace
      stats.py              # mean/median/p95 helpers
    collectors/
      routes.py             # ip -j route / rule (v4 + v6), all tables
      resolvers.py          # resolv.conf, resolvectl status
      sockets.py            # ss -tunap parsing
      sysctl.py             # ipv6 disable flags, rp_filter
    analyzers/
      route_predictor.py    # longest-prefix-match + policy rules
      packet_classifier.py  # allowlist classifier over PacketRecord
      leak_window.py        # kill-switch metrics
    capture/
      pcap.py               # start/stop tcpdump, parse pcap -> PacketRecord
    probes/
      traffic.py            # UDP/TCP/IPv6 probe senders
      dns.py                # unique-label DNS probes
      identity.py           # "what source IP does the target see"
    lab/
      builder.py            # create/destroy namespaces, veths, addressing
      services.py           # canary/beacon + fake resolvers (run inside namespaces)
      profiles/             # *.yaml lab profiles (section 8)
    faults/
      injector.py           # link-down, delete-iface, endpoint-block
    tests_impl/             # one module per test ID (section 6)
    report/
      terminal.py
      jsonout.py
      markdown.py
      remediation.py        # fix snippets per finding
  scripts/
    run_matrix.py           # run all profiles, compare to expected, precision/recall
  tests/
    unit/                   # no root; fixtures in tests/fixtures/
    integration/            # marked @pytest.mark.root
    fixtures/               # route JSON, ss output, generated pcaps
  docs/
    DEMO.md
```

---

## 5. Data models (`models.py`)

```python
class Status(str, Enum): PASS="pass"; FAIL="fail"; WARN="warn"; SKIP="skip"; ERROR="error"
class Severity(str, Enum): INFO="info"; LOW="low"; MEDIUM="medium"; HIGH="high"; CRITICAL="critical"

class PacketRecord(BaseModel):
    ts: float                 # epoch seconds from pcap
    iface: str
    l2: str                   # "ether"
    l3: str | None            # "ipv4" | "ipv6" | "arp" | None
    proto: str | None         # "udp" | "tcp" | "icmp" | "icmp6" | ...
    src: str | None; dst: str | None
    sport: int | None; dport: int | None
    size: int
    icmp6_type: int | None

class Finding(BaseModel):
    test_id: str              # e.g. "LP-DNS-01"
    title: str
    status: Status
    severity: Severity
    summary: str
    evidence: list[str]       # short, human-readable lines
    metrics: dict[str, float | int | str] = {}
    remediation: str | None = None

class Report(BaseModel):
    tool_version: str
    started_at: datetime
    mode: Literal["lab","real"]
    environment: dict[str, str]     # kernel, tunnel iface, physical iface, vpn type
    findings: list[Finding]
    overall: Status
```

Exit codes: `0` all PASS (WARN allowed unless `--strict`), `1` at least one FAIL, `2` tool/setup error.

---

## 6. Test catalogue

Every test returns one or more `Finding`s. IDs are stable.

| ID | Name | Method | PASS when | Severity if FAIL |
|---|---|---|---|---|
| LP-ROUTE-01 | Route audit | Collect routes/rules; predict egress interface for test destinations | All external destinations egress via tunnel; no more-specific route bypasses the tunnel | HIGH |
| LP-V6-01 | IPv6 leak | Send IPv6 probe; capture on physical iface; static check of `::/0` route and sysctl | No non-allowlisted IPv6 on physical iface | HIGH |
| LP-DNS-01 | DNS leak | Resolve unique `lp-<uuid8>.leakprobe.test`; check which resolver observed it | Only the expected (tunnel) resolver saw the label | HIGH |
| LP-KILL-01 | Kill switch | Fault-inject tunnel failure under steady probe traffic; measure leak window over N trials | Zero leaked packets after the fault in all trials | CRITICAL |
| LP-START-01 | Startup race | Probe traffic while the tunnel comes up; count leaks before first handshake | Zero leaked packets before tunnel ready | MEDIUM |
| LP-SPLIT-01 | Split-tunnel audit | Parse sockets bound to physical IP, `ip rule` fwmark/uidrange entries | No unexpected bypass sockets/rules | LOW (WARN) |
| LP-EGRESS-01 | Allowlist audit | Classify all physical-interface packets seen during the whole run | Only ENDPOINT / HOUSEKEEPING classes | HIGH |
| LP-IDENT-01 | Egress identity | Ask beacon which source IP it sees | Observed IP is in `--expected-exit` set (not the ISP-side IP) | HIGH |

### 6.1 LP-ROUTE-01 (pure, fixture-testable)
- Input: parsed `ip -j route show table all`, `ip -j -6 route show table all`, `ip -j rule`, `ip -j -6 rule`.
- Implement `predict_egress(dst, routing_state) -> RouteDecision(dev, via, table, prefix, reason)`:
  1. Walk `ip rule` in priority order. Support: `from`, `to`, `fwmark`, `lookup <table>`, `suppress_prefixlength N`.
  2. Within the selected table, choose the longest matching prefix; tie-break on lowest metric.
  3. If a rule has `suppress_prefixlength` and the match prefix length is `<= N`, skip to the next rule.
- Test destinations: `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `2606:4700:4700::1111`, plus the lab canary.
- Findings:
  - FAIL if any test destination predicts a non-tunnel egress device.
  - FAIL (explicit message "more-specific route bypasses tunnel, TunnelVision-style, see CVE-2024-3661") if a route with a longer prefix than the tunnel's default (e.g. `0.0.0.0/1` + `128.0.0.0/1`) points at a non-tunnel device.
  - Allowed exceptions: route to the VPN endpoint /32 (or /128) via the physical gateway; LAN prefixes only if `--allow-lan`.

### 6.2 LP-EGRESS-01 / packet classifier (pure)
`classify(pkt, ctx) -> Class` where `ctx` has: endpoint IP, endpoint port, physical IPs, `allow_lan`, local prefixes.

| Class | Rule |
|---|---|
| `ENDPOINT` | UDP/TCP to or from endpoint IP:port |
| `HOUSEKEEPING` | ARP; ICMPv6 types 133–137 (NDP); DHCPv4 (udp 67/68); DHCPv6 (udp 546/547) |
| `LAN` | dst/src in local prefixes, only if `allow_lan` |
| `LEAK` | everything else |

Each `LEAK` also gets a `reason` tag: `dns` (port 53/853), `ipv6`, `other`.

### 6.3 LP-DNS-01
- Generate label `lp-<uuid8>.leakprobe.test`.
- Send it two ways: system resolution (`getaddrinfo`) and direct to each nameserver listed by the collectors.
- **Lab mode:** the fake ISP resolver (in `isp` namespace) and the fake VPN resolver (in `vpn` namespace) each log received qnames. Leak = label seen by the ISP resolver.
- **Real mode (stretch, M10):** a beacon authoritative DNS server logs the querying resolver IP; compare against the egress identity IP; report WARN when the result is ambiguous.

### 6.4 LP-KILL-01 (the headline test)
Procedure per trial:
1. Start capture on the physical interface.
2. Start steady probe: UDP packets with sequence numbers, **100 packets/s**, to the lab canary. Wait 2 s for steady state.
3. Record `t_fault = time.time()` immediately after the fault command returns.
4. Inject the fault (`link-down`, `delete-iface`, or `endpoint-block`; see section 7).
5. Continue the probe for 3 s, stop capture, restore the tunnel.
6. Analyze the pcap:
   ```
   leaks = [p for p in pkts if p.ts >= t_fault and classify(p) == LEAK and p is probe_flow]
   leak_packets          = len(leaks)
   time_to_first_leak_ms = (leaks[0].ts  - t_fault) * 1000   if leaks
   leak_window_ms        = (leaks[-1].ts - t_fault) * 1000   if leaks
   ```
7. Repeat for `--trials` (default 20). Report: fraction of trials that leaked, mean/median/p95/max of `leak_packets` and `leak_window_ms`.

Notes: use pcap kernel timestamps and `time.time()` on the same host so the clocks agree. The `endpoint-block` fault should produce a *blackholed* tunnel, not a leak, so it checks "dead tunnel, interface still up" behavior; its expected result is PASS for any sane config.

### 6.5 LP-START-01
Tear tunnel down, start probe + capture, run the profile's bring-up command, poll `wg show <if> latest-handshakes` (or OpenVPN log marker) to find `t_ready`. Leaks = LEAK-class probe packets with `ts < t_ready`.

### 6.6 LP-SPLIT-01
- Parse `ss -tunapH`; flag sockets whose local address is a physical-interface IP (not tunnel IP) and whose peer is not the endpoint or LAN.
- Report `ip rule` entries using `uidrange` or custom `fwmark` not owned by the VPN client.
- Always WARN, never FAIL (cannot see `SO_BINDTODEVICE`; state that limitation in the output).

### 6.7 LP-IDENT-01
Connect to the beacon (`198.51.100.10:8080`); it replies with the source IP it observed. In the lab: via VPN exit = `192.0.2.2`, via ISP direct path = `198.51.100.1`. PASS only if the observed IP is in the expected exit set.

### 6.8 LP-V6-01
- Static: tunnel has a `::/0` route (or IPv6 is disabled on the physical interface via sysctl).
- Dynamic: send UDP to `2001:db8:198::10` (lab canary, IPv6) and check the physical capture for IPv6 packets classified LEAK.

---

## 7. Fault injection (`faults/injector.py`)

| Method | Action | What it simulates |
|---|---|---|
| `link-down` | `ip link set <tun> down` | Client crash or manual disconnect |
| `delete-iface` | `ip link del <tun>` | Tunnel torn down and routes removed |
| `endpoint-block` | nftables drop in the `isp` namespace for endpoint IP | Server unreachable, interface still up |

Each injector exposes `inject()` and `restore()`; the kill-switch test must always call `restore()` in a `finally` block.

---

## 8. Lab design

### 8.1 Topology (all four namespaces prefixed `lp-`)

```
lp-client ---- lp-isp ---- lp-vpn ---- lp-inet
                  \_____________________/
                   (direct ISP -> inet path)
```

| Link | Addresses |
|---|---|
| client `c-phys` <-> isp `i-c` | `192.168.100.2/24` <-> `192.168.100.1/24` (+ v6 `fd00:100::2/64` <-> `fd00:100::1/64`) |
| isp `i-v` <-> vpn `v-i` | `203.0.113.1/24` <-> `203.0.113.10/24` (VPN endpoint = `203.0.113.10:51820`) |
| isp `i-n` <-> inet `n-i` | `198.51.100.1/24` <-> `198.51.100.254/24` |
| vpn `v-n` <-> inet `n-v` | `192.0.2.2/24` <-> `192.0.2.254/24` |
| tunnel | `wg0`: client `10.66.0.2/24`, vpn `10.66.0.1/24` |

- `lp-inet` holds the canary/beacon at `198.51.100.10` (loopback alias, reachable via both the ISP path and the VPN exit path) and IPv6 `2001:db8:198::10`.
- `lp-isp` does NAT (masquerade) toward `lp-inet`, so a leak is visible as source `198.51.100.1`.
- `lp-vpn` does NAT toward `lp-inet`, so tunneled traffic appears as `192.0.2.2`.
- All lab addresses come from private ranges or RFC 5737 / RFC 3849 documentation ranges. Nothing touches the real internet.
- **Capture point:** inside `lp-client` on `c-phys` (equivalent to what the ISP sees).
- Per-namespace resolver config via `/etc/netns/lp-client/resolv.conf`.
- Fake ISP resolver at `192.168.100.1:53`, fake VPN resolver at `10.66.0.1:53`, both tiny UDP responders that log qnames to a file.

### 8.2 Lifecycle rules
- `lab up` is idempotent; `lab down` removes everything with the `lp-` prefix, even after a crash.
- State file at `/run/leakprobe/lab.json`.
- Use a context manager and `atexit` so a failed test never leaves a namespace behind.
- Key generation with `wg genkey` / `wg pubkey` per lab run; never commit keys.

### 8.3 Profiles (`lab/profiles/*.yaml`)

```yaml
name: wg-default-leaky
description: Full-tunnel IPv4 only; DNS from ISP; no kill switch
wireguard:
  allowed_ips: ["0.0.0.0/0"]
  dns: null
firewall: none
extra_routes: []
expected:            # ground truth used by the validation matrix
  LP-ROUTE-01: pass
  LP-V6-01: fail
  LP-DNS-01: fail
  LP-KILL-01: fail
  LP-START-01: fail
  LP-EGRESS-01: fail
  LP-IDENT-01: pass
```

Ship these profiles:

| Profile | Description |
|---|---|
| `wg-default-leaky` | As above |
| `wg-hardened` | `AllowedIPs 0.0.0.0/0, ::/0`, DNS 10.66.0.1, nftables kill switch (section 9) |
| `wg-ipv6-leak` | v4-only tunnel, IPv6 left on |
| `wg-dns-leak` | Correct routes, resolver left as the ISP's |
| `wg-no-killswitch` | Everything correct except no firewall rule |
| `wg-tunnelvision` | Adds `0.0.0.0/1` and `128.0.0.0/1` via the physical gateway (simulating DHCP-injected routes) |
| `control-broken` | Tunnel never established; all tests should FAIL |

---

## 9. Remediation snippets (`report/remediation.py`)

Attach to findings; example kill-switch rule for WireGuard (substitute interface and endpoint):

```nft
table inet leakprobe_killswitch {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    oifname "wg0" accept
    ip daddr 203.0.113.10 udp dport 51820 accept   # VPN endpoint
    udp sport 68 udp dport 67 accept               # DHCPv4 (optional)
    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
  }
}
```

Other fixes to template: `AllowedIPs = 0.0.0.0/0, ::/0`, pinning `DNS =` to the tunnel resolver, `sysctl net.ipv6.conf.<phys>.disable_ipv6=1`, removing the offending more-specific routes (or ignoring DHCP option 121 routes on the VPN-bound interface).

---

## 10. Milestones

| # | Deliverable | Acceptance criteria |
|---|---|---|
| **M0** | Scaffolding: `pyproject.toml`, package skeleton, CI config running `ruff`, `mypy`, `pytest` | `leakprobe --version` works; CI green on empty tests |
| **M1** | `models.py`, `util/sh.py`, `report/` (terminal + JSON + Markdown), CLI skeleton with `doctor` stub | Report renders from hand-built `Finding`s; JSON round-trips; `--format md` works |
| **M2** | Collectors for routes/rules/resolvers/sockets + `route_predictor` + LP-ROUTE-01 | Unit tests on fixtures prove: normal tunnel passes; `/1 + /1` bypass fails with the TunnelVision message; `suppress_prefixlength` handled; IPv6 covered |
| **M3** | `capture/pcap.py` parser + `packet_classifier` + LP-EGRESS-01 | Fixture pcaps (generated by scapy in tests) classify correctly: endpoint, NDP, DHCP, DNS leak, IPv6 leak, unknown |
| **M4** | Lab builder, services, profiles, `lab up/down/status` | Integration test: `lab up` then ping canary through the tunnel and directly; `lab down` leaves no `lp-*` namespace |
| **M5** | Probes + LP-DNS-01, LP-V6-01, LP-IDENT-01 | Against each profile, results match the `expected:` map |
| **M6** | Fault injector + LP-KILL-01 with stats | `wg-hardened` has 0 leaked packets in 20 trials; `wg-no-killswitch` leaks in most trials; stats output includes mean/median/p95/max |
| **M7** | LP-START-01 and LP-SPLIT-01 | Startup race detected on a leaky profile; hardened profile clean; split-tunnel warns on a deliberately bound socket |
| **M8** | `run` orchestration, remediation text, overall status and exit codes | `leakprobe run` against a lab profile produces a complete report with fix snippets |
| **M9** | `scripts/run_matrix.py` | Produces a Markdown matrix of profiles x tests plus precision/recall versus `expected:`; target 100% agreement on shipped profiles |
| **M10** | Docs, `docs/DEMO.md`, README; optional real-mode beacon | Fresh clone + README gets a working demo; optional stretch below |

### Optional stretch (only after M9)
- **Real mode:** a small beacon server for a VPS you own (HTTP "your IP is X" + authoritative DNS logging resolver IPs), selected with `--beacon host`.
- OpenVPN lab profile alongside WireGuard.
- Per-trial histogram of leak windows.

---

## 11. CLI specification

```
leakprobe doctor                                  # check root, tools, kernel module, namespaces
leakprobe lab up   --profile wg-default-leaky
leakprobe lab down
leakprobe lab status
leakprobe audit-routes [--from-file routes.json]   # LP-ROUTE-01 only; no root if from file
leakprobe analyze capture.pcap --endpoint 203.0.113.10:51820 [--allow-lan]
leakprobe run --mode lab --profile wg-hardened [--tests all|LP-DNS-01,LP-KILL-01] [--trials 20]
leakprobe run --mode real --tunnel wg0 --physical eth0 --endpoint IP:PORT --beacon HOST
leakprobe drop-test --method link-down|delete-iface|endpoint-block --trials 25
leakprobe report results.json --format md|json|term
leakprobe matrix                                   # wraps scripts/run_matrix.py
```

Global flags: `--format`, `--output FILE`, `--strict`, `--verbose`, `--allow-lan`.

---

## 12. Testing strategy

- **Unit (no root, run in CI):** route predictor, packet classifier, leak-window math, stats, report rendering, remediation text. Generate pcaps with scapy inside the tests instead of committing binaries.
- **Integration (root + lab):** marked `@pytest.mark.root`; skipped unless `EUID == 0` and `LEAKPROBE_LAB=1`. Cover lab lifecycle, each profile against `expected:`, fault injection, cleanup after failure.
- **Seeded-fault validation:** `run_matrix.py` compares measured vs expected for every profile and reports precision, recall, and any disagreements.
- Optionally try a privileged GitHub Actions job for integration tests, but unit tests alone must keep CI green.

---

## 13. Safety and ethics

- Use only on machines and networks you own or administer.
- Lab mode must never route to real public addresses.
- `real` mode must print a one-line notice that it sends probe traffic and requires `--yes` to proceed.
- Document the limitations in the README: no browser-level or app-level (DoH) leaks, `SO_BINDTODEVICE` invisible, evidence of leaks not proof of safety.

---

## 14. Definition of done

- All milestones M0–M9 complete; `pytest`, `ruff`, `mypy` clean.
- `leakprobe matrix` shows results matching ground truth for all shipped profiles.
- README plus `docs/DEMO.md` allow a new user to reproduce the before/after demo.
- A sample report (`docs/sample-report.md`) is committed.

## 15. Demo script (for the viva)

1. `sudo leakprobe lab up --profile wg-default-leaky`
2. `sudo leakprobe run --mode lab --profile wg-default-leaky` — show IPv6 leak, DNS leak, and a kill-switch leak window of some hundreds of milliseconds.
3. `sudo leakprobe lab down`; bring up `wg-hardened`; rerun and show all PASS.
4. `leakprobe matrix` — show the profiles x tests table and precision/recall.

