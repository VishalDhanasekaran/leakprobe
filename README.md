# LeakProbe

A Linux CLI that measures whether a VPN tunnel actually protects traffic. It checks for DNS
leaks, IPv6 leaks, route bypasses (TunnelVision, CVE-2024-3661), kill-switch failures,
startup races and split-tunnel surprises, and reports PASS / FAIL / WARN per test with
evidence and a fix snippet.

The core idea: while the VPN is up, the physical interface should carry only encrypted
traffic to the VPN endpoint plus local housekeeping (ARP, NDP/MLD, DHCP). LeakProbe captures
that interface while it probes, classifies every packet against this allowlist, and counts
everything else as a leak.

It ships a deterministic **lab** built from Linux network namespaces, so results can be
reproduced without a VPN account, plus seven lab profiles with known ground truth that
validate the tool itself.

```
lp-client ---- lp-isp ---- lp-vpn ---- lp-inet      capture: lp-client / c-phys
                  \_____________________/           (what the ISP sees)
```

## Quick start

Requirements: Linux, Python 3.11+, [uv](https://docs.astral.sh/uv/), and for the lab
`iproute2`, `wireguard-tools`, `nftables` and `tcpdump`
(Arch: `sudo pacman -S wireguard-tools nftables tcpdump`;
Debian/Ubuntu: `sudo apt install wireguard-tools nftables tcpdump`).

```bash
git clone <this repo> leakprobe && cd leakprobe
uv sync                                   # add --extra dev for tests and linters
uv run leakprobe doctor                   # checks root, tools, the wireguard module, netns
```

The lab needs root (`CAP_NET_ADMIN`). `sudo` resets `PATH`, so call the venv binary:

```bash
sudo .venv/bin/leakprobe run --mode lab --profile wg-default-leaky   # leaky: several FAILs
sudo .venv/bin/leakprobe run --mode lab --profile wg-hardened        # all PASS
sudo .venv/bin/leakprobe matrix                                      # all profiles vs ground truth
```

No sudo? `scripts/sandbox.sh` runs a command as root inside an unprivileged user + network
namespace. Nothing touches the host, and everything is removed when the command exits:

```bash
scripts/sandbox.sh uv run leakprobe run --profile wg-hardened --trials 5
```

For the step-by-step before/after walkthrough see [`docs/DEMO.md`](docs/DEMO.md), and for a
full report from the leaky profile see [`docs/sample-report.md`](docs/sample-report.md).

## Tests

| ID | Name | PASS when | Severity |
|---|---|---|---|
| LP-ROUTE-01 | Route audit | Every test destination egresses via the tunnel; no more-specific route bypasses it | HIGH |
| LP-V6-01 | IPv6 leak | No IPv6 probe packet leaves on the physical interface | HIGH |
| LP-DNS-01 | DNS leak | Only the tunnel resolver saw the unique `lp-<uuid8>.leakprobe.test` label | HIGH |
| LP-KILL-01 | Kill switch | No probe packet leaks after a tunnel fault, over N trials | CRITICAL |
| LP-START-01 | Startup race | No probe packet leaks before the first handshake | MEDIUM |
| LP-SPLIT-01 | Split-tunnel audit | No socket pinned to the physical side, no foreign `uidrange`/`fwmark` rule (WARN only) | LOW |
| LP-EGRESS-01 | Allowlist audit | Only endpoint/housekeeping packets seen during normal operation | HIGH |
| LP-IDENT-01 | Egress identity | The beacon sees the VPN exit address | HIGH |

LP-KILL-01 reports how many trials leaked, plus mean / median / p95 / max of leaked packets
and of the leak window in milliseconds.

`run` runs the tests that don't disrupt the tunnel inside one LP-EGRESS-01 capture first,
then LP-START-01 and LP-KILL-01, which tear the tunnel down on purpose.

## Commands

```bash
leakprobe doctor                                          # environment checks
leakprobe run --mode lab --profile NAME [--tests all|LP-DNS-01,LP-KILL-01] [--trials 20]
              [--method link-down|delete-iface|endpoint-block]
leakprobe run --mode real --tunnel wg0 --physical eth0 --endpoint IP:PORT \
              [--beacon IP] [--expected-exit IP] --yes   # see "Real mode" below
leakprobe matrix [--profiles all|a,b] [--trials 5] [--save-dir DIR]   # validation matrix
leakprobe matrix --from-dir DIR                           # re-score saved reports, no root
leakprobe lab up --profile NAME | lab down | lab status   # manage the lab yourself
leakprobe drop-test --method link-down --trials 25        # LP-KILL-01 on the running lab
leakprobe audit-routes [--from-file routes.json] [--save routes.json]   # LP-ROUTE-01
leakprobe analyze capture.pcap --endpoint IP:PORT [--allow-lan]        # LP-EGRESS-01, no root
leakprobe report results.json --format term|json|md      # re-render a saved JSON report
```

Report commands take `--format term|json|md`, `--output FILE`, `--strict` and `--allow-lan`
where relevant. Exit codes: `0` all pass (WARN allowed), `1` at least one FAIL (or a WARN
with `--strict`; for `matrix`, any disagreement with ground truth), `2` tool or setup error.

If the lab is already up for the same profile, `run` reuses it and leaves it running.
Otherwise it builds a temporary lab and tears it down afterwards.
`scripts/run_matrix.py` is the same as `leakprobe matrix`.

## Lab profiles

| Profile | What it simulates |
|---|---|
| `wg-default-leaky` | Full IPv4 tunnel, IPv6 left on, ISP DNS, no kill switch |
| `wg-hardened` | `AllowedIPs 0.0.0.0/0, ::/0`, tunnel DNS, nftables kill switch |
| `wg-ipv6-leak` | IPv4-only tunnel with an IPv4-only kill switch; IPv6 still leaks |
| `wg-dns-leak` | Correct routes, resolver left as the ISP's |
| `wg-no-killswitch` | Everything correct except the firewall |
| `wg-tunnelvision` | DHCP-style `0.0.0.0/1` + `128.0.0.0/1` via the physical gateway |
| `control-broken` | The tunnel never comes up |

Each profile in `leakprobe/lab/profiles/*.yaml` carries an `expected:` map. `leakprobe matrix`
compares measured results against it and reports agreement, plus precision and recall
with FAIL as the positive class.

The lab uses only private and documentation ranges (RFC 1918, RFC 5737, RFC 3849) and never
routes to the real internet. WireGuard keys are generated per run and never written to the
repository.

## Real mode

`--mode real` runs against this host's own tunnel. It prints a notice that it sends probe
traffic, and it needs `--yes`. LP-START-01 and LP-KILL-01 briefly take the real tunnel down.
There is no beacon server yet (the optional stretch in PLAN.md), so:
- LP-DNS-01 is SKIP because there are no resolver logs.
- LP-IDENT-01 needs a host passed with `--beacon` that replies with the source IP it sees.
  Without one it is WARN.
- Probes otherwise target documentation addresses, so LP-V6-01, LP-EGRESS-01 and LP-KILL-01
  still show where packets leave, but nothing answers them.

## Limitations

- Use it only on machines and networks you own or administer.
- A leak found is evidence; no leak found is not proof of safety.
- It has no browser- or app-level view: WebRTC and DNS-over-HTTPS inside applications are out
  of scope.
- `SO_BINDTODEVICE` and per-socket `SO_MARK` are invisible to LP-SPLIT-01, so it only
  ever WARNs.
- Only WireGuard is covered, and only on Linux.

## Development

```bash
uv sync --extra dev
uv run pytest -q                          # unit tests, no root
uv run ruff check . && uv run mypy leakprobe
sudo -E LEAKPROBE_LAB=1 .venv/bin/pytest -m root   # lab integration tests
scripts/sandbox.sh uv run pytest -q                # whole suite incl. root tests, no sudo
```

`PLAN.md` is the full design. Code that needs root (lab, capture, probes, fault injection) is
kept apart from analysis and reporting, which are pure functions with unit tests.
