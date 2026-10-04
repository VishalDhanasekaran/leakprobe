# LeakProbe

A Linux CLI that measures whether a VPN tunnel actually protects traffic: DNS leaks, IPv6 leaks,
route bypasses, kill-switch failures, startup races and split-tunnel surprises.

Status: early development. See `PLAN.md` for the full design.

## Install (development)

```bash
uv sync --extra dev
uv run leakprobe --version
```

## Usage (implemented so far)

```bash
leakprobe doctor                                         # root, tools, kernel support
leakprobe audit-routes --tunnel wg0                      # LP-ROUTE-01 on this machine
leakprobe audit-routes --save routes.json                # save routing state ...
leakprobe audit-routes --from-file routes.json           # ... and audit it later, no root
leakprobe analyze capture.pcap --endpoint 203.0.113.10:51820 [--allow-lan]   # LP-EGRESS-01
leakprobe report results.json --format md                # re-render a saved JSON report

sudo leakprobe lab up --profile wg-default-leaky         # build the namespace lab
leakprobe lab status                                     # exit 0 when the lab is up
sudo leakprobe drop-test --method link-down --trials 20  # LP-KILL-01 on the running lab
sudo leakprobe lab down                                  # remove every lp-* namespace
```

Lab profiles: `wg-default-leaky`, `wg-hardened`, `wg-ipv6-leak`, `wg-dns-leak`,
`wg-no-killswitch`, `wg-tunnelvision`, `control-broken` (see `leakprobe/lab/profiles/`).
The lab needs `iproute2`, `wireguard-tools`, `nftables` and `tcpdump`. It uses only private and
documentation address ranges and never touches the real internet.

All commands take `--format term|json|md`, `--output FILE` and `--strict`. Exit codes: 0 pass,
1 at least one FAIL (or WARN with `--strict`), 2 tool/setup error.

## Checks

```bash
uv run pytest -q
uv run ruff check .
uv run mypy leakprobe
sudo -E LEAKPROBE_LAB=1 .venv/bin/pytest -m root    # lab integration tests
scripts/sandbox.sh uv run pytest -q                 # same, without sudo (user namespaces)
```
