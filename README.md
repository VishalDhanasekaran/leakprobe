# LeakProbe

A Linux CLI that measures whether a VPN tunnel actually protects traffic: DNS leaks, IPv6 leaks,
route bypasses, kill-switch failures, startup races and split-tunnel surprises.

Status: early development. See `PLAN.md` for the full design.

## Install (development)

```bash
uv sync --extra dev
uv run leakprobe --version
```

## Checks

```bash
uv run pytest -q
uv run ruff check .
uv run mypy leakprobe
```
