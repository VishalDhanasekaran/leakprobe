#!/usr/bin/env bash
# Run a command as "root" in an unprivileged sandbox, for developing the lab without sudo.
#
#   scripts/sandbox.sh uv run pytest -m root
#   scripts/sandbox.sh bash          # then: uv run leakprobe lab up -p wg-hardened
#
# The sandbox is a fresh user + mount + network namespace (`unshare -rnm`) with a tmpfs on
# /run and a throwaway overlay on /etc, so lab namespaces, /run/leakprobe and /etc/netns
# never touch the host. Everything disappears when the command exits. Needs unprivileged
# user namespaces (kernel.unprivileged_userns_clone=1, the default on most distros).
# Real root (sudo) remains the supported way to run the lab.
set -euo pipefail
[ $# -gt 0 ] || { echo "usage: $0 COMMAND [ARGS...]" >&2; exit 2; }

tmp=$(mktemp -d)
cleanup() { chmod -R u+rwx "$tmp" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT

LEAKPROBE_LAB=1 unshare -rnm --propagation private bash -c '
  set -e
  ip link set lo up
  mount -t tmpfs tmpfs /run
  mkdir -p "$1/upper" "$1/work"
  mount -t overlay overlay -o "lowerdir=/etc,upperdir=$1/upper,workdir=$1/work" /etc
  shift
  exec "$@"
' sandbox "$tmp" "$@"
