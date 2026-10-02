#!/usr/bin/env bash
# Regenerate routing-state fixtures from real `ip -j` output.
# Each scenario runs in a throwaway unprivileged user+network namespace
# (`unshare -rn`), so no root is needed and the host is never touched.
# Output format matches `leakprobe audit-routes --save`.
set -euo pipefail
cd "$(dirname "$0")"

base() {
  ip link add c-phys type dummy && ip link set c-phys up
  ip addr add 192.168.100.2/24 dev c-phys
  ip -6 addr add fd00:100::2/64 dev c-phys nodad
  ip route add default via 192.168.100.1 dev c-phys
  ip -6 route add default via fd00:100::1 dev c-phys
}

wg_v4() {
  ip link add wg0 type wireguard && ip link set wg0 up
  ip addr add 10.66.0.2/24 dev wg0
  ip route add default dev wg0 table 51820
  ip rule add not fwmark 0xca6c table 51820
  ip rule add table main suppress_prefixlength 0
}

wg_v6() {
  ip -6 addr add fd66::2/64 dev wg0 nodad
  ip -6 route add default dev wg0 table 51820
  ip -6 rule add not fwmark 0xca6c table 51820
  ip -6 rule add table main suppress_prefixlength 0
}

dump() {
  printf '{"routes4": %s, "routes6": %s, "rules4": %s, "rules6": %s}\n' \
    "$(ip -j -4 route show table all)" "$(ip -j -6 route show table all)" \
    "$(ip -j -4 rule)" "$(ip -j -6 rule)"
}

scenario() {  # scenario <name> <shell commands>
  unshare -rn bash -c "set -e; $(declare -f base wg_v4 wg_v6 dump); $2; dump" \
    | python3 -m json.tool --indent 1 > "$1.json"
  echo "wrote $1.json"
}

scenario wg_quick_full "base; wg_v4; wg_v6"
scenario wg_quick_v4only "base; wg_v4"
scenario tunnelvision "base; wg_v4; wg_v6
  ip route add 0.0.0.0/1 via 192.168.100.1 dev c-phys proto dhcp
  ip route add 128.0.0.0/1 via 192.168.100.1 dev c-phys proto dhcp"
scenario tunnelvision_v6 "base; wg_v4; wg_v6
  ip -6 route add ::/1 via fd00:100::1 dev c-phys
  ip -6 route add 8000::/1 via fd00:100::1 dev c-phys"
scenario openvpn_def1 "base
  ip link add tun0 type dummy && ip link set tun0 up
  ip addr add 10.8.0.2/24 dev tun0
  ip route add 0.0.0.0/1 dev tun0
  ip route add 128.0.0.0/1 dev tun0
  ip route add 203.0.113.10/32 via 192.168.100.1 dev c-phys
  ip -6 route add ::/1 dev tun0
  ip -6 route add 8000::/1 dev tun0"
scenario lan_route "base; wg_v4; wg_v6
  ip route add 10.0.0.0/8 via 192.168.100.1 dev c-phys"
scenario no_tunnel "base"
