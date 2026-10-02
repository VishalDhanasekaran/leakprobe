"""Lab address plan (PLAN.md section 8.1). Only private and documentation ranges.

    lp-client ---- lp-isp ---- lp-vpn ---- lp-inet
                      \\_____________________/
"""

PREFIX = "lp-"
CLIENT, ISP, VPN, INET = "lp-client", "lp-isp", "lp-vpn", "lp-inet"
NAMESPACES = (CLIENT, ISP, VPN, INET)

# (ns_a, dev_a, addrs_a, ns_b, dev_b, addrs_b)
LINKS: tuple[tuple[str, str, tuple[str, ...], str, str, tuple[str, ...]], ...] = (
    (CLIENT, "c-phys", ("192.168.100.2/24", "fd00:100::2/64"),
     ISP, "i-c", ("192.168.100.1/24", "fd00:100::1/64")),
    (ISP, "i-v", ("203.0.113.1/24",), VPN, "v-i", ("203.0.113.10/24",)),
    (ISP, "i-n", ("198.51.100.1/24", "2001:db8:51::1/64"),
     INET, "n-i", ("198.51.100.254/24", "2001:db8:51::254/64")),
    (VPN, "v-n", ("192.0.2.2/24", "2001:db8:192::2/64"),
     INET, "n-v", ("192.0.2.254/24", "2001:db8:192::254/64")),
)

PHYSICAL = "c-phys"
TUNNEL = "wg0"
CLIENT_IP, CLIENT_IP6 = "192.168.100.2", "fd00:100::2"
ISP_GW, ISP_GW6 = "192.168.100.1", "fd00:100::1"
ENDPOINT_IP, ENDPOINT_PORT = "203.0.113.10", 51820
WG_CLIENT = ("10.66.0.2/24", "fd66::2/64")
WG_SERVER = ("10.66.0.1/24", "fd66::1/64")
WG_FWMARK = 0xCA6C
WG_TABLE = "51820"

CANARY_IP, CANARY_IP6 = "198.51.100.10", "2001:db8:198::10"
BEACON_PORT = 8080
CANARY_UDP_PORT = 9000
EXIT_VIA_VPN, EXIT_VIA_ISP = "192.0.2.2", "198.51.100.1"
EXIT_VIA_VPN6, EXIT_VIA_ISP6 = "2001:db8:192::2", "2001:db8:51::1"

ISP_RESOLVER = "192.168.100.1"
VPN_RESOLVER = "10.66.0.1"

STATE_DIR = "/run/leakprobe"
NETNS_ETC = "/etc/netns"
