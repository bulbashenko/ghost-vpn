package tun

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// savedRoutes stores the original default route so TeardownRoutes can restore it.
var savedRoutes struct {
	gw    string
	iface string
}

// ApplyDNS backs up /etc/resolv.conf and overwrites it with the given servers.
// Returns a restore function that writes back the original content.
// If servers is empty, returns a no-op restore.
func ApplyDNS(servers []string) (restore func(), err error) {
	if len(servers) == 0 {
		return func() {}, nil
	}

	orig, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("tun: read /etc/resolv.conf: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("# managed by ghost-vpn — do not edit\n")
	for _, s := range servers {
		sb.WriteString("nameserver ")
		sb.WriteString(s)
		sb.WriteString("\n")
	}
	if err := os.WriteFile("/etc/resolv.conf", []byte(sb.String()), 0644); err != nil {
		return nil, fmt.Errorf("tun: write /etc/resolv.conf: %w", err)
	}

	return func() { _ = os.WriteFile("/etc/resolv.conf", orig, 0644) }, nil
}

// defaultRoute parses `ip route show default` and returns the gateway IP and
// interface name of the current default route.
func defaultRoute() (gw, iface string, err error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("tun: ip route show default: %w", err)
	}
	// typical line: "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.10 metric 100"
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && fields[0] == "default" && fields[1] == "via" {
			return fields[2], fields[4], nil
		}
	}
	return "", "", fmt.Errorf("tun: no default route found in: %s", strings.TrimSpace(string(out)))
}

// GatewayFromAddress derives the expected TUN gateway (server-side TUN IP) from
// the client's TUN address. Convention: first host in the subnet.
// e.g. "10.7.0.2/24" → "10.7.0.1"
func GatewayFromAddress(addr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		return "", fmt.Errorf("tun: parse CIDR %s: %w", addr, err)
	}
	gw := make(net.IP, len(ipnet.IP))
	copy(gw, ipnet.IP)
	gw[len(gw)-1]++
	return gw.String(), nil
}

// SetupRoutes configures the routing table for a VPN client:
//  1. Saves the current default gateway.
//  2. Adds a host route for serverIP via the original gateway (so the VPN
//     connection itself doesn't loop through the tunnel).
//  3. Replaces the default route to go through the TUN gateway.
func SetupRoutes(serverIP, tunGW string) error {
	gw, iface, err := defaultRoute()
	if err != nil {
		return err
	}
	savedRoutes.gw = gw
	savedRoutes.iface = iface

	// Host route to VPN server via original gateway.
	if out, err := exec.Command("ip", "route", "add",
		serverIP+"/32", "via", gw, "dev", iface,
	).CombinedOutput(); err != nil {
		return fmt.Errorf("tun: add server host route: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Replace default route via TUN.
	if out, err := exec.Command("ip", "route", "replace", "default", "via", tunGW).CombinedOutput(); err != nil {
		_ = exec.Command("ip", "route", "del", serverIP+"/32").Run()
		return fmt.Errorf("tun: replace default route: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}

// TeardownRoutes restores the original default route and removes the VPN server
// host route. Safe to call multiple times or even when SetupRoutes was not called.
func TeardownRoutes(serverIP string) {
	if savedRoutes.gw == "" {
		return
	}
	_ = exec.Command("ip", "route", "replace", "default",
		"via", savedRoutes.gw, "dev", savedRoutes.iface,
	).Run()
	_ = exec.Command("ip", "route", "del", serverIP+"/32").Run()
}

const killSwitchChain = "GHOST_KILL_SWITCH"

// EnableKillSwitch creates an iptables chain that drops all OUTPUT traffic
// except: packets to serverIP (so the VPN connection itself survives),
// packets out the TUN interface, and loopback.
func EnableKillSwitch(tunIface, serverIP string) error {
	// Create or flush the chain.
	_ = exec.Command("iptables", "-N", killSwitchChain).Run()
	_ = exec.Command("iptables", "-F", killSwitchChain).Run()

	rules := [][]string{
		{"-A", killSwitchChain, "-d", serverIP + "/32", "-j", "ACCEPT"},
		{"-A", killSwitchChain, "-o", tunIface, "-j", "ACCEPT"},
		{"-A", killSwitchChain, "-o", "lo", "-j", "ACCEPT"},
		{"-A", killSwitchChain, "-j", "DROP"},
	}
	for _, r := range rules {
		if out, err := exec.Command("iptables", r...).CombinedOutput(); err != nil {
			_ = DisableKillSwitch()
			return fmt.Errorf("tun: iptables %v: %s: %w", r, strings.TrimSpace(string(out)), err)
		}
	}

	// Insert jump at the top of OUTPUT so it takes priority.
	if out, err := exec.Command("iptables", "-I", "OUTPUT", "-j", killSwitchChain).CombinedOutput(); err != nil {
		_ = DisableKillSwitch()
		return fmt.Errorf("tun: iptables -I OUTPUT: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Also block IPv6 to prevent IPv6 leak.
	if err := enableIPv6Block(tunIface); err != nil {
		// Non-fatal: ip6tables may not be available.
		_ = err
	}

	return nil
}

// DisableKillSwitch removes the GHOST_KILL_SWITCH iptables chain and the IPv6
// block. Safe to call when the kill switch was never enabled.
func DisableKillSwitch() error {
	_ = exec.Command("iptables", "-D", "OUTPUT", "-j", killSwitchChain).Run()
	_ = exec.Command("iptables", "-F", killSwitchChain).Run()
	_ = exec.Command("iptables", "-X", killSwitchChain).Run()
	disableIPv6Block()
	return nil
}

const ipv6BlockChain = "GHOST_IPV6_BLOCK"

func enableIPv6Block(tunIface string) error {
	_ = exec.Command("ip6tables", "-N", ipv6BlockChain).Run()
	_ = exec.Command("ip6tables", "-F", ipv6BlockChain).Run()

	rules := [][]string{
		{"-A", ipv6BlockChain, "-o", tunIface, "-j", "ACCEPT"},
		{"-A", ipv6BlockChain, "-o", "lo", "-j", "ACCEPT"},
		{"-A", ipv6BlockChain, "-j", "DROP"},
	}
	for _, r := range rules {
		if out, err := exec.Command("ip6tables", r...).CombinedOutput(); err != nil {
			disableIPv6Block()
			return fmt.Errorf("tun: ip6tables %v: %s: %w", r, strings.TrimSpace(string(out)), err)
		}
	}
	if out, err := exec.Command("ip6tables", "-I", "OUTPUT", "-j", ipv6BlockChain).CombinedOutput(); err != nil {
		disableIPv6Block()
		return fmt.Errorf("tun: ip6tables -I OUTPUT: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func disableIPv6Block() {
	_ = exec.Command("ip6tables", "-D", "OUTPUT", "-j", ipv6BlockChain).Run()
	_ = exec.Command("ip6tables", "-F", ipv6BlockChain).Run()
	_ = exec.Command("ip6tables", "-X", ipv6BlockChain).Run()
}
