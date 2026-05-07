// Package tun manages the GHOST TUN network interface (Linux).
//
// Uses raw ioctl to create the TUN device without IFF_VNET_HDR, which avoids
// the GRO/GSO complexity that causes "invalid argument" and "too many segments"
// errors with the wireguard/tun library. Simple, reliable single-packet I/O.
package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Device wraps a Linux TUN file descriptor with simple Read/Write.
type Device struct {
	fd   *os.File
	name string
	mtu  int
}

// Config holds the parameters for creating a TUN device.
type Config struct {
	// Name is the interface name (e.g. "ghost0").
	Name string

	// Address is the local IP + CIDR (e.g. "10.7.0.1/24").
	Address string

	// MTU for the interface (e.g. 1400).
	MTU int
}

// ifreq is the Linux ioctl interface request structure.
type ifreq struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	_     [22]byte // padding to match sizeof(struct ifreq)
}

// New creates and configures a TUN device. Requires CAP_NET_ADMIN or root.
func New(cfg *Config) (*Device, error) {
	// Open /dev/net/tun via syscall so we can set O_NONBLOCK before
	// wrapping in os.File — this lets Go's runtime poller (epoll) work.
	rawFD, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}

	// Set up the interface: IFF_TUN (L3) | IFF_NO_PI (no packet info header).
	var ifr ifreq
	copy(ifr.name[:], cfg.Name)
	ifr.flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(rawFD),
		unix.TUNSETIFF,
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		unix.Close(rawFD)
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}

	// Set non-blocking so Go's poller can manage the fd.
	if err := unix.SetNonblock(rawFD, true); err != nil {
		unix.Close(rawFD)
		return nil, fmt.Errorf("tun: set nonblock: %w", err)
	}

	// Wrap in os.File — Go takes ownership of the fd.
	fd := os.NewFile(uintptr(rawFD), "/dev/net/tun")

	// Read back the assigned name (kernel may have modified it).
	name := strings.TrimRight(string(ifr.name[:]), "\x00")

	d := &Device{
		fd:   fd,
		name: name,
		mtu:  cfg.MTU,
	}

	// Configure IP address.
	if err := d.configureAddr(cfg.Address); err != nil {
		fd.Close()
		return nil, err
	}

	// Set MTU.
	if err := d.setMTU(cfg.MTU); err != nil {
		fd.Close()
		return nil, err
	}

	// Disable IPv6 on the TUN to avoid kernel-generated Router Solicitations
	// and other IPv6 traffic that would be forwarded through the tunnel.
	d.disableIPv6()

	// Bring interface up.
	if err := d.setUp(); err != nil {
		fd.Close()
		return nil, err
	}

	return d, nil
}

// Name returns the interface name.
func (d *Device) Name() string { return d.name }

// MTU returns the configured MTU.
func (d *Device) MTU() int { return d.mtu }

// Read reads a single IP packet from the TUN device.
func (d *Device) Read(buf []byte) (int, error) {
	n, err := d.fd.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("tun: read: %w", err)
	}
	return n, nil
}

// Write writes a single IP packet to the TUN device.
func (d *Device) Write(pkt []byte) (int, error) {
	n, err := d.fd.Write(pkt)
	if err != nil {
		return 0, fmt.Errorf("tun: write: %w", err)
	}
	return n, nil
}

// Close tears down the TUN device.
func (d *Device) Close() error {
	return d.fd.Close()
}

// configureAddr assigns an IP address to the interface via `ip addr add`.
func (d *Device) configureAddr(addr string) error {
	out, err := exec.Command("ip", "addr", "add", addr, "dev", d.name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: ip addr add %s dev %s: %s: %w", addr, d.name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// setMTU sets the interface MTU.
func (d *Device) setMTU(mtu int) error {
	out, err := exec.Command("ip", "link", "set", d.name, "mtu", fmt.Sprint(mtu)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: set mtu %d: %s: %w", mtu, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// disableIPv6 turns off IPv6 on this interface to suppress kernel-generated
// Router Solicitations and other IPv6 traffic.
func (d *Device) disableIPv6() {
	_ = exec.Command("sysctl", "-w", "net.ipv6.conf."+d.name+".disable_ipv6=1").Run()
}

// setUp brings the interface up via `ip link set up`.
func (d *Device) setUp() error {
	out, err := exec.Command("ip", "link", "set", d.name, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: ip link set %s up: %s: %w", d.name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// AddRoute adds a route via this TUN device.
func (d *Device) AddRoute(cidr string) error {
	out, err := exec.Command("ip", "route", "add", cidr, "dev", d.name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: ip route add %s dev %s: %s: %w", cidr, d.name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// EnableIPForward enables IPv4 forwarding (server side).
func EnableIPForward() error {
	out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: sysctl ip_forward: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// SetupNAT configures iptables MASQUERADE for the tunnel subnet.
func SetupNAT(tunSubnet string) error {
	out, err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", tunSubnet, "-j", "MASQUERADE").CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: iptables NAT %s: %s: %w", tunSubnet, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// CleanupNAT removes the MASQUERADE rule.
func CleanupNAT(tunSubnet string) error {
	_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", tunSubnet, "-j", "MASQUERADE").Run()
	return nil
}

// SubnetFromAddress extracts the network CIDR from an address string
// (e.g. "10.7.0.1/24" → "10.7.0.0/24").
func SubnetFromAddress(addr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		return "", fmt.Errorf("tun: parse CIDR %s: %w", addr, err)
	}
	return ipNet.String(), nil
}
