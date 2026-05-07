// Package ghostnm implements a NetworkManager VPN plugin for the GHOST protocol.
//
// It registers on the system D-Bus as org.freedesktop.NetworkManager.ghost and
// implements the org.freedesktop.NetworkManager.VPN.Plugin interface. When NM
// calls Connect(), the plugin writes a temporary config file and launches
// ghost-client as a subprocess. Once the TUN interface appears, it emits the
// Ip4Config and Config signals so NM can configure routing and DNS.
package ghostnm

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"gopkg.in/yaml.v3"
)

const (
	busName    = "org.freedesktop.NetworkManager.ghost"
	objectPath = dbus.ObjectPath("/org/freedesktop/NetworkManager/VPN/Plugin")
	vpnIface   = "org.freedesktop.NetworkManager.VPN.Plugin"
	propsIface = "org.freedesktop.DBus.Properties"

	// NM VPN plugin state values (NMVPNServiceState).
	stateUnknown  = uint32(1)
	stateInit     = uint32(2)
	stateShutdown = uint32(3)
	stateStarting = uint32(4)
	stateStarted  = uint32(5)
	stateStopping = uint32(6)
	stateStopped  = uint32(7)

	// NM VPN failure reasons.
	failureUnknown      = uint32(0)
	failureConnectFailed = uint32(2)
)

// Plugin holds runtime state shared across D-Bus calls.
type Plugin struct {
	log        *slog.Logger
	conn       *dbus.Conn
	mu         sync.Mutex
	state      uint32
	proc       *exec.Cmd
	cfgTmp     string
	cancelWatch context.CancelFunc // cancels the watchTunAndReport goroutine
}

// New creates an uninitialised Plugin; call Run() to start.
func New(logger *slog.Logger) (*Plugin, error) {
	return &Plugin{
		log:   logger,
		state: stateInit,
	}, nil
}

// Run connects to the system bus, claims the bus name, and blocks.
func (p *Plugin) Run() error {
	var err error
	p.conn, err = dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("system bus: %w", err)
	}
	defer p.conn.Close()

	reply, err := p.conn.RequestName(busName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("request name: %w", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("bus name %q already taken", busName)
	}

	if err := p.conn.Export(&vpnHandler{p}, objectPath, vpnIface); err != nil {
		return fmt.Errorf("export vpn interface: %w", err)
	}
	if err := p.conn.Export(&propsHandler{p}, objectPath, propsIface); err != nil {
		return fmt.Errorf("export properties interface: %w", err)
	}

	p.log.Info("GHOST VPN NM plugin running", "bus", busName, "path", objectPath)
	select {} // block until process is killed by NM
}

// ── D-Bus method handler for the VPN plugin interface ─────────────────────

type vpnHandler struct{ p *Plugin }

// Connect is called by NM to establish the VPN.
// connection is a{sa{sv}}: outer key = settings group ("vpn", "ipv4", …).
func (h *vpnHandler) Connect(connection map[string]map[string]dbus.Variant, _ map[string]dbus.Variant) *dbus.Error {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()

	if h.p.state == stateStarted || h.p.state == stateStarting {
		return dbusErr("already connected")
	}

	vpnSection, ok := connection["vpn"]
	if !ok {
		return dbusErr("no 'vpn' section in connection")
	}
	data, err := extractStringMap(vpnSection["data"])
	if err != nil {
		return dbusErr("vpn.data: " + err.Error())
	}
	secrets, _ := extractStringMap(vpnSection["secrets"]) // secrets may arrive separately
	if secrets == nil {
		secrets = map[string]string{}
	}

	cfg, err := buildClientConfig(data, secrets)
	if err != nil {
		return dbusErr(err.Error())
	}

	f, err := os.CreateTemp("", "ghost-nm-*.yaml")
	if err != nil {
		return dbusErr("temp config: " + err.Error())
	}
	if encErr := yaml.NewEncoder(f).Encode(cfg); encErr != nil {
		f.Close()
		os.Remove(f.Name())
		return dbusErr("write config: " + encErr.Error())
	}
	f.Close()
	h.p.cfgTmp = f.Name()

	ghostBin := findGhostClient()
	cmd := exec.Command(ghostBin, "-config", h.p.cfgTmp)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if startErr := cmd.Start(); startErr != nil {
		os.Remove(h.p.cfgTmp)
		h.p.cfgTmp = ""
		return dbusErr("start ghost-client: " + startErr.Error())
	}
	h.p.proc = cmd
	h.p.emitState(stateStarting)

	tunName := cfg.TUN.Name
	if tunName == "" {
		tunName = "ghost0"
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.p.cancelWatch = cancel
	go h.p.watchTunAndReport(ctx, cmd, tunName, cfg.TUN.Address, cfg.TUN.DNS, cfg.ServerAddr)
	return nil
}

// ConnectInteractive is the interactive variant; we treat it identically.
func (h *vpnHandler) ConnectInteractive(connection map[string]map[string]dbus.Variant, details map[string]dbus.Variant) *dbus.Error {
	return h.Connect(connection, details)
}

// NeedSecrets returns the name of the first missing secret, or "" if all present.
func (h *vpnHandler) NeedSecrets(settings map[string]map[string]dbus.Variant) (string, *dbus.Error) {
	vpn := settings["vpn"]
	secrets, _ := extractStringMap(vpn["secrets"])
	if secrets["private-key"] == "" {
		return "private-key", nil
	}
	return "", nil
}

// Disconnect stops ghost-client and cleans up.
func (h *vpnHandler) Disconnect() *dbus.Error {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()

	// Cancel the watcher goroutine first so it doesn't emit StateStarted
	// after we've already emitted StateStopping/StateStopped.
	if h.p.cancelWatch != nil {
		h.p.cancelWatch()
		h.p.cancelWatch = nil
	}

	h.p.emitState(stateStopping)

	if h.p.proc != nil && h.p.proc.Process != nil {
		_ = h.p.proc.Process.Signal(syscall.SIGTERM)
		proc := h.p.proc
		go func() {
			_ = proc.Wait()
			h.p.mu.Lock()
			h.p.cleanup()
			h.p.emitState(stateStopped)
			h.p.mu.Unlock()
		}()
	} else {
		h.p.cleanup()
		h.p.emitState(stateStopped)
	}
	return nil
}

// SetConfig / SetIp4Config / SetIp6Config / SetFailure are called by NM helper
// processes in some flows; not used in our direct-launch model.
func (h *vpnHandler) SetConfig(_ map[string]dbus.Variant) *dbus.Error    { return nil }
func (h *vpnHandler) SetIp4Config(_ map[string]dbus.Variant) *dbus.Error { return nil }
func (h *vpnHandler) SetIp6Config(_ map[string]dbus.Variant) *dbus.Error { return nil }
func (h *vpnHandler) SetFailure(_ string) *dbus.Error                    { return nil }

// ── D-Bus Properties handler ───────────────────────────────────────────────

type propsHandler struct{ p *Plugin }

func (ph *propsHandler) Get(iface, prop string) (dbus.Variant, *dbus.Error) {
	if iface == vpnIface && prop == "State" {
		ph.p.mu.Lock()
		s := ph.p.state
		ph.p.mu.Unlock()
		return dbus.MakeVariant(s), nil
	}
	return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("unknown property %s.%s", iface, prop))
}

func (ph *propsHandler) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	ph.p.mu.Lock()
	s := ph.p.state
	ph.p.mu.Unlock()
	return map[string]dbus.Variant{"State": dbus.MakeVariant(s)}, nil
}

func (ph *propsHandler) Set(_, _ string, _ dbus.Variant) *dbus.Error {
	return dbus.MakeFailedError(fmt.Errorf("read-only"))
}

// ── Internal helpers ───────────────────────────────────────────────────────

func (p *Plugin) emitState(s uint32) {
	p.state = s
	_ = p.conn.Emit(objectPath, vpnIface+".StateChanged", s)
	p.log.Info("state", "s", stateStr(s))
}

func (p *Plugin) cleanup() {
	if p.cfgTmp != "" {
		os.Remove(p.cfgTmp)
		p.cfgTmp = ""
	}
	p.proc = nil
}

// watchTunAndReport waits for the TUN device to appear (max 30 s), then
// emits the Config and Ip4Config signals that NM needs to configure routing.
// ctx is cancelled by Disconnect() to abort the goroutine before it can emit
// StateStarted after a disconnect has already been signalled.
func (p *Plugin) watchTunAndReport(ctx context.Context, cmd *exec.Cmd, tunName, tunAddr string, dns []string, serverAddr string) {
	deadline := time.Now().Add(30 * time.Second)
	var found bool
	for !found && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		if _, err := net.InterfaceByName(tunName); err == nil {
			found = true
		}
	}

	if !found {
		p.log.Error("TUN device did not appear", "name", tunName)
		p.mu.Lock()
		_ = cmd.Process.Signal(syscall.SIGTERM)
		p.cleanup()
		p.emitState(stateStopped)
		p.mu.Unlock()
		_ = p.conn.Emit(objectPath, vpnIface+".Failure", failureConnectFailed)
		return
	}
	p.log.Info("TUN up", "name", tunName)

	// Check if Disconnect() was already called while we were waiting.
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Give NM a moment to discover the new interface via netlink before we
	// emit Config/Ip4Config — otherwise NM may not find ghost0 in its device
	// list and reject the configuration as invalid.
	time.Sleep(1500 * time.Millisecond)

	// Final check before emitting signals.
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Parse address and prefix from "10.7.0.3/24".
	addrStr, prefixStr, _ := strings.Cut(tunAddr, "/")
	prefix := uint32(24)
	if n, err := strconv.Atoi(prefixStr); err == nil {
		prefix = uint32(n)
	}

	// Derive a gateway: the conventional .1 address in the TUN subnet.
	// NM 1.x requires a gateway when never-default=false so it can install
	// the default route.  For a point-to-point TUN there is no real
	// gateway host — using .1 (or .2 if client is .1) is harmless: the
	// kernel routes via the TUN device regardless of whether .1 exists.
	gatewayStr := deriveGateway(addrStr)

	// NM VPN D-Bus API expects address and gateway as uint32 in the same
	// byte order as struct in_addr / inet_aton() — i.e. network byte order
	// bytes interpreted as a host-endian uint32 (little-endian on x86).
	// Using binary.LittleEndian.Uint32 on the big-endian To4() bytes gives
	// exactly that value.
	addrU32 := binary.LittleEndian.Uint32(net.ParseIP(addrStr).To4())
	gwU32 := binary.LittleEndian.Uint32(net.ParseIP(gatewayStr).To4())
	p.log.Info("Ip4Config", "addr", addrStr, "prefix", prefix, "gw", gatewayStr)

	// Config signal — tells NM the device name and that we have IPv4.
	// "gateway" here is the EXTERNAL gateway (VPN server IP), type u (uint32).
	// NM stores it as ip4_external_gw and uses it as the routing gateway.
	cfgDict := map[string]dbus.Variant{
		"tundev":  dbus.MakeVariant(tunName),
		"banner":  dbus.MakeVariant("GHOST VPN"),
		"has-ip4": dbus.MakeVariant(true),
		"has-ip6": dbus.MakeVariant(false),
	}
	serverHost, _, _ := strings.Cut(serverAddr, ":")
	if srvIP := net.ParseIP(serverHost).To4(); srvIP != nil {
		cfgDict["gateway"] = dbus.MakeVariant(binary.LittleEndian.Uint32(srvIP))
	}
	_ = p.conn.Emit(objectPath, vpnIface+".Config", cfgDict)

	// Small gap so NM can process Config before Ip4Config arrives.
	time.Sleep(100 * time.Millisecond)

	// Ip4Config signal — address, prefix, internal-gateway, DNS, routing.
	// All IP addresses MUST be uint32 (network-byte-order as host uint32).
	// The key for the VPN-internal peer IP is "internal-gateway", NOT "gateway".
	// "gateway" (external) belongs in the Config signal; NM ignores it here.
	// never-default: true tells NM NOT to install a default route via the VPN.
	// ghost-client handles routing itself (auto_routes: true in the temp config):
	// it pins the server /32 via the original gateway and then replaces the
	// default route. This avoids the race where NM installs the VPN default
	// route before pinning the server host route, which breaks internet access.
	ip4 := map[string]dbus.Variant{
		"address":          dbus.MakeVariant(addrU32),
		"prefix":           dbus.MakeVariant(prefix),
		"internal-gateway": dbus.MakeVariant(gwU32),
		"tundev":           dbus.MakeVariant(tunName),
		"never-default":    dbus.MakeVariant(true),
	}
	if dnsU := parseDNS(dns); len(dnsU) > 0 {
		ip4["dns"] = dbus.MakeVariant(dnsU)
	}
	_ = p.conn.Emit(objectPath, vpnIface+".Ip4Config", ip4)

	p.mu.Lock()
	p.emitState(stateStarted)
	p.mu.Unlock()

	// Block until ghost-client exits.
	_ = cmd.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == stateStarted {
		p.log.Warn("ghost-client exited unexpectedly")
		p.cleanup()
		p.emitState(stateStopped)
	}
}

// deriveGateway returns the .1 address of the /24 subnet (or .2 if the client
// itself is .1).  Used as a synthetic gateway for NM's default-route setup.
func deriveGateway(addr string) string {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return addr
	}
	gw := make(net.IP, 4)
	copy(gw, ip)
	if ip[3] == 1 {
		gw[3] = 2
	} else {
		gw[3] = 1
	}
	return gw.String()
}

// extractStringMap coerces a dbus.Variant containing a{ss} or a{sv}(strings)
// into map[string]string.
func extractStringMap(v dbus.Variant) (map[string]string, error) {
	switch m := v.Value().(type) {
	case map[string]string:
		return m, nil
	case map[string]dbus.Variant:
		out := make(map[string]string, len(m))
		for k, vv := range m {
			if s, ok := vv.Value().(string); ok {
				out[k] = s
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected type %T", v.Value())
	}
}

// parseDNS converts a slice of dotted-decimal DNS strings into the uint32
// network-byte-order format that NM expects in the Ip4Config "dns" field.
func parseDNS(addrs []string) []uint32 {
	var out []uint32
	for _, a := range addrs {
		ip := net.ParseIP(strings.TrimSpace(a)).To4()
		if ip == nil {
			continue
		}
		// NM stores IPs as the raw network-order bytes reinterpreted as a
		// uint32 on the host (== little-endian read of big-endian bytes).
		out = append(out, binary.LittleEndian.Uint32(ip))
	}
	return out
}

// findGhostClient returns the path to the ghost-client binary.
func findGhostClient() string {
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), "ghost-client"); fileExists(p) {
			return p
		}
	}
	for _, p := range []string{"/usr/lib/NetworkManager/ghost-client", "/usr/local/bin/ghost-client", "/usr/bin/ghost-client"} {
		if fileExists(p) {
			return p
		}
	}
	return "ghost-client"
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func dbusErr(msg string) *dbus.Error {
	return dbus.MakeFailedError(fmt.Errorf("%s", msg))
}

func stateStr(s uint32) string {
	switch s {
	case stateInit:
		return "init"
	case stateStarting:
		return "starting"
	case stateStarted:
		return "started"
	case stateStopping:
		return "stopping"
	case stateStopped:
		return "stopped"
	case stateShutdown:
		return "shutdown"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}
