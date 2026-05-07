// Package config loads and validates GHOST server and client YAML configs.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig is the YAML config for ghost-server.
type ServerConfig struct {
	// Listen address for TLS (e.g. ":443").
	Listen string `yaml:"listen"`

	// TLS certificate and key paths (Let's Encrypt).
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// Server's Noise IK static keypair (base64).
	PrivateKey string `yaml:"private_key"`

	// Allowed client public keys (base64). Empty = refuse to start unless
	// AllowAll is explicitly set to true.
	AllowedClients []string `yaml:"allowed_clients"`

	// AllowAll disables the allowed_clients check and lets any client with a
	// valid Noise IK handshake connect. Dangerous — set only for testing or
	// when all clients are pre-shared via the Noise static key.
	AllowAll bool `yaml:"allow_all"`

	// FallbackTarget is the URL to reverse-proxy for unauthenticated requests
	// (e.g. "https://example.com").
	FallbackTarget string `yaml:"fallback_target"`

	// TunnelPath must match the client's tunnel_path. Defaults to
	// "/api/v1/stream". See ClientConfig.TunnelPath for rationale.
	TunnelPath string `yaml:"tunnel_path"`

	// ProfilePath is an optional path to a JSON traffic distribution
	// profile. Drives the L5 shaper's keepalive/cover cadence on the
	// server side. When empty, profile.DefaultProfile() is used.
	ProfilePath string `yaml:"profile_path"`

	// TUN interface configuration.
	TUN TUNConfig `yaml:"tun"`
}

// ClientConfig is the YAML config for ghost-client.
type ClientConfig struct {
	// Server address (host:port).
	ServerAddr string `yaml:"server_addr"`

	// SNI for TLS (defaults to host part of ServerAddr).
	//
	// Set to a different domain to enable "outer SNI" — the value here
	// goes into the TLS ClientHello, while the HTTP/2 Host header uses
	// FrontHost (or ServerAddr's host if FrontHost is empty). This is
	// the building block for domain fronting via a CDN that serves both
	// the front domain and your origin.
	//
	// Example: SNI="cdn.example.com", FrontHost="real.example.com"
	// (works only when both names resolve through a CDN that selects
	// the origin by Host header — Cloudflare, Fastly, CloudFront).
	SNI string `yaml:"sni"`

	// FrontHost is the value used for the HTTP/2 :authority pseudo-header
	// and the Host header. Defaults to SNI (or ServerAddr's host).
	// Override only when doing domain fronting through a CDN.
	FrontHost string `yaml:"front_host"`

	// Client's Noise IK static keypair (base64).
	PrivateKey string `yaml:"private_key"`

	// Server's static public key (base64).
	ServerPublicKey string `yaml:"server_public_key"`

	// Browser fingerprint: "chrome", "firefox", "safari", "random".
	Fingerprint string `yaml:"fingerprint"`

	// UserAgent override for the HTTP/2 :user-agent header. If empty, a
	// recent Chrome UA is used. Must stay consistent with Fingerprint —
	// e.g. fingerprint=chrome ⇒ UA should be a Chrome string. A mismatch
	// (Firefox UA + Chrome JA4) is itself a probe-detectable signal.
	UserAgent string `yaml:"user_agent"`

	// TunnelPath is the HTTP path used to initiate the tunnel. Defaults
	// to "/api/v1/stream". Override (along with the matching server-side
	// setting) if you suspect ТСПУ has built a per-path signature.
	TunnelPath string `yaml:"tunnel_path"`

	// ProfilePath is an optional path to a JSON traffic distribution
	// profile (see internal/profile). When set, the L5 shaper uses this
	// profile to drive cover-traffic and lifetime sampling. When empty,
	// profile.DefaultProfile() is used.
	ProfilePath string `yaml:"profile_path"`

	// ConnLifetimeSec controls how long a single TCP/TLS tunnel
	// connection is kept open before being rotated. The actual lifetime
	// is randomized in [Sec * 0.7, Sec * 1.3] to avoid a periodic
	// signal. A new connection is established and traffic migrates to
	// it before the old one closes (no observable downtime).
	//
	// Default 90 (range 63-117 s). Set 0 to disable rotation.
	//
	// Why: real browsers naturally close HTTP/2 connections after
	// short idle periods. A single 10-minute TCP connection to one
	// IP is a textbook VPN signal that ML classifiers exploit.
	ConnLifetimeSec int `yaml:"conn_lifetime_sec"`

	// TUN interface configuration.
	TUN TUNConfig `yaml:"tun"`
}

// FrontHostOrSNI returns FrontHost if set, otherwise the SNI (or the host
// part of ServerAddr). This is what should appear in the HTTP/2 :authority
// header and the Host header of tunnel requests.
func (c *ClientConfig) FrontHostOrSNI() string {
	if c.FrontHost != "" {
		return c.FrontHost
	}
	if c.SNI != "" {
		return c.SNI
	}
	// Strip port from ServerAddr.
	addr := c.ServerAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// ConnLifetime returns the configured rotation interval, or the default
// 90s if unset. Returns 0 if rotation is explicitly disabled.
func (c *ClientConfig) ConnLifetime() int {
	if c.ConnLifetimeSec < 0 {
		return 0 // explicit disable
	}
	if c.ConnLifetimeSec == 0 {
		return 90
	}
	return c.ConnLifetimeSec
}

// TUNConfig configures the tunnel network interface.
type TUNConfig struct {
	// Name of the TUN device (default "ghost0").
	Name string `yaml:"name"`

	// Address is the local IP + CIDR (e.g. "10.7.0.2/24").
	Address string `yaml:"address"`

	// MTU of the TUN device (default 1400 to leave room for encapsulation).
	MTU int `yaml:"mtu"`

	// DNS server addresses. When set, ghost-client rewrites /etc/resolv.conf
	// to use these servers and restores the original on shutdown, preventing
	// DNS queries from leaking outside the tunnel.
	DNS []string `yaml:"dns"`

	// AutoRoutes configures the default route to go through the VPN tunnel
	// and adds a host route to the VPN server via the original gateway.
	// Routes are restored on clean shutdown. Default false.
	AutoRoutes bool `yaml:"auto_routes"`

	// KillSwitch blocks all non-VPN traffic via iptables when enabled.
	// Prevents traffic leaks if the tunnel drops unexpectedly.
	// Also blocks IPv6 to prevent IPv6 leak. Default false.
	KillSwitch bool `yaml:"kill_switch"`
}

func (t *TUNConfig) applyDefaults() {
	if t.Name == "" {
		t.Name = "ghost0"
	}
	if t.MTU == 0 {
		t.MTU = 1400
	}
}

// LoadServer reads and parses a server YAML config file.
func LoadServer(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	cfg.TUN.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadClient reads and parses a client YAML config file.
func LoadClient(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	cfg.TUN.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *ServerConfig) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("config: server.listen is required")
	}
	if c.PrivateKey == "" {
		return fmt.Errorf("config: server.private_key is required")
	}
	if c.FallbackTarget == "" {
		return fmt.Errorf("config: server.fallback_target is required")
	}
	if c.TUN.Address == "" {
		return fmt.Errorf("config: server.tun.address is required")
	}
	if len(c.AllowedClients) == 0 && !c.AllowAll {
		return fmt.Errorf("config: allowed_clients is empty; set allow_all: true to accept any authenticated client (dangerous)")
	}
	return nil
}

func (c *ClientConfig) validate() error {
	if c.ServerAddr == "" {
		return fmt.Errorf("config: client.server_addr is required")
	}
	if c.PrivateKey == "" {
		return fmt.Errorf("config: client.private_key is required")
	}
	if c.ServerPublicKey == "" {
		return fmt.Errorf("config: client.server_public_key is required")
	}
	if c.TUN.Address == "" {
		return fmt.Errorf("config: client.tun.address is required")
	}
	return nil
}
