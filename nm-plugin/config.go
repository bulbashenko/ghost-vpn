package ghostnm

import (
	"fmt"
	"strconv"
)

// clientConfig mirrors internal/config.ClientConfig for YAML serialisation.
// It lives here to avoid importing internal/ from the nm-plugin package and to
// keep the NM plugin self-contained — the struct is only used to write a temp
// config file that ghost-client then reads via its own config.LoadClient().
type clientConfig struct {
	ServerAddr      string    `yaml:"server_addr"`
	SNI             string    `yaml:"sni,omitempty"`
	FrontHost       string    `yaml:"front_host,omitempty"`
	PrivateKey      string    `yaml:"private_key"`
	ServerPublicKey string    `yaml:"server_public_key"`
	Fingerprint     string    `yaml:"fingerprint,omitempty"`
	UserAgent       string    `yaml:"user_agent,omitempty"`
	TunnelPath      string    `yaml:"tunnel_path,omitempty"`
	ProfilePath     string    `yaml:"profile_path,omitempty"`
	ConnLifetimeSec int       `yaml:"conn_lifetime_sec,omitempty"`
	TUN             tunConfig `yaml:"tun"`
}

type tunConfig struct {
	Name       string   `yaml:"name,omitempty"`
	Address    string   `yaml:"address"`
	MTU        int      `yaml:"mtu,omitempty"`
	DNS        []string `yaml:"dns,omitempty"`
	AutoRoutes bool     `yaml:"auto_routes"`
	KillSwitch bool     `yaml:"kill_switch"`
}

// buildClientConfig maps the NM connection data/secrets dictionaries onto a
// clientConfig ready to be marshalled to YAML.
//
// NM VPN data keys (stored in the connection profile):
//
//	server-addr        — host:port  (required)
//	server-public-key  — base64     (required)
//	tun-addr           — IP/CIDR    (required)
//	sni, front-host, fingerprint, user-agent, tunnel-path, profile-path
//	tun-name, tun-mtu, dns, conn-lifetime-sec
//
// NM VPN secrets keys (stored in the keyring):
//
//	private-key        — base64     (required)
func buildClientConfig(data, secrets map[string]string) (*clientConfig, error) {
	get := func(key string) string { return data[key] }

	cfg := &clientConfig{
		ServerAddr:      get("server-addr"),
		SNI:             get("sni"),
		FrontHost:       get("front-host"),
		ServerPublicKey: get("server-public-key"),
		Fingerprint:     get("fingerprint"),
		UserAgent:       get("user-agent"),
		TunnelPath:      get("tunnel-path"),
		ProfilePath:     get("profile-path"),
		PrivateKey:      secrets["private-key"],
	}

	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("server-addr is required")
	}
	if cfg.ServerPublicKey == "" {
		return nil, fmt.Errorf("server-public-key is required")
	}
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("private-key secret is required")
	}
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = "chrome"
	}

	cfg.TUN.Name = get("tun-name")
	if cfg.TUN.Name == "" {
		cfg.TUN.Name = "ghost0"
	}
	// Always enable auto_routes so ghost-client pins the server /32 via the
	// original GW before adding the default route through the TUN. Without
	// this, NM's route management races and often drops the server route,
	// breaking the tunnel connection on activation.
	cfg.TUN.AutoRoutes = true
	cfg.TUN.KillSwitch = true
	cfg.TUN.Address = get("tun-addr")
	if cfg.TUN.Address == "" {
		return nil, fmt.Errorf("tun-addr is required")
	}
	cfg.TUN.MTU = 1400
	if mtu := get("tun-mtu"); mtu != "" {
		if n, err := strconv.Atoi(mtu); err == nil {
			cfg.TUN.MTU = n
		}
	}
	if dns := get("dns"); dns != "" {
		for _, d := range splitComma(dns) {
			cfg.TUN.DNS = append(cfg.TUN.DNS, d)
		}
	}
	if lt := get("conn-lifetime-sec"); lt != "" {
		if n, err := strconv.Atoi(lt); err == nil {
			cfg.ConnLifetimeSec = n
		}
	}

	return cfg, nil
}

func splitComma(s string) []string {
	var out []string
	for _, part := range splitOn(s, ',') {
		if t := trimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func splitOn(s string, sep rune) []string {
	var parts []string
	start := 0
	for i, r := range s {
		if r == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func trimSpace(s string) string {
	return trimLeft(trimRight(s))
}

func trimLeft(s string) string {
	for i, r := range s {
		if r != ' ' && r != '\t' {
			return s[i:]
		}
	}
	return ""
}

func trimRight(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != ' ' && s[i] != '\t' {
			return s[:i+1]
		}
	}
	return ""
}
