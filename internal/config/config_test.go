package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServer_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	os.WriteFile(path, []byte(`
listen: ":443"
cert_file: /etc/ghost/cert.pem
key_file: /etc/ghost/key.pem
private_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
fallback_target: https://example.com
tun:
  address: "10.7.0.1/24"
`), 0644)

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != ":443" {
		t.Errorf("listen=%q", cfg.Listen)
	}
	if cfg.FallbackTarget != "https://example.com" {
		t.Errorf("fallback=%q", cfg.FallbackTarget)
	}
	if cfg.TUN.Name != "ghost0" {
		t.Errorf("tun.name=%q (default not applied)", cfg.TUN.Name)
	}
	if cfg.TUN.MTU != 1400 {
		t.Errorf("tun.mtu=%d (default not applied)", cfg.TUN.MTU)
	}
}

func TestLoadServer_MissingFields(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name, yaml string
	}{
		{"no listen", `private_key: x
fallback_target: https://example.com
tun: {address: "10.7.0.1/24"}`},
		{"no private_key", `listen: ":443"
fallback_target: https://example.com
tun: {address: "10.7.0.1/24"}`},
		{"no fallback", `listen: ":443"
private_key: x
tun: {address: "10.7.0.1/24"}`},
		{"no tun addr", `listen: ":443"
private_key: x
fallback_target: https://example.com`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			os.WriteFile(path, []byte(tt.yaml), 0644)
			_, err := LoadServer(path)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadClient_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	os.WriteFile(path, []byte(`
server_addr: "example.com:443"
private_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
server_public_key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
fingerprint: chrome
tun:
  name: ghost1
  address: "10.7.0.2/24"
  mtu: 1300
`), 0644)

	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ServerAddr != "example.com:443" {
		t.Errorf("server_addr=%q", cfg.ServerAddr)
	}
	if cfg.TUN.Name != "ghost1" {
		t.Errorf("tun.name=%q", cfg.TUN.Name)
	}
	if cfg.TUN.MTU != 1300 {
		t.Errorf("tun.mtu=%d", cfg.TUN.MTU)
	}
	if cfg.Fingerprint != "chrome" {
		t.Errorf("fingerprint=%q", cfg.Fingerprint)
	}
}

func TestLoadClient_MissingFields(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name, yaml string
	}{
		{"no server_addr", `private_key: x
server_public_key: y
tun: {address: "10.7.0.2/24"}`},
		{"no private_key", `server_addr: "x:443"
server_public_key: y
tun: {address: "10.7.0.2/24"}`},
		{"no server_pub", `server_addr: "x:443"
private_key: x
tun: {address: "10.7.0.2/24"}`},
		{"no tun addr", `server_addr: "x:443"
private_key: x
server_public_key: y`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			os.WriteFile(path, []byte(tt.yaml), 0644)
			_, err := LoadClient(path)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadServer_FileNotFound(t *testing.T) {
	_, err := LoadServer("/nonexistent/server.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadClient_FileNotFound(t *testing.T) {
	_, err := LoadClient("/nonexistent/client.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTUNConfig_Defaults(t *testing.T) {
	var tc TUNConfig
	tc.applyDefaults()
	if tc.Name != "ghost0" {
		t.Errorf("name=%q", tc.Name)
	}
	if tc.MTU != 1400 {
		t.Errorf("mtu=%d", tc.MTU)
	}
}
