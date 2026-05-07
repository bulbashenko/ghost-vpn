package tun

import "testing"

func TestSubnetFromAddress(t *testing.T) {
	tests := []struct {
		addr, want string
	}{
		{"10.7.0.1/24", "10.7.0.0/24"},
		{"10.7.0.2/24", "10.7.0.0/24"},
		{"192.168.1.100/16", "192.168.0.0/16"},
		{"172.16.5.1/32", "172.16.5.1/32"},
	}
	for _, tt := range tests {
		got, err := SubnetFromAddress(tt.addr)
		if err != nil {
			t.Errorf("SubnetFromAddress(%q): %v", tt.addr, err)
			continue
		}
		if got != tt.want {
			t.Errorf("SubnetFromAddress(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestSubnetFromAddress_Invalid(t *testing.T) {
	_, err := SubnetFromAddress("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

// Note: TUN device creation (New) requires root/CAP_NET_ADMIN and is tested
// in integration tests (test/integration/), not here.
