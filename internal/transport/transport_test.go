package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedCert generates a self-signed TLS certificate for testing.
// The cert is valid for 127.0.0.1 and "localhost".
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"GHOST Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

// startEchoServer starts a TLS listener that echoes back everything it reads
// on each connection. Returns the listener address.
func startEchoServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()

	ln, err := Listen(&ListenerConfig{
		ListenAddr:   "127.0.0.1:0",
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func TestDialAndEcho(t *testing.T) {
	cert := selfSignedCert(t)
	addr := startEchoServer(t, cert)

	// uTLS client must skip verify because the cert is self-signed.
	conn, err := Dial(context.Background(), &DialerConfig{
		ServerAddr:         addr,
		SNI:                "localhost",
		Fingerprint:        FingerprintChromeAuto,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send data and verify echo.
	msg := []byte("hello ghost transport layer")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

func TestDialNegotiatesTLS13(t *testing.T) {
	cert := selfSignedCert(t)
	addr := startEchoServer(t, cert)

	conn, err := Dial(context.Background(), &DialerConfig{
		ServerAddr:         addr,
		SNI:                "localhost",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got %#x", state.Version)
	}
}

func TestDialNegotiatesH2(t *testing.T) {
	cert := selfSignedCert(t)
	addr := startEchoServer(t, cert)

	conn, err := Dial(context.Background(), &DialerConfig{
		ServerAddr:         addr,
		SNI:                "localhost",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("expected ALPN h2, got %q", state.NegotiatedProtocol)
	}
}

func TestDialTimeout(t *testing.T) {
	// Listen but never accept — simulates an unresponsive server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = Dial(ctx, &DialerConfig{
		ServerAddr:         ln.Addr().String(),
		SNI:                "localhost",
		InsecureSkipVerify: true,
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestDialBadAddress(t *testing.T) {
	_, err := Dial(context.Background(), &DialerConfig{
		ServerAddr:     "127.0.0.1:1", // nothing listening
		SNI:            "localhost",
		ConnectTimeout: 500 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected connection refused")
	}
}

func TestListenRequiresConfig(t *testing.T) {
	_, err := Listen(&ListenerConfig{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestFingerprintSelection(t *testing.T) {
	tests := []struct {
		fp   Fingerprint
		name string
	}{
		{FingerprintChromeAuto, "Chrome"},
		{FingerprintFirefoxAuto, "Firefox"},
		{FingerprintSafariAuto, "Safari"},
		{FingerprintRandomized, "Random"},
		{"", "Default→Chrome"},
		{"unknown", "Unknown→Chrome"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := helloID(tt.fp)
			if id.Client == "" && tt.fp != FingerprintRandomized {
				t.Fatal("empty ClientHelloID")
			}
		})
	}
}

func TestDialMultipleFingerprints(t *testing.T) {
	cert := selfSignedCert(t)
	addr := startEchoServer(t, cert)

	fingerprints := []Fingerprint{
		FingerprintChromeAuto,
		FingerprintFirefoxAuto,
	}

	for _, fp := range fingerprints {
		t.Run(string(fp), func(t *testing.T) {
			conn, err := Dial(context.Background(), &DialerConfig{
				ServerAddr:         addr,
				SNI:                "localhost",
				Fingerprint:        fp,
				InsecureSkipVerify: true,
			})
			if err != nil {
				t.Fatalf("dial with %s: %v", fp, err)
			}
			defer conn.Close()

			msg := []byte(fmt.Sprintf("hello from %s", fp))
			if _, err := conn.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(buf) != string(msg) {
				t.Fatalf("echo mismatch")
			}
		})
	}
}
