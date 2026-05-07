package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DialerConfig configures the client-side TLS transport (L1).
type DialerConfig struct {
	// ServerAddr is the server's host:port (e.g. "example.com:443").
	ServerAddr string

	// SNI is the TLS Server Name Indication. Defaults to the host part of
	// ServerAddr if empty.
	SNI string

	// Fingerprint selects the browser TLS fingerprint to mimic. Default is
	// Chrome auto-rotate.
	Fingerprint Fingerprint

	// InsecureSkipVerify disables certificate verification. Use ONLY in
	// tests — never in production.
	InsecureSkipVerify bool

	// RootCAs, if non-nil, overrides the system certificate pool. Useful
	// for integration tests with self-signed certs.
	RootCAs *tls.Certificate

	// ConnectTimeout limits the TCP + TLS handshake phase. Default 15s.
	ConnectTimeout time.Duration

	// KeepAlive sets the TCP keepalive interval. Default 30s (matches
	// browser defaults).
	KeepAlive time.Duration
}

func (c *DialerConfig) sni() string {
	if c.SNI != "" {
		return c.SNI
	}
	host, _, err := net.SplitHostPort(c.ServerAddr)
	if err != nil {
		return c.ServerAddr
	}
	return host
}

func (c *DialerConfig) connectTimeout() time.Duration {
	if c.ConnectTimeout > 0 {
		return c.ConnectTimeout
	}
	return 15 * time.Second
}

func (c *DialerConfig) keepAlive() time.Duration {
	if c.KeepAlive > 0 {
		return c.KeepAlive
	}
	return 30 * time.Second
}

// Dial establishes a TCP connection to the server and performs a TLS 1.3
// handshake using the configured browser fingerprint (uTLS). The returned
// *utls.UConn can be used as a regular net.Conn and additionally exposes the
// negotiated TLS state.
//
// The caller should pass a context with a deadline for the overall connect
// phase. If ctx has no deadline, DialerConfig.ConnectTimeout is applied.
func Dial(ctx context.Context, cfg *DialerConfig) (*utls.UConn, error) {
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("transport: ServerAddr is required")
	}

	// Apply default timeout if context has no deadline.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.connectTimeout())
		defer cancel()
	}

	// TCP dial with keepalive.
	netDialer := &net.Dialer{
		Timeout:   cfg.connectTimeout(),
		KeepAlive: cfg.keepAlive(),
	}
	rawConn, err := netDialer.DialContext(ctx, "tcp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: tcp dial: %w", err)
	}

	// uTLS wraps the raw TCP connection with a browser-fingerprinted
	// TLS handshake. The server sees a ClientHello identical to the
	// selected browser.
	tlsCfg := &utls.Config{
		ServerName:         cfg.sni(),
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}
	uconn := utls.UClient(rawConn, tlsCfg, helloID(cfg.Fingerprint))

	// Perform TLS handshake within the context deadline.
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("transport: tls handshake: %w", err)
	}

	// Verify we negotiated TLS 1.3 (required for Chrome fingerprint match).
	state := uconn.ConnectionState()
	if state.Version < tls.VersionTLS13 {
		_ = uconn.Close()
		return nil, fmt.Errorf("transport: negotiated TLS %#x, require >=TLS 1.3", state.Version)
	}

	return uconn, nil
}
