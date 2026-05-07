package transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ListenerConfig configures the server-side TLS listener (L1).
type ListenerConfig struct {
	// ListenAddr is the address to bind (e.g. ":443").
	ListenAddr string

	// CertFile and KeyFile are paths to the PEM-encoded TLS certificate and
	// private key (typically from Let's Encrypt via certbot or acme.sh).
	CertFile string
	KeyFile  string

	// Certificates, if non-nil, is used directly instead of loading from
	// CertFile/KeyFile. Useful for tests with in-memory certs.
	Certificates []tls.Certificate

	// NextProtos is the ALPN list advertised by the server. Defaults to
	// ["h2", "http/1.1"] if empty.
	NextProtos []string

	// TCPKeepAlive sets the keepalive interval for accepted connections.
	// Default 30s.
	TCPKeepAlive time.Duration
}

func (c *ListenerConfig) nextProtos() []string {
	if len(c.NextProtos) > 0 {
		return c.NextProtos
	}
	return []string{"h2", "http/1.1"}
}

func (c *ListenerConfig) tcpKeepAlive() time.Duration {
	if c.TCPKeepAlive > 0 {
		return c.TCPKeepAlive
	}
	return 30 * time.Second
}

// Listen creates a TLS listener ready to accept connections. The server uses
// standard crypto/tls (not uTLS) — it only needs a valid certificate; the
// fingerprint camouflage is entirely on the client side.
//
// The returned net.Listener yields *tls.Conn on Accept(). The caller is
// responsible for closing it.
func Listen(cfg *ListenerConfig) (net.Listener, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("transport: ListenAddr is required")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: cfg.nextProtos(),
	}

	// Load certificates.
	if len(cfg.Certificates) > 0 {
		tlsCfg.Certificates = cfg.Certificates
	} else if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("transport: load cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else {
		return nil, fmt.Errorf("transport: either Certificates or CertFile+KeyFile required")
	}

	// Bind TCP.
	tcpLn, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: tcp listen: %w", err)
	}

	// Enable TCP keepalive on accepted connections.
	ln := &keepAliveListener{
		Listener:  tcpLn,
		keepAlive: cfg.tcpKeepAlive(),
	}

	// Wrap with TLS.
	tlsLn := tls.NewListener(ln, tlsCfg)
	return tlsLn, nil
}

// keepAliveListener wraps a net.Listener to set TCP keepalive on accepted
// connections, matching browser-side behavior.
type keepAliveListener struct {
	net.Listener
	keepAlive time.Duration
}

func (l *keepAliveListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(l.keepAlive)
	}
	return conn, nil
}
