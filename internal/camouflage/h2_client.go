package camouflage

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

// ClientConfig configures the HTTP/2 camouflage client.
type ClientConfig struct {
	// ServerURL is the full URL for the tunnel endpoint, e.g.
	// "https://example.com/api/v1/stream". Built automatically if empty.
	ServerURL string

	// Host is the SNI / Host header value (e.g. "example.com").
	Host string

	// UserAgent mimics a real browser. Defaults to a recent Chrome UA.
	UserAgent string
}

func (c *ClientConfig) userAgent() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	// Chrome 133 — must stay in sync with the uTLS HelloChrome_Auto
	// fingerprint emitted by transport.Dial(). A mismatch (UA says 131,
	// JA4 says 133) is itself a probe-detectable signal.
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
}

func (c *ClientConfig) serverURL() string {
	if c.ServerURL != "" {
		return c.ServerURL
	}
	return "https://" + c.Host + TunnelPath
}

// TunnelConn represents an established tunnel over an HTTP/2 stream.
// It provides bidirectional Read/Write over the HTTP/2 DATA frames.
type TunnelConn struct {
	resp   *http.Response
	body   io.ReadCloser
	writer io.WriteCloser
}

// Read reads tunnel data from the server (HTTP/2 response body).
func (tc *TunnelConn) Read(p []byte) (int, error) {
	return tc.body.Read(p)
}

// Write sends tunnel data to the server (HTTP/2 request body).
func (tc *TunnelConn) Write(p []byte) (int, error) {
	return tc.writer.Write(p)
}

// Close closes both directions of the tunnel.
func (tc *TunnelConn) Close() error {
	tc.writer.Close()
	return tc.body.Close()
}

// Handshake sends the Noise IK msg1 to the server and reads the msg2
// response. On success it returns the msg2 bytes and a TunnelConn for
// bidirectional tunnel data.
//
// The conn parameter should be a TLS connection from transport.Dial().
// This function creates an HTTP/2 client transport on top of it and sends
// the tunnel initiation request with browser-like headers.
func Handshake(ctx context.Context, conn net.Conn, cfg *ClientConfig, msg1 []byte) ([]byte, *TunnelConn, error) {
	// Build HTTP/2 transport over the existing TLS connection.
	h2transport, err := newH2Transport(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("camouflage: h2 transport: %w", err)
	}

	// Use a pipe for the request body: we write length-prefixed msg1 now,
	// and raw tunnel data later. The pipe stays open for the tunnel lifetime.
	pr, pw := io.Pipe()

	// Write length-prefixed msg1 as the initial request body content.
	go func() {
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg1)))
		_, _ = pw.Write(lenBuf[:])
		_, _ = pw.Write(msg1)
		// Don't close pw — it stays open for tunnel data.
	}()

	req, err := http.NewRequestWithContext(ctx, TunnelMethod, cfg.serverURL(), pr)
	if err != nil {
		pw.Close()
		return nil, nil, fmt.Errorf("camouflage: build request: %w", err)
	}

	// Browser-like headers. Match what real Chrome 133 sends for a
	// fetch() POST with a streaming body. The previous header set used
	// "Accept-Encoding: identity" which is a strong DPI signal — only
	// scripts/curl/wget request identity; real browsers always advertise
	// gzip/deflate/br/zstd. The sec-fetch-* headers are also mandatory
	// on modern Chrome and their absence is itself a fingerprint.
	req.Header.Set("User-Agent", cfg.userAgent())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Ch-Ua", `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Origin", "https://"+cfg.Host)
	req.Header.Set("Referer", "https://"+cfg.Host+"/")

	// Send request and read response.
	client := &http.Client{Transport: h2transport}
	resp, err := client.Do(req)
	if err != nil {
		pw.Close()
		return nil, nil, fmt.Errorf("camouflage: tunnel request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		pw.Close()
		resp.Body.Close()
		return nil, nil, fmt.Errorf("camouflage: server returned %d", resp.StatusCode)
	}

	// Read length-prefixed Noise msg2 from the response.
	msg2, err := readLengthPrefixed(resp.Body)
	if err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, nil, fmt.Errorf("camouflage: read msg2: %w", err)
	}

	tc := &TunnelConn{
		resp:   resp,
		body:   resp.Body,
		writer: pw,
	}

	return msg2, tc, nil
}

// newH2Transport creates an http2.Transport that uses the given connection
// directly. This avoids TLS re-negotiation — we reuse the uTLS connection
// from transport.Dial().
func newH2Transport(conn net.Conn) (*http2.Transport, error) {
	t := &http2.Transport{
		// Allow using the connection we already have.
		AllowHTTP: false,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			// Return the existing uTLS connection.
			return conn, nil
		},
	}
	return t, nil
}

// SimpleRequest sends a regular HTTP request through the camouflage layer.
// Used for cover traffic or probing the server without tunnel initiation.
func SimpleRequest(ctx context.Context, conn net.Conn, method, url string, body []byte) (*http.Response, error) {
	h2transport, err := newH2Transport(conn)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Transport: h2transport}
	return client.Do(req)
}
