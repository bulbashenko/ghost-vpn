// Package integration tests the full GHOST tunnel pipeline:
//
//	Client → uTLS/H2 → Noise IK → Mux → data echo
//
// Uses h2c (HTTP/2 cleartext) and net.Pipe to avoid TLS certs and TUN (root).
package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/bulbashenko/ghost/internal/auth"
	"github.com/bulbashenko/ghost/internal/camouflage"
	"github.com/bulbashenko/ghost/internal/mux"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// pipeRWC combines an io.Reader and io.Writer into io.ReadWriteCloser.
type pipeRWC struct {
	r io.Reader
	w io.Writer
}

func (p *pipeRWC) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeRWC) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeRWC) Close() error {
	if c, ok := p.r.(io.Closer); ok {
		c.Close()
	}
	if c, ok := p.w.(io.Closer); ok {
		c.Close()
	}
	return nil
}

// TestTunnel_EndToEnd tests the full handshake + mux data transfer without TUN.
//
// Setup:
//   - Server listens via h2c on a TCP port
//   - Client connects via plain TCP + h2c
//   - Noise IK handshake inside HTTP/2 POST
//   - Mux streams carry test data bidirectionally
//   - Server echoes data back on each mux stream
func TestTunnel_EndToEnd(t *testing.T) {
	// Generate keypairs.
	serverKP, err := auth.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate server keypair: %v", err)
	}
	clientKP, err := auth.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate client keypair: %v", err)
	}

	allowedClients := map[string]bool{
		auth.EncodeKey(clientKP.Public): true,
	}

	// ---- Server side ----
	onAuth := func(msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
		resp, err := auth.NewResponder(serverKP)
		if err != nil {
			return nil, nil, err
		}
		if _, err := resp.ReadMessage(msg1); err != nil {
			return nil, nil, err
		}
		clientPub := auth.EncodeKey(resp.PeerStatic())
		if !allowedClients[clientPub] {
			return nil, nil, fmt.Errorf("client not allowed")
		}
		msg2, _, err := resp.WriteMessage(nil)
		if err != nil {
			return nil, nil, err
		}

		// Create pipes for mux↔HTTP bridge.
		pipe1R, pipe1W := io.Pipe() // HTTP writes → mux reads
		pipe2R, pipe2W := io.Pipe() // mux writes → HTTP reads

		muxRW := &pipeRWC{r: pipe1R, w: pipe2W}
		_ = mux.NewConn(muxRW, false, func(s *mux.Stream) {
			// Echo server: read data, echo it back.
			go func() {
				defer s.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := s.Read(buf)
					if n > 0 {
						if _, werr := s.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		})

		httpRW := &pipeRWC{r: pipe2R, w: pipe1W}
		return msg2, httpRW, nil
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fallback website"))
	})

	tunnelHandler := camouflage.TunnelHandler(onAuth, fallback)
	router := camouflage.NewRouter(tunnelHandler, fallback)

	// h2c server.
	h2srv := &http2.Server{}
	handler := h2c.NewHandler(router, h2srv)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	defer srv.Close()

	// ---- Client side ----
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect via plain TCP (h2c, no TLS).
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Noise IK: build msg1.
	initiator, err := auth.NewInitiator(clientKP, serverKP.Public)
	if err != nil {
		t.Fatalf("new initiator: %v", err)
	}
	msg1, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatalf("write msg1: %v", err)
	}

	// HTTP/2 handshake over h2c.
	// We need to use h2c-aware transport for the client.
	h2transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return conn, nil
		},
	}

	msg2, tunnelConn, err := handshakeH2C(ctx, h2transport, ln.Addr().String(), msg1)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer tunnelConn.Close()

	// Process Noise msg2.
	_, _, err = initiator.ReadMessage(msg2)
	if err != nil {
		t.Fatalf("read msg2: %v", err)
	}
	t.Log("Noise handshake complete")

	// Mux over tunnel.
	muxConn := mux.NewConn(tunnelConn, true, nil)
	defer muxConn.Close()

	// Open a stream and send test data.
	stream, err := muxConn.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// Send 1MB of random data, verify echo.
	const dataSize = 1 << 20 // 1MB
	rng := rand.New(rand.NewSource(42))
	testData := make([]byte, dataSize)
	rng.Read(testData)

	sendHash := sha256.Sum256(testData)

	var wg sync.WaitGroup
	var writeErr, readErr error
	var recvHash [32]byte

	// Writer goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, writeErr = stream.Write(testData)
		// Signal we're done writing by closing the write direction.
		// (In real tunnel, the stream stays open. For test, we just
		// need to verify the echo.)
	}()

	// Reader goroutine: read back exactly dataSize bytes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		h := sha256.New()
		received := 0
		buf := make([]byte, 32*1024)
		for received < dataSize {
			n, err := stream.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				received += n
			}
			if err != nil {
				if received < dataSize {
					readErr = fmt.Errorf("read after %d bytes: %w", received, err)
				}
				break
			}
		}
		copy(recvHash[:], h.Sum(nil))
	}()

	wg.Wait()

	if writeErr != nil {
		t.Fatalf("write error: %v", writeErr)
	}
	if readErr != nil {
		t.Fatalf("read error: %v", readErr)
	}
	if sendHash != recvHash {
		t.Fatalf("data corruption: send hash %x != recv hash %x", sendHash, recvHash)
	}

	t.Logf("Successfully echoed %d bytes through tunnel", dataSize)
}

// TestTunnel_FallbackOnBadAuth verifies that invalid auth falls through to fallback.
func TestTunnel_FallbackOnBadAuth(t *testing.T) {
	serverKP, _ := auth.GenerateKeypair()
	wrongKP, _ := auth.GenerateKeypair() // client uses wrong server key

	onAuth := func(msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
		resp, _ := auth.NewResponder(serverKP)
		if _, err := resp.ReadMessage(msg1); err != nil {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("not allowed")
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome to example.com"))
	})

	tunnelHandler := camouflage.TunnelHandler(onAuth, fallback)
	router := camouflage.NewRouter(tunnelHandler, fallback)

	h2srv := &http2.Server{}
	handler := h2c.NewHandler(router, h2srv)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	defer srv.Close()

	// Client with wrong server key — Noise handshake will fail at server.
	clientKP, _ := auth.GenerateKeypair()
	initiator, _ := auth.NewInitiator(clientKP, wrongKP.Public) // wrong key!
	msg1, _ := initiator.WriteMessage(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	h2transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return conn, nil
		},
	}

	// The server should return fallback content, not a tunnel.
	_, _, err := handshakeH2C(ctx, h2transport, ln.Addr().String(), msg1)
	if err == nil {
		t.Fatal("expected handshake to fail with wrong key")
	}
	t.Logf("correctly rejected: %v", err)
}

// handshakeH2C performs the tunnel handshake over h2c (for testing without TLS).
func handshakeH2C(ctx context.Context, transport *http2.Transport, addr string, msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
	pr, pw := io.Pipe()

	// Write length-prefixed msg1.
	go func() {
		buf := make([]byte, 2+len(msg1))
		buf[0] = byte(len(msg1) >> 8)
		buf[1] = byte(len(msg1))
		copy(buf[2:], msg1)
		pw.Write(buf)
	}()

	url := "http://" + addr + camouflage.TunnelPath
	req, err := http.NewRequestWithContext(ctx, "POST", url, pr)
	if err != nil {
		pw.Close()
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		pw.Close()
		return nil, nil, fmt.Errorf("request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		pw.Close()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	// Read length-prefixed msg2.
	var lenBuf [2]byte
	if _, err := io.ReadFull(resp.Body, lenBuf[:]); err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, nil, fmt.Errorf("read msg2 length: %w", err)
	}
	msg2Len := int(lenBuf[0])<<8 | int(lenBuf[1])
	msg2 := make([]byte, msg2Len)
	if _, err := io.ReadFull(resp.Body, msg2); err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, nil, fmt.Errorf("read msg2: %w", err)
	}

	tc := &tunnelConn{
		body:   resp.Body,
		writer: pw,
	}
	return msg2, tc, nil
}

type tunnelConn struct {
	body   io.ReadCloser
	writer io.WriteCloser
}

func (tc *tunnelConn) Read(p []byte) (int, error)  { return tc.body.Read(p) }
func (tc *tunnelConn) Write(p []byte) (int, error) { return tc.writer.Write(p) }
func (tc *tunnelConn) Close() error {
	tc.writer.Close()
	return tc.body.Close()
}
