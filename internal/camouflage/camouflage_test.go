package camouflage

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// lengthPrefixed wraps data with a 2-byte big-endian length prefix.
func lengthPrefixed(data []byte) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(len(data)))
	return append(buf[:], data...)
}

func TestRouter_TunnelPathRouted(t *testing.T) {
	tunnelCalled := false
	tunnel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tunnelCalled = true
		w.WriteHeader(http.StatusOK)
	})
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("fallback should not be called for tunnel path")
	})

	router := NewRouter(tunnel, fallback)

	req := httptest.NewRequest("POST", TunnelPath, bytes.NewReader(lengthPrefixed([]byte("noise-msg1"))))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if !tunnelCalled {
		t.Fatal("tunnel handler not called for POST /api/v1/stream")
	}
}

func TestRouter_NonTunnelPathFallback(t *testing.T) {
	tunnel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("tunnel should not be called for non-tunnel path")
	})
	fallbackCalled := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.Write([]byte("fallback response"))
	})

	router := NewRouter(tunnel, fallback)

	// Various non-tunnel requests should all go to fallback.
	paths := []struct {
		method, path string
	}{
		{"GET", "/"},
		{"GET", "/index.html"},
		{"GET", TunnelPath},       // GET, not POST → fallback
		{"PUT", TunnelPath},       // PUT, not POST → fallback
		{"POST", "/other"},        // wrong path → fallback
		{"GET", "/api/v1/data"},   // similar but different path
		{"DELETE", TunnelPath},    // wrong method
	}

	for _, p := range paths {
		fallbackCalled = false
		req := httptest.NewRequest(p.method, p.path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if !fallbackCalled {
			t.Errorf("%s %s did not route to fallback", p.method, p.path)
		}
	}
}

func TestTunnelHandler_AuthSuccess(t *testing.T) {
	authResp := []byte("noise-msg2-response")

	onAuth := func(msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
		if !bytes.Equal(msg1, []byte("noise-msg1")) {
			t.Errorf("unexpected msg1: %q", msg1)
		}
		return authResp, nil, nil
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("fallback should not be called on auth success")
	})

	handler := TunnelHandler(onAuth, fallback)

	req := httptest.NewRequest("POST", TunnelPath, bytes.NewReader(lengthPrefixed([]byte("noise-msg1"))))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	// Response should be length-prefixed msg2.
	expectedResp := lengthPrefixed(authResp)
	if !bytes.Equal(body, expectedResp) {
		t.Fatalf("body=%x, want %x", body, expectedResp)
	}
	if resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("content-type=%q", resp.Header.Get("Content-Type"))
	}
}

func TestTunnelHandler_AuthFailure_FallsThrough(t *testing.T) {
	onAuth := func(msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
		return nil, nil, io.ErrUnexpectedEOF // simulate auth failure
	}

	fallbackCalled := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.Write([]byte("real website content"))
	})

	handler := TunnelHandler(onAuth, fallback)

	req := httptest.NewRequest("POST", TunnelPath, bytes.NewReader(lengthPrefixed([]byte("garbage-data"))))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !fallbackCalled {
		t.Fatal("fallback not called on auth failure")
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != "real website content" {
		t.Fatalf("body=%q", body)
	}
}

func TestTunnelHandler_EmptyBody_FallsThrough(t *testing.T) {
	onAuth := func(msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
		t.Error("onAuth should not be called with empty body")
		return nil, nil, nil
	}

	fallbackCalled := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
	})

	handler := TunnelHandler(onAuth, fallback)

	req := httptest.NewRequest("POST", TunnelPath, strings.NewReader(""))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !fallbackCalled {
		t.Fatal("fallback not called for empty body")
	}
}

func TestRouter_FullIntegration(t *testing.T) {
	// Simulate a full setup: router with tunnel handler + fallback.
	onAuth := func(msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
		return []byte("server-reply"), nil, nil
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome to example.com"))
	})

	tunnel := TunnelHandler(onAuth, fallback)
	router := NewRouter(tunnel, fallback)

	// Test: active prober hitting GET /
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != "welcome to example.com" {
		t.Fatalf("prober GET /: %q", body)
	}

	// Test: active prober hitting POST /api/v1/stream with garbage
	garbage := func(msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	tunnelStrict := TunnelHandler(garbage, fallback)
	routerStrict := NewRouter(tunnelStrict, fallback)

	req2 := httptest.NewRequest("POST", TunnelPath, bytes.NewReader(lengthPrefixed([]byte("random-garbage"))))
	rec2 := httptest.NewRecorder()
	routerStrict.ServeHTTP(rec2, req2)
	body2, _ := io.ReadAll(rec2.Result().Body)
	if string(body2) != "welcome to example.com" {
		t.Fatalf("prober POST garbage: %q", body2)
	}

	// Test: legitimate client hitting POST /api/v1/stream with valid auth
	req3 := httptest.NewRequest("POST", TunnelPath, bytes.NewReader(lengthPrefixed([]byte("valid-noise-msg1"))))
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)
	if rec3.Result().StatusCode != http.StatusOK {
		t.Fatalf("valid auth: status=%d", rec3.Result().StatusCode)
	}
	body3, _ := io.ReadAll(rec3.Result().Body)
	expectedBody3 := lengthPrefixed([]byte("server-reply"))
	if !bytes.Equal(body3, expectedBody3) {
		t.Fatalf("valid auth body: %x, want %x", body3, expectedBody3)
	}
}

func TestNewServer_H2C(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("h2c works"))
	})

	h2handler := NewServer(&ServerConfig{
		Handler:  handler,
		AllowH2C: true,
	})

	srv := httptest.NewServer(h2handler)
	defer srv.Close()

	// Regular HTTP/1.1 request should still work through h2c handler.
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "h2c works" {
		t.Fatalf("body=%q", body)
	}
}

func TestClientConfig_Defaults(t *testing.T) {
	cfg := &ClientConfig{Host: "example.com"}
	if cfg.userAgent() == "" {
		t.Fatal("default user agent is empty")
	}
	if !strings.Contains(cfg.userAgent(), "Chrome") {
		t.Fatalf("default UA should mimic Chrome: %q", cfg.userAgent())
	}
	want := "https://example.com" + TunnelPath
	if cfg.serverURL() != want {
		t.Fatalf("serverURL=%q, want %q", cfg.serverURL(), want)
	}
}
