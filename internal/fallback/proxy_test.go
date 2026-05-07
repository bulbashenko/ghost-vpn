package fallback

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxy_ForwardsRequest(t *testing.T) {
	// Upstream "real website" that the fallback proxies to.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "real-site")
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("welcome to the real site"))
	}))
	defer upstream.Close()

	proxy, err := New(upstream.URL)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	// Simulate a prober hitting the GHOST server.
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if string(body) != "welcome to the real site" {
		t.Fatalf("body=%q", body)
	}
	if resp.Header.Get("Server") != "nginx/1.24.0" {
		t.Fatalf("Server header not forwarded: %q", resp.Header.Get("Server"))
	}
}

func TestProxy_ForwardsAllPaths(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("path=" + r.URL.Path))
	}))
	defer upstream.Close()

	proxy, err := New(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	paths := []string{"/", "/index.html", "/about", "/random/page", "/api/data"}
	for _, p := range paths {
		req := httptest.NewRequest("GET", p, nil)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Result().Body)
		if string(body) != "path="+p {
			t.Errorf("path %s: got %q", p, body)
		}
	}
}

func TestProxy_StripsProxyHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upstream adds proxy-revealing headers.
		w.Header().Set("Via", "1.1 ghost-server")
		w.Header().Set("X-Forwarded-For", "1.2.3.4")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := New(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.Header.Get("Via") != "" {
		t.Error("Via header leaked")
	}
	if resp.Header.Get("X-Forwarded-For") != "" {
		t.Error("X-Forwarded-For header leaked")
	}
}

func TestProxy_Target(t *testing.T) {
	proxy, err := New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Target().Host != "example.com" {
		t.Fatalf("target=%v", proxy.Target())
	}
}
