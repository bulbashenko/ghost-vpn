// Package fallback implements the reverse proxy that serves as the GHOST
// server's cover story. Any request that fails L3 authentication (or never
// attempts it) is transparently forwarded to a real website — the fallback
// target. An active prober therefore sees the same responses it would get
// from the real site, making the GHOST server indistinguishable from a
// plain reverse proxy / CDN edge.
//
// Design goals (Principle 3 — active probing resistance):
//   - Response bodies identical to fallback target
//   - Response headers sanitized to match (no "Via", no "X-Forwarded-*" leak)
//   - Latency overhead <50ms over direct-to-target
package fallback

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Proxy is a thin wrapper around httputil.ReverseProxy configured for
// camouflage use. It strips headers that would reveal proxying.
type Proxy struct {
	target *url.URL
	rp     *httputil.ReverseProxy
}

// New creates a fallback reverse proxy to the given target URL (e.g.
// "https://example.com"). The proxy rewrites Host and sanitizes response
// headers to make the forwarded response indistinguishable from a direct
// connection to the target.
func New(target string) (*Proxy, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	// Ensure scheme is present.
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	rp := httputil.NewSingleHostReverseProxy(u)

	// Rewrite the outgoing request to look like a direct client→target
	// connection. We override Director to control headers precisely.
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = u.Host
		// Remove headers that reveal proxying.
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Forwarded-Host")
		req.Header.Del("X-Real-Ip")
	}

	// Sanitize response headers before sending them to the prober.
	rp.ModifyResponse = sanitizeResponse

	return &Proxy{target: u, rp: rp}, nil
}

// ServeHTTP forwards the request to the fallback target.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.rp.ServeHTTP(w, r)
}

// Target returns the configured fallback URL.
func (p *Proxy) Target() *url.URL {
	return p.target
}

// sanitizeResponse strips headers from the upstream response that could
// reveal the presence of a reverse proxy.
func sanitizeResponse(resp *http.Response) error {
	// Remove hop-by-hop / proxy-revealing headers that the upstream might
	// have added. A real direct connection would never have these.
	for _, h := range []string{
		"Via",
		"X-Forwarded-For",
		"X-Forwarded-Proto",
		"X-Forwarded-Host",
		"X-Real-Ip",
	} {
		resp.Header.Del(h)
	}

	// If the upstream returns a Server header, keep it — that's what a
	// prober expects to see from the real site. We only strip our own
	// fingerprints.
	// Remove any accidental "ghost" mentions (defense in depth).
	for key, vals := range resp.Header {
		for i, v := range vals {
			if strings.Contains(strings.ToLower(v), "ghost") {
				resp.Header[key][i] = ""
			}
		}
	}

	return nil
}
