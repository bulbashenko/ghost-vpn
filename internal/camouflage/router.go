// Package camouflage implements L2 of the GHOST protocol stack: HTTP/2
// semantic wrapping that makes tunnel traffic look like ordinary HTTPS API
// requests. The server routes authenticated tunnel requests to the tunnel
// handler and everything else to the fallback reverse proxy, so an active
// prober sees a real website.
package camouflage

import (
	"net/http"
)

const (
	// DefaultTunnelPath is the path used when the operator does not
	// override it via config. All other paths are routed to the fallback.
	DefaultTunnelPath = "/api/v1/stream"

	// TunnelMethod is the HTTP method for tunnel initiation. POST is chosen
	// because it naturally carries a request body (the Noise handshake
	// message) and a response body (the server's reply + tunnel data).
	TunnelMethod = "POST"
)

// TunnelPath is the path the camouflage layer matches against. Mutated
// at startup via SetTunnelPath() if the operator provides an override
// in the YAML config; otherwise stays at DefaultTunnelPath. Both client
// (h2_client.go default URL) and server (router) read this.
//
// We keep it as a package-level variable rather than threading a config
// struct through every callsite because there is exactly one router and
// one client config per process — a global is the honest representation.
var TunnelPath = DefaultTunnelPath

// SetTunnelPath overrides the tunnel endpoint path used by both the
// router (server-side match) and the default client URL builder. Must
// be called before any tunnel is established. Empty path resets to the
// default.
func SetTunnelPath(p string) {
	if p == "" {
		TunnelPath = DefaultTunnelPath
		return
	}
	TunnelPath = p
}

// Router dispatches incoming HTTP requests. Requests matching the tunnel
// endpoint are sent to the tunnel handler; everything else goes to the
// fallback handler (reverse proxy to a real website).
//
// From an active prober's perspective, the server behaves identically to a
// real website that happens to have a POST API endpoint — which is completely
// normal for any modern web application.
type Router struct {
	tunnel   http.Handler
	fallback http.Handler
}

// NewRouter creates a camouflage router.
//   - tunnel: handles authenticated GHOST tunnel requests
//   - fallback: reverse proxy to a real website for all other requests
func NewRouter(tunnel, fallback http.Handler) *Router {
	return &Router{
		tunnel:   tunnel,
		fallback: fallback,
	}
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == TunnelMethod && req.URL.Path == TunnelPath {
		r.tunnel.ServeHTTP(w, req)
		return
	}
	r.fallback.ServeHTTP(w, req)
}
