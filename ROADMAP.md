# Ghost — Roadmap

## Where we are

The core protocol is implemented and validated against a real Russian ТСПУ network. Two rounds of live DPI analysis (Moscow → Helsinki) confirmed the following fingerprints have been eliminated:

| Signal | Status |
|--------|--------|
| Active probe `POST /api/v1/stream` → HTTP 502 | ✅ Fixed — returns identical response to real site |
| Packet sizes 99% in 100–199 byte range | ✅ Fixed — 85.8% MTU-sized, matches HTTPS download |
| TLS ClientHello fingerprint mismatch | ✅ Fixed — Chrome 133 JA4 exact match |
| Single 128s TCP connection | ✅ Fixed — rotating sessions every 16–42s |
| `Accept-Encoding: identity` header | ✅ Fixed — full Chrome 131+ header set |
| Speed: 4 Mbps | ✅ Fixed — 125 Mbps sustained |

The protocol now produces traffic that looks like a Chrome 133 browser continuously loading HTTPS content and periodically refreshing its connection — which is exactly what Slack, WhatsApp Web, and Telegram Web do.

See [docs/dpi-analysis.md](docs/dpi-analysis.md) for full measurement data.

---

## v0.2 — Remaining fingerprints (near term)

### ECH — Encrypted Client Hello

**Status:** plumbing exists; not deployed  
**Impact:** eliminates SNI from ТСПУ passive inspection

Currently the server's real domain name appears in the TLS `server_name` extension in plaintext. ТСПУ can use this to whitelist/blacklist specific domains regardless of traffic shape.

Real Encrypted Client Hello hides the inner SNI inside an encrypted wrapper, revealing only a CDN outer SNI (e.g. `cloudflare.com`). This requires:

- Server behind Cloudflare (free tier sufficient)
- Cloudflare publishes an ECH config in the domain's HTTPS DNS record automatically
- Client connects to Cloudflare IP, outer SNI = CDN domain, inner SNI = real server domain

The `front_host` config field is already implemented (`internal/config/config.go`). What remains is the CDN deployment.

### Multi-stream HTTP/2

**Status:** not started  
**Impact:** eliminates single-stream pattern

Currently all tunnel traffic flows over one HTTP/2 stream (one long POST body). Real browsers maintain 6–20 concurrent streams per connection: page HTML, CSS, JS, images, API calls, WebSocket upgrades.

Plan:
- Open 3–6 parallel HTTP/2 streams per TCP connection
- Distribute mux frames across streams by stream ID
- Add lightweight `GET /static/*.js` and `GET /favicon.ico` decoy streams with plausible small bodies

### ML profile shaping

**Status:** partially implemented  
**Impact:** defeats per-flow ML classifiers using distribution matching

The write coalescer currently pads to a uniform random target in [1100, 1450] bytes. This produces a flat distribution at MTU, which passes basic histogram checks but would be flagged by an ML classifier trained to recognize "uniform MTU padding."

`internal/profile/` already contains empirical inter-arrival time and size distributions captured from real browsing sessions. The coalescer needs to:

1. Sample flush timing from the captured IAT distribution (currently fixed 8ms)
2. Sample target packet sizes from the captured size distribution (currently uniform)
3. Vary the asymmetry ratio (upstream:downstream) to match typical browsing (1:8 to 1:15)

### Per-frame Noise encryption

**Status:** session keys derived, not applied to L4 headers  
**Impact:** low (only matters for co-located observer on the server's network)

Noise IK derives session cipher keys after the handshake. Currently these keys encrypt the L4 frame payload but the frame header (Version/Type/StreamID/Length) is sent in plaintext inside the TLS record stream. A co-located passive observer on the Helsinki server's network (e.g. a compromised switch) can see the inner protocol structure.

Fix: encrypt the full frame (header + payload) under the session cipher. 8 bytes of overhead per frame.

---

## v0.3 — CDN relay

**Status:** config field ready; deployment not started  
**Impact:** bypasses IP-based blocking of the server

If ТСПУ moves to an IP whitelist (only allow traffic to known-good ASNs), a direct TCP connection to a Hetzner VPS will be blocked regardless of how legitimate the traffic looks.

CDN relay places the server behind Cloudflare:

```
Client → Cloudflare edge (IP is in whitelist) → origin server
```

The `front_host` field decouples TLS SNI from the HTTP/2 `:authority` header, enabling CDN routing:

```yaml
server_addr: cloudflare-edge.example.com:443
sni: cloudflare-edge.example.com          # TLS outer SNI (reaches CF edge)
front_host: ghost.your-origin.com         # HTTP Host header (CF routes to origin)
```

What remains:
1. Put the Ghost server behind Cloudflare (origin-pull, not the default CDN mode)
2. Ensure CF passes the HTTP/2 POST body through without buffering (needs `Cache-Control: no-store` and a path pattern that bypasses caching)
3. Test that Cloudflare doesn't kill long-lived POST streams (WebSocket proxy mode is an alternative)

---

## v1.0 — Polish and hardening

These items are necessary for a production-grade release but don't affect DPI evasion:

**Server:**
- [ ] Prometheus metrics endpoint (connections, bytes, rotation count)
- [ ] Graceful server reload on SIGHUP (new config without dropping existing sessions)
- [ ] Rate limiting / per-client bandwidth caps
- [ ] Structured JSON logging

**Client:**
- [ ] Automatic reconnect backoff (currently restarts immediately)
- [ ] DNS leak prevention built into the client (force DNS through tunnel automatically)
- [ ] IPv6 tunnel support
- [ ] Health check endpoint (`/metrics` or `/healthz` on a local port)

**Protocol:**
- [ ] Stream migration (`MIGRATE` frame, v2) — move streams between TCP connections without packet loss
- [ ] Protocol version negotiation

**Tooling:**
- [ ] `ghost-tools diagnose` — run active probe and fingerprint checks against your own server
- [ ] `ghost-tools capture` — capture and summarize flow statistics for DPI analysis
- [ ] Config validation with helpful error messages

---

## v2.0 — Platform expansion

After the Linux implementation is solid:

**Client platforms:**
- Windows (WinTUN)
- macOS (utun)
- Android (TUN, VpnService API)

**Server modes:**
- Multi-client with per-client bandwidth and ACL
- QUIC/HTTP-3 transport as an alternative to TCP
- Server mesh (multiple servers, client can failover)

**GUI:**
- Desktop app (Electron or native)
- Mobile apps

---

## Won't do (v1)

These are explicitly out of scope to keep the implementation focused:

- **Peer-to-peer mode** — requires NAT traversal, complicates the threat model
- **Key exchange via QR code / deep link** — out-of-band distribution, separate problem
- **Onion routing / multi-hop** — different threat model, different project
- **Traffic obfuscation without TLS** — goes against the core design principle (single TLS, no nesting)
