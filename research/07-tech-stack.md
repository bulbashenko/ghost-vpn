# Technical Stack & Dependencies

## Language: Go

**Why Go:**
- First-class uTLS support (`github.com/refraction-networking/utls`)
- Excellent crypto library (`golang.org/x/crypto`)
- Standard library HTTP/2 support
- Easy cross-compilation for multiple targets
- Low memory footprint, good concurrency (goroutines)
- Xray-core ecosystem compatibility (can borrow battle-tested code)
- Good TUN/TAP support via gVisor and golang.zx2c4.com/wireguard/tun

## Core Dependencies

### Cryptography

| Package | Purpose |
|---------|---------|
| `github.com/flynn/noise` | Noise Protocol Framework implementation |
| `golang.org/x/crypto/chacha20poly1305` | Session encryption |
| `golang.org/x/crypto/curve25519` | Key exchange (via Noise) |
| `golang.org/x/crypto/blake2s` | Noise hashing |
| `crypto/subtle` | Constant-time comparisons (stdlib) |
| `crypto/rand` | Cryptographic randomness (stdlib) |

### TLS Camouflage

| Package | Purpose |
|---------|---------|
| `github.com/refraction-networking/utls` | Chrome/Firefox TLS fingerprint mimicry |

### Transport

| Package | Purpose |
|---------|---------|
| `net` (stdlib) | TCP |
| `golang.org/x/net/http2` | HTTP/2 client and server |
| `nhooyr.io/websocket` or `github.com/gorilla/websocket` | WebSocket for CDN relay |

### TUN Interface

| Package | Purpose |
|---------|---------|
| `golang.zx2c4.com/wireguard/tun` | Cross-platform TUN (from WireGuard-go) |
| `gvisor.dev/gvisor/pkg/tcpip` | Userspace networking (alternative) |

### IP Packet Handling

| Package | Purpose |
|---------|---------|
| `github.com/google/gopacket` | Packet parsing (for testing) |
| stdlib `net/netip` | Modern IP address types |

### Configuration

| Package | Purpose |
|---------|---------|
| `github.com/BurntSushi/toml` or `gopkg.in/yaml.v3` | Config parsing |

### Logging

| Package | Purpose |
|---------|---------|
| `log/slog` (stdlib Go 1.21+) | Structured logging |

### Testing Dependencies

| Package | Purpose |
|---------|---------|
| Standard `testing` | Unit tests |
| `github.com/stretchr/testify` | Test assertions |
| `tcpdump` / `tshark` | Packet capture for traffic analysis |

## Development Tools

### Traffic Analysis

- **Wireshark / tshark**: Packet inspection, JA3 verification
- **tcpdump**: Raw capture for offline analysis
- **mitmproxy**: HTTPS traffic inspection for shaping calibration

### ML Classifier Testing

- **Python + scikit-learn**: Train baseline classifier on our vs real traffic
- **CICFlowMeter**: Flow feature extraction (standard tool in academic papers)
- **Joy**: Cisco's flow feature extractor

### DPI Testing

- **Suricata**: Open-source DPI with VPN signatures
- **Snort**: Alternative DPI
- **nDPI**: Protocol detection library

## Reference Implementations to Study

| Project | What to learn |
|---------|---------------|
| `github.com/XTLS/Xray-core` | Production VPN server, Reality protocol, Vision padding |
| `github.com/v2fly/v2ray-core` | V2Ray, transport layer design |
| `github.com/wireguard/wireguard-go` | Userspace VPN in Go, Noise usage, TUN handling |
| `github.com/cbeuw/Cloak` | HTTPS mimicry approach |
| `github.com/Yawning/obfs4` | Protocol obfuscation (Go-like, Pyobfsproxy) |
| `github.com/flynn/noise` | Noise Protocol library |
| `github.com/refraction-networking/utls` | uTLS usage examples |

## Infrastructure

### Development Machine

- Linux (Debian/Ubuntu)
- Go 1.22+
- Git
- Docker (optional, for isolated test environments)

### Test Environment

- VPS in location outside Russia (for real server)
- Cloudflare account (free tier) for Worker deployment
- Test client on Russian ISP (Rostelecom/MTS/MegaFon) for real-world verification
- Alternative: VPS inside Russia for simulated ISP testing

### CDN Setup (for Mode B)

- Cloudflare Workers account (free tier supports 100K requests/day)
- Custom domain (not *.workers.dev — too recognizable)
- Worker code in JavaScript/TypeScript

## Project Layout (Go module structure)

```
github.com/bulbashenko/ghost/
├── cmd/
│   ├── ghost-client/         # Client binary
│   ├── ghost-server/         # Server binary
│   └── ghost-tools/          # Utilities (keygen, capture, test)
├── internal/
│   ├── transport/            # L1: TCP, TLS, CDN
│   ├── camouflage/           # L2: HTTP/2 wrapping
│   ├── auth/                 # L3: Noise handshake
│   ├── mux/                  # L4: Stream multiplexer
│   ├── shaper/               # L5: Traffic shaper
│   ├── tun/                  # TUN interface management
│   ├── config/               # Config loader
│   ├── fallback/             # Real-website fallback server
│   └── profile/              # Shaping profiles (distributions)
├── pkg/
│   └── ghost/                # Public API (if any)
├── test/
│   ├── integration/          # End-to-end tests
│   ├── detection/            # ML classifier harness
│   └── fixtures/             # Test pcaps, sample configs
├── worker/                   # Cloudflare Worker code (TS)
├── docs/
│   └── protocol.md           # Wire format specification
├── research/                 # This directory
├── go.mod
├── go.sum
└── README.md
```

## Build Requirements

- Linux amd64 (primary target)
- Linux arm64 (for ARM VPS)
- macOS (for development)
- Windows (client only, eventually)

## External Resources Needed

1. Domain name (for real TLS cert)
2. VPS with public IP (server hosting)
3. Let's Encrypt account (free TLS certs)
4. Cloudflare account (Worker relay mode)
5. Traffic capture samples (real HTTPS from browser sessions)

## Ethical/Legal Note

This is a censorship circumvention tool. Development is legal in most jurisdictions. Deployment in Russia may violate local laws. Project documentation should include appropriate warnings.
