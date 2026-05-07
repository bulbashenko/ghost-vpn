# Proposed Protocol Architecture

Working name: **GHOST** (or TBD — placeholder)

## Layered Architecture

```
+-------------------------------------------------------------+
| L5: Traffic Shaper                                          |
|     - Statistical mimicry (packet sizes, IATs)              |
|     - Asymmetry enforcement                                 |
|     - Burst pattern simulation                              |
|     - Connection lifecycle manager                          |
+-------------------------------------------------------------+
| L4: Multiplexer + Stream Manager                            |
|     - Bidirectional streams over single connection          |
|     - Flow control                                          |
|     - Stream migration between connections                  |
|     - Binary frame format                                   |
+-------------------------------------------------------------+
| L3: Authentication & Key Exchange                           |
|     - Noise Protocol IK pattern                             |
|     - Embedded in HTTP/2 request body                       |
|     - Constant-time verification                            |
|     - Session token + replay protection                     |
+-------------------------------------------------------------+
| L2: Application Camouflage                                  |
|     - HTTP/2 or HTTP/1.1 semantic request/response          |
|     - Looks like normal API traffic                         |
|     - Server: fallback to real website on invalid auth      |
+-------------------------------------------------------------+
| L1: Transport Camouflage                                    |
|     - TLS 1.3 with uTLS browser fingerprint                 |
|     - Real CA-signed certificate                            |
|     - Direct mode: TCP to server                            |
|     - Relay mode: WebSocket through Cloudflare Workers      |
+-------------------------------------------------------------+
```

## Data Flow Example

### Client sends IP packet through tunnel

```
1. Application opens socket, sends data
2. OS routes via TUN interface (ghost0)
3. L5 shaper: batch packets, decide timing
4. L4 mux: wrap in stream frame with stream_id
5. L3 auth: encrypt with session key (ChaCha20-Poly1305)
6. L2 app: wrap in HTTP/2 DATA frame
7. L1 TLS: encrypt via Chrome-fingerprinted uTLS
8. Network: TCP packet to server (or CF Worker)
```

### Server receives and forwards

```
1. TCP packet arrives at server (or forwarded from CF Worker)
2. L1 TLS: decrypt via matching uTLS server config
3. L2 app: parse HTTP/2 frame
4. L3 auth: verify session token, decrypt payload
5. L4 mux: extract stream frame, route to stream handler
6. L5 shaper: reassemble shaped traffic into original packets
7. Server: forward to destination IP
8. Response travels back same path
```

## Connection Establishment Sequence

```
Client                              CDN (optional)           Server
  |                                     |                      |
  | 1. TCP connect                      |                      |
  |------------------------------------>|--------------------->|
  |                                     |                      |
  | 2. TLS 1.3 ClientHello (uTLS Chrome fingerprint)           |
  |------------------------------------>|--------------------->|
  |                                     |                      |
  | 3. TLS handshake completes with server's real cert         |
  |<------------------------------------|<---------------------|
  |                                     |                      |
  | 4. HTTP/2 connection preface + SETTINGS                    |
  |------------------------------------>|--------------------->|
  |                                     |                      |
  | 5. HTTP/2 request: POST /api/v1/stream                     |
  |    Headers: normal browser headers                         |
  |    Body: Noise IK handshake message (encrypted pubkey)     |
  |------------------------------------>|--------------------->|
  |                                     |                      |
  |    [Server verifies Noise handshake in constant time]      |
  |                                     |                      |
  | 6a. If valid: HTTP/2 response with session token           |
  |     Response body: Noise handshake response + session key  |
  |     Then DATA frames = tunnel traffic                      |
  |<------------------------------------|<---------------------|
  |                                     |                      |
  | 6b. If invalid: forward to real fallback website           |
  |     Return real HTML response                              |
  |<------------------------------------|<---------------------|
  |                                     |                      |
  | 7. Tunnel data exchange (bidirectional)                    |
  |<----------------------------------->|<-------------------->|
```

## L3: Noise Protocol Authentication Details

Pattern: `Noise_IK_25519_ChaChaPoly_BLAKE2s`

### IK Pattern Flow

```
-> s (server static public key known to client out-of-band)
-> e, es, s, ss  (client sends, authenticates immediately)
<- e, ee, se     (server responds)
```

### Embedded in HTTP/2

```
Request body structure (binary):
+------------------+------------------+---------------------+
| NoiseMsgLen (2)  | NoiseMsg (var)   | Padding (random)    |
+------------------+------------------+---------------------+

The padding ensures request body size matches distribution
of real API request bodies (captured from target cover traffic).
```

### Timing Attack Resistance

```go
// All comparisons use crypto/subtle
if subtle.ConstantTimeCompare(expected, received) != 1 {
    // DO NOT return error immediately
    // Continue to fallback path without timing difference
    return forwardToFallback(request)
}
```

## L4: Multiplexer Frame Format

```
+---------+----------+-----------+----------+-------------+
| Version | Type (1) | StreamID  | Length   | Payload     |
| 1 byte  | 1 byte   | 4 bytes   | 2 bytes  | N bytes     |
+---------+----------+-----------+----------+-------------+
            |
            +-- 0x00: DATA
                0x01: WINDOW_UPDATE
                0x02: STREAM_OPEN
                0x03: STREAM_CLOSE
                0x04: PING (keepalive)
                0x05: PADDING (dummy frame for shaping)
                0x06: MIGRATE (move stream to new connection)
```

Payload is already encrypted by L3 (session key). Frame header is visible inside TLS (which encrypts everything).

## L5: Traffic Shaper Design

### Components

1. **Distribution Sampler**
   - Loaded from empirical distributions (pcap captures of cover protocol)
   - Samples: packet size, IAT, burst size, burst gap
   - Per-session seeding for variance

2. **Asymmetry Enforcer**
   - Tracks upload/download byte ratio
   - Injects PADDING frames in download direction to maintain target ratio (default 1:5)
   - Padding data is random, consumed on client side

3. **Burst Simulator**
   - Models request-response pattern (not continuous stream)
   - Burst: N frames in rapid succession
   - Gap: random interval from log-normal distribution

4. **Connection Lifecycle Manager**
   - Opens connections with random lifetime (from distribution)
   - Before connection closes, migrates active streams to new connection
   - Old connection closes with realistic FIN/RST pattern

### Calibration Profile

Ship with multiple profiles:
- `youtube`: Mimics YouTube video streaming
- `api`: Mimics generic JSON REST API traffic
- `cdn`: Mimics static asset downloads
- `realtime`: Mimics WebSocket chat

User selects profile based on cover story. Each profile has different distributions loaded.

## L1 Transport Modes

### Mode A: Direct TCP + TLS

```
Client --- TLS --- Your Server (VPS)
```

Requirements:
- Server: clean residential-looking IP (or CDN-origin-proxied)
- Real domain with CA-signed certificate (Let's Encrypt)
- Reverse proxy setup: nginx + your server on different ports
- Fallback: nginx serves real content for non-auth requests

### Mode B: CDN Relay (Cloudflare Workers)

```
Client --- TLS --- Cloudflare --- WebSocket --- Your Server
```

Requirements:
- Cloudflare account with Worker deployed
- Worker proxies WebSocket to your backend
- Backend can have any IP (not blocked because traffic originates from CF)
- Bypasses IP-based whitelists (CF is always whitelisted)

### Mode C: Domain Fronting (if possible)

```
Client --- TLS (SNI: popular.com) --- CDN --- (Host: yours.com) --- Your Server
```

Most CDNs have ended domain fronting support. Only viable with specific providers.

## Component Responsibility Matrix

| Component | Responsibility |
|-----------|----------------|
| `transport/` | TCP, TLS with uTLS, CDN WebSocket client |
| `camouflage/` | HTTP/2 wrapping, fallback server |
| `auth/` | Noise Protocol handshake, session management |
| `mux/` | Stream multiplexing, frame encoding |
| `shaper/` | Traffic shaping, distribution sampling |
| `tun/` | TUN interface, IP packet routing |
| `config/` | Config file parsing |
| `server/` | Server main: orchestrates all layers |
| `client/` | Client main: orchestrates all layers |
| `tools/` | Traffic capture, profile generation, classifier testing |

## Wire Protocol Summary

Everything a network observer sees:

```
TCP packet:
  - IP header: real
  - TCP header: real
  - TLS record: encrypted by TLS with real cert
    - HTTP/2 frame: standard
      - HTTP/2 DATA: contains our encrypted payload
        - Payload (encrypted by session key, observer sees noise)
          - Mux frame header
          - Actual tunnel data
```

From DPI perspective: looks like HTTPS to a website. Statistical shaping makes flow metrics match real web traffic. Server behavioral fallback ensures probing gets real responses.

## Open Questions for Design Review

1. **Profile selection**: Should profile be per-server or per-connection?
2. **Stream migration**: Required for v1, or defer to v2?
3. **CDN relay**: Build Worker in v1, or Direct-TCP only?
4. **Fallback target**: Static site, or dynamically proxy to real website?
5. **Config format**: YAML vs TOML vs JSON?
6. **Key distribution**: How does client get server's public key? (Out-of-band, like WireGuard)
