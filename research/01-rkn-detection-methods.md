# RKN Detection Methods (TSPU + Android-level)

Source: https://github.com/xtclovver/RKNHardering

## Overview

TSPU (Технические Средства Противодействия Угрозам) — hardware boxes installed at ISP exchange points (Rostelecom, MTT, etc.). Perform DPI + active probing + ML classification.

The RKNHardering Android app simulates device-level detection, but reveals the *mindset* and detection vectors RKN uses at network level too.

---

## 1. Signature-Based Protocol Detection (TSPU)

TSPU detects protocols by static byte patterns:

| Protocol | Signature | Status |
|----------|-----------|--------|
| WireGuard | First byte 0x01-0x04, fixed handshake structure, UDP | Blocked |
| OpenVPN | 0x00 0x00 header, opcode byte, UDP/TCP 1194 | Blocked |
| IPSec/IKE | UDP 500/4500, IKE magic bytes | Partially blocked |
| Shadowsocks (raw) | High entropy without TLS wrapper | Detected by entropy |
| VLESS+Reality | See section 3 | Intermittently detected |

## 2. TLS Fingerprinting (JA3/JA3S)

TSPU extracts JA3 fingerprint from TLS ClientHello:
- Cipher suite order
- TLS extensions and their order
- Elliptic curves
- Point formats

Non-browser JA3 = suspicious. Go's `crypto/tls` has a distinct JA3 different from any browser.

**Countermeasure**: uTLS (github.com/refraction-networking/utls) with HelloChrome_Auto or HelloFirefox_Auto.

**Limitation of uTLS**: Only mimics ClientHello. Post-handshake behavior (ServerHello, application data patterns) not mimicked.

## 3. Why VLESS+Reality Gets Detected

### 3a. Encapsulated TLS Handshake Fingerprinting (USENIX 2024)

Paper: "Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes" by Xue et al.

- **TPR**: >70% detection rate
- **FPR**: 0.054% (practical for deployment)
- **Method**: Similarity-based classifiers on packet size sequences during TLS-in-TLS
- Even with Vision padding (900-1400 bytes), nested handshake round-trips remain detectable
- Stream multiplexing alone insufficient

### 3b. Flow-Level Statistical Anomalies

| Feature | Real HTTPS | VLESS+Reality Tunnel |
|---------|------------|---------------------|
| Upload/Download ratio | ~1:10 (asymmetric) | ~1:1 (symmetric) |
| Session duration | Seconds | Hours |
| TLS record sizes | Variable, often MTU-bound 1300-1400 | Frequently max 16KB |
| Traffic pattern | Burst -> silence -> burst | Continuous bidirectional |
| Packet size distribution | High variance | More uniform |
| Inter-arrival times | Irregular (user think time) | Regular |

### 3c. Active Probing Timing

- TSPU probes suspected servers, measures response timing
- Reality fallback to real site introduces measurable latency delta vs direct connection to that site
- HMAC verification may have timing side-channels (not constant-time)

### 3d. Iran Research Confirms

From Iran's censorship research (arXiv):
- Symmetric traffic ratios flag proxies
- Traffic volume thresholds trigger detection
- Low-user servers (1-2 clients) evade; detection triggers at scale

## 4. Active Probing Attacks

TSPU and agents actively connect to suspicious servers:

1. **HTTP GET probe**: Does server return real HTML? Self-signed cert = red flag
2. **Garbage data probe**: VPN servers often drop connection on invalid data (detectable behavior vs real nginx which returns 400)
3. **Version mismatch probe**: Invalid Xray version in session ID -> observe timing differences
4. **Repeated probing**: Build behavioral fingerprint over multiple connections
5. **Certificate chain analysis**: Temporary ed25519 certs vs real CA-signed chains

## 5. ML-Based Classification (Neural Detectors)

### Features Used (~150 per flow)

**Packet-level:**
- Packet size: mean, std, min, max, percentiles (25/50/75/95)
- Packet size distribution: skewness, kurtosis
- Direction-dependent sizes (upstream vs downstream separately)

**Timing:**
- Inter-arrival time (IAT): mean, std, min, max, jitter
- Burst patterns: size, duration, gap between bursts
- Short-term features (STF: 5-10ms windows)
- Long-term features (LTF: 40-1000ms windows)

**Flow-level:**
- Total bytes (up/down/ratio)
- Total packets (up/down/ratio)
- Flow duration
- Bytes/sec, packets/sec
- Packets before first payload
- TCP flags and behaviors (ACK patterns, retransmissions)

**TLS-specific:**
- TLS record size distribution
- Application data records vs handshake records ratio
- Number of round trips in handshake

### Classifier Architectures

| Model | Accuracy | Notes |
|-------|----------|-------|
| Decision Tree (SDN) | 99.81% | Statistical features |
| CNN + Stacked Deep Ensemble | 99.34% | HTTPS classification |
| CS-BiGAN | 99.29% F1 | Detects obfs4 too |
| LSTM+CNN | 98% | VPN detection |
| XGBoost/LightGBM | ~97% | Likely TSPU candidate (fast inference) |

### Key Insight

ML doesn't look for your protocol specifically. It looks for "NOT normal HTTPS". Anything that deviates from the statistical distribution of legitimate web traffic gets flagged.

## 6. Whitelist Regime

Expected future model:
- Only traffic to approved domains/IPs passes
- Custom server IP not in whitelist = blocked regardless of protocol
- **Only bypass**: Route through whitelisted infrastructure (CDN: Cloudflare, Google, Yandex)
- CDN IPs are whitelisted because blocking them = massive collateral damage

## 7. GeoIP and IP Reputation

From RKNHardering:
- Three GeoIP providers vote (ip-api.com, ipapi.is, iplocate.io)
- Flags: hosting=true, proxy=true, foreign country code
- Datacenter ASN = red flag
- "Clean" residential/CDN IP = passes

## 8. Android-Level Detection (from RKNHardering app)

Not relevant for our protocol design, but for completeness:
- TRANSPORT_VPN flag in NetworkCapabilities
- tun0/wg0/ppp0 interface names, MTU < 1500
- DNS through loopback (127.x.x.x)
- Localhost port scanning (1024-65535, 200 concurrent, 80ms timeout)
- SOCKS5/HTTP CONNECT handshake detection
- Xray gRPC API discovery on localhost
- Known VPN app package names (24 apps catalogued)
- Split-tunnel detection (underlying network IP vs VPN IP)
- Cell tower / WiFi geolocation vs GeoIP mismatch

## 9. Verdict Engine Logic

From RKNHardering — shows how multiple weak signals combine:

**Automatic DETECTED**: Split-tunnel, Xray API, VPN gateway leak, location+foreign GeoIP
**Matrix**: Geo + Direct + Indirect signals combined:
- 2+ categories hit = DETECTED
- 1 category = NEEDS_REVIEW or NOT_DETECTED
- Requires corroboration across independent detection categories
