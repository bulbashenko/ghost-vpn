# ML-Based Traffic Classification & Evasion

## State of the Art Detection (2024-2025)

### Top Classifier Performance

| Model | Accuracy/F1 | Target |
|-------|-------------|--------|
| Decision Tree (SDN) | 99.81% | General encrypted traffic |
| CNN + Stacked Ensemble | 99.34% | HTTPS classification |
| CS-BiGAN | 99.29% F1 | obfs4 detection |
| LSTM+CNN | 98% | VPN detection |
| CNN+LSTM | 92% | Skype protocol |
| Real-time P4 switch RF | Line-rate | Programmable hardware |

### Feature Categories Used

**1. Packet-level statistical features**
- Mean, std, skewness, kurtosis of packet sizes
- Direction-separated statistics
- Payload size transitions

**2. Timing features**
- Inter-arrival time (IAT): mean, variance, distribution
- Burst timing: STF (5-10ms), LTF (40-1000ms)
- Flow duration

**3. Protocol behavior**
- TCP flags, ACKs, retransmissions
- Round-trip count
- Connection establishment patterns

**4. Sequential features (for CNN/LSTM)**
- Packet direction sequences
- Packet size sequences
- IAT sequences

## Existing Obfuscation Tools — Why They Fail

### obfs4 (Tor)

**What it does:**
- ntor handshake with Curve25519 + Elligator 2 for key obfuscation
- Handshake padding: client 85-8,128 bytes, server 45-8,096 bytes
- Frame length XOR with SipHash-2-4 mask (OFB mode)
- NaCl secretbox encryption (XSalsa20-Poly1305), max 1,448 byte frames

**Why it's detected:**
- CS-BiGAN achieves 99.29% F1 detection
- IEEE paper: 100% detection accuracy from first packet
- Padding patterns are learned by ML
- Doesn't mimic real application traffic — statistical signatures remain

### Cloak (Shadowsocks plugin)

**What it does:**
- Disguises proxy traffic as HTTPS
- Cryptographic steganography eliminates fingerprints
- Fallback to real website for non-Cloak connections
- Multi-user support, CDN compatibility

**Why it's detected:**
- Viber's Cloak mode: static TLS fingerprints, easily flagged
- HTTPS mimicry is superficial — statistical features diverge
- Modern anti-bot systems: JA3 + HTTP/2 settings + behavior

### Meek (Tor domain fronting)

**What it does:**
- Traffic goes to CDN (Azure/Google historically), Host header redirects to hidden service
- HTTPS to CDN looks legitimate

**Why it's detected/broken:**
- Google, Amazon ended domain fronting
- Only Azure remains
- Timing attacks: CDN latency patterns distinctive
- Single endpoint = enumerable

## What Works (Partially)

### 1. Format-Transforming Encryption (FTE)

- Cryptographically transforms plaintext to match regex of target protocol
- FTEProxy reference implementation
- ~16% bandwidth overhead
- Defeats proprietary DPI; less effective against ML

### 2. Statistical Traffic Mimicry

**Approach**: Capture real traffic (YouTube, streaming) -> learn packet size + IAT distributions -> generate synthetic traffic matching distribution.

**Proposed research**: LSTM-based pluggable transport "mimicry-pt" for Tor.

**Limitations:**
- High latency overhead from traffic shaping
- Mimicry must match cover traffic across ALL features simultaneously
- Defenders can retrain on mimicry output

### 3. Adversarial ML (GANs)

**AdvTraffic**: GAN-generated adversarial perturbations to traffic features
**CS-BiGAN**: Conditional GAN used for both detection AND evasion

**Effectiveness:**
- CGAN-generated evasion: 15% reduction in classifier accuracy
- GAN-based IDS evasion: up to 20% accuracy drop
- Transferable adversarial attacks work across different models

### 4. Cloudflare Workers as Relay

**Architecture:**
```
Client -> Cloudflare Worker (workers.dev or custom domain) -> Origin server
```

**Examples:**
- V-Bridge-Worker: WebSocket reverse proxy for VLESS/VMess/Trojan

**Evasion features:**
- Decoy mode: Direct access returns standard 404
- Custom domains (not *.workers.dev which is detectable)
- CF IP ranges = high collateral damage to block

**Limitations:**
- CF can be compelled to block
- CF adds detectable latency signature
- Repeated connections to same worker stand out behaviorally

## Noise Protocol Framework

Best choice for key exchange layer.

### Patterns

| Pattern | Properties | Use case |
|---------|------------|----------|
| NN | No auth | Anonymous encryption |
| NK | Responder known | Client doesn't authenticate |
| IK | Initiator known to responder | 0-RTT after first message |
| XX | Mutual auth | Both authenticate each other |

**Recommended: IK pattern** — enables 0-RTT encryption, initiator's key authenticates, no round-trip for handshake.

### Cryptographic Building Blocks

- DH: Curve25519 (32 bytes) or Curve448 (56 bytes)
- Ciphers: ChaCha20-Poly1305 or AES-256-GCM
- Hash: SHA-256, SHA-512, BLAKE2s, BLAKE2b

**Recommended**: `Noise_IK_25519_ChaChaPoly_BLAKE2s` (same as WireGuard but embedded differently)

### Embedding in HTTP

1. HTTP Upgrade header to negotiate after TLS
2. Hide in HTTP body (fake Content-Type)
3. WebSocket transport
4. HTTP/2 DATA frames

## Key Design Takeaways

### What NOT to do (lessons from failures)

1. **Don't nest TLS in TLS** — inherent round-trip fingerprint
2. **Don't use symmetric traffic patterns** — biggest tell
3. **Don't hold persistent long connections** — real browsing is bursty
4. **Don't max out TLS record sizes** — real HTTPS records are MTU-bound
5. **Don't use static TLS fingerprints** — randomize or rotate
6. **Don't rely on single detection feature** — ML uses 150+ features

### What TO do

1. **Single unified handshake** — no nested TLS
2. **Statistical mimicry** — learn distribution, sample from it
3. **Asymmetric traffic shaping** — force ~1:5 ratio via download padding
4. **Short sessions** — reconnect periodically like browsing
5. **Variable record sizes** — match real HTTPS distribution (1300-1400 typical)
6. **Constant-time auth** — no timing side-channels
7. **Behavioral consistency** — server behaves identically with/without valid auth
8. **Multi-feature defense** — defeat 150+ feature classifiers, not just JA3
9. **CDN relay for whitelist resistance** — Cloudflare Workers or similar

## Adversarial Robustness Considerations

When designing:
- Assume adversary has full protocol knowledge
- Assume adversary can retrain on our traffic
- Assume adversary uses ensemble of classifiers
- Design should approach information-theoretic indistinguishability from real HTTPS
- Test against actual ML classifiers, not just DPI signatures
