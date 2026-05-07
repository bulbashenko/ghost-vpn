# Protocol Requirements & Threat Model

## Project Goal

Design and implement a custom VPN protocol that:
1. Cannot be detected by current RKN/TSPU signature-based DPI
2. Cannot be detected by ML-based flow classifiers (current or next-gen)
3. Survives active probing from TSPU
4. Works under potential whitelist regime (route via CDN)
5. Better than VLESS+Reality in all weaknesses identified

## Threat Model

### Adversary Capabilities

1. **Passive traffic monitoring** (TSPU at ISP level)
   - Full packet capture
   - Flow-level feature extraction
   - ML classification in real-time
   - Long-term traffic statistics per flow

2. **Active probing**
   - Connect to suspected servers
   - Send crafted probes (valid TLS, garbage, version variations)
   - Measure response timing
   - Multi-probe behavioral analysis

3. **IP/Domain blacklisting**
   - Block known VPN server IPs
   - Block suspicious ASNs (hosting, datacenter)
   - Dynamic blacklisting based on ML verdict

4. **Whitelist regime** (future)
   - Only allowed destinations pass
   - Must tunnel through whitelisted CDN

5. **Certificate analysis**
   - CA chain inspection
   - Self-signed = flag
   - Temporary cert = flag

6. **Protocol version detection**
   - Known VPN protocol signatures
   - Entropy analysis for raw encrypted traffic

### Adversary Limitations

1. Cannot break strong cryptography (ChaCha20, Curve25519, AES-GCM)
2. Cannot block entire CDNs (Cloudflare, etc.) without massive collateral damage
3. Cannot perform per-packet deep analysis at line-rate for ALL traffic (only flagged flows)
4. Cannot compel foreign CDN providers to reveal all Worker code
5. Limited ML training data — retraining takes time

## Protocol Requirements

### Functional

- **F1**: TCP-based transport (UDP flagged more aggressively by TSPU)
- **F2**: Tunnel arbitrary IP traffic (full VPN, not just proxy)
- **F3**: Multi-client support per server
- **F4**: Client and server in Go (uTLS, ecosystem)
- **F5**: Optional CDN relay mode (Cloudflare Workers)
- **F6**: Fallback to real website on invalid auth
- **F7**: Configurable via simple config file

### Security

- **S1**: Forward secrecy (ephemeral keys per session)
- **S2**: Authenticated encryption (Noise Protocol)
- **S3**: Replay protection
- **S4**: Constant-time authentication (no timing side-channels)
- **S5**: Server identity authentication (client verifies server)
- **S6**: Client authentication (server verifies client — prevents unauthorized use)

### Anti-Detection

- **AD1**: TLS 1.3 with randomized browser fingerprint (uTLS)
- **AD2**: No nested TLS (single handshake)
- **AD3**: Statistical traffic mimicry (packet sizes, IATs match real HTTPS)
- **AD4**: Asymmetric traffic ratio (force 1:5 download:upload via padding)
- **AD5**: Short session model (reconnect periodically)
- **AD6**: Variable TLS record sizes (1300-1400 typical, not 16KB)
- **AD7**: Active probing resistance (indistinguishable from real nginx fallback)
- **AD8**: Constant-time operations for all auth-related code
- **AD9**: Behavioral consistency (server looks identical to real website under any probe)

### Performance

- **P1**: Throughput: target >50 Mbps on commodity hardware
- **P2**: Latency: <50ms added by protocol overhead
- **P3**: Connection establishment: <500ms including handshake
- **P4**: Memory per connection: <10MB
- **P5**: CPU overhead: <20% single core under load

## Out of Scope (for v1)

- Mobile clients (Android/iOS) — will follow after core protocol stable
- GUI applications
- Kernel-level implementation
- Multi-hop routing
- Onion routing style obfuscation
- P2P discovery (like Snowflake)

## Success Criteria

The protocol is successful if:

1. **Survives signature DPI**: Not detected by Suricata/Snort with VPN rules
2. **Survives ML detection**: <5% TPR from trained classifier (CNN on flow features) while maintaining >99% specificity on real HTTPS
3. **Survives active probing**: Server responds identically to valid/invalid/probing connections — no behavioral differences detectable in 1000 probes
4. **Works in RF**: Real-world test through Russian ISP — sustained connection for 24+ hours without blocking
5. **Performance targets met**: All P1-P5 metrics achieved

## Non-Goals

- "Unbreakable" — no such thing exists
- Zero latency — traffic shaping adds overhead
- Compatibility with existing VPN protocols
- Open relay / public service model (private use, small user count)
