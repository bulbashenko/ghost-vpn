# Research Index

Background research gathered during protocol design (2026-04-09 / 2026-04-10). This context informed the architecture decisions that are now implemented and validated.

**Current status:** Protocol implemented and live. See [docs/](../docs/) for implementation docs and [ROADMAP.md](../ROADMAP.md) for what's next.

---

## Files

| File | Purpose |
|------|---------|
| `01-rkn-detection-methods.md` | How RKN/ТСПУ detects VPNs: signatures, ML, active probing |
| `02-xtls-reality-analysis.md` | Why VLESS+Reality is detectable (>70% TPR per USENIX 2024) |
| `03-ml-classifiers-and-evasion.md` | ML classifier state of the art and evasion strategies |
| `04-protocol-requirements.md` | Threat model + functional and security requirements |
| `05-design-principles.md` | 12 core design principles |
| `06-proposed-architecture.md` | Original 5-layer architecture proposal |
| `07-tech-stack.md` | Go dependencies and project structure |

---

## Key findings that drove the design

**Why Reality fails:**
- Nested TLS handshake is detectable (USENIX Security 2024, >70% true-positive rate at <0.1% false-positive)
- Symmetric traffic ratio (~1:1) vs real HTTPS (~1:10)
- Long session duration vs short browser connections
- Uniform TLS record sizes

**What ML classifiers look at:**
- 150+ flow features: packet sizes, inter-arrival times, burst patterns, byte ratios, session duration
- Not looking for a specific signature — looking for "not normal HTTPS"
- Best published results: 99.81% accuracy (Decision Tree), 99.29% F1 (CS-BiGAN vs obfs4)

**Design conclusions:**
1. Single TLS only — no nested handshakes
2. Statistical mimicry of real HTTPS browsing — not just JA3 matching
3. Forced asymmetric byte ratio (1:5 to 1:15 via padding)
4. Short sessions with connection rotation
5. Noise IK handshake hidden in HTTP/2 POST body
6. Constant-time authentication (no timing leaks)
7. Reverse proxy fallback for active probing resistance
8. CDN relay as IP-whitelist countermeasure (v0.3)

---

## Architecture decisions that were confirmed correct

| Decision | Validation |
|----------|-----------|
| uTLS Chrome fingerprint | Chrome 133 JA4 matches real Chrome exactly after clean build |
| HTTP/2 POST as tunnel carrier | Indistinguishable from real API calls (XHR, WebSocket upgrade) |
| Noise IK in POST body | Works; active probe returns identical response to real site |
| Connection rotation | 16–42s sessions match Slack/Telegram Web patterns |
| Write coalescer | Packet size distribution: 99.3% tiny → 85.8% MTU-sized |
| Reverse proxy fallback | Active probe response byte-identical to nginx.org |

---

## Architecture decisions still to validate

| Decision | Status |
|----------|--------|
| CDN relay for whitelist bypass | `front_host` field implemented; Cloudflare deployment pending |
| Multi-stream HTTP/2 | Not implemented |
| Statistical IAT shaping (not just MTU padding) | Profile data exists; coalescer uses uniform range |
| Real ECH | Requires CDN; placeholder ECH in ClientHello only |
