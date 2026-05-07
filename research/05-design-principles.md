# Protocol Design Principles

These are the foundational principles that guide all decisions in protocol design. When in doubt, refer back to these.

## Principle 1: Statistical Indistinguishability, Not Handshake Mimicry

Reality's mistake was focusing on making the *handshake* look real. Modern ML classifiers analyze the *entire flow*. Our protocol must be statistically indistinguishable from real HTTPS across all 150+ ML features, not just JA3 fingerprint.

**Implication**: Traffic shaping layer is mandatory, not optional.

## Principle 2: Single-Layer TLS Only

Nested TLS (TLS-in-TLS) creates inherent round-trip patterns that cannot be hidden. Our protocol uses ONE TLS layer.

**Implication**: Inner tunnel is plain binary framed over a single TLS stream. No inner TLS handshake.

## Principle 3: Behavioral Consistency Under Probing

A server that behaves differently for valid vs invalid clients is detectable. Our server must respond IDENTICALLY to:
- Valid authenticated client (after auth verification)
- Invalid client with wrong credentials
- Random garbage
- Real HTTP browser
- Empty connection

**Implication**: Authentication must happen AFTER server has committed to a response pattern. Invalid clients get served the real website. Valid clients get served the tunnel — but from the outside it looks like the same request-response pattern.

## Principle 4: Constant-Time Everything Security-Sensitive

Timing side-channels defeat Reality. All authentication-related code must be constant-time:
- Key comparison
- HMAC verification
- Version checking
- ShortId matching
- Timestamp validation

**Implication**: Use `crypto/subtle` package for all comparisons. No early-exit on auth failures.

## Principle 5: Asymmetric Traffic by Design

Real HTTPS is heavily asymmetric (download >> upload). Symmetric tunnel traffic is the #1 flow-level tell for proxies.

**Implication**: Traffic shaper forces asymmetric ratio via download-direction padding. Even if user is uploading, the flow ratio looks like downloading.

## Principle 6: Short Sessions, Not Persistent Tunnels

Real browsing: connection opens, burst of requests, connection closes. Typical HTTPS connection lifetime: seconds to minutes.

VPN tunnels: single connection for hours.

**Implication**: Connection lifecycle manager periodically rotates connections. Client maintains pool of short-lived connections, migrates streams between them.

## Principle 7: Defense in Depth

No single technique survives. Combine:
- Cryptographic hiding (Noise Protocol)
- Protocol camouflage (uTLS + real HTTP)
- Statistical mimicry (traffic shaper)
- Active probing resistance (fallback server)
- Infrastructure diversity (CDN relay option)

**Implication**: Protocol stack has 5 independent layers, each providing different protection.

## Principle 8: Realistic Over Random

"Random" traffic is detectable as "not like anything real". Mimicry must be based on REAL captured traffic distributions, not random noise.

**Implication**: Traffic shaper uses empirical distributions from captured pcaps of target cover protocol (e.g., YouTube streaming, VK browsing).

## Principle 9: Adversary Retraining Must Fail

Assume adversary will collect samples of our traffic and retrain their classifier. Our protocol must remain indistinguishable even after retraining.

**Implication**: Randomness per-session in shaping parameters. Different clients have different shaping profiles. Approach information-theoretic indistinguishability — not just "look different enough to current classifier".

## Principle 10: Whitelist-Ready Architecture

The protocol design must support routing through whitelisted CDN infrastructure from day one. Not as an afterthought.

**Implication**: Transport layer is abstracted. Direct-TCP and CDN-WebSocket are both first-class transport modes.

## Principle 11: KISS for Cryptography

Don't invent crypto. Use well-audited primitives:
- Noise Protocol Framework (IK pattern)
- ChaCha20-Poly1305 or AES-256-GCM
- Curve25519
- BLAKE2s or SHA-256

**Implication**: No custom ciphers, no novel key exchange. Composition of standard primitives only.

## Principle 12: Testability Against Real Detectors

Design must be testable against actual ML classifiers and real DPI systems during development.

**Implication**: Build test harness early. Train a classifier on our traffic + real HTTPS, measure detection rate iteratively.

## Priority Order When Trade-offs Arise

When principles conflict, resolve in this order:

1. **Security** (cryptographic correctness) — never compromise
2. **Detection resistance** (AD1-AD9 requirements) — primary goal
3. **Behavioral indistinguishability** — the "why" of the project
4. **Performance** — only after detection resistance is solid
5. **Simplicity** — helps audit but secondary to correctness
6. **Features** — last priority, add after core works
