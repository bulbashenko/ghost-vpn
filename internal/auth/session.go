package auth

import (
	"errors"
	"fmt"

	"github.com/flynn/noise"
)

// Session is the post-handshake symmetric state for one tunnel: a pair of
// ChaCha20-Poly1305 cipher states derived from the Noise IK handshake.
//
// Encrypt uses the send cipher; Decrypt uses the recv cipher. Each direction's
// nonce is managed by the underlying Noise CipherState (sequential, starting
// at 0). Reordering messages within a direction is not supported in v1 — the
// transport (TCP+TLS+HTTP/2) guarantees in-order delivery, so any out-of-order
// arrival or replay manifests as a decryption failure, which is exactly the
// behavior we want.
//
// For v2 (stream migration over multiple connections, possibly UDP) the
// ReplayWindow type in this package can be wired into Session to allow
// out-of-order delivery within a 64-nonce window.
type Session struct {
	send *noise.CipherState
	recv *noise.CipherState
}

func newSession(send, recv *noise.CipherState) *Session {
	return &Session{send: send, recv: recv}
}

// Encrypt seals plaintext with the send cipher. ad is associated data
// (typically the L4 frame header — Version|Type|StreamID|Length). The returned
// slice is freshly allocated and contains ciphertext || tag.
func (s *Session) Encrypt(ad, plaintext []byte) ([]byte, error) {
	if s == nil || s.send == nil {
		return nil, errors.New("auth: session not initialized")
	}
	out, err := s.send.Encrypt(nil, ad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("auth: session encrypt: %w", err)
	}
	return out, nil
}

// Decrypt opens ciphertext with the recv cipher. ad must match what was
// passed to Encrypt on the peer. Returns an error on any AEAD failure;
// nonce sequencing is automatic.
func (s *Session) Decrypt(ad, ciphertext []byte) ([]byte, error) {
	if s == nil || s.recv == nil {
		return nil, errors.New("auth: session not initialized")
	}
	out, err := s.recv.Decrypt(nil, ad, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("auth: session decrypt: %w", err)
	}
	return out, nil
}

// SendNonce returns the next nonce that will be used by the send cipher.
// Useful for diagnostics and triggering rekey before the 2^64-1 limit.
func (s *Session) SendNonce() uint64 {
	if s == nil || s.send == nil {
		return 0
	}
	return s.send.Nonce()
}

// RecvNonce returns the next nonce expected by the recv cipher.
func (s *Session) RecvNonce() uint64 {
	if s == nil || s.recv == nil {
		return 0
	}
	return s.recv.Nonce()
}
