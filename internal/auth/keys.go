// Package auth implements GHOST's L3 authentication: Noise IK handshake,
// session ciphers, and key management.
//
// All comparisons of secret-derived material in this package use crypto/subtle
// to avoid timing side channels (Principle 4 in research/05-design-principles.md).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// KeySize is the byte length of a Curve25519 public or private key.
const KeySize = 32

// GenerateKeypair returns a fresh Curve25519 keypair drawn from crypto/rand.
func GenerateKeypair() (noise.DHKey, error) {
	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("auth: generate keypair: %w", err)
	}
	return kp, nil
}

// KeypairFromPrivate reconstructs a keypair from a 32-byte Curve25519 private
// key by deriving the matching public key. The returned struct holds copies of
// the input bytes so callers may safely zero their own buffers afterwards.
func KeypairFromPrivate(priv []byte) (noise.DHKey, error) {
	if len(priv) != KeySize {
		return noise.DHKey{}, fmt.Errorf("auth: private key length %d != %d", len(priv), KeySize)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("auth: derive public key: %w", err)
	}
	p := make([]byte, KeySize)
	copy(p, priv)
	return noise.DHKey{Private: p, Public: pub}, nil
}

// EncodeKey returns the standard base64 (with padding) encoding of a key,
// matching WireGuard's textual key format.
func EncodeKey(k []byte) string {
	return base64.StdEncoding.EncodeToString(k)
}

// DecodeKey parses a base64-encoded 32-byte Curve25519 key. It accepts both
// standard and URL-safe encodings, with or without padding.
func DecodeKey(s string) ([]byte, error) {
	encs := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var (
		b   []byte
		err error
	)
	for _, enc := range encs {
		b, err = enc.DecodeString(s)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("auth: decode key: %w", err)
	}
	if len(b) != KeySize {
		return nil, fmt.Errorf("auth: key has wrong length: got %d, want %d", len(b), KeySize)
	}
	return b, nil
}

// EqualKey reports whether two keys are byte-equal in constant time.
// Inputs of differing length compare unequal in constant time as well.
func EqualKey(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
