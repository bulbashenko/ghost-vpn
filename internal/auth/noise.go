package auth

import (
	"errors"
	"fmt"

	"github.com/flynn/noise"
)

// CipherSuite is the GHOST L3 Noise cipher suite:
//
//	Noise_IK_25519_ChaChaPoly_BLAKE2s
//
// Curve25519 for DH, ChaCha20-Poly1305 AEAD, BLAKE2s hash. This is the same
// suite WireGuard uses for its primitives, with a different handshake pattern
// (IK gives us 0-RTT initiator authentication, suitable for embedding in a
// single HTTP/2 request body — see docs/protocol.md §L3).
var CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// HandshakePrologue is mixed into the Noise handshake hash on both sides.
// It binds the handshake to the protocol version and rejects clients that
// disagree on the wire format. Bumped on any breaking change.
//
// The byte 0x01 here matches version.Protocol.
var HandshakePrologue = []byte("ghost-v1")

// Initiator drives the client side of the IK handshake.
//
//	-> e, es, s, ss            (msg1, written by initiator)
//	<- e, ee, se               (msg2, read by initiator)
//
// After ReadMessage succeeds the handshake state may be discarded; the
// returned *Session holds the derived send/recv ciphers.
type Initiator struct {
	hs *noise.HandshakeState
}

// NewInitiator creates an IK initiator. local is the client's static keypair
// (sent encrypted to the server inside msg1). remoteStatic is the server's
// static public key, learned out of band (config file, like WireGuard).
func NewInitiator(local noise.DHKey, remoteStatic []byte) (*Initiator, error) {
	if len(remoteStatic) != KeySize {
		return nil, fmt.Errorf("auth: remote static key length %d != %d", len(remoteStatic), KeySize)
	}
	if len(local.Private) != KeySize || len(local.Public) != KeySize {
		return nil, errors.New("auth: local static keypair must be 32-byte Curve25519")
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   CipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      HandshakePrologue,
		StaticKeypair: local,
		PeerStatic:    remoteStatic,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: new initiator: %w", err)
	}
	return &Initiator{hs: hs}, nil
}

// WriteMessage builds the first IK handshake message and returns the wire bytes.
// payload may be nil; any bytes provided are encrypted and authenticated as
// part of the handshake (0-RTT data).
func (i *Initiator) WriteMessage(payload []byte) ([]byte, error) {
	out, _, _, err := i.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("auth: write IK msg1: %w", err)
	}
	return out, nil
}

// ReadMessage processes the responder's reply (msg2). On success, returns the
// decrypted server payload (may be empty) and a Session ready for tunnel data.
//
// On any verification failure (wrong key, tampered ciphertext, malformed) it
// returns an error. Callers MUST NOT branch on the error in a way that leaks
// timing — the L2 layer's response is to fall through to the fallback path,
// which happens regardless of error type.
func (i *Initiator) ReadMessage(msg []byte) ([]byte, *Session, error) {
	// Per Noise spec §5.3 Split(): the first returned CipherState is used by
	// the initiator to encrypt and the responder to decrypt; the second is
	// used by the responder to encrypt and the initiator to decrypt.
	payload, csInitSend, csInitRecv, err := i.hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: read IK msg2: %w", err)
	}
	if csInitSend == nil || csInitRecv == nil {
		return nil, nil, errors.New("auth: handshake incomplete after IK msg2")
	}
	return payload, newSession(csInitSend, csInitRecv), nil
}

// Responder drives the server side of the IK handshake.
type Responder struct {
	hs *noise.HandshakeState
}

// NewResponder creates an IK responder. local is the server's static keypair.
func NewResponder(local noise.DHKey) (*Responder, error) {
	if len(local.Private) != KeySize || len(local.Public) != KeySize {
		return nil, errors.New("auth: local static keypair must be 32-byte Curve25519")
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   CipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      HandshakePrologue,
		StaticKeypair: local,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: new responder: %w", err)
	}
	return &Responder{hs: hs}, nil
}

// ReadMessage processes the initiator's first message (msg1). On success the
// initiator's static public key is recoverable via PeerStatic.
//
// IMPORTANT: An error here means the client is unauthenticated. The L2 layer
// must respond by reverse-proxying to the fallback target — and it must do so
// on the SAME code path that valid auth would take, modulo the actual response
// bytes, to preserve constant-time behavior. See Principle 3 + 4.
func (r *Responder) ReadMessage(msg []byte) ([]byte, error) {
	payload, _, _, err := r.hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, fmt.Errorf("auth: read IK msg1: %w", err)
	}
	return payload, nil
}

// WriteMessage builds the responder's reply (msg2) and finalizes the handshake.
// Returns the wire bytes plus a Session ready for tunnel data.
func (r *Responder) WriteMessage(payload []byte) ([]byte, *Session, error) {
	// Same Noise convention: cs1 = initiator-send / responder-recv,
	// cs2 = responder-send / initiator-recv.
	out, csInitSend, csInitRecv, err := r.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: write IK msg2: %w", err)
	}
	if csInitSend == nil || csInitRecv == nil {
		return nil, nil, errors.New("auth: handshake incomplete after IK msg2")
	}
	// From responder's perspective: send=csInitRecv, recv=csInitSend.
	return out, newSession(csInitRecv, csInitSend), nil
}

// PeerStatic returns the client's static public key, valid only after a
// successful ReadMessage. Use EqualKey to compare against an allow-list.
func (r *Responder) PeerStatic() []byte {
	return r.hs.PeerStatic()
}
