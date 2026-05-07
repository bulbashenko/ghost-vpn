// Package crypto provides per-frame AEAD encryption built on top of an
// auth.Session derived from the Noise IK handshake. It wraps the
// underlying io.ReadWriteCloser (typically the L2 tunnel byte stream)
// with a length-prefixed sealed-frame format so that everything above
// it — the L4 mux, the L5 shaper, application data — is authenticated
// and confidential end-to-end, independent of the surrounding TLS
// layer.
//
// Wire format per sealed frame:
//
//	[uint32 BE length][ciphertext || tag]
//
// length covers the ciphertext+tag bytes. Each call to Write produces
// exactly one sealed frame; each call to Read returns the plaintext of
// exactly one sealed frame (truncated to fit the caller's buffer with
// any leftover queued for the next Read). Nonces are sequential and
// managed by the Noise CipherState — there is no nonce on the wire.
package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/bulbashenko/ghost/internal/auth"
)

// MaxSealedPayload caps a single sealed frame's plaintext size. With the
// Poly1305 tag (16 B) and the 4-byte length prefix, the on-wire frame
// stays under 64 KiB which fits comfortably inside one TLS record.
const MaxSealedPayload = 60 * 1024

// FrameCipher wraps an io.ReadWriteCloser, sealing each Write call with
// the auth.Session.Encrypt and opening each Read call with Decrypt.
//
// Concurrency: a single FrameCipher allows one concurrent reader and
// one concurrent writer (matching the standard io.ReadWriteCloser
// contract). Multiple writers serialize via writeMu so the length
// prefix and ciphertext stay paired on the wire.
type FrameCipher struct {
	inner   io.ReadWriteCloser
	session *auth.Session

	writeMu sync.Mutex

	// Read state — single reader, no mutex needed.
	readBuf []byte // leftover plaintext from the most recent sealed frame
}

// New wraps inner with sealed framing using session for both directions.
// The caller is responsible for ensuring that the same session is paired
// across the two endpoints (initiator's send cipher == responder's recv
// cipher and vice versa — this is handled inside auth.NewInitiator /
// NewResponder).
func New(inner io.ReadWriteCloser, session *auth.Session) *FrameCipher {
	return &FrameCipher{inner: inner, session: session}
}

// Write seals p into a single sealed frame and writes it to the inner
// stream. Returns len(p) on success — the ciphertext expansion is
// invisible to the caller.
func (c *FrameCipher) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > MaxSealedPayload {
		return 0, fmt.Errorf("crypto: write %d > MaxSealedPayload %d", len(p), MaxSealedPayload)
	}

	ciphertext, err := c.session.Encrypt(nil, p)
	if err != nil {
		return 0, err
	}

	// Prepend the 4-byte length header to the ciphertext in a single
	// buffer so that inner.Write is called once. Two separate writes would
	// produce two io.Pipe operations (two goroutine wakeups, two HTTP/2
	// DATA frames) for what is logically one sealed frame.
	frame := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(ciphertext)))
	copy(frame[4:], ciphertext)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if _, err := c.inner.Write(frame); err != nil {
		return 0, fmt.Errorf("crypto: write frame: %w", err)
	}
	return len(p), nil
}

// Read returns plaintext from the inner stream, decrypting one sealed
// frame at a time. Frames larger than len(p) are buffered and returned
// across multiple Read calls.
func (c *FrameCipher) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	var hdr [4]byte
	if _, err := io.ReadFull(c.inner, hdr[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length == 0 {
		return 0, errors.New("crypto: zero-length sealed frame")
	}
	if length > MaxSealedPayload+64 { // +tag + small headroom
		return 0, fmt.Errorf("crypto: sealed frame length %d exceeds limit", length)
	}

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(c.inner, ciphertext); err != nil {
		return 0, fmt.Errorf("crypto: read ciphertext: %w", err)
	}

	plaintext, err := c.session.Decrypt(nil, ciphertext)
	if err != nil {
		return 0, err
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.readBuf = plaintext[n:]
	}
	return n, nil
}

// Close closes the inner stream.
func (c *FrameCipher) Close() error {
	return c.inner.Close()
}
