package auth

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSession_RoundtripBidirectional(t *testing.T) {
	cli, srv, _, _ := fullHandshake(t, nil, nil)

	// client -> server
	for i := 0; i < 100; i++ {
		pt := make([]byte, 64+i)
		_, _ = rand.Read(pt)
		ad := []byte{0x01, byte(i)}
		ct, err := cli.Encrypt(ad, pt)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := srv.Decrypt(ad, ct)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("frame %d: roundtrip mismatch", i)
		}
	}

	// server -> client
	for i := 0; i < 100; i++ {
		pt := make([]byte, 32+i*2)
		_, _ = rand.Read(pt)
		ct, err := srv.Encrypt(nil, pt)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := cli.Decrypt(nil, ct)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("frame %d: roundtrip mismatch", i)
		}
	}
}

func TestSession_NonceAdvances(t *testing.T) {
	cli, srv, _, _ := fullHandshake(t, nil, nil)
	if cli.SendNonce() != 0 || srv.RecvNonce() != 0 {
		t.Fatalf("expected fresh nonces, got cli.send=%d srv.recv=%d", cli.SendNonce(), srv.RecvNonce())
	}
	ct, err := cli.Encrypt(nil, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if cli.SendNonce() != 1 {
		t.Fatalf("send nonce did not advance: %d", cli.SendNonce())
	}
	if _, err := srv.Decrypt(nil, ct); err != nil {
		t.Fatal(err)
	}
	if srv.RecvNonce() != 1 {
		t.Fatalf("recv nonce did not advance: %d", srv.RecvNonce())
	}
}

func TestSession_ReplayDetected(t *testing.T) {
	cli, srv, _, _ := fullHandshake(t, nil, nil)

	// First valid message succeeds.
	ct, err := cli.Encrypt(nil, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Decrypt(nil, ct); err != nil {
		t.Fatal(err)
	}

	// Replaying the SAME ciphertext must fail: server's recv nonce has
	// already advanced past the one that ct was sealed under.
	if _, err := srv.Decrypt(nil, ct); err == nil {
		t.Fatal("server accepted a replayed ciphertext")
	}

	// flynn/noise advances the recv nonce only on successful decrypt, so
	// the failed replay above did NOT desync the session: a fresh, in-order
	// message must still decrypt cleanly.
	ct2, err := cli.Encrypt(nil, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := srv.Decrypt(nil, ct2)
	if err != nil {
		t.Fatalf("session became unusable after replay attempt: %v", err)
	}
	if string(pt2) != "second" {
		t.Fatalf("got %q", pt2)
	}
}

func TestSession_TamperedCiphertextRejected(t *testing.T) {
	cli, srv, _, _ := fullHandshake(t, nil, nil)
	ct, err := cli.Encrypt(nil, []byte("important data"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0x80
	if _, err := srv.Decrypt(nil, ct); err == nil {
		t.Fatal("server accepted tampered ciphertext")
	}
}

func TestSession_AssociatedDataMustMatch(t *testing.T) {
	cli, srv, _, _ := fullHandshake(t, nil, nil)
	ct, err := cli.Encrypt([]byte("ad-A"), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Decrypt([]byte("ad-B"), ct); err == nil {
		t.Fatal("decrypt succeeded with wrong AD")
	}
}

func TestSession_NilSessionReturnsError(t *testing.T) {
	var s *Session
	if _, err := s.Encrypt(nil, []byte("x")); err == nil {
		t.Error("nil session accepted Encrypt")
	}
	if _, err := s.Decrypt(nil, []byte("x")); err == nil {
		t.Error("nil session accepted Decrypt")
	}
}
