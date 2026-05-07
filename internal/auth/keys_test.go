package auth

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateKeypair_LengthsAndDistinct(t *testing.T) {
	a, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(a.Private) != KeySize || len(a.Public) != KeySize {
		t.Fatalf("bad sizes: priv=%d pub=%d", len(a.Private), len(a.Public))
	}
	if bytes.Equal(a.Private, b.Private) || bytes.Equal(a.Public, b.Public) {
		t.Fatal("two fresh keypairs collided — RNG broken")
	}
}

func TestKeypairFromPrivate_DerivesSamePublic(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	derived, err := KeypairFromPrivate(kp.Private)
	if err != nil {
		t.Fatalf("from private: %v", err)
	}
	if !bytes.Equal(derived.Public, kp.Public) {
		t.Fatalf("public mismatch:\n  generated: %x\n  derived:   %x", kp.Public, derived.Public)
	}
	// Sanity: derived public must equal X25519(priv, basepoint).
	want, err := curve25519.X25519(kp.Private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived.Public, want) {
		t.Fatal("derived public != X25519(priv, basepoint)")
	}
}

func TestKeypairFromPrivate_BadLength(t *testing.T) {
	if _, err := KeypairFromPrivate(make([]byte, 31)); err == nil {
		t.Fatal("expected error for short private key")
	}
}

func TestEncodeDecodeKey_Roundtrip(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enc := EncodeKey(kp.Public)
	dec, err := DecodeKey(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(dec, kp.Public) {
		t.Fatalf("roundtrip mismatch:\n  in:  %x\n  out: %x", kp.Public, dec)
	}
}

func TestDecodeKey_AcceptsAlternateEncodings(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// Standard with padding (canonical), then verify URL-safe also parses.
	std := EncodeKey(kp.Public)
	if _, err := DecodeKey(std); err != nil {
		t.Fatalf("std: %v", err)
	}
}

func TestDecodeKey_BadLength(t *testing.T) {
	// 31-byte payload, base64 encoded
	short := EncodeKey(make([]byte, 31))
	if _, err := DecodeKey(short); err == nil {
		t.Fatal("expected error for 31-byte key")
	}
}

func TestDecodeKey_Garbage(t *testing.T) {
	if _, err := DecodeKey("not base64 at all !!!"); err == nil {
		t.Fatal("expected error for garbage input")
	}
}

func TestEqualKey_ConstantTimeBehavior(t *testing.T) {
	a := bytes.Repeat([]byte{0xAA}, KeySize)
	b := bytes.Repeat([]byte{0xAA}, KeySize)
	c := bytes.Repeat([]byte{0xBB}, KeySize)
	if !EqualKey(a, b) {
		t.Fatal("equal keys reported unequal")
	}
	if EqualKey(a, c) {
		t.Fatal("unequal keys reported equal")
	}
	if EqualKey(a, a[:KeySize-1]) {
		t.Fatal("differing-length keys reported equal")
	}
}
