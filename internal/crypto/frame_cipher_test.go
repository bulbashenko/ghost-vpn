package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bulbashenko/ghost/internal/auth"
)

// pairedSessions runs a real Noise IK handshake in-memory and returns
// (initiatorSession, responderSession) ready for FrameCipher use.
func pairedSessions(t *testing.T) (*auth.Session, *auth.Session) {
	t.Helper()
	clientKP, err := auth.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverKP, err := auth.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := auth.NewResponder(serverKP)
	if err != nil {
		t.Fatal(err)
	}
	init, err := auth.NewInitiator(clientKP, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := init.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.ReadMessage(msg1); err != nil {
		t.Fatal(err)
	}
	msg2, serverSess, err := resp.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, clientSess, err := init.ReadMessage(msg2)
	if err != nil {
		t.Fatal(err)
	}
	return clientSess, serverSess
}

func TestFrameCipher_Roundtrip(t *testing.T) {
	cs, ss := pairedSessions(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))

	client := New(a, cs)
	server := New(b, ss)

	want := []byte("hello ghost")
	go func() { _, _ = client.Write(want) }()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFrameCipher_LargeFrameSplitRead(t *testing.T) {
	cs, ss := pairedSessions(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))

	client := New(a, cs)
	server := New(b, ss)

	payload := make([]byte, 8192)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = client.Write(payload) }()

	// Read in chunks smaller than the frame to exercise readBuf.
	got := make([]byte, 0, len(payload))
	chunk := make([]byte, 512)
	for len(got) < len(payload) {
		n, err := server.Read(chunk)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, chunk[:n]...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestFrameCipher_SequentialFrames(t *testing.T) {
	cs, ss := pairedSessions(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))

	client := New(a, cs)
	server := New(b, ss)

	frames := [][]byte{
		[]byte("frame-1"),
		[]byte("frame-2-longer"),
		[]byte("3"),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, f := range frames {
			if _, err := client.Write(f); err != nil {
				t.Errorf("write: %v", err)
				return
			}
		}
	}()

	for _, want := range frames {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("got %q want %q", got, want)
		}
	}
	wg.Wait()
}

func TestFrameCipher_TamperDetection(t *testing.T) {
	cs, ss := pairedSessions(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))

	client := New(a, cs)
	server := New(b, ss)

	go func() {
		// Write a valid frame then directly inject a tampered second
		// frame on the underlying pipe (after `client` already moved
		// the cipher state forward). We have to write through `a`
		// using New() to keep nonce in sync — simpler: write a junk
		// 16-byte ciphertext and a length prefix.
		_, _ = client.Write([]byte("ok"))
		// Tamper: write 4-byte length then garbage of that length.
		_, _ = a.Write([]byte{0, 0, 0, 16})
		_, _ = a.Write(make([]byte, 16))
	}()

	got := make([]byte, 2)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("got %q", got)
	}
	_, err := server.Read(make([]byte, 16))
	if err == nil {
		t.Fatal("expected decrypt failure on tampered frame")
	}
}
