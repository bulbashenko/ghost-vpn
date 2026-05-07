package auth

import (
	"bytes"
	"testing"

	"github.com/flynn/noise"
)

// fullHandshake runs the IK handshake to completion between freshly generated
// initiator and responder keypairs and returns the resulting two sessions.
// The 0-RTT payloads (initiator and responder) are echoed back as well so
// tests can verify the embedded data path.
func fullHandshake(t *testing.T, initPayload, respPayload []byte) (cliSess, srvSess *Session, srvSawInit []byte, cliSawResp []byte) {
	t.Helper()

	clientKP, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverKP, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	init, err := NewInitiator(clientKP, serverKP.Public)
	if err != nil {
		t.Fatalf("new initiator: %v", err)
	}
	resp, err := NewResponder(serverKP)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}

	msg1, err := init.WriteMessage(initPayload)
	if err != nil {
		t.Fatalf("write msg1: %v", err)
	}
	srvSawInit, err = resp.ReadMessage(msg1)
	if err != nil {
		t.Fatalf("server read msg1: %v", err)
	}
	if !EqualKey(resp.PeerStatic(), clientKP.Public) {
		t.Fatal("server learned wrong client static key from IK handshake")
	}

	msg2, srv, err := resp.WriteMessage(respPayload)
	if err != nil {
		t.Fatalf("write msg2: %v", err)
	}
	cliSawResp, cli, err := init.ReadMessage(msg2)
	if err != nil {
		t.Fatalf("client read msg2: %v", err)
	}
	return cli, srv, srvSawInit, cliSawResp
}

func TestIK_RoundtripHandshakeAndPayloads(t *testing.T) {
	initWant := []byte("hello server, this is the 0-RTT payload")
	respWant := []byte("hello client, here is your session token")

	cli, srv, gotInit, gotResp := fullHandshake(t, initWant, respWant)

	if !bytes.Equal(gotInit, initWant) {
		t.Fatalf("server saw wrong init payload:\n  got:  %q\n  want: %q", gotInit, initWant)
	}
	if !bytes.Equal(gotResp, respWant) {
		t.Fatalf("client saw wrong resp payload:\n  got:  %q\n  want: %q", gotResp, respWant)
	}
	if cli == nil || srv == nil {
		t.Fatal("nil session after successful handshake")
	}
}

func TestIK_NilPayloads(t *testing.T) {
	cli, srv, gotInit, gotResp := fullHandshake(t, nil, nil)
	if len(gotInit) != 0 || len(gotResp) != 0 {
		t.Fatalf("expected empty payloads, got %d/%d", len(gotInit), len(gotResp))
	}
	// Sessions must still work.
	ct, err := cli.Encrypt(nil, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := srv.Decrypt(nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "ping" {
		t.Fatalf("got %q", pt)
	}
}

func TestIK_WrongServerKey_FailsCleanly(t *testing.T) {
	clientKP, _ := GenerateKeypair()
	realServerKP, _ := GenerateKeypair()
	wrongServerKP, _ := GenerateKeypair()

	// Client thinks the server's public key is the wrong one.
	init, err := NewInitiator(clientKP, wrongServerKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	// Real server has the real keypair.
	resp, err := NewResponder(realServerKP)
	if err != nil {
		t.Fatal(err)
	}

	msg1, err := init.WriteMessage([]byte("auth attempt"))
	if err != nil {
		t.Fatal(err)
	}
	// Server attempts to read a message that was encrypted to the wrong key.
	// MUST fail with an error, MUST NOT panic, MUST NOT crash.
	_, err = resp.ReadMessage(msg1)
	if err == nil {
		t.Fatal("server accepted handshake encrypted to wrong key")
	}
	t.Logf("got expected error: %v", err)
}

func TestIK_WrongPrologue_Fails(t *testing.T) {
	// We patch the package prologue temporarily; tests run sequentially
	// inside one package so this is safe.
	orig := HandshakePrologue
	t.Cleanup(func() { HandshakePrologue = orig })

	clientKP, _ := GenerateKeypair()
	serverKP, _ := GenerateKeypair()

	HandshakePrologue = []byte("ghost-v1")
	init, _ := NewInitiator(clientKP, serverKP.Public)
	msg1, err := init.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Now flip the responder to a different prologue.
	HandshakePrologue = []byte("ghost-v9999")
	resp, _ := NewResponder(serverKP)
	if _, err := resp.ReadMessage(msg1); err == nil {
		t.Fatal("server accepted handshake with mismatched prologue")
	}
}

func TestIK_TamperedMsg1_Fails(t *testing.T) {
	clientKP, _ := GenerateKeypair()
	serverKP, _ := GenerateKeypair()

	init, _ := NewInitiator(clientKP, serverKP.Public)
	resp, _ := NewResponder(serverKP)

	msg1, err := init.WriteMessage([]byte("legit"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the payload region (after the ephemeral pubkey).
	msg1[len(msg1)-1] ^= 0x01
	if _, err := resp.ReadMessage(msg1); err == nil {
		t.Fatal("server accepted tampered msg1")
	}
}

func TestIK_TamperedMsg2_Fails(t *testing.T) {
	clientKP, _ := GenerateKeypair()
	serverKP, _ := GenerateKeypair()

	init, _ := NewInitiator(clientKP, serverKP.Public)
	resp, _ := NewResponder(serverKP)

	msg1, _ := init.WriteMessage(nil)
	if _, err := resp.ReadMessage(msg1); err != nil {
		t.Fatal(err)
	}
	msg2, _, err := resp.WriteMessage([]byte("legit response"))
	if err != nil {
		t.Fatal(err)
	}
	msg2[len(msg2)-1] ^= 0x01
	if _, _, err := init.ReadMessage(msg2); err == nil {
		t.Fatal("client accepted tampered msg2")
	}
}

func TestNewInitiator_BadInputs(t *testing.T) {
	good, _ := GenerateKeypair()
	if _, err := NewInitiator(good, make([]byte, 31)); err == nil {
		t.Error("accepted short remote static key")
	}
	if _, err := NewInitiator(good, nil); err == nil {
		t.Error("accepted nil remote static key")
	}
}

func TestNewResponder_BadInputs(t *testing.T) {
	bad := noise.DHKey{Private: make([]byte, 31), Public: make([]byte, 32)}
	if _, err := NewResponder(bad); err == nil {
		t.Error("accepted short private key")
	}
}
