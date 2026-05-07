package mux

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// netPipe returns a pair of connected net.Conns for testing.
func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// --- Codec tests ---

func TestCodec_RoundtripFrame(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	dec := NewDecoder(&buf)

	original := &Frame{
		Version:  ProtocolVersion,
		Type:     TypeData,
		StreamID: 42,
		Payload:  []byte("hello ghost mux"),
	}

	if err := enc.WriteFrame(original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := dec.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Version != original.Version {
		t.Errorf("version=%d, want %d", got.Version, original.Version)
	}
	if got.Type != original.Type {
		t.Errorf("type=%v, want %v", got.Type, original.Type)
	}
	if got.StreamID != original.StreamID {
		t.Errorf("streamID=%d, want %d", got.StreamID, original.StreamID)
	}
	if !bytes.Equal(got.Payload, original.Payload) {
		t.Errorf("payload=%q, want %q", got.Payload, original.Payload)
	}
}

func TestCodec_EmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	dec := NewDecoder(&buf)

	if err := enc.WriteFrame(&Frame{
		Version:  ProtocolVersion,
		Type:     TypeStreamOpen,
		StreamID: 1,
	}); err != nil {
		t.Fatal(err)
	}

	f, err := dec.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeStreamOpen || f.StreamID != 1 || len(f.Payload) != 0 {
		t.Fatalf("unexpected: %+v", f)
	}
}

func TestCodec_AllFrameTypes(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	dec := NewDecoder(&buf)

	types := []FrameType{
		TypeData, TypeWindowUpdate, TypeStreamOpen,
		TypeStreamClose, TypePing, TypePadding,
	}

	for _, ft := range types {
		err := enc.WriteFrame(&Frame{
			Version:  ProtocolVersion,
			Type:     ft,
			StreamID: 0,
			Payload:  []byte{0x01, 0x02},
		})
		if err != nil {
			t.Fatalf("write %v: %v", ft, err)
		}
	}

	for _, ft := range types {
		f, err := dec.ReadFrame()
		if err != nil {
			t.Fatalf("read %v: %v", ft, err)
		}
		if f.Type != ft {
			t.Fatalf("type=%v, want %v", f.Type, ft)
		}
	}
}

func TestCodec_WireSize(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	payload := make([]byte, 100)
	enc.WriteFrame(&Frame{
		Version:  ProtocolVersion,
		Type:     TypeData,
		StreamID: 1,
		Payload:  payload,
	})

	if buf.Len() != HeaderSize+100 {
		t.Fatalf("wire size=%d, want %d", buf.Len(), HeaderSize+100)
	}
}

func TestCodec_BadVersion(t *testing.T) {
	// Manually craft a frame with bad version.
	var buf bytes.Buffer
	buf.Write([]byte{
		0xFF,       // bad version
		0x00,       // DATA
		0, 0, 0, 1, // streamID=1
		0, 0, // length=0
	})

	dec := NewDecoder(&buf)
	_, err := dec.ReadFrame()
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestCodec_PayloadTooLarge(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	err := enc.WriteFrame(&Frame{
		Version:  ProtocolVersion,
		Type:     TypeData,
		StreamID: 1,
		Payload:  make([]byte, MaxPayload+1),
	})
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestFrameType_String(t *testing.T) {
	if TypeData.String() != "DATA" {
		t.Fatalf("got %q", TypeData.String())
	}
	if TypePing.String() != "PING" {
		t.Fatalf("got %q", TypePing.String())
	}
	if FrameType(0xFF).String() != "UNKNOWN" {
		t.Fatalf("got %q", FrameType(0xFF).String())
	}
}

// --- Conn + Stream tests ---

func TestConn_OpenStreamAndEcho(t *testing.T) {
	a, b := netPipe(t)

	var serverStream *Stream
	streamReady := make(chan struct{})

	// Server side.
	server := NewConn(b, false, func(s *Stream) {
		serverStream = s
		close(streamReady)
		// Echo loop.
		io.Copy(s, s)
	})
	defer server.Close()

	// Client side.
	client := NewConn(a, true, nil)
	defer client.Close()

	s, err := client.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// Wait for server to see the stream.
	select {
	case <-streamReady:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server stream")
	}

	_ = serverStream // used in echo goroutine

	msg := []byte("hello from client")
	if _, err := s.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: %q vs %q", buf, msg)
	}
}

func TestConn_MultipleStreams(t *testing.T) {
	a, b := netPipe(t)

	// Server echoes on each stream.
	server := NewConn(b, false, func(s *Stream) {
		io.Copy(s, s)
	})
	defer server.Close()

	client := NewConn(a, true, nil)
	defer client.Close()

	const numStreams = 5
	var wg sync.WaitGroup

	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s, err := client.OpenStream()
			if err != nil {
				t.Errorf("stream %d: open: %v", idx, err)
				return
			}

			msg := make([]byte, 256)
			rand.Read(msg)

			if _, err := s.Write(msg); err != nil {
				t.Errorf("stream %d: write: %v", idx, err)
				return
			}

			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(s, buf); err != nil {
				t.Errorf("stream %d: read: %v", idx, err)
				return
			}

			if !bytes.Equal(buf, msg) {
				t.Errorf("stream %d: mismatch", idx)
			}
		}(i)
	}

	wg.Wait()
}

func TestConn_StreamClose(t *testing.T) {
	a, b := netPipe(t)

	server := NewConn(b, false, func(s *Stream) {
		// Read until EOF.
		io.ReadAll(s)
	})
	defer server.Close()

	client := NewConn(a, true, nil)
	defer client.Close()

	s, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	s.Write([]byte("data"))
	s.Close()

	// Write after close should fail.
	_, err = s.Write([]byte("more"))
	if err != ErrStreamClosed {
		t.Fatalf("expected ErrStreamClosed, got %v", err)
	}
}

func TestConn_Ping(t *testing.T) {
	a, b := netPipe(t)

	server := NewConn(b, false, nil)
	defer server.Close()

	client := NewConn(a, true, nil)
	defer client.Close()

	// Ping should succeed (server auto-echoes).
	if err := client.SendPing(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Give the readLoop time to process.
	time.Sleep(50 * time.Millisecond)
}

func TestConn_Padding(t *testing.T) {
	a, b := netPipe(t)

	server := NewConn(b, false, nil)
	defer server.Close()

	client := NewConn(a, true, nil)
	defer client.Close()

	// Padding should be silently consumed.
	if err := client.SendPadding(1024); err != nil {
		t.Fatalf("padding: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
}

func TestConn_LargeTransfer(t *testing.T) {
	a, b := netPipe(t)

	const size = 1 << 20 // 1MB

	server := NewConn(b, false, func(s *Stream) {
		io.Copy(s, s) // echo
	})
	defer server.Close()

	client := NewConn(a, true, nil)
	defer client.Close()

	s, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	// Generate random data and track hash.
	data := make([]byte, size)
	rand.Read(data)
	sendHash := sha256.Sum256(data)

	// Write in a goroutine so we can read simultaneously.
	go func() {
		s.Write(data)
	}()

	// Read all echoed data.
	received := make([]byte, 0, size)
	buf := make([]byte, 32*1024)
	for len(received) < size {
		n, err := s.Read(buf)
		if err != nil {
			t.Fatalf("read at %d: %v", len(received), err)
		}
		received = append(received, buf[:n]...)
	}

	recvHash := sha256.Sum256(received)
	if sendHash != recvHash {
		t.Fatalf("checksum mismatch: sent %x, recv %x", sendHash, recvHash)
	}
}

func TestConn_StreamIDParity(t *testing.T) {
	a, b := netPipe(t)

	server := NewConn(b, false, func(s *Stream) {})
	defer server.Close()

	client := NewConn(a, true, nil)
	defer client.Close()

	s1, _ := client.OpenStream()
	s2, _ := client.OpenStream()
	s3, _ := client.OpenStream()

	if s1.ID()%2 != 1 || s2.ID()%2 != 1 || s3.ID()%2 != 1 {
		t.Fatalf("client streams should be odd: %d, %d, %d", s1.ID(), s2.ID(), s3.ID())
	}
	if s1.ID() != 1 || s2.ID() != 3 || s3.ID() != 5 {
		t.Fatalf("expected 1,3,5 got %d,%d,%d", s1.ID(), s2.ID(), s3.ID())
	}
}

func TestConn_ServerOpensStream(t *testing.T) {
	a, b := netPipe(t)

	clientReady := make(chan *Stream, 1)

	// Client accepts incoming streams from server.
	client := NewConn(a, true, func(s *Stream) {
		clientReady <- s
	})
	defer client.Close()

	server := NewConn(b, false, nil)
	defer server.Close()

	ss, err := server.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	// Server-initiated streams should be even.
	if ss.ID()%2 != 0 {
		t.Fatalf("server stream ID should be even: %d", ss.ID())
	}

	select {
	case cs := <-clientReady:
		if cs.ID() != ss.ID() {
			t.Fatalf("client got stream %d, server sent %d", cs.ID(), ss.ID())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for client to receive stream")
	}
}
