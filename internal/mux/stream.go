package mux

import (
	"errors"
	"io"
	"sync"
)

var (
	ErrStreamClosed = errors.New("mux: stream closed")
	ErrStreamReset  = errors.New("mux: stream reset by peer")
)

// Stream is a logical bidirectional channel multiplexed over a Conn.
// It implements io.ReadWriteCloser.
//
// Unlike a byte stream, Read preserves message boundaries: each DATA frame
// from the peer is delivered as a discrete message. A single Read call
// returns data from at most one frame. This is critical for TUN-based VPNs
// where each frame carries exactly one IP packet.
type Stream struct {
	id   uint32
	conn *Conn

	// Read side: incoming messages queued from received DATA frames.
	readMu   sync.Mutex
	readMsgs [][]byte // queue of complete messages (one per DATA frame)
	readOff  int      // offset into readMsgs[0] for partial reads
	readCond *sync.Cond
	readErr  error // permanent error (EOF or reset)

	// Write side.
	closed   bool
	closedMu sync.Mutex
}

func newStream(id uint32, c *Conn) *Stream {
	s := &Stream{
		id:   id,
		conn: c,
	}
	s.readCond = sync.NewCond(&s.readMu)
	return s
}

// ID returns the stream identifier.
func (s *Stream) ID() uint32 { return s.id }

// Read reads the next message (or part of one) received from the peer.
// Each DATA frame is a discrete message; a single Read never spans two
// frames. This preserves IP packet boundaries when used for TUN traffic.
// Blocks until data is available or the stream is closed.
func (s *Stream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for len(s.readMsgs) == 0 && s.readErr == nil {
		s.readCond.Wait()
	}

	if len(s.readMsgs) > 0 {
		msg := s.readMsgs[0]
		n := copy(p, msg[s.readOff:])
		s.readOff += n
		if s.readOff >= len(msg) {
			// Consumed entire message — advance to next.
			s.readMsgs = s.readMsgs[1:]
			s.readOff = 0
		}
		return n, nil
	}

	return 0, s.readErr
}

// Write sends data to the peer via the multiplexer.
func (s *Stream) Write(p []byte) (int, error) {
	s.closedMu.Lock()
	if s.closed {
		s.closedMu.Unlock()
		return 0, ErrStreamClosed
	}
	s.closedMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPayload {
			chunk = chunk[:MaxPayload]
		}

		err := s.conn.enc.WriteFrame(&Frame{
			Version:  ProtocolVersion,
			Type:     TypeData,
			StreamID: s.id,
			Payload:  chunk,
		})
		if err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Close sends a STREAM_CLOSE frame and marks the stream as closed.
func (s *Stream) Close() error {
	s.closedMu.Lock()
	if s.closed {
		s.closedMu.Unlock()
		return nil
	}
	s.closed = true
	s.closedMu.Unlock()

	// Signal read side.
	s.deliverErr(io.EOF)

	// Notify peer.
	return s.conn.enc.WriteFrame(&Frame{
		Version:  ProtocolVersion,
		Type:     TypeStreamClose,
		StreamID: s.id,
	})
}

// deliverData enqueues a complete message and wakes readers.
// Each call corresponds to one DATA frame from the peer.
func (s *Stream) deliverData(data []byte) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.readErr != nil {
		return // stream already closed
	}
	// Copy to decouple from decoder buffer lifetime.
	msg := make([]byte, len(data))
	copy(msg, data)
	s.readMsgs = append(s.readMsgs, msg)
	s.readCond.Signal()
}

// deliverErr sets a permanent error on the read side and wakes all readers.
func (s *Stream) deliverErr(err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.readErr == nil {
		s.readErr = err
	}
	s.readCond.Broadcast()
}
