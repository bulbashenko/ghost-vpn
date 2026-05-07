package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// Encoder writes frames to an underlying writer. It is safe for concurrent
// use — a mutex serializes writes so that frames from different goroutines
// don't interleave on the wire.
type Encoder struct {
	mu sync.Mutex
	w  io.Writer
}

// NewEncoder creates a frame encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// WriteFrame serializes a frame and writes it atomically.
func (e *Encoder) WriteFrame(f *Frame) error {
	if len(f.Payload) > MaxPayload {
		return fmt.Errorf("mux: payload %d exceeds max %d", len(f.Payload), MaxPayload)
	}

	// Build header + payload into a single buffer for atomic write.
	buf := make([]byte, HeaderSize+len(f.Payload))
	buf[0] = f.Version
	buf[1] = byte(f.Type)
	binary.BigEndian.PutUint32(buf[2:6], f.StreamID)
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(f.Payload)))
	copy(buf[8:], f.Payload)

	e.mu.Lock()
	defer e.mu.Unlock()

	_, err := e.w.Write(buf)
	return err
}

// Decoder reads frames from an underlying reader. NOT safe for concurrent
// use — only one goroutine should call ReadFrame at a time.
type Decoder struct {
	r      io.Reader
	header [HeaderSize]byte
}

// NewDecoder creates a frame decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

// ReadFrame reads the next frame from the wire. Blocks until a full frame
// is available or the reader errors (typically io.EOF on connection close).
func (d *Decoder) ReadFrame() (*Frame, error) {
	// Read fixed header.
	if _, err := io.ReadFull(d.r, d.header[:]); err != nil {
		return nil, err
	}

	version := d.header[0]
	if version != ProtocolVersion {
		return nil, fmt.Errorf("mux: unsupported version %#x", version)
	}

	ftype := FrameType(d.header[1])
	streamID := binary.BigEndian.Uint32(d.header[2:6])
	length := binary.BigEndian.Uint16(d.header[6:8])

	// Read payload.
	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(d.r, payload); err != nil {
			return nil, fmt.Errorf("mux: payload read: %w", err)
		}
	}

	return &Frame{
		Version:  version,
		Type:     ftype,
		StreamID: streamID,
		Payload:  payload,
	}, nil
}
