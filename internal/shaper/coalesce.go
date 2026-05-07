package shaper

import (
	"encoding/binary"
	"io"
	mathrand "math/rand"
	"sync"
	"time"

	"github.com/bulbashenko/ghost/internal/mux"
)

// CoalesceConfig configures the write-coalescing wrapper.
type CoalesceConfig struct {
	// FlushInterval is the maximum time the coalescer waits before flushing
	// pending writes to the underlying transport. Default 8ms.
	//
	// Lower values reduce latency at the cost of revealing more small TLS
	// records (each TUN packet becomes its own record). Higher values
	// improve packet-size camouflage but add latency.
	FlushInterval time.Duration

	// FlushBytes is the buffer size threshold at which a flush is forced
	// regardless of the timer. Default 1300 (≈ Ethernet MTU minus headers).
	FlushBytes int

	// MinPaddedSize and MaxPaddedSize define the random target size used
	// when padding small flushes. The coalescer picks a random size in
	// [Min, Max] and pads the buffer up to that size with a TypePadding
	// mux frame. Default 1100..1450 bytes.
	//
	// Pick values that match what real HTTPS browsers produce on this
	// network. With Hetzner/Selectel typical egress MTU ≈ 1420.
	MinPaddedSize int
	MaxPaddedSize int

	// CoverInterval is how often (when no real traffic flowed) the
	// coalescer emits a pure-padding flush to keep the connection looking
	// alive — like a real HTTPS keepalive. Default 25s. Zero disables.
	CoverInterval time.Duration
}

// Apply defaults.
func (c *CoalesceConfig) defaults() {
	if c.FlushInterval <= 0 {
		c.FlushInterval = 8 * time.Millisecond
	}
	if c.FlushBytes <= 0 {
		c.FlushBytes = 1300
	}
	if c.MinPaddedSize <= 0 {
		c.MinPaddedSize = 1100
	}
	if c.MaxPaddedSize < c.MinPaddedSize {
		c.MaxPaddedSize = 1450
	}
	if c.CoverInterval == 0 {
		c.CoverInterval = 25 * time.Second
	}
}

// CoalescingConn wraps an io.ReadWriteCloser (the L3 tunnel byte stream) and
// batches outbound writes so that multiple small mux frames coalesce into one
// MTU-sized TLS record on the wire. Pads small flushes with a mux PADDING
// frame so every flush produces a near-MTU packet.
//
// This is the single most effective DPI countermeasure against the "VPN over
// HTTPS" classifier — without it the protocol generates a uniform stream of
// 100-byte TLS records for every TUN packet, which is a textbook fingerprint.
//
// Read is passed through unchanged: the inbound side stays message-oriented.
type CoalescingConn struct {
	inner io.ReadWriteCloser
	cfg   CoalesceConfig

	mu        sync.Mutex
	buf       []byte
	timer     *time.Timer
	closed    bool
	closeChan chan struct{}

	// stats for diagnostics / tests
	totalFlushes uint64
	totalPadding uint64
	totalBytes   uint64
}

// NewCoalescingConn wraps inner with write coalescing.
func NewCoalescingConn(inner io.ReadWriteCloser, cfg CoalesceConfig) *CoalescingConn {
	cfg.defaults()
	c := &CoalescingConn{
		inner:     inner,
		cfg:       cfg,
		buf:       make([]byte, 0, cfg.FlushBytes*2),
		closeChan: make(chan struct{}),
	}
	if cfg.CoverInterval > 0 {
		go c.coverLoop()
	}
	return c
}

// Read passes through to inner. Coalescing only applies to writes — the
// remote peer sends data in MTU-sized records anyway because we wrap them
// the same way on the other side.
func (c *CoalescingConn) Read(p []byte) (int, error) {
	return c.inner.Read(p)
}

// Write enqueues data into the batch buffer. Flushes when the buffer
// reaches FlushBytes, or after FlushInterval, whichever comes first.
//
// Note: the caller is mux.Encoder.WriteFrame which writes complete frames.
// Writes are appended verbatim — the underlying stream is still framed.
func (c *CoalescingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, io.ErrClosedPipe
	}

	c.buf = append(c.buf, p...)

	// Force flush if buffer is full enough.
	if len(c.buf) >= c.cfg.FlushBytes {
		if err := c.flushLocked(false); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	// Otherwise schedule a deferred flush.
	if c.timer == nil {
		c.timer = time.AfterFunc(c.cfg.FlushInterval, c.timerFlush)
	}
	return len(p), nil
}

// timerFlush is invoked by the AfterFunc timer.
func (c *CoalescingConn) timerFlush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timer = nil
	if c.closed {
		return
	}
	_ = c.flushLocked(false)
}

// flushLocked writes the current buffer to the inner conn, padding to a
// randomized MTU-ish size if it's too small. Caller must hold c.mu.
//
// If pureCover is true the buffer is empty and we emit a single PADDING
// frame of MTU size — used by the cover-traffic loop to maintain an
// HTTPS-like keepalive cadence.
func (c *CoalescingConn) flushLocked(pureCover bool) error {
	// Cancel pending timer if any (we're flushing now).
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	if len(c.buf) == 0 && !pureCover {
		return nil
	}

	// Pick a target size. Real HTTPS rarely sends packets exactly at MTU;
	// jitter prevents ML classifiers from learning a fixed size.
	span := c.cfg.MaxPaddedSize - c.cfg.MinPaddedSize
	target := c.cfg.MinPaddedSize
	if span > 0 {
		target += mathrand.Intn(span + 1)
	}

	// If the buffer is already big enough, send as-is.
	if len(c.buf) >= target {
		_, err := c.inner.Write(c.buf)
		c.totalBytes += uint64(len(c.buf))
		c.totalFlushes++
		c.buf = c.buf[:0]
		return err
	}

	// Otherwise append a PADDING mux frame to reach the target size.
	// PADDING frame layout (per internal/mux): [Ver 1B][Type 1B][SID 4B][Len 2B][payload]
	padPayloadLen := target - len(c.buf) - mux.HeaderSize
	if padPayloadLen < 1 {
		// Buffer is just shy of target — send as-is, not worth a
		// degenerate padding frame.
		_, err := c.inner.Write(c.buf)
		c.totalBytes += uint64(len(c.buf))
		c.totalFlushes++
		c.buf = c.buf[:0]
		return err
	}
	if padPayloadLen > mux.MaxPayload {
		padPayloadLen = mux.MaxPayload
	}

	frame := make([]byte, mux.HeaderSize+padPayloadLen)
	frame[0] = mux.ProtocolVersion
	frame[1] = byte(mux.TypePadding)
	// StreamID = 0 for control/padding frames (big-endian uint32)
	binary.BigEndian.PutUint16(frame[6:8], uint16(padPayloadLen))
	// Padding payload bytes are left as zero — the entire CoalescingConn
	// output is encrypted by the FrameCipher layer, so the padding content
	// is never visible to any observer. crypto/rand here was a hot-path
	// syscall with no security benefit.

	c.buf = append(c.buf, frame...)
	_, err := c.inner.Write(c.buf)
	c.totalBytes += uint64(len(c.buf))
	c.totalFlushes++
	c.totalPadding += uint64(padPayloadLen)
	c.buf = c.buf[:0]
	return err
}

// coverLoop emits a single MTU-sized PADDING flush every CoverInterval if
// no real traffic has happened. Real HTTPS keepalives have similar cadence.
func (c *CoalescingConn) coverLoop() {
	t := time.NewTicker(c.cfg.CoverInterval)
	defer t.Stop()
	for {
		select {
		case <-c.closeChan:
			return
		case <-t.C:
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return
			}
			// Only emit cover if buffer is empty (no recent real traffic).
			if len(c.buf) == 0 {
				_ = c.flushLocked(true)
			}
			c.mu.Unlock()
		}
	}
}

// Close flushes any pending data and closes the underlying conn.
func (c *CoalescingConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.closeChan)
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if len(c.buf) > 0 {
		_, _ = c.inner.Write(c.buf)
		c.buf = nil
	}
	c.mu.Unlock()
	return c.inner.Close()
}

// Stats returns coalescer statistics for diagnostics.
func (c *CoalescingConn) Stats() (flushes, padding, bytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalFlushes, c.totalPadding, c.totalBytes
}
