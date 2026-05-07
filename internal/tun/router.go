package tun

import (
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/bulbashenko/ghost/internal/mux"
)

// tunWriteQueue is the number of packets that can be buffered between the
// TUN reader and the mux stream writer. When the queue is full packets are
// dropped explicitly (tail-drop) rather than blocking TUN.Read — blocking
// TUN.Read causes the kernel's TUN queue to fill and drop packets silently
// with no visibility or control.
const tunWriteQueue = 512

// Bridge copies packets bidirectionally between a TUN device and a mux stream.
//
//	TUN → Stream: IP packets read from TUN are written as DATA frames
//	Stream → TUN: DATA frames received from peer are written as IP packets
//
// Bridge blocks until either direction encounters an error or the stream/device
// is closed. It returns the first error that caused shutdown.
func Bridge(dev *Device, stream *mux.Stream) error {
	errc := make(chan error, 3)
	stopCh := make(chan struct{})

	// pktCh decouples TUN reads from mux writes. The reader goroutine fills
	// it without ever blocking on stream.Write. The writer goroutine drains
	// it and writes to the mux stream (which may block on HTTP/2 flow
	// control). If pktCh is full the reader drops the packet — explicit
	// drop is always better than stalling TUN.Read.
	pktCh := make(chan []byte, tunWriteQueue)

	// TUN reader — never blocks on the mux write path.
	go func() {
		defer close(pktCh)
		buf := make([]byte, dev.MTU()+100)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				select {
				case errc <- err:
				default:
				}
				return
			}
			if n == 0 {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			// Check stop signal before the channel send so we exit
			// immediately when Bridge() has already returned.
			select {
			case <-stopCh:
				return
			default:
			}
			select {
			case pktCh <- pkt:
			default:
				// Queue full: drop this packet. The TCP stack above us
				// will retransmit; explicit drop is preferable to
				// stalling TUN.Read.
			}
		}
	}()

	// Mux writer — drains pktCh and writes to the stream.
	go func() {
		for pkt := range pktCh {
			if _, err := stream.Write(pkt); err != nil {
				select {
				case errc <- err:
				default:
				}
				return
			}
		}
	}()

	// mux stream → TUN
	go func() {
		buf := make([]byte, dev.MTU()+100)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if err == io.EOF {
					errc <- nil
				} else {
					errc <- err
				}
				return
			}
			if n == 0 {
				continue
			}

			pkt := buf[:n]

			// Validate IP packet before writing to TUN.
			// The kernel rejects anything that isn't a valid IP packet
			// with EINVAL. Log and skip rather than crashing the bridge.
			if !isValidIPPacket(pkt) {
				hdr := pkt
				if len(hdr) > 32 {
					hdr = hdr[:32]
				}
				slog.Warn("bridge: dropping non-IP packet",
					"len", n,
					"hex", hex.EncodeToString(hdr),
				)
				continue
			}

			if _, err := dev.Write(pkt); err != nil {
				// Log the packet header for diagnostics.
				hdr := pkt
				if len(hdr) > 32 {
					hdr = hdr[:32]
				}
				slog.Error("tun write failed",
					"error", err,
					"pkt_len", n,
					"hex", hex.EncodeToString(hdr),
				)
				errc <- err
				return
			}
		}
	}()

	err := <-errc
	close(stopCh) // unblock the TUN reader if it's in the select
	if err != nil {
		slog.Debug("tun bridge stopped", "error", err)
	}
	return err
}

// TunRouter dispatches TUN→client packets by destination IP while allowing
// a single goroutine to own TUN.Read. Without this, each connected client's
// bridge goroutine would race on dev.Read: each IP packet is delivered to
// exactly one reader, so ~50% of packets for any given client end up in
// the wrong session when two clients are connected simultaneously.
//
// Usage:
//
//	router := tun.NewTunRouter(tunDev)
//	// In the mux onStream callback:
//	router.Bridge(stream)
type TunRouter struct {
	dev *Device

	mu     sync.RWMutex
	routes map[string]chan []byte // raw IP bytes (4 or 16 bytes) → per-client inbound channel
}

// NewTunRouter creates a TunRouter and starts its single background TUN reader.
func NewTunRouter(dev *Device) *TunRouter {
	r := &TunRouter{
		dev:    dev,
		routes: make(map[string]chan []byte),
	}
	go r.readLoop()
	return r
}

// readLoop is the single goroutine that owns dev.Read. It extracts the
// destination IP from each packet and dispatches to the registered client
// channel, or drops the packet if no client is registered for that IP.
func (r *TunRouter) readLoop() {
	buf := make([]byte, r.dev.MTU()+100)
	for {
		n, err := r.dev.Read(buf)
		if err != nil {
			slog.Error("tun router: read error", "error", err)
			return
		}
		if n == 0 {
			continue
		}

		dst := dstIPKey(buf[:n])
		if dst == "" {
			continue
		}

		r.mu.RLock()
		ch, ok := r.routes[dst]
		r.mu.RUnlock()

		if !ok {
			// No client registered for this destination — drop.
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		select {
		case ch <- pkt:
		default:
			// Per-client queue full: tail-drop.
		}
	}
}

func (r *TunRouter) register(ipKey string) chan []byte {
	ch := make(chan []byte, tunWriteQueue)
	r.mu.Lock()
	r.routes[ipKey] = ch
	r.mu.Unlock()
	return ch
}

// unregister removes the channel for ipKey only if it still matches myCh.
// This prevents a departing session from closing a channel that was already
// replaced by a new session for the same client IP (session rotation race).
func (r *TunRouter) unregister(ipKey string, myCh chan []byte) {
	r.mu.Lock()
	if r.routes[ipKey] == myCh {
		delete(r.routes, ipKey)
	}
	r.mu.Unlock()
	// Always close our own channel so the TUN→stream goroutine can exit.
	close(myCh)
}

// Bridge bridges a mux stream bidirectionally through the TUN device.
// The client's TUN IP is learned from the source IP of the first IP packet
// received from the stream. Bridge blocks until the session ends and returns
// the first error (nil on clean EOF).
func (r *TunRouter) Bridge(stream *mux.Stream) error {
	// Read the first packet to discover the client's TUN IP address.
	first := make([]byte, r.dev.MTU()+100)
	n, err := stream.Read(first)
	if err != nil {
		return fmt.Errorf("tun router: read first packet: %w", err)
	}
	first = first[:n]

	srcKey := srcIPKey(first)
	if srcKey == "" {
		return fmt.Errorf("tun router: first packet is not a valid IP packet (len=%d)", n)
	}

	// Register this client before forwarding the first packet so that any
	// immediate reply from the TUN side lands in our channel.
	inbound := r.register(srcKey)
	defer r.unregister(srcKey, inbound)

	// Forward the first packet to TUN.
	if isValidIPPacket(first) {
		if _, err := r.dev.Write(first); err != nil {
			slog.Error("tun router: write first packet", "error", err)
		}
	}

	errc := make(chan error, 2)

	// TUN → stream: drain per-client inbound channel and write to mux stream.
	go func() {
		for pkt := range inbound {
			if _, err := stream.Write(pkt); err != nil {
				errc <- err
				return
			}
		}
		// Channel was closed by unregister — normal shutdown path.
		errc <- nil
	}()

	// stream → TUN: read mux stream and write IP packets to TUN.
	go func() {
		buf := make([]byte, r.dev.MTU()+100)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if err == io.EOF {
					errc <- nil
				} else {
					errc <- err
				}
				return
			}
			if n == 0 {
				continue
			}
			pkt := buf[:n]
			if !isValidIPPacket(pkt) {
				hdr := pkt
				if len(hdr) > 32 {
					hdr = hdr[:32]
				}
				slog.Warn("tun router: dropping non-IP packet from stream",
					"len", n,
					"hex", hex.EncodeToString(hdr),
				)
				continue
			}
			if _, err := r.dev.Write(pkt); err != nil {
				slog.Error("tun router: write to tun", "error", err)
				errc <- err
				return
			}
		}
	}()

	return <-errc
}

// isValidIPPacket checks the minimum requirements for writing to a TUN device:
//   - At least 20 bytes (minimum IPv4 header)
//   - IP version nibble is 4 (IPv4) or 6 (IPv6)
//   - For IPv4: total length in header matches packet length (±tolerance)
func isValidIPPacket(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}

	version := pkt[0] >> 4

	switch version {
	case 4:
		// IPv4: minimum header is 20 bytes.
		if len(pkt) < 20 {
			return false
		}
		// Check that IP total length is consistent with buffer.
		totalLen := int(pkt[2])<<8 | int(pkt[3])
		if totalLen < 20 || totalLen > len(pkt) {
			return false
		}
		return true

	case 6:
		// IPv6: minimum header is 40 bytes.
		if len(pkt) < 40 {
			return false
		}
		return true

	default:
		return false
	}
}

// dstIPKey returns the destination IP address of an IP packet as a raw byte
// string (4 bytes for IPv4, 16 bytes for IPv6). Returns "" for non-IP packets.
// Using raw bytes as map keys avoids net.IP allocation on every packet.
func dstIPKey(pkt []byte) string {
	if len(pkt) < 1 {
		return ""
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return ""
		}
		return string(pkt[16:20])
	case 6:
		if len(pkt) < 40 {
			return ""
		}
		return string(pkt[24:40])
	}
	return ""
}

// srcIPKey returns the source IP address of an IP packet as a raw byte string.
func srcIPKey(pkt []byte) string {
	if len(pkt) < 1 {
		return ""
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return ""
		}
		return string(pkt[12:16])
	case 6:
		if len(pkt) < 40 {
			return ""
		}
		return string(pkt[8:24])
	}
	return ""
}
