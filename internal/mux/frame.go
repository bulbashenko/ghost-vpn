// Package mux implements L4 of the GHOST protocol stack: a binary stream
// multiplexer over a single bidirectional byte stream (the HTTP/2 DATA
// channel after L3 handshake).
//
// Wire format per frame:
//
//	[Version 1B][Type 1B][StreamID 4B BE][Length 2B BE][Payload]
//
// See docs/protocol.md §L4 for the full specification.
package mux

// HeaderSize is the fixed overhead of every frame on the wire.
const HeaderSize = 8 // 1 + 1 + 4 + 2

// MaxPayload is the maximum payload length in a single frame (uint16 max).
const MaxPayload = 65535

// DefaultWindow is the initial per-stream flow-control credit in bytes.
const DefaultWindow = 65536

// ProtocolVersion is the version byte written into every frame.
const ProtocolVersion byte = 0x01

// FrameType identifies the kind of multiplexer frame.
type FrameType byte

const (
	// TypeData carries tunnel payload bytes.
	TypeData FrameType = 0x00

	// TypeWindowUpdate grants additional flow-control credit.
	TypeWindowUpdate FrameType = 0x01

	// TypeStreamOpen creates a new logical stream.
	TypeStreamOpen FrameType = 0x02

	// TypeStreamClose terminates a logical stream.
	TypeStreamClose FrameType = 0x03

	// TypePing is a keepalive probe. The receiver must reply with TypePong
	// containing the same 8-byte cookie.
	TypePing FrameType = 0x04

	// TypePadding carries random bytes for traffic shaping. Receiver discards.
	TypePadding FrameType = 0x05

	// TypeMigrate is reserved for v2 stream migration.
	TypeMigrate FrameType = 0x06

	// TypePong is the reply to a PING frame, carrying the same cookie.
	// Distinct from TypePing so that both sides can run independent
	// keepalive loops without an infinite ping-pong cascade.
	TypePong FrameType = 0x07
)

func (t FrameType) String() string {
	switch t {
	case TypeData:
		return "DATA"
	case TypeWindowUpdate:
		return "WINDOW_UPDATE"
	case TypeStreamOpen:
		return "STREAM_OPEN"
	case TypeStreamClose:
		return "STREAM_CLOSE"
	case TypePing:
		return "PING"
	case TypePadding:
		return "PADDING"
	case TypeMigrate:
		return "MIGRATE"
	case TypePong:
		return "PONG"
	default:
		return "UNKNOWN"
	}
}

// Frame is an in-memory representation of a multiplexer frame.
type Frame struct {
	Version  byte
	Type     FrameType
	StreamID uint32
	Payload  []byte // len(Payload) == Length field on the wire
}
