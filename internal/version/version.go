// Package version exposes build-time identifiers for GHOST binaries.
package version

// Version is the semantic version of the GHOST build.
// Pre-release builds use 0.x.y until v1.0.0.
const Version = "0.0.1-dev"

// Protocol is the wire-protocol version GHOST speaks.
// Bumped on any breaking change to frame format or handshake.
const Protocol uint8 = 1
