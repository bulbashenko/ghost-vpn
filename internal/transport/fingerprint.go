// Package transport implements L1 of the GHOST protocol stack: TCP connections
// wrapped in TLS 1.3 with browser-matching fingerprints (uTLS on the client
// side, standard crypto/tls on the server side with a real CA-signed cert).
//
// The goal is that a passive observer sees a TLS ClientHello indistinguishable
// from a real Chrome browser connecting to a real HTTPS website.
package transport

import (
	utls "github.com/refraction-networking/utls"
)

// Fingerprint selects which browser TLS fingerprint the client should mimic.
// The zero value ("") is treated as FingerprintChromeAuto.
type Fingerprint string

const (
	// FingerprintChromeAuto tracks the latest Chrome release. Recommended
	// for most deployments — it auto-rotates with uTLS library updates.
	FingerprintChromeAuto Fingerprint = "chrome"

	// FingerprintFirefoxAuto tracks the latest Firefox release.
	FingerprintFirefoxAuto Fingerprint = "firefox"

	// FingerprintSafariAuto tracks the latest Safari release.
	FingerprintSafariAuto Fingerprint = "safari"

	// FingerprintRandomized uses a randomized fingerprint that still
	// produces a valid TLS 1.3 handshake. Less tested against DPI but
	// harder to pin to a specific browser version.
	FingerprintRandomized Fingerprint = "random"
)

// helloID maps a Fingerprint to the uTLS ClientHelloID used during the
// handshake. Unknown or empty values fall back to Chrome auto.
func helloID(fp Fingerprint) utls.ClientHelloID {
	switch fp {
	case FingerprintChromeAuto, "":
		return utls.HelloChrome_Auto
	case FingerprintFirefoxAuto:
		return utls.HelloFirefox_Auto
	case FingerprintSafariAuto:
		return utls.HelloSafari_Auto
	case FingerprintRandomized:
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}
