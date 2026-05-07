package auth

// ReplayWindow is a 64-entry sliding window for nonce-based replay protection.
//
// It allows out-of-order delivery within a 64-nonce window of the highest
// nonce ever marked, while rejecting duplicates and stale nonces. The
// algorithm matches the classic IPsec/WireGuard sliding-window replay check
// (compressed to a single 64-bit word for v1's modest window size).
//
// v1 does NOT use this on the live data path: GHOST runs over TCP+HTTP/2
// which delivers in order, so Session relies on Noise's built-in sequential
// nonces. ReplayWindow exists for v2 (stream migration / multi-connection /
// possible UDP transport) where wire-level nonces become explicit and may
// arrive out of order. It is exported and unit-tested so v2 can adopt it
// without revisiting correctness.
//
// Zero value is ready to use: it accepts any first nonce (including 0).
type ReplayWindow struct {
	// head is the highest nonce ever observed (+1: see Mark for invariant).
	// hasAny tracks whether Mark has been called yet, since head=0 is also
	// a legitimate first observation.
	head   uint64
	bitmap uint64 // bit i set ⇒ nonce (head - i) has been seen
	hasAny bool
}

// WindowSize is the number of nonces tracked by ReplayWindow.
const WindowSize = 64

// Mark records nonce n as observed. Returns true if n is fresh (not a replay
// and not too old), false otherwise. A return of true means the caller may
// process the corresponding message; false means it must be dropped.
func (w *ReplayWindow) Mark(n uint64) bool {
	if !w.hasAny {
		w.hasAny = true
		w.head = n
		w.bitmap = 1
		return true
	}

	if n > w.head {
		// New highest nonce — shift the window forward.
		shift := n - w.head
		if shift >= WindowSize {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.head = n
		return true
	}

	// n <= head: check whether it's within the window and unseen.
	diff := w.head - n
	if diff >= WindowSize {
		return false // too old
	}
	mask := uint64(1) << diff
	if w.bitmap&mask != 0 {
		return false // already seen
	}
	w.bitmap |= mask
	return true
}

// Head returns the highest nonce ever marked, or 0 if Mark was never called.
func (w *ReplayWindow) Head() uint64 {
	return w.head
}

// Reset clears the window, returning it to its zero state.
func (w *ReplayWindow) Reset() {
	w.head = 0
	w.bitmap = 0
	w.hasAny = false
}
