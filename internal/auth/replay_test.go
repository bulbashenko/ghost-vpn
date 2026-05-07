package auth

import "testing"

func TestReplayWindow_ZeroValueAcceptsFirst(t *testing.T) {
	var w ReplayWindow
	if !w.Mark(0) {
		t.Fatal("zero-value window rejected first nonce 0")
	}
	if w.Head() != 0 {
		t.Fatalf("head=%d", w.Head())
	}
}

func TestReplayWindow_SequentialAllAccepted(t *testing.T) {
	var w ReplayWindow
	for i := uint64(0); i < 1000; i++ {
		if !w.Mark(i) {
			t.Fatalf("sequential nonce %d rejected", i)
		}
	}
}

func TestReplayWindow_DuplicateRejected(t *testing.T) {
	var w ReplayWindow
	for i := uint64(0); i < 10; i++ {
		w.Mark(i)
	}
	if w.Mark(5) {
		t.Fatal("duplicate nonce 5 accepted")
	}
}

func TestReplayWindow_OutOfOrderWithinWindow(t *testing.T) {
	var w ReplayWindow
	w.Mark(100)
	// 99..(100-63) are still in the window — must be accepted, each only once.
	for n := uint64(99); n >= 100-WindowSize+1; n-- {
		if !w.Mark(n) {
			t.Fatalf("in-window out-of-order nonce %d rejected", n)
		}
		if w.Mark(n) {
			t.Fatalf("duplicate of in-window nonce %d accepted", n)
		}
	}
}

func TestReplayWindow_TooOldRejected(t *testing.T) {
	var w ReplayWindow
	w.Mark(1000)
	// 1000-64 = 936 is exactly out of the window (window covers 937..1000).
	if w.Mark(1000 - WindowSize) {
		t.Fatal("nonce exactly WindowSize behind head accepted")
	}
	if w.Mark(0) {
		t.Fatal("very stale nonce accepted")
	}
}

func TestReplayWindow_LargeJumpFlushesWindow(t *testing.T) {
	var w ReplayWindow
	for i := uint64(0); i < 30; i++ {
		w.Mark(i)
	}
	// Jump well beyond WindowSize: old marks should be forgotten.
	if !w.Mark(1000) {
		t.Fatal("large forward jump rejected")
	}
	// All previously-seen old nonces are now out of window — too old, rejected.
	for i := uint64(0); i < 30; i++ {
		if w.Mark(i) {
			t.Fatalf("stale nonce %d accepted after large jump", i)
		}
	}
	// But fresh nonces near the new head still work.
	if !w.Mark(999) {
		t.Fatal("nonce just below new head rejected")
	}
}

func TestReplayWindow_HeadAndReset(t *testing.T) {
	var w ReplayWindow
	w.Mark(42)
	w.Mark(100)
	w.Mark(50)
	if w.Head() != 100 {
		t.Fatalf("head=%d, want 100", w.Head())
	}
	w.Reset()
	if w.Head() != 0 {
		t.Fatalf("head after reset=%d", w.Head())
	}
	// Post-reset accepts any first nonce.
	if !w.Mark(7) {
		t.Fatal("post-reset Mark(7) rejected")
	}
}

func TestReplayWindow_BoundaryExactlyAtEdge(t *testing.T) {
	var w ReplayWindow
	w.Mark(WindowSize - 1) // head = 63
	// Nonce 0 is exactly diff=63, which is < WindowSize ⇒ in window, fresh.
	if !w.Mark(0) {
		t.Fatal("nonce 0 with head=63 should be accepted (diff=63 < 64)")
	}
	// Now make head=64, nonce 0 has diff=64 ⇒ exactly at window edge ⇒ stale.
	var w2 ReplayWindow
	w2.Mark(WindowSize) // head = 64
	if w2.Mark(0) {
		t.Fatal("nonce 0 with head=64 should be rejected (diff=64 == window size)")
	}
}
