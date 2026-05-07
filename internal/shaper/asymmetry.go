package shaper

import (
	"sync"
	"sync/atomic"
)

// AsymmetryEnforcer tracks the byte ratio between download (server→client)
// and upload (client→server) directions and decides when padding is needed
// to maintain the target ratio.
//
// Real HTTPS browsing has a strong asymmetry (typically 5:1 or more
// download:upload). VPN tunnels tend toward 1:1 or 2:1. Padding injects
// extra bytes in the deficient direction to match the target.
type AsymmetryEnforcer struct {
	targetRatio float64 // download:upload ratio

	upBytes   atomic.Int64 // total upstream bytes counted
	downBytes atomic.Int64 // total downstream bytes counted

	mu sync.Mutex
}

// NewAsymmetryEnforcer creates an enforcer targeting the given download:upload
// byte ratio (e.g. 5.0 means 5 bytes downstream per 1 byte upstream).
func NewAsymmetryEnforcer(targetRatio float64) *AsymmetryEnforcer {
	if targetRatio <= 0 {
		targetRatio = 5.0
	}
	return &AsymmetryEnforcer{targetRatio: targetRatio}
}

// RecordUp records n upstream bytes.
func (a *AsymmetryEnforcer) RecordUp(n int) {
	a.upBytes.Add(int64(n))
}

// RecordDown records n downstream bytes.
func (a *AsymmetryEnforcer) RecordDown(n int) {
	a.downBytes.Add(int64(n))
}

// CurrentRatio returns the current download:upload ratio.
// Returns 0 if no upstream bytes recorded yet.
func (a *AsymmetryEnforcer) CurrentRatio() float64 {
	up := a.upBytes.Load()
	down := a.downBytes.Load()
	if up == 0 {
		return 0
	}
	return float64(down) / float64(up)
}

// PaddingNeeded returns how many bytes of padding should be injected in
// the given direction to bring the ratio closer to the target.
//
// Returns (downPad, upPad) — the number of padding bytes needed in each
// direction. Typically only one will be non-zero.
//
// tolerance is the acceptable deviation (e.g. 0.1 for ±10%).
func (a *AsymmetryEnforcer) PaddingNeeded(tolerance float64) (downPad, upPad int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	up := a.upBytes.Load()
	down := a.downBytes.Load()

	if up == 0 && down == 0 {
		return 0, 0
	}

	// Avoid division by zero: if no upstream yet, pad downstream to 0.
	if up == 0 {
		return 0, 0
	}

	currentRatio := float64(down) / float64(up)
	target := a.targetRatio

	low := target * (1 - tolerance)
	high := target * (1 + tolerance)

	if currentRatio >= low && currentRatio <= high {
		return 0, 0 // within tolerance
	}

	if currentRatio < low {
		// Need more downstream bytes.
		// target = (down + pad) / up → pad = target*up - down
		need := int(target*float64(up) - float64(down))
		if need < 0 {
			need = 0
		}
		return need, 0
	}

	// currentRatio > high: too much downstream, pad upstream.
	// target = down / (up + pad) → pad = down/target - up
	need := int(float64(down)/target - float64(up))
	if need < 0 {
		need = 0
	}
	return 0, need
}

// Stats returns accumulated byte counts.
func (a *AsymmetryEnforcer) Stats() (upBytes, downBytes int64) {
	return a.upBytes.Load(), a.downBytes.Load()
}
