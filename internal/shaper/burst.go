package shaper

import (
	"time"

	"github.com/bulbashenko/ghost/internal/profile"
)

// BurstController simulates the bursty nature of real HTTPS traffic.
//
// Real browsing produces bursts of packets (e.g. loading page resources)
// separated by gaps (reading/thinking time). Continuous tunnel traffic
// is a strong VPN indicator, so the burst controller batches outgoing
// frames and inserts inter-burst delays sampled from the profile.
type BurstController struct {
	burstSize *Sampler // packets per burst
	burstGap  *Sampler // ms between bursts

	remaining int       // packets left in current burst
	nextBurst time.Time // when the next burst can start
}

// NewBurstController creates a burst controller from profile histograms.
func NewBurstController(burstSize, burstGap profile.Histogram) *BurstController {
	bc := &BurstController{
		burstSize: NewSampler(burstSize, true),
		burstGap:  NewSampler(burstGap, true),
	}
	bc.startNewBurst()
	return bc
}

// ShouldSend returns true if a frame can be sent now, or returns the
// duration to wait before the next send is allowed.
//
// Usage pattern:
//
//	for each outgoing frame:
//	    ok, wait := bc.ShouldSend()
//	    if !ok { time.Sleep(wait) }
//	    send(frame)
//	    bc.FrameSent()
func (bc *BurstController) ShouldSend() (ok bool, wait time.Duration) {
	now := time.Now()

	// If we're in an inter-burst gap, wait.
	if now.Before(bc.nextBurst) {
		return false, bc.nextBurst.Sub(now)
	}

	// If this burst is exhausted, start a new one after a gap.
	if bc.remaining <= 0 {
		gap := bc.burstGap.SampleDurationMs()
		bc.nextBurst = now.Add(gap)
		bc.remaining = bc.burstSize.SampleInt()
		if bc.remaining < 1 {
			bc.remaining = 1
		}
		return false, gap
	}

	return true, 0
}

// FrameSent records that a frame was sent as part of the current burst.
func (bc *BurstController) FrameSent() {
	bc.remaining--
}

// startNewBurst initializes the first burst.
func (bc *BurstController) startNewBurst() {
	bc.remaining = bc.burstSize.SampleInt()
	if bc.remaining < 1 {
		bc.remaining = 1
	}
	bc.nextBurst = time.Now()
}

// MaxDelay is the ceiling on any single burst gap. Real data queued beyond
// this limit is sent immediately to avoid unacceptable latency.
const MaxDelay = 100 * time.Millisecond
