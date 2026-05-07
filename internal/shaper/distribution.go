// Package shaper implements L5 of the GHOST protocol stack: statistical
// traffic mimicry that makes tunnel flows indistinguishable from real HTTPS
// browsing to ML-based flow classifiers.
//
// The shaper controls:
//   - When frames are emitted (burst timing, IAT distribution)
//   - What padding is injected (asymmetry enforcement)
//   - How long connections live (lifecycle rotation)
package shaper

import (
	"math/rand"
	"time"

	"github.com/bulbashenko/ghost/internal/profile"
)

// Sampler draws random values from an empirical histogram distribution.
// Each call to Sample() returns a value sampled proportional to bin weights.
type Sampler struct {
	bins    []profile.Bin
	cumul   []float64 // cumulative weight thresholds
	total   float64
	rng     *rand.Rand
	jitter  bool // if true, add uniform jitter within bin spacing
}

// NewSampler creates a sampler from a histogram. If jitter is true, sampled
// values are perturbed by ±half the distance to the nearest bin to avoid
// producing only exact bin center values (which would itself be a fingerprint).
func NewSampler(h profile.Histogram, jitter bool) *Sampler {
	s := &Sampler{
		bins:   h.Bins,
		cumul:  make([]float64, len(h.Bins)),
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
		jitter: jitter,
	}

	var total float64
	for i, b := range h.Bins {
		total += b.W
		s.cumul[i] = total
	}
	s.total = total
	return s
}

// SeedFrom creates a new Sampler with the given random source seed.
// Useful for per-session deterministic sampling in tests.
func (s *Sampler) SeedFrom(seed int64) *Sampler {
	cp := *s
	cp.rng = rand.New(rand.NewSource(seed))
	return &cp
}

// Sample returns a random value from the distribution.
func (s *Sampler) Sample() float64 {
	if len(s.bins) == 0 {
		return 0
	}

	r := s.rng.Float64() * s.total
	idx := 0
	for i, c := range s.cumul {
		if r <= c {
			idx = i
			break
		}
	}

	v := s.bins[idx].V

	if s.jitter && len(s.bins) > 1 {
		// Compute half-bin-width for jitter.
		var halfWidth float64
		if idx == 0 && len(s.bins) > 1 {
			halfWidth = (s.bins[1].V - s.bins[0].V) / 2
		} else if idx == len(s.bins)-1 {
			halfWidth = (s.bins[idx].V - s.bins[idx-1].V) / 2
		} else {
			halfWidth = (s.bins[idx+1].V - s.bins[idx-1].V) / 4
		}
		v += (s.rng.Float64()*2 - 1) * halfWidth
		if v < 0 {
			v = 0
		}
	}

	return v
}

// SampleInt returns Sample() rounded to the nearest integer.
func (s *Sampler) SampleInt() int {
	return int(s.Sample() + 0.5)
}

// SampleDuration returns Sample() interpreted as microseconds, converted to
// time.Duration.
func (s *Sampler) SampleDuration() time.Duration {
	return time.Duration(s.Sample()) * time.Microsecond
}

// SampleDurationMs returns Sample() interpreted as milliseconds.
func (s *Sampler) SampleDurationMs() time.Duration {
	return time.Duration(s.Sample()) * time.Millisecond
}

// SampleDurationSec returns Sample() interpreted as seconds.
func (s *Sampler) SampleDurationSec() time.Duration {
	return time.Duration(s.Sample()) * time.Second
}
