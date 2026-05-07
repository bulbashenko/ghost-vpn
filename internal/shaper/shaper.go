package shaper

import (
	"log/slog"
	"time"

	"github.com/bulbashenko/ghost/internal/mux"
	"github.com/bulbashenko/ghost/internal/profile"
)

// Config configures the traffic shaper.
type Config struct {
	// Profile is the empirical distribution to mimic. If nil, the default
	// generic HTTPS profile is used.
	Profile *profile.Profile

	// Enabled controls whether shaping is active. When false, data is
	// passed through without modification (useful for debugging).
	Enabled bool

	// AsymmetryTolerance is the acceptable deviation from the target ratio
	// (e.g. 0.1 for ±10%). Default 0.15.
	AsymmetryTolerance float64

	// PaddingInterval is how often the shaper checks and injects padding
	// to maintain the asymmetry ratio. Default 5s.
	PaddingInterval time.Duration
}

func (c *Config) profile() *profile.Profile {
	if c.Profile != nil {
		return c.Profile
	}
	return profile.DefaultProfile()
}

func (c *Config) tolerance() float64 {
	if c.AsymmetryTolerance > 0 {
		return c.AsymmetryTolerance
	}
	return 0.15
}

func (c *Config) paddingInterval() time.Duration {
	if c.PaddingInterval > 0 {
		return c.PaddingInterval
	}
	return 5 * time.Second
}

// Shaper wraps a mux.Conn and applies traffic shaping to make tunnel
// traffic statistically resemble the configured profile.
type Shaper struct {
	conn  *mux.Conn
	cfg   *Config
	prof  *profile.Profile
	asym  *AsymmetryEnforcer
	burst *BurstController

	pktSizeUp   *Sampler
	pktSizeDown *Sampler
	iatUp       *Sampler
	iatDown     *Sampler
	lifetime    *Sampler

	stopCh chan struct{}
}

// New creates a traffic shaper wrapping the given mux connection.
func New(conn *mux.Conn, cfg *Config) *Shaper {
	p := cfg.profile()
	s := &Shaper{
		conn:        conn,
		cfg:         cfg,
		prof:        p,
		asym:        NewAsymmetryEnforcer(p.AsymmetryRatio),
		burst:       NewBurstController(p.BurstSize, p.BurstGap),
		pktSizeUp:   NewSampler(p.PacketSizeUp, true),
		pktSizeDown: NewSampler(p.PacketSizeDown, true),
		iatUp:       NewSampler(p.IATUp, true),
		iatDown:     NewSampler(p.IATDown, true),
		lifetime:    NewSampler(p.ConnLifetime, true),
		stopCh:      make(chan struct{}),
	}
	return s
}

// Start begins the background shaping goroutines:
//   - Padding injector (maintains asymmetry ratio)
//   - Keepalive pings
func (s *Shaper) Start() {
	if !s.cfg.Enabled {
		return
	}
	go s.paddingLoop()
	go s.keepaliveLoop()
}

// Stop terminates the shaper's background goroutines.
func (s *Shaper) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

// RecordUp records upstream bytes for asymmetry tracking.
func (s *Shaper) RecordUp(n int) {
	if s.cfg.Enabled {
		s.asym.RecordUp(n)
	}
}

// RecordDown records downstream bytes for asymmetry tracking.
func (s *Shaper) RecordDown(n int) {
	if s.cfg.Enabled {
		s.asym.RecordDown(n)
	}
}

// ShouldDelay returns whether the shaper wants to delay the next send,
// and for how long. The caller should respect this delay unless it exceeds
// MaxDelay (in which case real data takes priority).
func (s *Shaper) ShouldDelay() (bool, time.Duration) {
	if !s.cfg.Enabled {
		return false, 0
	}
	ok, wait := s.burst.ShouldSend()
	if ok {
		return false, 0
	}
	// Cap delay to avoid unacceptable latency.
	if wait > MaxDelay {
		wait = MaxDelay
	}
	return true, wait
}

// FrameSent notifies the burst controller that a frame was sent.
func (s *Shaper) FrameSent() {
	if s.cfg.Enabled {
		s.burst.FrameSent()
	}
}

// SampleLifetime returns a random connection lifetime from the profile.
func (s *Shaper) SampleLifetime() time.Duration {
	return s.lifetime.SampleDurationSec()
}

// AsymmetryRatio returns the current download:upload ratio.
func (s *Shaper) AsymmetryRatio() float64 {
	return s.asym.CurrentRatio()
}

// paddingLoop periodically checks the asymmetry ratio and injects PADDING
// frames to maintain the target.
func (s *Shaper) paddingLoop() {
	ticker := time.NewTicker(s.cfg.paddingInterval())
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			downPad, upPad := s.asym.PaddingNeeded(s.cfg.tolerance())

			// Inject padding in chunks of reasonable size.
			const maxChunk = 8192
			pad := downPad + upPad
			for pad > 0 {
				chunk := pad
				if chunk > maxChunk {
					chunk = maxChunk
				}
				if err := s.conn.SendPadding(chunk); err != nil {
					slog.Debug("shaper: padding send error", "error", err)
					return
				}
				// Record the padding in the appropriate direction.
				if downPad > 0 {
					s.asym.RecordDown(chunk)
					downPad -= chunk
				} else {
					s.asym.RecordUp(chunk)
					upPad -= chunk
				}
				pad -= chunk
			}
		}
	}
}

// keepaliveLoop sends PING frames at a regular interval.
func (s *Shaper) keepaliveLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			if err := s.conn.SendPing(); err != nil {
				slog.Debug("shaper: ping error", "error", err)
				return
			}
		}
	}
}
