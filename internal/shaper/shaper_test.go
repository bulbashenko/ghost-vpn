package shaper

import (
	"math"
	"testing"
	"time"

	"github.com/bulbashenko/ghost/internal/profile"
)

// --- Sampler tests ---

func TestSampler_BasicSampling(t *testing.T) {
	h := profile.Histogram{Bins: []profile.Bin{
		{V: 10, W: 1},
		{V: 20, W: 1},
		{V: 30, W: 1},
	}}
	s := NewSampler(h, false)

	// Sample many times, all values should be one of the bin centers.
	counts := make(map[float64]int)
	for i := 0; i < 10000; i++ {
		v := s.Sample()
		counts[v]++
	}
	if len(counts) != 3 {
		t.Fatalf("expected 3 distinct values, got %d", len(counts))
	}
	for _, v := range []float64{10, 20, 30} {
		if counts[v] < 2000 {
			t.Errorf("value %v: count=%d, expected ~3333", v, counts[v])
		}
	}
}

func TestSampler_WeightedSampling(t *testing.T) {
	h := profile.Histogram{Bins: []profile.Bin{
		{V: 1, W: 9}, // 90%
		{V: 2, W: 1}, // 10%
	}}
	s := NewSampler(h, false)

	count1 := 0
	n := 10000
	for i := 0; i < n; i++ {
		if s.Sample() == 1 {
			count1++
		}
	}
	ratio := float64(count1) / float64(n)
	if ratio < 0.85 || ratio > 0.95 {
		t.Errorf("expected ~90%% for value 1, got %.1f%%", ratio*100)
	}
}

func TestSampler_Jitter(t *testing.T) {
	h := profile.Histogram{Bins: []profile.Bin{
		{V: 100, W: 1},
		{V: 200, W: 1},
	}}
	s := NewSampler(h, true) // with jitter

	seenNonExact := false
	for i := 0; i < 1000; i++ {
		v := s.Sample()
		if v != 100 && v != 200 {
			seenNonExact = true
			break
		}
	}
	if !seenNonExact {
		t.Error("jitter enabled but all samples are exact bin centers")
	}
}

func TestSampler_NoJitter(t *testing.T) {
	h := profile.Histogram{Bins: []profile.Bin{
		{V: 42, W: 1},
	}}
	s := NewSampler(h, false)

	for i := 0; i < 100; i++ {
		if v := s.Sample(); v != 42 {
			t.Fatalf("without jitter, expected 42, got %v", v)
		}
	}
}

func TestSampler_EmptyHistogram(t *testing.T) {
	s := NewSampler(profile.Histogram{}, false)
	if v := s.Sample(); v != 0 {
		t.Fatalf("empty histogram should return 0, got %v", v)
	}
}

func TestSampler_SampleInt(t *testing.T) {
	h := profile.Histogram{Bins: []profile.Bin{
		{V: 3.7, W: 1},
	}}
	s := NewSampler(h, false)
	if v := s.SampleInt(); v != 4 {
		t.Fatalf("SampleInt(3.7) = %d, want 4", v)
	}
}

func TestSampler_SampleDuration(t *testing.T) {
	h := profile.Histogram{Bins: []profile.Bin{
		{V: 1000, W: 1}, // 1000 microseconds
	}}
	s := NewSampler(h, false)
	d := s.SampleDuration()
	if d != 1*time.Millisecond {
		t.Fatalf("SampleDuration = %v, want 1ms", d)
	}
}

func TestSampler_SeedFrom(t *testing.T) {
	h := profile.Histogram{Bins: []profile.Bin{
		{V: 1, W: 1}, {V: 2, W: 1}, {V: 3, W: 1},
	}}
	s := NewSampler(h, false)

	a := s.SeedFrom(42)
	b := s.SeedFrom(42)

	for i := 0; i < 100; i++ {
		va := a.Sample()
		vb := b.Sample()
		if va != vb {
			t.Fatalf("seeded samplers diverged at i=%d: %v vs %v", i, va, vb)
		}
	}
}

// --- Asymmetry enforcer tests ---

func TestAsymmetry_InitialState(t *testing.T) {
	a := NewAsymmetryEnforcer(5.0)
	if r := a.CurrentRatio(); r != 0 {
		t.Fatalf("initial ratio=%v", r)
	}
	down, up := a.PaddingNeeded(0.1)
	if down != 0 || up != 0 {
		t.Fatalf("padding needed with no traffic: down=%d up=%d", down, up)
	}
}

func TestAsymmetry_PerfectRatio(t *testing.T) {
	a := NewAsymmetryEnforcer(5.0)
	a.RecordUp(1000)
	a.RecordDown(5000)

	r := a.CurrentRatio()
	if math.Abs(r-5.0) > 0.01 {
		t.Fatalf("ratio=%v, want 5.0", r)
	}

	down, up := a.PaddingNeeded(0.1) // 10% tolerance
	if down != 0 || up != 0 {
		t.Fatalf("no padding needed at target: down=%d up=%d", down, up)
	}
}

func TestAsymmetry_NeedsDownstreamPadding(t *testing.T) {
	a := NewAsymmetryEnforcer(5.0)
	a.RecordUp(1000)
	a.RecordDown(2000) // ratio 2.0, target 5.0

	down, up := a.PaddingNeeded(0.1)
	if down == 0 {
		t.Fatal("expected downstream padding needed")
	}
	if up != 0 {
		t.Fatalf("unexpected upstream padding: %d", up)
	}
	// Should need ~3000 bytes: 5.0*1000 - 2000 = 3000
	if down < 2500 || down > 3500 {
		t.Fatalf("down padding=%d, expected ~3000", down)
	}
}

func TestAsymmetry_NeedsUpstreamPadding(t *testing.T) {
	a := NewAsymmetryEnforcer(5.0)
	a.RecordUp(100)
	a.RecordDown(1000) // ratio 10.0, target 5.0

	down, up := a.PaddingNeeded(0.1)
	if up == 0 {
		t.Fatal("expected upstream padding needed")
	}
	if down != 0 {
		t.Fatalf("unexpected downstream padding: %d", down)
	}
	// down/target - up = 1000/5.0 - 100 = 100
	if up < 50 || up > 150 {
		t.Fatalf("up padding=%d, expected ~100", up)
	}
}

func TestAsymmetry_Stats(t *testing.T) {
	a := NewAsymmetryEnforcer(5.0)
	a.RecordUp(100)
	a.RecordDown(500)
	up, down := a.Stats()
	if up != 100 || down != 500 {
		t.Fatalf("stats: up=%d down=%d", up, down)
	}
}

// --- Burst controller tests ---

func TestBurst_InitialBurst(t *testing.T) {
	bc := NewBurstController(
		profile.Histogram{Bins: []profile.Bin{{V: 5, W: 1}}},
		profile.Histogram{Bins: []profile.Bin{{V: 100, W: 1}}},
	)

	// Should be able to send immediately (first burst).
	ok, wait := bc.ShouldSend()
	if !ok {
		t.Fatalf("first send should be allowed, wait=%v", wait)
	}
}

func TestBurst_BurstExhaustion(t *testing.T) {
	bc := NewBurstController(
		profile.Histogram{Bins: []profile.Bin{{V: 3, W: 1}}}, // burst of 3
		profile.Histogram{Bins: []profile.Bin{{V: 50, W: 1}}}, // 50ms gap
	)

	// Send 3 frames (burst).
	for i := 0; i < 3; i++ {
		ok, _ := bc.ShouldSend()
		if !ok {
			t.Fatalf("frame %d should be sendable", i)
		}
		bc.FrameSent()
	}

	// 4th frame should be delayed (burst exhausted).
	ok, wait := bc.ShouldSend()
	if ok {
		t.Fatal("should need to wait after burst exhaustion")
	}
	if wait == 0 {
		t.Fatal("wait should be non-zero")
	}
}

func TestBurst_MaxDelay(t *testing.T) {
	if MaxDelay != 100*time.Millisecond {
		t.Fatalf("MaxDelay=%v, want 100ms", MaxDelay)
	}
}

// --- Default profile tests ---

func TestDefaultProfile_Valid(t *testing.T) {
	p := profile.DefaultProfile()
	if p.Name != "generic_https" {
		t.Fatalf("name=%q", p.Name)
	}
	if p.AsymmetryRatio != 5.0 {
		t.Fatalf("ratio=%v", p.AsymmetryRatio)
	}
	if len(p.PacketSizeUp.Bins) == 0 {
		t.Fatal("empty packet size up")
	}
	if len(p.PacketSizeDown.Bins) == 0 {
		t.Fatal("empty packet size down")
	}
	if len(p.IATUp.Bins) == 0 {
		t.Fatal("empty IAT up")
	}
	if len(p.BurstSize.Bins) == 0 {
		t.Fatal("empty burst size")
	}
	if len(p.ConnLifetime.Bins) == 0 {
		t.Fatal("empty conn lifetime")
	}
}

func TestDefaultProfile_Sampleable(t *testing.T) {
	p := profile.DefaultProfile()

	// Ensure all histograms can be sampled without panic.
	samplers := []*Sampler{
		NewSampler(p.PacketSizeUp, true),
		NewSampler(p.PacketSizeDown, true),
		NewSampler(p.IATUp, true),
		NewSampler(p.IATDown, true),
		NewSampler(p.BurstSize, true),
		NewSampler(p.BurstGap, true),
		NewSampler(p.ConnLifetime, true),
	}

	for _, s := range samplers {
		for i := 0; i < 100; i++ {
			v := s.Sample()
			if v < 0 {
				t.Fatalf("negative sample: %v", v)
			}
		}
	}
}

// --- Profile JSON roundtrip ---

func TestProfile_ParseJSON(t *testing.T) {
	json := `{
		"name": "test",
		"description": "test profile",
		"packet_size_up": {"bins": [{"v": 100, "w": 1}]},
		"packet_size_down": {"bins": [{"v": 1400, "w": 1}]},
		"iat_up_us": {"bins": [{"v": 1000, "w": 1}]},
		"iat_down_us": {"bins": [{"v": 500, "w": 1}]},
		"burst_size": {"bins": [{"v": 5, "w": 1}]},
		"burst_gap_ms": {"bins": [{"v": 50, "w": 1}]},
		"conn_lifetime_s": {"bins": [{"v": 300, "w": 1}]},
		"asymmetry_ratio": 3.0
	}`

	p, err := profile.Parse([]byte(json))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Name != "test" {
		t.Fatalf("name=%q", p.Name)
	}
	if p.AsymmetryRatio != 3.0 {
		t.Fatalf("ratio=%v", p.AsymmetryRatio)
	}
	if len(p.PacketSizeUp.Bins) != 1 {
		t.Fatalf("bins=%d", len(p.PacketSizeUp.Bins))
	}
}
