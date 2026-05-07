// Package profile defines the empirical traffic distribution format used by
// the L5 traffic shaper. Distributions are captured from real HTTPS browsing
// sessions and stored as JSON histograms.
//
// A profile contains:
//   - Packet size distributions (upload/download, separate)
//   - Inter-arrival time (IAT) distributions
//   - Burst size + gap distributions
//   - Connection lifetime distribution
//   - Asymmetry ratio target (download:upload byte ratio)
package profile

import (
	"encoding/json"
	"fmt"
	"os"
)

// Profile is the top-level structure loaded from a JSON profile file.
type Profile struct {
	// Name identifies this profile (e.g. "generic_https").
	Name string `json:"name"`

	// Description of the traffic this profile mimics.
	Description string `json:"description"`

	// PacketSizeUp is the histogram of upstream (client→server) payload sizes in bytes.
	PacketSizeUp Histogram `json:"packet_size_up"`

	// PacketSizeDown is the histogram of downstream (server→client) payload sizes.
	PacketSizeDown Histogram `json:"packet_size_down"`

	// IATUp is the inter-arrival time histogram for upstream packets (microseconds).
	IATUp Histogram `json:"iat_up_us"`

	// IATDown is the inter-arrival time histogram for downstream packets (microseconds).
	IATDown Histogram `json:"iat_down_us"`

	// BurstSize is the histogram of packets per burst.
	BurstSize Histogram `json:"burst_size"`

	// BurstGap is the histogram of inter-burst gaps (milliseconds).
	BurstGap Histogram `json:"burst_gap_ms"`

	// ConnLifetime is the histogram of connection durations (seconds).
	ConnLifetime Histogram `json:"conn_lifetime_s"`

	// AsymmetryRatio is the target download:upload byte ratio (e.g. 5.0 means
	// 5 bytes downloaded per 1 byte uploaded).
	AsymmetryRatio float64 `json:"asymmetry_ratio"`
}

// Histogram is a weighted distribution represented as (value, weight) pairs.
// To sample, pick a bin proportional to its weight, then return the value
// (optionally with jitter within the bin width).
type Histogram struct {
	// Bins are the histogram buckets. Each bin has a center Value and a Weight
	// proportional to how often that value appears in real traffic.
	Bins []Bin `json:"bins"`
}

// Bin is a single bucket in a histogram.
type Bin struct {
	V float64 `json:"v"` // Center value of this bin
	W float64 `json:"w"` // Relative weight (need not sum to 1)
}

// Load reads a profile from a JSON file.
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: read %s: %w", path, err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("profile: parse %s: %w", path, err)
	}
	return &p, nil
}

// Parse parses a profile from raw JSON bytes.
func Parse(data []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("profile: parse: %w", err)
	}
	return &p, nil
}
