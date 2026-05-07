package profile

// DefaultProfile returns a built-in generic HTTPS browsing profile.
//
// These distributions are based on typical web browsing patterns observed in
// academic traffic analysis literature. They represent a mix of:
//   - News site browsing (text-heavy, small objects)
//   - JSON API calls (small request, medium response)
//   - Image loading (small request, large response)
//   - Occasional video chunks (large responses)
//
// This profile should be replaced with distributions captured from actual
// traffic using `ghost-tools capture` for best results. The defaults provide
// a reasonable starting point that avoids obvious VPN traffic signatures.
func DefaultProfile() *Profile {
	return &Profile{
		Name:        "generic_https",
		Description: "Generic HTTPS browsing (news, APIs, images)",

		// Upstream packet sizes: mostly small (HTTP requests, ACKs).
		// Typical: 0-100B (ACKs/small requests), 200-600B (HTTP headers),
		// occasional 1200-1400B (POST bodies, uploads).
		PacketSizeUp: Histogram{Bins: []Bin{
			{V: 0, W: 5},
			{V: 40, W: 15},    // TCP ACKs
			{V: 100, W: 10},   // Small requests
			{V: 200, W: 8},    // HTTP GET headers
			{V: 350, W: 12},   // Medium requests
			{V: 500, W: 8},    // Larger headers (cookies)
			{V: 700, W: 5},    // POST with small body
			{V: 1000, W: 3},   // Medium POST
			{V: 1300, W: 2},   // Large request
			{V: 1400, W: 1},   // MTU-sized
		}},

		// Downstream packet sizes: bimodal — small ACKs + large data.
		PacketSizeDown: Histogram{Bins: []Bin{
			{V: 0, W: 3},
			{V: 40, W: 8},     // ACKs
			{V: 100, W: 5},    // Small responses (204, redirects)
			{V: 200, W: 4},    // JSON snippets
			{V: 500, W: 6},    // Small HTML/JSON
			{V: 800, W: 5},    // Medium content
			{V: 1100, W: 8},   // Large content chunks
			{V: 1300, W: 12},  // Near-MTU (image/video chunks)
			{V: 1400, W: 20},  // Full MTU (bulk transfer)
			{V: 1452, W: 15},  // Jumbo-ish TLS records
		}},

		// IAT upstream: bursty with pauses (reading time).
		// Microseconds.
		IATUp: Histogram{Bins: []Bin{
			{V: 50, W: 5},        // Back-to-back (burst)
			{V: 200, W: 10},      // Fast burst
			{V: 1000, W: 15},     // 1ms — intra-request
			{V: 5000, W: 12},     // 5ms — between objects
			{V: 20000, W: 10},    // 20ms — page load gaps
			{V: 100000, W: 8},    // 100ms — inter-page think time
			{V: 500000, W: 5},    // 500ms — reading
			{V: 2000000, W: 3},   // 2s — longer pause
			{V: 5000000, W: 2},   // 5s — tab idle
		}},

		// IAT downstream: server responds fast, then gaps.
		IATDown: Histogram{Bins: []Bin{
			{V: 30, W: 8},        // Back-to-back TCP segments
			{V: 100, W: 15},      // Fast burst from server
			{V: 500, W: 12},      // Pipelined responses
			{V: 2000, W: 10},     // 2ms — between objects
			{V: 10000, W: 8},     // 10ms — server processing
			{V: 50000, W: 6},     // 50ms — CDN latency
			{V: 200000, W: 4},    // 200ms — slow server
			{V: 1000000, W: 3},   // 1s — idle
		}},

		// Burst size: how many packets in a burst.
		BurstSize: Histogram{Bins: []Bin{
			{V: 1, W: 15},   // Single packet
			{V: 2, W: 12},   // Pair
			{V: 3, W: 10},   // Small burst
			{V: 5, W: 8},    // Medium burst
			{V: 8, W: 6},    // Larger burst
			{V: 12, W: 4},   // Image load
			{V: 20, W: 3},   // Big object
			{V: 40, W: 2},   // Video chunk
			{V: 80, W: 1},   // Large download burst
		}},

		// Burst gap: milliseconds between bursts.
		BurstGap: Histogram{Bins: []Bin{
			{V: 5, W: 8},      // Near-continuous
			{V: 20, W: 12},    // Fast page load
			{V: 50, W: 10},    // Normal browsing
			{V: 100, W: 8},    // Think time
			{V: 300, W: 6},    // Reading
			{V: 1000, W: 5},   // 1s pause
			{V: 3000, W: 3},   // Longer pause
			{V: 10000, W: 2},  // Idle
		}},

		// Connection lifetime: seconds. HTTPS connections are kept alive
		// but eventually closed. We rotate to avoid long-lived flows
		// which are a VPN fingerprint.
		ConnLifetime: Histogram{Bins: []Bin{
			{V: 30, W: 5},    // Short API call
			{V: 60, W: 8},    // Quick browse
			{V: 120, W: 10},  // 2 min session
			{V: 300, W: 12},  // 5 min — typical browse
			{V: 600, W: 8},   // 10 min
			{V: 900, W: 5},   // 15 min
			{V: 1800, W: 3},  // 30 min
		}},

		// Asymmetry: typical web browsing is ~5:1 download:upload.
		AsymmetryRatio: 5.0,
	}
}
