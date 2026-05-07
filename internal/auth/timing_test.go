package auth

import (
	"crypto/rand"
	"testing"
)

// Constant-time discipline test (Principle 4).
//
// We benchmark the responder's auth path on the two cases an active prober
// can put it in:
//
//   BenchmarkAuthValid   — well-formed Noise IK msg1 from a legitimate client
//   BenchmarkAuthInvalid — random garbage of the same length
//
// The plan target is <5% delta between the two means. We do not assert that
// here (microbenchmark variance + GC noise makes a hard threshold flaky in
// CI), but the numbers are reported every run so timing regressions are
// visible. For a strict check, run:
//
//   go test -bench=BenchmarkAuth -benchtime=2s ./internal/auth/...
//
// and compare ns/op manually. For statistically rigorous timing analysis,
// use a tool like `dudect` against a release build.

func benchmarkAuth(b *testing.B, validMsg bool) {
	b.Helper()

	clientKP, _ := GenerateKeypair()
	serverKP, _ := GenerateKeypair()

	// Pre-build a valid msg1 to use as a template, so we know its exact length.
	init, _ := NewInitiator(clientKP, serverKP.Public)
	good, err := init.WriteMessage(make([]byte, 64))
	if err != nil {
		b.Fatal(err)
	}
	garbage := make([]byte, len(good))
	if _, err := rand.Read(garbage); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Fresh responder per iteration: ReadMessage mutates handshake state.
		resp, _ := NewResponder(serverKP)
		if validMsg {
			// Re-derive a fresh valid msg1 every K iterations to avoid the
			// CipherState ratcheting effect from reusing the same initiator.
			// We use the precomputed `good` payload — IK msg1 is bound to a
			// fresh ephemeral so reusing the same bytes is fine for timing
			// purposes (server still does the full DH).
			_, _ = resp.ReadMessage(good)
		} else {
			_, _ = resp.ReadMessage(garbage)
		}
	}
}

func BenchmarkAuthValid(b *testing.B)   { benchmarkAuth(b, true) }
func BenchmarkAuthInvalid(b *testing.B) { benchmarkAuth(b, false) }
