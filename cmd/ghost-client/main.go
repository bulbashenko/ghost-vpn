// Command ghost-client is the GHOST VPN client.
//
// It connects to a ghost-server via TLS (uTLS Chrome fingerprint),
// authenticates with Noise IK inside HTTP/2, and bridges the tunnel
// to a local TUN interface.
//
// Connection rotation:
//   The client periodically rebuilds the underlying TCP/TLS connection
//   (interval ~ ConnLifetimeSec ± 30%) so that the wire pattern matches
//   real browsers (many short HTTP/2 connections) rather than a single
//   long-lived flow (the textbook VPN signal exploited by ТСПУ ML
//   classifiers). Migration is hitless: a new connection is established
//   and TUN traffic is atomically switched to it before the old one
//   closes.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bulbashenko/ghost/internal/auth"
	"github.com/bulbashenko/ghost/internal/camouflage"
	"github.com/bulbashenko/ghost/internal/config"
	ghostcrypto "github.com/bulbashenko/ghost/internal/crypto"
	"github.com/bulbashenko/ghost/internal/mux"
	"github.com/bulbashenko/ghost/internal/profile"
	"github.com/bulbashenko/ghost/internal/shaper"
	"github.com/bulbashenko/ghost/internal/transport"
	"github.com/bulbashenko/ghost/internal/tun"
	"github.com/bulbashenko/ghost/internal/version"
)

// tunnelSession holds everything we need to write into / tear down one
// tunnel connection. Each rotation produces a new tunnelSession.
type tunnelSession struct {
	id        uint64    // monotonic — increases on every rotation
	conn      io.Closer // raw TLS conn
	tunnelCnn io.Closer // HTTP/2 stream
	coalesced *shaper.CoalescingConn
	muxConn   *mux.Conn
	stream    *mux.Stream
	shaperL5  *shaper.Shaper // L5 shaper, may be nil if disabled
	closed    chan struct{}
}

func (s *tunnelSession) close() {
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}
	if s.shaperL5 != nil {
		s.shaperL5.Stop()
	}
	if s.stream != nil {
		_ = s.stream.Close()
	}
	if s.muxConn != nil {
		_ = s.muxConn.Close()
	}
	if s.coalesced != nil {
		_ = s.coalesced.Close()
	}
	if s.tunnelCnn != nil {
		_ = s.tunnelCnn.Close()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

func main() {
	var (
		configPath  = flag.String("config", "/etc/ghost/client.yaml", "path to YAML config")
		showVersion = flag.Bool("version", false, "print version and exit")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("ghost-client %s (protocol v%d)\n", version.Version, version.Protocol)
		return
	}

	var lvl slog.Level
	switch *logLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(logger)

	cfg, err := config.LoadClient(*configPath)
	if err != nil {
		logger.Error("config load failed", "error", err)
		os.Exit(1)
	}
	camouflage.SetTunnelPath(cfg.TunnelPath)

	// Load the L5 traffic profile. An explicit profile_path overrides
	// the built-in generic-HTTPS distribution; failure to read it is
	// fatal because the operator clearly intended a specific profile.
	var prof *profile.Profile
	if cfg.ProfilePath != "" {
		prof, err = profile.Load(cfg.ProfilePath)
		if err != nil {
			logger.Error("load profile", "path", cfg.ProfilePath, "error", err)
			os.Exit(1)
		}
	} else {
		prof = profile.DefaultProfile()
	}

	logger.Info("config loaded",
		"server", cfg.ServerAddr,
		"sni", cfg.SNI,
		"front_host", cfg.FrontHostOrSNI(),
		"conn_lifetime_sec", cfg.ConnLifetime(),
		"tunnel_path", camouflage.TunnelPath,
		"profile", prof.Name,
	)

	privBytes, err := auth.DecodeKey(cfg.PrivateKey)
	if err != nil {
		logger.Error("decode private key", "error", err)
		os.Exit(1)
	}
	clientKP, err := auth.KeypairFromPrivate(privBytes)
	if err != nil {
		logger.Error("derive keypair", "error", err)
		os.Exit(1)
	}
	logger.Info("client identity", "public_key", auth.EncodeKey(clientKP.Public))

	serverPub, err := auth.DecodeKey(cfg.ServerPublicKey)
	if err != nil {
		logger.Error("decode server public key", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TUN device — stays alive across all rotations.
	tunDev, err := tun.New(&tun.Config{
		Name:    cfg.TUN.Name,
		Address: cfg.TUN.Address,
		MTU:     cfg.TUN.MTU,
	})
	if err != nil {
		logger.Error("tun create", "error", err)
		os.Exit(1)
	}
	defer tunDev.Close()
	logger.Info("tun device created", "name", tunDev.Name(), "address", cfg.TUN.Address)

	// Active session — atomic pointer so the TUN→stream goroutine can
	// always grab the latest one without locking on the hot path.
	var activeSession atomic.Pointer[tunnelSession]
	var sessionCounter atomic.Uint64

	establish := func(parent context.Context) (*tunnelSession, error) {
		id := sessionCounter.Add(1)
		log := logger.With("session", id)

		// Two contexts:
		//   dialCtx — short timeout, cancelled the moment establish()
		//             returns; used ONLY for the TLS handshake which
		//             must complete by then.
		//   reqCtx  — derived from parent, lives as long as the session.
		//             The HTTP/2 streaming POST that carries the tunnel
		//             must NOT be tied to dialCtx, otherwise its body
		//             closes the moment establish() returns and the
		//             tunnel dies after ~1 round trip. (This was the
		//             reconnect-every-2-seconds bug.)
		dialCtx, dialCancel := context.WithTimeout(parent, 15*time.Second)
		defer dialCancel()

		log.Info("connecting", "addr", cfg.ServerAddr, "sni", cfg.SNI)
		conn, err := transport.Dial(dialCtx, &transport.DialerConfig{
			ServerAddr:  cfg.ServerAddr,
			SNI:         cfg.SNI,
			Fingerprint: transport.Fingerprint(cfg.Fingerprint),
		})
		if err != nil {
			return nil, fmt.Errorf("tls dial: %w", err)
		}

		state := conn.ConnectionState()
		log.Info("tls connected",
			"version", fmt.Sprintf("%#x", state.Version),
			"alpn", state.NegotiatedProtocol,
			"server_name", state.ServerName,
		)

		initiator, err := auth.NewInitiator(clientKP, serverPub)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("noise initiator: %w", err)
		}
		msg1, err := initiator.WriteMessage(nil)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("noise msg1: %w", err)
		}

		// Use parent ctx (long-lived) for the streaming POST so it
		// stays open across the entire session lifetime.
		msg2, tunnelCnn, err := camouflage.Handshake(parent, conn, &camouflage.ClientConfig{
			Host:      cfg.FrontHostOrSNI(),
			UserAgent: cfg.UserAgent,
		}, msg1)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("tunnel handshake: %w", err)
		}

		_, session, err := initiator.ReadMessage(msg2)
		if err != nil {
			tunnelCnn.Close()
			conn.Close()
			return nil, fmt.Errorf("noise msg2: %w", err)
		}
		log.Info("noise handshake complete")

		// Wrap the tunnel byte stream in per-frame Noise AEAD. From this
		// point on every byte the L4 mux writes is sealed with
		// ChaCha20-Poly1305 keyed by the IK-derived session — protecting
		// against a co-located passive observer that has stripped TLS
		// (e.g. a CDN-side attacker on the Helsinki origin path).
		sealed := ghostcrypto.New(tunnelCnn, session)

		coalesced := shaper.NewCoalescingConn(sealed, shaper.CoalesceConfig{
			FlushInterval: 8 * time.Millisecond,
			FlushBytes:    1300,
			MinPaddedSize: 1100,
			MaxPaddedSize: 1450,
			CoverInterval: 25 * time.Second,
		})

		muxConn := mux.NewConn(coalesced, true, nil)
		stream, err := muxConn.OpenStream()
		if err != nil {
			coalesced.Close()
			tunnelCnn.Close()
			conn.Close()
			return nil, fmt.Errorf("open stream: %w", err)
		}
		log.Info("tunnel stream opened", "stream_id", stream.ID())

		// L5 shaper: profile-driven cover traffic and asymmetry padding.
		// Mux already runs its own ping loop for liveness; the shaper's
		// keepalive is redundant but harmless and runs at the same 30s
		// cadence. The valuable bit is paddingLoop() which keeps the
		// download:upload byte ratio close to the profile's target
		// (5:1 for generic HTTPS).
		sh := shaper.New(muxConn, &shaper.Config{
			Profile: prof,
			Enabled: true,
		})
		sh.Start()

		return &tunnelSession{
			id:        id,
			conn:      conn,
			tunnelCnn: tunnelCnn,
			coalesced: coalesced,
			muxConn:   muxConn,
			stream:    stream,
			shaperL5:  sh,
			closed:    make(chan struct{}),
		}, nil
	}

	// Initial connection.
	sess, err := establish(ctx)
	if err != nil {
		logger.Error("initial connect failed", "error", err)
		os.Exit(1)
	}
	activeSession.Store(sess)
	logger.Info("tunnel active — routing traffic through GHOST",
		"session", sess.id,
		"rotation_sec", cfg.ConnLifetime(),
	)

	// TUN → active stream pipeline. Split into two goroutines with a
	// bounded packet channel between them so that TUN.Read is never
	// blocked by a slow mux stream.Write (which can stall on HTTP/2 flow
	// control). When the channel is full packets are dropped explicitly;
	// explicit drops are always better than stalling TUN.Read and letting
	// the kernel silently discard packets from its own queue.
	const tunClientQueue = 512
	tunPktCh := make(chan []byte, tunClientQueue)
	tunReadCancel := make(chan struct{})

	// Reader goroutine: TUN → channel (never blocks on stream.Write).
	go func() {
		defer close(tunPktCh)
		buf := make([]byte, tunDev.MTU()+100)
		for {
			n, rerr := tunDev.Read(buf)
			if rerr != nil {
				select {
				case <-tunReadCancel:
				default:
					logger.Error("tun read", "error", rerr)
				}
				return
			}
			if n == 0 {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case <-tunReadCancel:
				return
			default:
			}
			select {
			case tunPktCh <- pkt:
			default:
				// Queue full: drop. TCP will retransmit.
			}
		}
	}()

	// Writer goroutine: channel → active mux stream (may block on Write,
	// that's fine — TUN.Read is not affected).
	go func() {
		for pkt := range tunPktCh {
			// Try to write to active session; if it fails (session rotated
			// out mid-write), retry with the new active session.
			for retries := 0; retries < 3; retries++ {
				cur := activeSession.Load()
				if cur == nil {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				if _, werr := cur.stream.Write(pkt); werr != nil {
					if cur != activeSession.Load() {
						// Old session closed during write — the active
						// pointer already points to the new one, retry.
						continue
					}
					// Real failure on the active session; will be replaced
					// soon by the rotation loop or reconnect watchdog.
					time.Sleep(20 * time.Millisecond)
					continue
				}
				break
			}
		}
	}()

	// Per-session: stream → TUN goroutine. Spawned for each new session;
	// dies when the session closes. We can't share a single goroutine
	// because each session's stream is a distinct mux.Stream object.
	startStreamReader := func(s *tunnelSession) {
		go func() {
			defer logger.Debug("stream reader exit", "session", s.id)
			buf := make([]byte, tunDev.MTU()+100)
			for {
				n, rerr := s.stream.Read(buf)
				if rerr != nil {
					return
				}
				if n == 0 {
					continue
				}
				if _, werr := tunDev.Write(buf[:n]); werr != nil {
					logger.Debug("tun write error", "error", werr, "session", s.id)
					// Don't return — kernel may reject single bad packets.
				}
			}
		}()
	}
	startStreamReader(sess)

	// Rotation loop: every ~ConnLifetime seconds, build a new session,
	// swap it in, then close the old one after a grace period.
	rotationDone := make(chan struct{})
	if cfg.ConnLifetime() > 0 {
		go func() {
			defer close(rotationDone)
			for {
				base := time.Duration(cfg.ConnLifetime()) * time.Second
				// jitter ±30% so rotation doesn't appear as a periodic
				// signal in itself
				jitter := time.Duration(mathrand.Int63n(int64(base * 6 / 10)))
				wait := base*7/10 + jitter
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}

				logger.Info("rotating tunnel connection", "after", wait.Round(time.Second))

				newSess, err := establish(ctx)
				if err != nil {
					logger.Warn("rotation: establish failed, will retry", "error", err)
					// Keep the old session active; try again sooner.
					time.Sleep(5 * time.Second)
					continue
				}

				old := activeSession.Swap(newSess)
				startStreamReader(newSess)
				logger.Info("rotation complete — new session active",
					"new_session", newSess.id,
					"old_session", old.id,
				)

				// Drain old connection for a short grace period so any
				// in-flight packets finish, then close it.
				go func(s *tunnelSession) {
					time.Sleep(3 * time.Second)
					s.close()
				}(old)
			}
		}()
	}

	// Watchdog: if the active session dies (server kicked us, network
	// blip), reconnect immediately rather than waiting for next rotation.
	// Give a 5-second grace window after each session swap so the rotation
	// loop's own swap doesn't race with this watchdog.
	go func() {
		sessionStart := make(map[uint64]time.Time)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			cur := activeSession.Load()
			if cur == nil {
				continue
			}
			if _, seen := sessionStart[cur.id]; !seen {
				sessionStart[cur.id] = time.Now()
				continue
			}
			// Grace period: don't trip on a session younger than 5s.
			if time.Since(sessionStart[cur.id]) < 5*time.Second {
				continue
			}
			select {
			case <-cur.muxConn.Done():
				logger.Warn("active session died, reconnecting", "session", cur.id)
				newSess, err := establish(ctx)
				if err != nil {
					logger.Error("reconnect failed", "error", err)
					time.Sleep(5 * time.Second)
					continue
				}
				old := activeSession.Swap(newSess)
				startStreamReader(newSess)
				logger.Info("reconnected", "new_session", newSess.id)
				if old != nil {
					old.close()
				}
			default:
				// still alive
			}
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	close(tunReadCancel)
	if cur := activeSession.Load(); cur != nil {
		cur.close()
	}
}
