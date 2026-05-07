// Command ghost-server is the GHOST VPN server.
//
// It listens for TLS connections, authenticates clients via Noise IK inside
// HTTP/2, and bridges authenticated tunnel traffic to a TUN interface.
// Unauthenticated requests are reverse-proxied to a fallback website.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bulbashenko/ghost/internal/auth"
	"github.com/bulbashenko/ghost/internal/camouflage"
	"github.com/bulbashenko/ghost/internal/config"
	ghostcrypto "github.com/bulbashenko/ghost/internal/crypto"
	"github.com/bulbashenko/ghost/internal/fallback"
	"github.com/bulbashenko/ghost/internal/mux"
	"github.com/bulbashenko/ghost/internal/profile"
	"github.com/bulbashenko/ghost/internal/shaper"
	"github.com/bulbashenko/ghost/internal/transport"
	"github.com/bulbashenko/ghost/internal/tun"
	"github.com/bulbashenko/ghost/internal/version"
)

func main() {
	var (
		configPath  = flag.String("config", "/etc/ghost/server.yaml", "path to YAML config")
		showVersion = flag.Bool("version", false, "print version and exit")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("ghost-server %s (protocol v%d)\n", version.Version, version.Protocol)
		return
	}

	// Logger.
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

	// Load config.
	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		logger.Error("config load failed", "error", err)
		os.Exit(1)
	}
	camouflage.SetTunnelPath(cfg.TunnelPath)

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
		"listen", cfg.Listen,
		"fallback", cfg.FallbackTarget,
		"tunnel_path", camouflage.TunnelPath,
		"profile", prof.Name,
	)

	// Decode server static keypair.
	privBytes, err := auth.DecodeKey(cfg.PrivateKey)
	if err != nil {
		logger.Error("decode private key", "error", err)
		os.Exit(1)
	}
	serverKP, err := auth.KeypairFromPrivate(privBytes)
	if err != nil {
		logger.Error("derive keypair", "error", err)
		os.Exit(1)
	}
	logger.Info("server identity", "public_key", auth.EncodeKey(serverKP.Public))

	// Build allowed client keys set.
	allowedClients := make(map[string]bool, len(cfg.AllowedClients))
	for _, k := range cfg.AllowedClients {
		allowedClients[k] = true
	}

	// Fallback reverse proxy.
	fb, err := fallback.New(cfg.FallbackTarget)
	if err != nil {
		logger.Error("fallback proxy", "error", err)
		os.Exit(1)
	}
	logger.Info("fallback target", "url", fb.Target().String())

	// TUN device.
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

	// Single TUN reader that dispatches packets to per-client channels by
	// destination IP. Without this, concurrent tun.Bridge() goroutines race
	// on dev.Read() and ~50% of packets for each client land in the wrong
	// session when multiple clients are connected simultaneously.
	tunRouter := tun.NewTunRouter(tunDev)

	// Enable IP forwarding and NAT.
	subnet, err := tun.SubnetFromAddress(cfg.TUN.Address)
	if err != nil {
		logger.Error("parse subnet", "error", err)
		os.Exit(1)
	}
	if err := tun.EnableIPForward(); err != nil {
		logger.Warn("ip forwarding", "error", err)
	}
	if err := tun.SetupNAT(subnet); err != nil {
		logger.Warn("NAT setup", "error", err)
	}
	defer tun.CleanupNAT(subnet)

	// activeSessions maps client_pubkey → currently-active server session.
	// When a new auth comes in from the same pubkey (because the client
	// rotated its TCP/TLS connection for DPI evasion), we close the old
	// session BEFORE starting the new one. Otherwise the old session's
	// bridge goroutine keeps reading from the shared TUN device and steals
	// reply packets from the new session — Helsinki→Moscow data path
	// breaks 100%.
	type serverSession struct {
		closeOnce sync.Once
		coalesced *shaper.CoalescingConn
		muxConn   *mux.Conn
		shaperL5  *shaper.Shaper
		pipe1R    *io.PipeReader
		pipe1W    *io.PipeWriter
		pipe2R    *io.PipeReader
		pipe2W    *io.PipeWriter
	}
	closeSession := func(s *serverSession) {
		s.closeOnce.Do(func() {
			if s.shaperL5 != nil {
				s.shaperL5.Stop()
			}
			if s.muxConn != nil {
				_ = s.muxConn.Close()
			}
			if s.coalesced != nil {
				_ = s.coalesced.Close()
			}
			// Closing the pipes terminates the HTTP bridge io.Copy loops,
			// which in turn lets the HTTP/2 stream complete cleanly.
			if s.pipe1W != nil {
				_ = s.pipe1W.Close()
			}
			if s.pipe2W != nil {
				_ = s.pipe2W.Close()
			}
			if s.pipe1R != nil {
				_ = s.pipe1R.Close()
			}
			if s.pipe2R != nil {
				_ = s.pipe2R.Close()
			}
		})
	}

	var sessionsMu sync.Mutex
	activeSessions := make(map[string]*serverSession)

	// Auth callback for the camouflage layer.
	onAuth := func(msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
		resp, err := auth.NewResponder(serverKP)
		if err != nil {
			return nil, nil, err
		}

		_, err = resp.ReadMessage(msg1)
		if err != nil {
			return nil, nil, err
		}

		clientPub := auth.EncodeKey(resp.PeerStatic())

		// Check allowed clients list.
		if len(allowedClients) > 0 {
			if !allowedClients[clientPub] {
				return nil, nil, fmt.Errorf("client not in allowed list")
			}
		}

		msg2, session, err := resp.WriteMessage(nil)
		if err != nil {
			return nil, nil, err
		}

		// Kick out any prior session for this client. The old session's
		// bridge goroutine will exit once its TUN-read loop notices the
		// stream is gone (next read or write fails).
		sessionsMu.Lock()
		if old := activeSessions[clientPub]; old != nil {
			logger.Info("kicking previous session for client",
				"client_pubkey", clientPub,
			)
			closeSession(old)
		}

		// Create two pipes for bidirectional data flow:
		//   pipe1: HTTP(write) → mux(read)   (client→server data)
		//   pipe2: mux(write) → HTTP(read)    (server→client data)
		pipe1R, pipe1W := io.Pipe() // HTTP writes, mux reads
		pipe2R, pipe2W := io.Pipe() // mux writes, HTTP reads

		// Per-frame Noise AEAD around the byte stream that L4 mux sees.
		// Server's send cipher == client's recv cipher (handled inside
		// auth.Responder.WriteMessage), so initiator/responder ordering
		// is symmetric on both ends.
		muxRW := &pipeReadWriter{r: pipe1R, w: pipe2W}
		sealed := ghostcrypto.New(muxRW, session)

		// Mux on the tunnel side: reads from sealed, writes to sealed.
		// Wrap in coalescer so multiple frames from this client get batched
		// into MTU-sized TLS records (defeats the "small uniform packets"
		// VPN fingerprint that ТСПУ uses for throttling).
		coalesced := shaper.NewCoalescingConn(sealed, shaper.CoalesceConfig{
			FlushInterval: 8 * time.Millisecond,
			FlushBytes:    1300,
			MinPaddedSize: 1100,
			MaxPaddedSize: 1450,
			CoverInterval: 25 * time.Second,
		})
		muxConn := mux.NewConn(coalesced, false, func(s *mux.Stream) {
			logger.Debug("tunnel stream opened", "stream_id", s.ID())
			if err := tunRouter.Bridge(s); err != nil {
				logger.Debug("bridge ended", "error", err)
			}
		})

		sh := shaper.New(muxConn, &shaper.Config{
			Profile: prof,
			Enabled: true,
		})
		sh.Start()

		newSess := &serverSession{
			coalesced: coalesced,
			muxConn:   muxConn,
			shaperL5:  sh,
			pipe1R:    pipe1R,
			pipe1W:    pipe1W,
			pipe2R:    pipe2R,
			pipe2W:    pipe2W,
		}
		activeSessions[clientPub] = newSess
		sessionsMu.Unlock()

		// When this session's mux dies (client disconnect, kicked, error),
		// remove it from the active map so the entry doesn't leak.
		go func() {
			<-muxConn.Done()
			sessionsMu.Lock()
			if activeSessions[clientPub] == newSess {
				delete(activeSessions, clientPub)
			}
			sessionsMu.Unlock()
		}()

		logger.Info("client authenticated",
			"client_pubkey", clientPub,
		)

		// HTTP side: writes to pipe1, reads from pipe2.
		httpRW := &pipeReadWriter{r: pipe2R, w: pipe1W}

		return msg2, httpRW, nil
	}

	// Build HTTP handler stack.
	tunnelHandler := camouflage.TunnelHandler(onAuth, fb)
	router := camouflage.NewRouter(tunnelHandler, fb)
	h2handler := camouflage.NewServer(&camouflage.ServerConfig{
		Handler: router,
	})

	// TLS listener.
	ln, err := transport.Listen(&transport.ListenerConfig{
		ListenAddr: cfg.Listen,
		CertFile:   cfg.CertFile,
		KeyFile:    cfg.KeyFile,
	})
	if err != nil {
		logger.Error("listen", "error", err)
		os.Exit(1)
	}
	defer ln.Close()
	logger.Info("listening", "addr", ln.Addr().String())

	// Graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{Handler: h2handler}
	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		srv.Close()
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}

// pipeReadWriter combines an io.Reader and io.Writer into an io.ReadWriter.
type pipeReadWriter struct {
	r io.Reader
	w io.Writer
}

func (p *pipeReadWriter) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeReadWriter) Write(b []byte) (int, error)  { return p.w.Write(b) }
func (p *pipeReadWriter) Close() error {
	if c, ok := p.r.(io.Closer); ok {
		c.Close()
	}
	if c, ok := p.w.(io.Closer); ok {
		c.Close()
	}
	return nil
}
