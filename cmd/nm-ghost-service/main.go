// Command nm-ghost-service is the NetworkManager VPN plugin for GHOST.
//
// NetworkManager starts this service via D-Bus activation when the user
// activates a Ghost VPN connection. The service implements
// org.freedesktop.NetworkManager.VPN.Plugin on the system bus, launches
// ghost-client as a subprocess, and signals Ip4Config / StateChanged back
// to NM once the TUN interface is up.
//
// Install with:
//
//	sudo make install-nm-plugin
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	ghostnm "github.com/bulbashenko/ghost/nm-plugin"
)

func main() {
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("nm-ghost-service (GHOST VPN NetworkManager plugin)")
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

	plugin, err := ghostnm.New(logger)
	if err != nil {
		logger.Error("plugin init", "error", err)
		os.Exit(1)
	}
	if err := plugin.Run(); err != nil {
		logger.Error("plugin error", "error", err)
		os.Exit(1)
	}
}
