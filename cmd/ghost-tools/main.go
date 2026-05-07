// Command ghost-tools is a multi-command utility for GHOST operators.
//
// Subcommands:
//
//	keygen   — generate Curve25519 static keypair (Noise IK)
//	version  — print build version
//	capture  — extract traffic distributions from pcap (Phase 6, TBD)
//	classify — run ML detection harness on pcap (Phase 7, TBD)
package main

import (
	"fmt"
	"os"

	"github.com/bulbashenko/ghost/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "version", "-version", "--version":
		fmt.Printf("ghost-tools %s (protocol v%d)\n", version.Version, version.Protocol)
	case "keygen":
		os.Exit(keygenCmd(args))
	case "capture", "classify":
		fmt.Fprintf(os.Stderr, "ghost-tools: %q is not implemented yet\n", cmd)
		os.Exit(1)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "ghost-tools: unknown subcommand %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: ghost-tools <command> [arguments]

Commands:
  keygen     Generate Curve25519 static keypair (Noise IK)
  version    Print build version
  capture    Extract traffic distributions from pcap (TBD)
  classify   Run ML detection harness on pcap (TBD)

Run "ghost-tools keygen -h" for subcommand flags.
`)
}
