package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bulbashenko/ghost/internal/auth"
)

// keygenCmd implements `ghost-tools keygen`.
//
// By default it prints a fresh Curve25519 keypair to stdout in a YAML-friendly
// two-line form:
//
//	private: <base64>
//	public:  <base64>
//
// With -public-only, only the public key is printed (useful when piping a
// server's public key to a client config).
//
// With -out <path>, the private key is written to <path> (mode 0600) and
// the public key to <path>.pub (mode 0644). Matches the WireGuard ergonomics.
func keygenCmd(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: ghost-tools keygen [flags]

Generates a fresh Curve25519 keypair (Noise IK static key) and prints it.

Flags:
  -out PATH        Write private key to PATH and public key to PATH.pub.
                   Without -out, keys are printed to stdout.
  -public-only     Print only the public key (ignored when -out is set).
`)
	}

	var (
		outPath    string
		publicOnly bool
	)
	fs.StringVar(&outPath, "out", "", "write keys to files rooted at this path")
	fs.BoolVar(&publicOnly, "public-only", false, "print only the public key")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "ghost-tools keygen: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	kp, err := auth.GenerateKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-tools keygen: %v\n", err)
		return 1
	}

	priv := auth.EncodeKey(kp.Private)
	pub := auth.EncodeKey(kp.Public)

	if outPath != "" {
		if err := writeKeyFile(outPath, priv, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "ghost-tools keygen: %v\n", err)
			return 1
		}
		if err := writeKeyFile(outPath+".pub", pub, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "ghost-tools keygen: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "wrote %s (mode 0600)\nwrote %s.pub (mode 0644)\n", outPath, outPath)
		return 0
	}

	return printKeys(os.Stdout, priv, pub, publicOnly)
}

func writeKeyFile(path, contents string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := io.WriteString(f, contents+"\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

func printKeys(w io.Writer, priv, pub string, publicOnly bool) int {
	if publicOnly {
		fmt.Fprintln(w, pub)
		return 0
	}
	fmt.Fprintf(w, "private: %s\npublic:  %s\n", priv, pub)
	return 0
}
