// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

// TODO we should build and provide the signer-app binary from a known
// tag T in the tillitis-key1-apps repo. This T is synchronized with a
// tag for this verification program?
const signerAppTag = "main"

const signaturesDir = "signatures"

// nolint:typecheck // Avoid lint error when the embedding file is missing.
//
//go:embed app.bin
var appBin []byte

// Use when printing err/diag msgs
var le = log.New(os.Stderr, "", 0)

func main() {
	var devPath string
	var verbose bool
	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.StringVar(&devPath, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	pflag.BoolVar(&verbose, "verbose", false,
		"Enable verbose output.")
	pflag.Usage = func() {
		desc := fmt.Sprintf(`Usage: tkey-verification command [flags...]

Commands:
  sign    Create the verification hash for a TKey and sign it with the vendor's
          signing private-key.
  verify  Verify that a TKey is genuine by recreating the hash, fetching the
          signature, and verifying it using the vendor's signing public-key.`)
		le.Printf("%s\n\n%s", desc,
			pflag.CommandLine.FlagUsagesWrapped(86))
	}
	pflag.Parse()

	if pflag.NArg() != 1 {
		if pflag.NArg() > 1 {
			le.Printf("Unexpected argument: %s\n\n", strings.Join(pflag.Args()[1:], " "))
		} else {
			le.Printf("Please pass a command: sign or verify\n\n")
		}
		pflag.Usage()
		os.Exit(2)
	}

	// Command funcs exit to OS themselves for now
	switch cmd := pflag.Args()[0]; cmd {
	case "sign":
		sign(devPath, verbose, appBin)
	case "verify":
		verify(devPath, verbose, appBin)
	default:
		le.Printf("%s is not a valid command.\n", cmd)
		pflag.Usage()
		os.Exit(2)
	}
}
