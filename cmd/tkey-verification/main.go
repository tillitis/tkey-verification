// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

const (
	caCertFile     = "certs/tillitis.crt"
	serverCertFile = "certs/localhost.crt"
	serverKeyFile  = "certs/localhost.key"
	clientCertFile = "certs/client.crt"
	clientKeyFile  = "certs/client.key"
	listenAddr     = "localhost:1337"
	serverAddr     = "localhost:1337"
)

// TODO we should build and provide the signer-app binary from a known
// tag T in the tillitis-key1-apps repo. This T is synchronized with a
// tag for this verification program?
const signerAppTag = "main"

// nolint:typecheck // Avoid lint error when the embedding file is missing.
//
//go:embed signing-tkey.pub
var signingPubKeyHex string
var signingPubKey []byte

// nolint:typecheck // Avoid lint error when the embedding file is missing.
//
//go:embed app.bin
var signerAppBin []byte

const signaturesDir = "signatures"

// Use when printing err/diag msgs
var le = log.New(os.Stderr, "", 0)

func main() {
	var devPath string
	var verbose bool
	var err error

	signingPubKey, err = hex.DecodeString(strings.Trim(signingPubKeyHex, "\r\n "))
	if err != nil {
		le.Printf("Failed to decode embedded signing pubkey: %s\n", err)
		os.Exit(1)
	}
	if len(signingPubKey) != ed25519.PublicKeySize {
		le.Printf("Embedded signing pubkey binary is %d bytes, expected %d\n",
			len(signingPubKey), ed25519.PublicKeySize)
		os.Exit(1)
	}

	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.StringVar(&devPath, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	pflag.BoolVar(&verbose, "verbose", false,
		"Enable verbose output.")
	pflag.Usage = func() {
		desc := fmt.Sprintf(`Usage: tkey-verification command [flags...]

Commands:
  serve-signer  TODO...
  remote-sign   TODO...
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
			le.Printf("Please pass a command: serve-signer, remote-sign, or verify\n\n")
		}
		pflag.Usage()
		os.Exit(2)
	}

	// Command funcs exit to OS themselves for now
	switch cmd := pflag.Args()[0]; cmd {
	case "serve-signer":
		serveSigner(devPath, verbose)
	case "remote-sign":
		remoteSign(devPath, verbose)
	case "verify":
		verify(devPath, verbose)
	default:
		le.Printf("%s is not a valid command.\n", cmd)
		pflag.Usage()
		os.Exit(2)
	}
}
