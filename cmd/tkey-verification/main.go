// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/vendorsigning"
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

// Note: this must be set at build time to the Tag of signer-app that
// is to run on the TKey device under verification (running command
// remote-sign; for command verify, the tag in the verification data
// is used). The signer-app should be built with
// TKEY_SIGNER_APP_NO_TOUCH=yes
var Tag = ""

const signaturesDir = "signatures"

// Use when printing err/diag msgs
var le = log.New(os.Stderr, "", 0)

func main() {
	if Tag == "" {
		le.Printf("main.Tag is empty, program is not built correctly!\n")
		os.Exit(1)
	}
	deviceSignerApp, err := appbins.Get(Tag)
	if err != nil {
		le.Printf("No AppBin for main.Tag: %s\n", err)
		os.Exit(1)
	}

	vendorPubKey := vendorsigning.GetCurrentPubKey()
	if vendorPubKey == nil {
		le.Printf("Found no usable embedded vendor signing pubkey\n")
		os.Exit(1)
	}

	var devPath string
	var checkConfigOnly, verbose bool

	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.BoolVar(&checkConfigOnly, "check-config", false,
		"Only check that the certificates/configuration can be loaded, then exit. For serve-signer and remote-sign commands.")
	pflag.StringVar(&devPath, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	pflag.BoolVar(&verbose, "verbose", false,
		"Enable verbose output.")
	pflag.Usage = func() {
		desc := fmt.Sprintf(`Usage: tkey-verification command [flags...]

Supported signer-app tags: %s
Signer-app tag for device signing: %s
%s

Commands:
  serve-signer  TODO write...
  remote-sign   TODO write...
  verify        Verify that a TKey is genuine by extracting the TKey UDI, using it
                to fetch the verification data, and then running the verification
                protocol.`,
			strings.Join(appbins.Tags(), " "), Tag, vendorPubKey.String())
		le.Printf("%s\n\n%s", desc, pflag.CommandLine.FlagUsagesWrapped(86))
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
		serveSigner(vendorPubKey, devPath, verbose, checkConfigOnly)

	case "remote-sign":
		remoteSign(deviceSignerApp, devPath, verbose, checkConfigOnly)

	case "verify":
		if checkConfigOnly {
			le.Printf("Cannot check-config for this command.\n\n")
			pflag.Usage()
			os.Exit(2)
		}
		verify(devPath, verbose)

	default:
		le.Printf("%s is not a valid command.\n", cmd)
		pflag.Usage()
		os.Exit(2)
	}
}
