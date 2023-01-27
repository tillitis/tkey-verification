// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/tkey"
)

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
		desc := fmt.Sprintf(`Usage: show-pubkey [flags...]`)
		le.Printf("%s\n\n%s", desc, pflag.CommandLine.FlagUsagesWrapped(86))
	}
	pflag.Parse()

	if pflag.NArg() > 1 {
		le.Printf("Unexpected argument: %s\n\n", strings.Join(pflag.Args()[1:], " "))
		pflag.Usage()
		os.Exit(2)
	}

	if pflag.NArg() < 1 {
		le.Printf("Please pass tag of the signer-app to run when extracting the public key.\n"+
			"Supported tags: %s\n", strings.Join(appbins.Tags(), " "))
		os.Exit(2)
	}

	appBin, err := appbins.Get(pflag.Args()[0])
	if err != nil {
		le.Printf("Failed: %s\n", err)
		le.Printf("Supported tags: %s\n", strings.Join(appbins.Tags(), " "))
		os.Exit(1)
	}

	udiBE, pubKey, ok := tkey.Load(appBin, devPath, verbose)
	if !ok {
		os.Exit(1)
	}
	le.Printf("TKey UDI(BE): %s\n", hex.EncodeToString(udiBE))

	le.Printf("Public Key follows on stdout:\n")
	fmt.Printf("%s\n", hex.EncodeToString(pubKey))
	os.Exit(0)
}
