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
	var verbose, helpOnly bool

	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.StringVar(&devPath, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	pflag.BoolVar(&verbose, "verbose", false,
		"Enable verbose output.")
	pflag.BoolVar(&helpOnly, "help", false, "Output this help.")
	pflag.Usage = func() {
		le.Printf(`Usage: show-pubkey [flags...] TAG

Flags:
%s

Supported verisigner-app tags: %s

`, pflag.CommandLine.FlagUsagesWrapped(86), strings.Join(appbins.Tags(), " "))
	}
	pflag.Parse()

	if helpOnly {
		pflag.Usage()
		os.Exit(0)
	}

	if pflag.NArg() > 1 {
		le.Printf("Unexpected argument: %s\n\n", strings.Join(pflag.Args()[1:], " "))
		pflag.Usage()
		os.Exit(2)
	}

	if pflag.NArg() < 1 {
		le.Printf("Please pass tag of the verisigner-app to run when extracting the public key.\n"+
			"Supported tags:\n%s\n", strings.Join(appbins.Tags(), " \n"))
		os.Exit(2)
	}

	tag := pflag.Args()[0]

	appBin, err := appbins.GetByTagOnly(tag)
	if err != nil {
		le.Printf("Getting embedded verisigner-app failed: %s\n", err)
		os.Exit(1)
	}

	udi, pubKey, ok := tkey.Load(appBin, devPath, verbose)
	if !ok {
		os.Exit(1)
	}
	le.Printf("TKey UDI: %s\n", udi.String())

	le.Printf("Public Key, app tag, and app hash (for vendor-signing-pubkeys.txt) follows on stdout:\n")
	fmt.Printf("%s %s %s\n", hex.EncodeToString(pubKey), tag, hex.EncodeToString(appBin.Hash()))
	os.Exit(0)
}
