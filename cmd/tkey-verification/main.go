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

// Note: this must be set at build time to the Tag of signer-app that
// is to run on the TKey device under verification (running command
// remote-sign; for command verify, the tag in the verification data
// is used). The signer-app should be built with
// TKEY_SIGNER_APP_NO_TOUCH=yes
var Tag = ""

const signaturesDir = "signatures"

const (
	defaultBaseURL    = "https://example.com/verify"
	defaultConfigFile = "./tkey-verification.yaml"
)

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
		le.Printf("Found no usable embedded vendor signing public key\n")
		os.Exit(1)
	}

	var devPath, baseURL, baseDir, configFile string
	var checkConfigOnly, verbose, showURLOnly bool

	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.StringVar(&devPath, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	pflag.BoolVar(&verbose, "verbose", false,
		"Enable verbose output.")
	pflag.StringVar(&configFile, "config", defaultConfigFile,
		"`PATH` to configuration file (commands: serve-signer, remote-sign).")
	pflag.BoolVar(&checkConfigOnly, "check-config", false,
		"Only check that the configuration is usable, then exit (commands: serve-signer, remote-sign).")
	pflag.BoolVarP(&showURLOnly, "show-url", "u", false,
		"Only output the URL to the verification data that should be downloaded (command: verify).")
	pflag.StringVarP(&baseDir, "base-dir", "d", "",
		"Read verification data from a file located in `DIRECTORY` and named after the TKey UDI in hex, instead of from a URL. You can for example first use \"verify --show-url\" and download the verification file manually on some other computer, then transfer the file back and use \"verify --base-dir .\" (command: verify).")
	pflag.StringVar(&baseURL, "base-url", defaultBaseURL,
		"Set the base `URL` of verification server for fetching verification data (command: verify).")
	pflag.Usage = func() {
		desc := fmt.Sprintf(`Usage: tkey-verification command [flags...]

Supported signer-app tags: %s
Signer-app tag for device signing: %s
%s

Commands:
  serve-signer  TODO write...

  remote-sign   TODO write...

  verify        Verify that a TKey is genuine by extracting the TKey UDI and using it
                to fetch the verification data, including tag and signature from the
                web. Then running the correct signer-app on the TKey, extracting the
                public key and verifying it using the vendor's signing public key.

                The flags --show-url and --base-dir can be used to show the URL for
                downloading the verification data on one machine, and verifying the
                TKey on another machine that lacks network, see more below.`,
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

	cmd := pflag.Args()[0]

	// Use Lookup to tell if user changed string with default value
	if cmd == "verify" && (pflag.CommandLine.Lookup("config").Changed || checkConfigOnly) {
		le.Printf("Cannot use --config/--check-config with this command.\n")
		os.Exit(2)
	}
	if cmd != "verify" && (showURLOnly || baseDir != "" || pflag.CommandLine.Lookup("base-url").Changed) {
		le.Printf("Cannot use --show-url/--base-dir/--base-url with this command.\n")
		os.Exit(2)
	}

	// Command funcs exit to OS themselves for now
	switch cmd {
	case "serve-signer":
		conf := loadServeSignerConfig(configFile)
		if err != nil {
			le.Printf("Couldn't read config file %v: %v\n", configFile, err)
			os.Exit(1)
		}
		serveSigner(conf, vendorPubKey, devPath, verbose, checkConfigOnly)

	case "remote-sign":
		if configFile == "" {
			configFile = defaultConfigFile
		}
		conf := loadRemoteSignConfig(configFile)
		remoteSign(conf, deviceSignerApp, devPath, verbose, checkConfigOnly)

	case "verify":
		if baseDir != "" && (showURLOnly || pflag.CommandLine.Lookup("base-url").Changed) {
			le.Printf("Cannot combine --base-dir and --show-url/--base-url\n")
			os.Exit(2)
		}
		verify(devPath, verbose, showURLOnly, baseDir, baseURL)

	default:
		le.Printf("%s is not a valid command.\n", cmd)
		pflag.Usage()
		os.Exit(2)
	}
}
