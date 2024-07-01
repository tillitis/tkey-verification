// Copyright (C) 2022-2024 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

const progname = "tkey-verification"

const signaturesDir = "signatures"

const (
	defaultBaseURL    = "https://tkey.tillitis.se/verify"
	defaultConfigFile = "./tkey-verification.yaml"
)

var version string

// Use when printing err/diag msgs
var le = log.New(os.Stderr, "", 0)

func main() {
	var devPath, baseURL, baseDir, configFile, binPath string
	var checkConfigOnly, verbose, showURLOnly, versionOnly, build, helpOnly bool

	if version == "" {
		version = readBuildInfo()
	}

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
	pflag.StringVarP(&binPath, "app", "a", "",
		"`PATH` to the device app to show vendor signing pubkey (command: show-pubkey).")
	pflag.BoolVar(&versionOnly, "version", false, "Output version information.")
	pflag.BoolVar(&build, "build", false, "Output build data about included device apps and firmwares")
	pflag.BoolVar(&helpOnly, "help", false, "Output this help.")
	pflag.Usage = usage
	pflag.Parse()

	if helpOnly {
		pflag.Usage()
		os.Exit(0)
	}
	if versionOnly {
		fmt.Printf("%s %s\n", progname, version)
		os.Exit(0)
	}

	if build {
		builtWith()
		os.Exit(0)
	}

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
		conf, err := loadServeSignerConfig(configFile)
		if err != nil {
			le.Printf("Couldn't load config: %v\n", err)
		}

		serveSigner(conf, devPath, verbose, checkConfigOnly)

	case "remote-sign":
		conf, err := loadRemoteSignConfig(configFile)
		if err != nil {
			le.Printf("Couldn't load config: %v\n", err)
		}

		if checkConfigOnly {
			os.Exit(0)
		}

		remoteSign(conf, devPath, verbose)

	case "verify":
		if baseDir != "" && (showURLOnly || pflag.CommandLine.Lookup("base-url").Changed) {
			le.Printf("Cannot combine --base-dir and --show-url/--base-url\n")
			os.Exit(2)
		}

		verify(devPath, verbose, showURLOnly, baseDir, baseURL)

	case "show-pubkey":
		if binPath == "" {
			le.Printf("Needs the path to an app, use `--app PATH`\n")
			os.Exit(2)
		}
		showPubkey(binPath, devPath, verbose)

	default:
		le.Printf("%s is not a valid command.\n", cmd)
		pflag.Usage()
		os.Exit(2)
	}
}
