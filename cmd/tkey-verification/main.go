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

// Define this to point to the current vendor signing public
// key by setting it to the hash of the binary that was used
// for signatures.
const currentVendorHash = "f8ecdcda53a296636a0297c250b27fb649860645626cc8ad935eabb4c43ea3e1841c40300544fade4189aa4143c1ca8fe82361e3d874b42b0e2404793a170142"

// Hash of latest signer, to be used for new vendor signing
const latestAppHash = "cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4"

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
		conf := loadServeSignerConfig(configFile)
		serveSigner(conf, devPath, verbose, checkConfigOnly)

	case "remote-sign":
		if configFile == "" {
			configFile = defaultConfigFile
		}
		server := loadRemoteSignConfig(configFile)

		if checkConfigOnly {
			os.Exit(0)
		}

		remoteSign(server, devPath, verbose)

	case "sign-challenge":
		_, udi, pubKey, _, err := signChallenge(devPath, verbose)
		if err != nil {
			le.Printf("Couldn't sign challenge: %v\n", err)
			os.Exit(2)
		}

		le.Printf("TKey UDI: %s\n", udi.String())
		le.Printf("Device app public key: %x\n", pubKey)

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
