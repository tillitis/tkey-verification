// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/pflag"
	"github.com/tillitis/tkeyclient"
)

const progname = "tkey-verify"

const (
	defaultBaseURL = "https://tkey.tillitis.se/verify"
)

// Use when printing err/diag msgs
var le = log.New(os.Stderr, "", 0)

type Device struct {
	Path  string
	Speed int
}

func main() {
	var dev Device
	var baseURL, baseDir string
	var sigsum, verbose, showURLOnly, versionOnly, build, helpOnly bool

	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.StringVar(&dev.Path, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	pflag.IntVarP(&dev.Speed, "speed", "s", tkeyclient.SerialSpeed,
		"Set serial port `speed` in bits per second.")
	pflag.BoolVar(&verbose, "verbose", false,
		"Enable verbose output.")
	pflag.BoolVarP(&showURLOnly, "show-url", "u", false,
		"Only output the URL to the verification data that should be downloaded.")
	pflag.StringVarP(&baseDir, "base-dir", "d", "",
		"Read verification data from a file located in `DIRECTORY` and named after the TKey UDI in hex, instead of from a URL. You can for example first use \"verify --show-url\" and download the verification file manually on some other computer, then transfer the file back and use \"verify --base-dir .\".")
	pflag.StringVar(&baseURL, "base-url", defaultBaseURL,
		"Set the base `URL` of verification server for fetching verification data.")
	pflag.BoolVar(&sigsum, "sigsum", false,
		"Demand a Sigsum proof in the verification file (command: verify).")
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
		fmt.Printf("%s\n", progname)
		os.Exit(0)
	}

	// if build {
	// 	builtWith()
	// 	os.Exit(0)
	// }

	if baseDir != "" && (showURLOnly || pflag.CommandLine.Lookup("base-url").Changed) {
		le.Printf("Cannot combine --base-dir and --show-url/--base-url\n")
		os.Exit(2)
	}

	if showURLOnly {
		verifyShowUrl(dev, baseURL)
	}

	verify(dev, verbose, baseDir, baseURL, sigsum)
}

func usage() {
	desc := fmt.Sprintf(`Usage: %s [flags...]

Verify that a TKey is genuine by extracting the TKey UDI and using it
to fetch the verification data, including tag and signature from the
web. Then running the correct verisigner-app on the TKey, extracting
the public key and verifying it using the vendor's signing public key.

The flags --show-url and --base-dir can be used to show the URL for
downloading the verification data on one machine, and verifying the
TKey on another machine that lacks network, see more below.
`, progname)

	le.Printf("%s\n\nFlags:\n%s\n", desc, pflag.CommandLine.FlagUsagesWrapped(86))
}
