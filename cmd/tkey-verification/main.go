// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/pflag"
	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/firmwares"
	"github.com/tillitis/tkey-verification/internal/vendorsigning"
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
	if version == "" {
		version = readBuildInfo()
	}

	deviceSignAppBin, err := appbins.GetDeviceSigner()
	if err != nil {
		le.Printf("Fail to get verisigner-app for device signing: %s\n", err)
		os.Exit(1)
	}

	vendorPubKey := vendorsigning.GetCurrentPubKey()
	if vendorPubKey == nil {
		le.Printf("Found no usable embedded vendor signing public key\n")
		os.Exit(1)
	}

	builtWith := fmt.Sprintf(`Built with:
Supported verisigner-app tags:
  %s
Device signing using:
  %s
Vendor signing:
  %s
Known firmwares:
  %s
`,
		strings.Join(appbins.Tags(), " \n  "),
		deviceSignAppBin.String(),
		vendorPubKey.String(),
		strings.Join(firmwares.Firmwares(), " \n  "))

	var devPath, baseURL, baseDir, configFile string
	var checkConfigOnly, verbose, showURLOnly, versionOnly, helpOnly bool

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
	pflag.BoolVar(&versionOnly, "version", false, "Output version information.")
	pflag.BoolVar(&helpOnly, "help", false, "Output this help.")
	pflag.Usage = func() {
		desc := fmt.Sprintf(`Usage: %s command [flags...]

Commands:
  serve-signer  TODO write...

  remote-sign   TODO write...

  verify        Verify that a TKey is genuine by extracting the TKey UDI and using it
                to fetch the verification data, including tag and signature from the
                web. Then running the correct verisigner-app on the TKey, extracting
                the public key and verifying it using the vendor's signing public key.

                The flags --show-url and --base-dir can be used to show the URL for
                downloading the verification data on one machine, and verifying the
                TKey on another machine that lacks network, see more below.`, progname)

		le.Printf("%s\n\nFlags:\n%s\n%s", desc, pflag.CommandLine.FlagUsagesWrapped(86), builtWith)
	}
	pflag.Parse()

	if helpOnly {
		pflag.Usage()
		os.Exit(0)
	}
	if versionOnly {
		fmt.Printf("%s %s\n\n%s", progname, version, builtWith)
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
		remoteSign(conf, deviceSignAppBin, devPath, verbose, checkConfigOnly)

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

func readBuildInfo() string {
	version := "devel without BuildInfo"
	if info, ok := debug.ReadBuildInfo(); ok {
		sb := strings.Builder{}
		sb.WriteString("devel")
		for _, setting := range info.Settings {
			if strings.HasPrefix(setting.Key, "vcs") {
				sb.WriteString(fmt.Sprintf(" %s=%s", setting.Key, setting.Value))
			}
		}
		version = sb.String()
	}
	return version
}
