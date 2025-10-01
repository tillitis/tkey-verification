// SPDX-FileCopyrightText: 2022 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/tillitis/tkey-verification/internal/util"
	"github.com/tillitis/tkeyclient"
)

const progname = "tkey-verification"

const signaturesDir = "signatures"

const (
	defaultConfigFile = "./tkey-verification.yaml"
)

var version string

// Use when printing err/diag msgs
var le = log.New(os.Stderr, "", 0)

type Device struct {
	Path  string
	Speed int
}

func main() {
	var dev Device
	var configFile, binPath string
	var checkConfigOnly, verbose, versionOnly, build, helpOnly bool

	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.StringVar(&dev.Path, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	pflag.IntVarP(&dev.Speed, "speed", "s", tkeyclient.SerialSpeed,
		"Set serial port `SPEED` in bits per second.")
	pflag.BoolVar(&verbose, "verbose", false,
		"Enable verbose output.")
	pflag.StringVar(&configFile, "config", defaultConfigFile,
		"`PATH` to configuration file (commands: serve-signer, remote-sign).")
	pflag.BoolVar(&checkConfigOnly, "check-config", false,
		"Only check that the configuration is usable, then exit (commands: serve-signer, remote-sign).")
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
		fmt.Printf("%s %s\n", progname, util.Version(version))
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

	// Command funcs exit to OS themselves for now
	switch cmd {
	case "serve-signer":
		conf, err := loadServeSignerConfig(configFile)
		if err != nil {
			le.Printf("Couldn't load config: %v\n", err)
		}

		serveSigner(conf, dev, verbose, checkConfigOnly)

	case "remote-sign":
		conf, err := loadRemoteSignConfig(configFile)
		if err != nil {
			le.Printf("Couldn't load config: %v\n", err)
		}

		if checkConfigOnly {
			os.Exit(0)
		}

		remoteSign(conf, dev, verbose)

	case "show-pubkey":
		if binPath == "" {
			le.Printf("Needs the path to an app, use `--app PATH`\n")
			os.Exit(2)
		}
		showPubkey(binPath, dev, verbose)

	default:
		le.Printf("%s is not a valid command.\n", cmd)
		pflag.Usage()
		os.Exit(2)
	}
}
