// Copyright (C) 2024 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/pflag"
)

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

func builtWith() {
	appBins, err := NewAppBins(currentAppHash)
	if err != nil {
		fmt.Printf("Failed to init embedded device apps: %v\n", err)
		os.Exit(1)
	}

	deviceSignAppBin := appBins.Current()

	vendorKeys, err := NewVendorKeys(appBins, currentVendorHash)
	if err != nil {
		le.Printf("Found no usable embedded vendor signing public key\n")
		os.Exit(1)
	}

	vendorPubKey := vendorKeys.Current()

	firmwares, err := NewFirmwares()
	if err != nil {
		le.Printf("Found no usable firmwares\n")
		os.Exit(1)
	}

	fmt.Printf(`Built with:
Supported verisigner-app tags:
  %s
Device signing using:
  %s
Vendor signing:
  %s
Known firmwares:
  %s
`,
		strings.Join(appBins.Tags(), " \n  "),
		deviceSignAppBin.String(),
		vendorPubKey.String(),
		strings.Join(firmwares.List(), " \n  "))

}

func usage() {

	desc := fmt.Sprintf(`Usage: %s command [flags...]

Commands:
  serve-signer  Run the server that offers an API for creating vendor signatures.

  sign-challenge Sign a random challenge and verify it against the reported public key

  remote-sign   Call the remote signing server to sign for a local TKey.

  verify        Verify that a TKey is genuine by extracting the TKey UDI and using it
                to fetch the verification data, including tag and signature from the
                web. Then running the correct verisigner-app on the TKey, extracting
                the public key and verifying it using the vendor's signing public key.

                The flags --show-url and --base-dir can be used to show the URL for
                downloading the verification data on one machine, and verifying the
                TKey on another machine that lacks network, see more below.

  show-pubkey	Prints the info needed for the vendor-signing-pubkeys.txt to stdout.
		This includes public key, app tag, and app hash in the right format.

		Use the flag --app to specify the path o the desired app to use, i.e.,
		tkey-verification show-pubkey --app /path/to/app`, progname)

	le.Printf("%s\n\nFlags:\n%s\n", desc, pflag.CommandLine.FlagUsagesWrapped(86))
}
