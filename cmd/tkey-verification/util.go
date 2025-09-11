// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/firmware"
	"github.com/tillitis/tkey-verification/internal/vendorkey"
)

func builtWith() {
	appBins, err := appbins.NewAppBins()
	if err != nil {
		fmt.Printf("Failed to init embedded device apps: %v\n", err)
		os.Exit(1)
	}

	var vendorKeys vendorkey.VendorKeys
	if err := vendorKeys.FromEmbedded(appBins); err != nil {
		le.Printf("Found no usable embedded vendor signing public key\n")
		os.Exit(1)
	}

	firmwares, err := firmware.NewFirmwares()
	if err != nil {
		le.Printf("Found no usable firmwares\n")
		os.Exit(1)
	}

	fmt.Printf(`Built with:
Supported verisigner-app tags:
  %s
Known vendor signing keys:
  %s
Known firmwares:
  %s
`,
		strings.Join(appBins.Tags(), " \n  "),
		vendorKeys.String(),
		strings.Join(firmwares.List(), " \n  "))

}

func usage() {

	desc := fmt.Sprintf(`Usage: %s command [flags...]

Commands:
  serve-signer  Run the server that offers an API for creating vendor signatures.

  remote-sign   Call the remote signing server to sign for a local TKey.

  show-pubkey	Prints the info needed for the embedded vendor pubkeys to stdout.
		This includes public key, app tag, and app hash in the right format.

		Use the flag --app to specify the path o the desired app to use, i.e.,
		tkey-verification show-pubkey --app /path/to/app`, progname)

	le.Printf("%s\n\nFlags:\n%s\n", desc, pflag.CommandLine.FlagUsagesWrapped(86))
}
