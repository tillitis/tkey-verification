// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

func showPubKey(devPath string, verbose bool) {
	udiBE, pubKey, ok := runSignerApp(devPath, verbose, signerAppBin)
	if !ok {
		os.Exit(1)
	}
	le.Printf("TKey UDI (BE): %s\n", hex.EncodeToString(udiBE[:]))

	fmt.Printf("%s\n", hex.EncodeToString(pubKey))
	os.Exit(0)
}
