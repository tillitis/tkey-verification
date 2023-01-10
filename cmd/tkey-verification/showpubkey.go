// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

func showPubKey(devPath string, verbose bool) {
	udi, pubKey, ok := runSignerApp(devPath, verbose, signerAppBin)
	if !ok {
		os.Exit(1)
	}
	le.Printf("TKey raw UDI: %s\n", hex.EncodeToString(udi))

	fmt.Printf("%s\n", hex.EncodeToString(pubKey))
	os.Exit(0)
}
