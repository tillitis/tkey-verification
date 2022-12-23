// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func verify(devPath string, verbose bool, appBin []byte) {
	udi, pubKey, ok := runSignerApp(devPath, verbose, appBin)
	if !ok {
		os.Exit(1)
	}
	le.Printf("TKey raw UDI: %s\n", hex.EncodeToString(udi))

	// The vendor's public key, for verifying the signature
	signingPubKey, err := getSigningPubKey()
	if err != nil {
		le.Printf("Failed to get signing pubkey: %s\n", err)
		os.Exit(1)
	}

	h := sha256.Sum256(append(udi, pubKey...))

	// Get the signature S by the hash H
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(h[:]))
	s, err := readHexLine(fn)
	if err != nil {
		le.Printf("%s", err)
		os.Exit(1)
	}

	// tag, err := os.ReadFile(base + ".tag")
	// if err != nil {
	// }

	// Do we have the right tag?

	// Check signature against vendor's pubkey
	if !ed25519.Verify(signingPubKey, h[:], s) {
		fmt.Printf("FAILED signature verification!\n")
		os.Exit(1)
	}
	fmt.Printf("Verified signature on looked-up hash, TKey is genuine!\n")

	os.Exit(0)
}
