// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

func sign(devPath string, verbose bool, appBin []byte) {
	udi, pubKey, ok := runSignerApp(devPath, verbose, appBin)
	if !ok {
		os.Exit(1)
	}
	le.Printf("TKey raw UDI: %s\n", hex.EncodeToString(udi))

	// The vendor's private key for signing the hash H
	signingPrivKey, err := getSigningPrivKey()
	if err != nil {
		le.Printf("Failed to get signing privkey: %s\n", err)
		os.Exit(1)
	}

	h := sha256.Sum256(append(udi, pubKey...))
	s := ed25519.Sign(signingPrivKey, h[:])

	outDir := "signatures"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		os.Exit(1)
	}

	// File named after the hash H (in hex) will contain the signature
	// S (in hex)
	fn := fmt.Sprintf("%s/%s", outDir, hex.EncodeToString(h[:]))
	if _, err := os.Stat(fn); err == nil || !errors.Is(err, os.ErrNotExist) {
		le.Printf("%s already exists?", fn)
		os.Exit(1)
	}
	if err := os.WriteFile(fn, []byte(hex.EncodeToString(s)+"\n"), 0o644); err != nil { //nolint:gosec
		fmt.Printf("WriteFile: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %s\n", fn)
	fmt.Printf("The signer-app tag used, and needed for verification: %s\n", signerAppTag)

	// TODO the way we thought about lookup of the hash, the UDI is
	// not needed for that. But it could perhaps be part of
	// "signing output"?

	os.Exit(0)
}
