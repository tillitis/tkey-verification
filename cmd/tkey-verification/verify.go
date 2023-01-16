// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/vendorsigning"
)

func verify(devPath string, verbose bool) {
	udiBE := tkey.GetUDI(devPath, verbose)
	if udiBE == nil {
		os.Exit(1)
	}
	fmt.Printf("TKey UDI (BE): %s\n", hex.EncodeToString(udiBE))

	// Get verification JSON by UDI
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(udiBE))
	verificationJSON, err := os.ReadFile(fn)
	if err != nil {
		le.Printf("ReadFile %s failed: %s", fn, err)
		os.Exit(1)
	}

	var verification Verification
	if err = json.Unmarshal(verificationJSON, &verification); err != nil {
		le.Printf("Unmarshal failed: %s", err)
		os.Exit(1)
	}

	if verification.Tag == "" {
		le.Printf("Tag in verification data is empty\n")
		os.Exit(1)
	}

	appBin, err := appbins.Get(verification.Tag)
	if err != nil {
		// Note: as we embed every signer-app binary ever used, this
		// should not ever happen. Only if one removes a file from
		// internal/appbins/bins/, which would be a major mistake.
		le.Printf("This tkey-verification does not support signer-app tag \"%s\".\n", verification.Tag)
		os.Exit(1)
	}

	_, pubKey, ok := tkey.Load(appBin, devPath, verbose)
	if !ok {
		os.Exit(1)
	}

	// Check the vendor signature over the device public key
	vSignature, err := hex.DecodeString(verification.Signature)
	if err != nil {
		le.Printf("Couldn't decode signature: %s", err)
		os.Exit(1)
	}

	// Note: we currently only support 1 single vendor signing pubkey
	vendorPubKey := vendorsigning.GetCurrentPubKey().PubKey[:]

	if !ed25519.Verify(vendorPubKey, pubKey, vSignature) {
		le.Printf("Vendor signature failed verification!")
		os.Exit(1)
	}

	// Get a device signature over a random challenge
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		le.Printf("rand.Read failed: %s", err)
		os.Exit(1)
	}

	signature, err := tkey.Sign(devPath, pubKey, challenge)
	if err != nil {
		le.Printf("tkey.Sign failed: %s", err)
		os.Exit(1)
	}

	// Verify device signature against device public key
	if !ed25519.Verify(pubKey, challenge, signature) {
		le.Printf("Vendor signature failed verification!")
		os.Exit(1)
	}

	fmt.Printf("TKey is genuine!\n")

	os.Exit(0)
}
