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
)

func verify(devPath string, verbose bool) {
	udiBE, pubKey, ok := runSignerApp(devPath, verbose, signerAppBin)
	if !ok {
		os.Exit(1)
	}
	fmt.Printf("TKey UDI (BE): %s\n", hex.EncodeToString(udiBE[:]))

	// Get verification JSON by UDI
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(udiBE[:]))
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

	if signerAppTag != verification.Tag {
		le.Printf("You need to use version \"%s\" of the tkey-verification program to verify this TKey. The version of this tkey-verification is \"%s\".\n", verification.Tag, signerAppTag)
		os.Exit(1)
	}

	// Check the vendor signature over the device public key
	vSignature, err := hex.DecodeString(verification.Signature)
	if err != nil {
		le.Printf("hex.DecodeString failed: %s", err)
		os.Exit(1)
	}

	if !ed25519.Verify(signingPubKey, pubKey, vSignature) {
		le.Printf("Vendor signature failed verification!")
		os.Exit(1)
	}

	// Get a device signature over a random challenge
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		le.Printf("rand.Read failed: %s", err)
		os.Exit(1)
	}

	signature, err := signWithApp(devPath, pubKey, challenge)
	if err != nil {
		le.Printf("sign failed: %s", err)
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
