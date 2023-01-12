// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

func verify(devPath string, verbose bool) {
	udi, pubKey, ok := runSignerApp(devPath, verbose, signerAppBin)
	if !ok {
		os.Exit(1)
	}
	fmt.Printf("TKey raw UDI: %s\n", hex.EncodeToString(udi))

	// Get a signature over the UDI as the message to be verified
	message, err := signWithApp(devPath, pubKey, udi)
	if err != nil {
		le.Printf("sign failed: %s", err)
		os.Exit(1)
	}

	// Get verification JSON by UDI
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(udi))
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

	vSignature, err := hex.DecodeString(verification.Signature)
	if err != nil {
		le.Printf("hex.DecodeString failed: %s", err)
		os.Exit(1)
	}

	if !ed25519.Verify(signingPubKey, message, vSignature) {
		fmt.Printf("Signature failed verification!\n")
		os.Exit(1)
	}
	fmt.Printf("Verified the vendor signature over a local signature over the UDI, TKey is genuine!\n")

	os.Exit(0)
}
