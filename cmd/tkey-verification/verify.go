// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func verify(devPath string, verbose bool, appBin []byte) {
	udi, pubKey, ok := runSignerApp(devPath, verbose, appBin)
	if !ok {
		os.Exit(1)
	}
	fmt.Printf("TKey raw UDI: %s\n", hex.EncodeToString(udi))

	// TODO picking up signing pubkey here for now
	signingPubKey, err := readHexLine("signing.pub")
	if err != nil {
		le.Printf("readHexLine failed: %s", err)
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

	vHash, err := hex.DecodeString(verification.Hash)
	if err != nil {
		le.Printf("hex.DecodeString failed: %s", err)
		os.Exit(1)
	}
	vSignature, err := hex.DecodeString(verification.Signature)
	if err != nil {
		le.Printf("hex.DecodeString failed: %s", err)
		os.Exit(1)
	}

	hash := sha256.Sum256(append(udi, pubKey...))
	if bytes.Compare(hash[:], vHash) != 0 {
		fmt.Printf("Hashes do not match!\n")
		os.Exit(1)
	}

	if !ed25519.Verify(signingPubKey, vHash, vSignature) {
		fmt.Printf("Signature failed verification!\n")
		os.Exit(1)
	}
	fmt.Printf("Verified signature over matching hash, TKey is genuine!\n")

	os.Exit(0)
}

func readHexLine(fn string) ([]byte, error) {
	data, err := os.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	bytes, err := hex.DecodeString(lines[0])
	if err != nil {
		return nil, fmt.Errorf("Failed to decode hex '%s': %w", lines[0], err)
	}
	return bytes, nil
}
