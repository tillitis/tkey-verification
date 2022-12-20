// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func getSigningPrivKey() (ed25519.PrivateKey, error) {
	privSeed, err := readHexLine("test-signing.priv")
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(privSeed), nil
}

func getSigningPubKey() (ed25519.PublicKey, error) {
	pubKey, err := readHexLine("test-signing.pub")
	if err != nil {
		return nil, err
	}
	return pubKey, nil
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
