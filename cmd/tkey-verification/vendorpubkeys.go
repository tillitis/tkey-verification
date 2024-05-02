// Copyright (C) Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
)

// nolint:typecheck // Avoid lint error when the embedding file is missing.
//
//go:embed vendor-signing-pubkeys.txt
var pubKeysData []byte

type PubKey struct {
	PubKey [ed25519.PublicKeySize]byte
	Tag    string
	AppBin AppBin
}

func (p *PubKey) String() string {
	return fmt.Sprintf("pubkey:%0x… %s", p.PubKey[:16], p.AppBin.String())
}

type VendorKeys struct {
	Keys           map[string]PubKey
	CurrentAppHash string
}

func (v VendorKeys) Current() PubKey {
	return v.Keys[v.CurrentAppHash]
}

func NewVendorKeys(appBins AppBins, currentVendorHash string) (VendorKeys, error) {
	lines := strings.Split(strings.Trim(strings.ReplaceAll(string(pubKeysData), "\r\n", "\n"), "\n"), "\n")

	var vendorKeys = VendorKeys{
		map[string]PubKey{},
		"",
	}

	for _, line := range lines {
		fields := strings.Fields(line)

		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			// ignoring empty/spaces-only lines and comments
			continue
		}

		if len(fields) != 3 {
			return vendorKeys, fmt.Errorf("Expected 3 space-separated fields: pubkey in hex, verisigner-app tag, and its hash in hex")
		}
		pubKeyHex, tag, appHashHex := fields[0], fields[1], fields[2]

		pubKey, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return vendorKeys, fmt.Errorf("decode hex \"%s\" failed: %w", pubKeyHex, err)
		}
		if l := len(pubKey); l != ed25519.PublicKeySize {
			return vendorKeys, fmt.Errorf("expected %d bytes public key, got %d", ed25519.PublicKeySize, l)
		}

		appHash, err := hex.DecodeString(appHashHex)
		if err != nil {
			return vendorKeys, fmt.Errorf("decode hex \"%s\" failed: %w", appHashHex, err)
		}
		if l := len(appHash); l != sha512.Size {
			return vendorKeys, fmt.Errorf("expected %d bytes app hash, got %d", sha512.Size, l)
		}

		var appBin AppBin
		if _, ok := appBins.Bins[appHashHex]; ok {
			appBin = appBins.Bins[appHashHex]
		} else {
			return vendorKeys, fmt.Errorf("getting embedded app failed: %w", err)
		}

		for _, pk := range vendorKeys.Keys {
			if bytes.Compare(pubKey, pk.PubKey[:]) == 0 {
				return vendorKeys, fmt.Errorf("public key \"%s\" already exists", pubKeyHex)
			}
		}

		vendorKeys.Keys[appHashHex] = PubKey{
			PubKey: *(*[ed25519.PublicKeySize]byte)(pubKey),
			Tag:    tag,
			AppBin: appBin,
		}
	}

	if l := len(vendorKeys.Keys); l > 1 {
		return vendorKeys, fmt.Errorf("We currently only support 1 vendor signing public key, but found %d", l)
	}

	if _, ok := vendorKeys.Keys[currentVendorHash]; ok {
		vendorKeys.CurrentAppHash = currentVendorHash
	} else {
		return VendorKeys{}, fmt.Errorf("Current key hash does not exist")
	}

	return vendorKeys, nil
}
