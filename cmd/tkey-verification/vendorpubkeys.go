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
	PubKey [ed25519.PublicKeySize]byte // Vendor public key
	Tag    string                      // Name and tag of the device app
	AppBin AppBin                      // The actual device app binary
}

func (p *PubKey) String() string {
	return fmt.Sprintf("pubkey:%0x… %s", p.PubKey[:16], p.AppBin.String())
}

// VendorKeys is a built-in database of vendor PubKeys
type VendorKeys struct {
	Keys           map[string]PubKey
	CurrentAppHash string
}

// Current returns the currently used vendor PubKey needed for vendor
// signing.
func (v VendorKeys) Current() PubKey {
	return v.Keys[v.CurrentAppHash]
}

// NewVendorKeys initializes all the known vendor public keys. It
// needs to know the existing device applications (get them with
// NewAppBins()) and the app hash digest of the currently used device
// app for vendor signing.
//
// It returns the vendor public keys and any error.
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
			return vendorKeys, SimpleParseError{msg: "Expected 3 space-separated fields: pubkey in hex, signer-app tag, and its hash in hex"}
		}

		pubKeyHex, tag, appHashHex := fields[0], fields[1], fields[2]

		pubKey, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return vendorKeys, ParseError{what: "public key hex", err: err}
		}
		if l := len(pubKey); l != ed25519.PublicKeySize {
			return vendorKeys, ErrWrongLen
		}

		appHash, err := hex.DecodeString(appHashHex)
		if err != nil {
			return vendorKeys, ParseError{what: "app digest hex", err: err}
		}
		if l := len(appHash); l != sha512.Size {
			return vendorKeys, ErrWrongLen
		}

		var appBin AppBin
		if _, ok := appBins.Bins[appHashHex]; ok {
			appBin = appBins.Bins[appHashHex]
		} else {
			return vendorKeys, ErrNotFound
		}

		for _, pk := range vendorKeys.Keys {
			if bytes.Compare(pubKey, pk.PubKey[:]) == 0 {
				return vendorKeys, ExistError{what: "public key"}
			}
		}

		vendorKeys.Keys[appHashHex] = PubKey{
			PubKey: *(*[ed25519.PublicKeySize]byte)(pubKey),
			Tag:    tag,
			AppBin: appBin,
		}
	}

	if _, ok := vendorKeys.Keys[currentVendorHash]; ok {
		vendorKeys.CurrentAppHash = currentVendorHash
	} else {
		return VendorKeys{}, ErrNotFound
	}

	return vendorKeys, nil
}
