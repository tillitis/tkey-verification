// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

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
	Keys map[string]PubKey
}

func (v *VendorKeys) String() string {
	var sb strings.Builder

	for _, k := range v.Keys {
		sb.WriteString(k.String())
	}

	return sb.String()
}

// NewVendorKeys initializes all the known vendor public keys. It
// needs to know the existing device applications (get them with
// NewAppBins())
//
// It returns the vendor public keys and any error.
func NewVendorKeys(appBins AppBins) (VendorKeys, error) {
	lines := strings.Split(strings.Trim(strings.ReplaceAll(string(pubKeysData), "\r\n", "\n"), "\n"), "\n")

	var vendorKeys = VendorKeys{
		map[string]PubKey{},
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
			if appBin.Tag != tag {
				return vendorKeys, EqualError{"embedded app tag", "vendor signing app tag"}
			}

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

	return vendorKeys, nil
}
