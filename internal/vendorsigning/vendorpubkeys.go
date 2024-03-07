// Copyright (C) Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package vendorsigning

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/tillitis/tkey-verification/internal/appbins"
)

var le = log.New(os.Stderr, "", 0)

// nolint:typecheck // Avoid lint error when the embedding file is missing.
//
//go:embed vendor-signing-pubkeys.txt
var pubKeysData []byte

type PubKey struct {
	PubKey [ed25519.PublicKeySize]byte
	Tag    string
	AppBin appbins.AppBin
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

func New(appBins appbins.AppBins, currentHash string) (VendorKeys, error) {
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
		pubKeyHex, tag, hashHex := fields[0], fields[1], fields[2]

		pubKey, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return vendorKeys, fmt.Errorf("decode hex \"%s\" failed: %w", pubKeyHex, err)
		}
		if l := len(pubKey); l != ed25519.PublicKeySize {
			return vendorKeys, fmt.Errorf("expected %d bytes public key, got %d", ed25519.PublicKeySize, l)
		}

		hash, err := hex.DecodeString(hashHex)
		if err != nil {
			return vendorKeys, fmt.Errorf("decode hex \"%s\" failed: %w", hashHex, err)
		}
		if l := len(hash); l != sha512.Size {
			return vendorKeys, fmt.Errorf("expected %d bytes app hash, got %d", sha512.Size, l)
		}

		appBin := appBins.Bins[string(hash)]
		if err != nil {
			return vendorKeys, fmt.Errorf("getting embedded verisigner-app failed: %w", err)
		}

		for _, pk := range vendorKeys.Keys {
			if bytes.Compare(pubKey, pk.PubKey[:]) == 0 {
				return vendorKeys, fmt.Errorf("public key \"%s\" already exists", pubKeyHex)
			}
		}

		vendorKeys.Keys[string(hash)] = PubKey{
			PubKey: *(*[ed25519.PublicKeySize]byte)(pubKey),
			Tag:    tag,
			AppBin: appBin,
		}
	}

	if l := len(vendorKeys.Keys); l > 1 {
		return vendorKeys, fmt.Errorf("We currently only support 1 vendor signing public key, but found %d", l)
	}

	if _, ok := vendorKeys.Keys[currentHash]; ok {
		vendorKeys.CurrentAppHash = currentHash
	} else {
		return VendorKeys{}, fmt.Errorf("Current key hash does not exist")
	}

	return vendorKeys, nil
}
