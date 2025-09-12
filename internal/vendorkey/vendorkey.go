// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package vendorkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/data"
	"github.com/tillitis/tkey-verification/internal/util"
)

type PubKey struct {
	PubKey [ed25519.PublicKeySize]byte // Vendor public key
	Tag    string                      // Name and tag of the device app
	AppBin appbins.AppBin              // The actual device app binary
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

// FromString initializes all the known vendor public keys. It
// needs to know the existing device applications (get them with
// NewAppBins())
//
// It returns the vendor public keys and any error.
func (v *VendorKeys) FromString(pubkeys string, appBins appbins.AppBins) error {
	lines := strings.Split(strings.Trim(strings.ReplaceAll(pubkeys, "\r\n", "\n"), "\n"), "\n")

	v.Keys = make(map[string]PubKey)

	for _, line := range lines {
		fields := strings.Fields(line)

		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			// ignoring empty/spaces-only lines and comments
			continue
		}

		if len(fields) != 3 {
			return errors.New("expected 3 space-separated fields: pubkey in hex, signer-app tag, and its hash in hex")
		}

		pubKeyHex, tag, appHashHex := fields[0], fields[1], fields[2]

		pubKey, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return fmt.Errorf("couldn't decode public key: %w", err)
		}
		if l := len(pubKey); l != ed25519.PublicKeySize {
			return errors.New("public key has wrong length")
		}

		var appHash [sha512.Size]byte

		if err := util.DecodeHex(appHash[:], appHashHex); err != nil {
			return fmt.Errorf("%w", err)
		}

		var appBin appbins.AppBin
		if _, ok := appBins.Bins[appHash]; ok {
			appBin = appBins.Bins[appHash]
			if appBin.Tag != tag {
				return errors.New("embedded app tag != vendor signing app tag")
			}

		} else {
			return fmt.Errorf("couldn't find device app for digest %v", appHashHex)
		}

		for _, pk := range v.Keys {
			if bytes.Equal(pubKey, pk.PubKey[:]) {
				return errors.New("public key already exists")
			}
		}

		v.Keys[appHashHex] = PubKey{
			PubKey: *(*[ed25519.PublicKeySize]byte)(pubKey),
			Tag:    tag,
			AppBin: appBin,
		}
	}

	return nil
}

func (v *VendorKeys) FromEmbedded(appBins appbins.AppBins) error {
	return v.FromString(string(data.VendorPubKeys), appBins)
}
