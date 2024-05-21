// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

var MessageLen = tkey.UDISize + sha512.Size + ed25519.PublicKeySize

func buildMessage(udiBE, fwHash, pubKey []byte) ([]byte, error) {
	var buf bytes.Buffer

	if l := len(udiBE); l != tkey.UDISize {
		return nil, fmt.Errorf("udiBE is not %d bytes, got %d", tkey.UDISize, l)
	}
	buf.Write(udiBE)

	if l := len(fwHash); l != sha512.Size {
		return nil, fmt.Errorf("fwHash is not %d bytes, got %d", sha512.Size, l)
	}
	buf.Write(fwHash)

	if l := len(pubKey); l != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubKey is not %d bytes, got %d", ed25519.PublicKeySize, l)
	}
	buf.Write(pubKey)

	return buf.Bytes(), nil
}

func verifyFirmwareHash(expectedFW Firmware, tk tkey.TKey, expectedPubKey []byte) (Firmware, error) {
	fwHash, err := tk.GetFirmwareHash(expectedFW.Size)
	if err != nil {
		return Firmware{}, fmt.Errorf("GetFirmwareHash failed: %w", err)
	}
	if !bytes.Equal(expectedFW.Hash[:], fwHash) {
		return Firmware{}, fmt.Errorf("TKey does not have expected firmware hash %0x…, but instead %0x…", expectedFW.Hash[:16], fwHash[:16])
	}

	return expectedFW, nil
}
