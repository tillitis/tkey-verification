// Copyright (C) 2023-2024 - Tillitis AB
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

func buildMessage(udiBE, fwHash, pubKey []byte) ([]byte, error) {
	var buf bytes.Buffer

	if l := len(udiBE); l != tkey.UDISize {
		return nil, ErrWrongLen
	}
	buf.Write(udiBE)

	if l := len(fwHash); l != sha512.Size {
		return nil, ErrWrongLen
	}
	buf.Write(fwHash)

	if l := len(pubKey); l != ed25519.PublicKeySize {
		return nil, ErrWrongLen
	}
	buf.Write(pubKey)

	return buf.Bytes(), nil
}

func verifyFirmwareHash(expectedFW Firmware, tk tkey.TKey) (Firmware, error) {
	fwHash, err := tk.GetFirmwareHash(expectedFW.Size)
	if err != nil {
		return Firmware{}, IOError{path: "TKey", err: err}
	}
	if !bytes.Equal(expectedFW.Hash[:], fwHash) {
		le.Printf("TKey does not have expected firmware hash %0x…, but instead %0x…", expectedFW.Hash[:16], fwHash[:16])
		return Firmware{}, ErrWrongFirmware
	}

	return expectedFW, nil
}
