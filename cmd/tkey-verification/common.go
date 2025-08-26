// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

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

func verifyFirmwareHash(tk tkey.TKey) (Firmware, error) {
	firmwares, err := NewFirmwares()
	if err != nil {
		return Firmware{}, fmt.Errorf("no firmware digests")
	}

	expectedFW, err := firmwares.GetFirmware(tk.Udi)
	if err != nil {
		return Firmware{}, fmt.Errorf("no firmware for UDI")
	}

	fwHash, err := tk.GetFirmwareHash(expectedFW.Size)
	if err != nil {
		return Firmware{}, fmt.Errorf("couldn't get firmware digest from TKey: %w", err)
	}
	if !bytes.Equal(expectedFW.Hash[:], fwHash) {
		le.Printf("TKey does not have expected firmware hash %0x…, but instead %0x…", expectedFW.Hash[:16], fwHash[:16])
		return Firmware{}, ErrWrongFirmware
	}

	return *expectedFW, nil
}
