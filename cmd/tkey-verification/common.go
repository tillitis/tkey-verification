// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"fmt"

	"github.com/tillitis/tkey-verification/internal/firmware"
	"github.com/tillitis/tkey-verification/internal/tkey"
)

func verifyFirmwareHash(tk tkey.TKey, firmwares firmware.Firmwares) (firmware.Firmware, error) {
	var expectedFW firmware.Firmware
	var err error

	expectedFW, err = firmwares.GetFirmware(tk.Udi)
	if err != nil {
		return expectedFW, fmt.Errorf("no firmware for UDI")
	}

	fwHash, err := tk.GetFirmwareHash(expectedFW.Size)
	if err != nil {
		return expectedFW, fmt.Errorf("couldn't get firmware digest from TKey: %w", err)
	}
	if !bytes.Equal(expectedFW.Hash[:], fwHash) {
		le.Printf("TKey does not have expected firmware hash %0x…, but instead %0x…", expectedFW.Hash[:16], fwHash[:16])
		return expectedFW, ErrWrongFirmware
	}

	return expectedFW, nil
}
