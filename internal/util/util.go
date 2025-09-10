// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package util

import (
	"encoding/hex"
	"fmt"
)

func DecodeHex(out []byte, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != len(out) {
		return fmt.Errorf("unexpected length of hex data, expected %d, got %d", len(out), len(b))
	}
	copy(out, b)

	return nil
}
