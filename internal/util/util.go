// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package util

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"runtime/debug"

	"github.com/tillitis/tkey-verification/internal/tkey"
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

func BuildMessage(udiBE, fwHash, pubKey []byte) ([]byte, error) {
	var buf bytes.Buffer

	if l := len(udiBE); l != tkey.UDISize {
		return nil, fmt.Errorf("wrong length of UDI")
	}
	buf.Write(udiBE)

	if l := len(fwHash); l != sha512.Size {
		return nil, fmt.Errorf("wrong length of digest")
	}
	buf.Write(fwHash)

	if l := len(pubKey); l != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wrong length of pubkey")
	}
	buf.Write(pubKey)

	return buf.Bytes(), nil
}

func Version(version string) string {
	if version == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			// When built with go install ...@version
			version = info.Main.Version
			if version != "(devel)" {
				return version
			}
		}
	}

	return version
}
