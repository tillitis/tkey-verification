// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package firmware

import (
	"strings"
	"testing"

	"github.com/tillitis/tkey-verification/internal/data"
)

func TestParseEmbeddedFirmwares(t *testing.T) {
	var f Firmwares

	if err := f.FromString(data.FirmwaresConf); err != nil {
		t.Fatal(err)
	}
}

const validFwHashHex = "06d0aafcc763307420380a8c5a324f3fccfbba6af7ff6fe0facad684ebd69dd43234c8531a096c77c2dc3543f8b8b629c94136ca7e257ca560da882e4dbbb025"

func TestWrongFirmware(t *testing.T) {
	var f = Firmwares{
		firmwares: make(map[hardware]Firmware),
	}

	// Not hex. Err should be filled
	err := f.addFirmware("oo", 01, 02, 03, 4711, validFwHashHex)
	assertErrorMsgStartsWith(t, err, "couldn't decode UDI: ")

	// Wrong UDI length
	err = f.addFirmware("000102", 16, 8, 3, 4711, validFwHashHex)
	assertErrorMsgStartsWith(t, err, "wrong length of UDI0")

	// firmware too small
	err = f.addFirmware("00010203", 16, 8, 3, 1999, validFwHashHex)
	assertErrorMsgStartsWith(t, err, "too small firmware size")

	// firmware too big
	err = f.addFirmware("00010203", 16, 8, 3, 8193, validFwHashHex)
	assertErrorMsgStartsWith(t, err, "too large firmware size")

	// Broken firmware digest hex
	err = f.addFirmware("00010203", 16, 8, 3, 8192, "oo")
	assertErrorMsgStartsWith(t, err, "encoding/hex: invalid byte: U+006F 'o'")

	// Wrong length of firmware digest hex
	err = f.addFirmware("00010203", 16, 8, 3, 8192, "ffff")
	assertErrorMsgStartsWith(t, err, "unexpected length of hex data, expected 64, got 2")

	// Wrong UDI0 compared to calculated UDI0
	err = f.addFirmware("00010203", 01, 02, 03, 8192, validFwHashHex)
	assertErrorMsgStartsWith(t, err, "udi0BEhex arg != calculated")

	// Add same hardware twice
	err = f.addFirmware("00010203", 16, 8, 3, 4711, validFwHashHex)
	assertNoError(t, err)
	err = f.addFirmware("00010203", 16, 8, 3, 4711, validFwHashHex)
	assertErrorMsgStartsWith(t, err, "hardware with same UDI")
}

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Log("Expected error")
		t.Fail()
	}
}

func assertErrorMsgStartsWith(t *testing.T, err error, want string) {
	t.Helper()

	if err == nil {
		t.Log("Expected error")
		t.Fail()
		return
	}

	if !strings.HasPrefix(err.Error(), want) {
		t.Logf("Unexpected error '%v', should start with '%v'", err, want)
		t.Fail()
	}
}
