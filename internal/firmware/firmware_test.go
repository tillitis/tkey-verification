// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package firmware

import (
	"testing"

	"github.com/tillitis/tkey-verification/internal/data"
)

func TestParseEmbeddedFirmwares(t *testing.T) {
	var f Firmwares

	if err := f.FromJSON([]byte(data.FirmwaresJSON)); err != nil {
		t.Fatal(err)
	}
}

func TestWrongFirmware(t *testing.T) {
	var f Firmwares

	// Not hex. Err should be filled
	if err := f.addFirmware("oo", 01, 02, 03, 4711, "cafebabe"); err == nil {
		t.Fatal(err)
	}

	// Wrong UDI length
	if err := f.addFirmware("cafebabe", 01, 02, 03, 4711, "cafebabe"); err == nil {
		t.Fatal(err)
	}

	// firmware too small
	if err := f.addFirmware("01020304", 01, 02, 03, 12, "cafebabe"); err == nil {
		t.Fatal(err)
	}

	// firmware too big
	if err := f.addFirmware("01020304", 01, 02, 03, 9000, "cafebabe"); err == nil {
		t.Fatal(err)
	}

	// Broken firmware digest hex
	if err := f.addFirmware("01020304", 01, 02, 03, 8192, "oo"); err == nil {
		t.Fatal(err)
	}

	// Wrong length of firmware digest hex
	if err := f.addFirmware("01020304", 01, 02, 03, 8192, "ffff"); err == nil {
		t.Fatal(err)
	}

	// Wrong UDI0 compared to calculated UDI0
	if err := f.addFirmware("01020304", 01, 02, 03, 8192, "06d0aafcc763307420380a8c5a324f3fccfbba6af7ff6fe0facad684ebd69dd43234c8531a096c77c2dc3543f8b8b629c94136ca7e257ca560da882e4dbbb025"); err == nil {
		t.Fatal(err)
	}

}
