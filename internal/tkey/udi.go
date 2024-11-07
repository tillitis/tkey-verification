// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package tkey

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const UDISize = 8

// Holds Big Endian UDI
type UDI struct {
	VendorID   uint16
	ProductID  uint8 // 6 bits
	ProductRev uint8 // 6 bits
	Bytes      []byte
}

func (u *UDI) String() string {
	return fmt.Sprintf("0x%s(BE) VendorID: 0x%04x ProductID: %d ProductRev: %d", hex.EncodeToString(u.Bytes), u.VendorID, u.ProductID, u.ProductRev)
}

// fromRawLE parses the 2 Little Endian uint32s of the Unique Device
// Identifier (as from the firmware protocol) to Big Endian.
func (u *UDI) fromRawLE(udiLE []byte) error {
	if l := len(udiLE); l != UDISize {
		return ErrWrongUDILen
	}

	vpr := binary.LittleEndian.Uint32(udiLE[0:4])
	if reserved := uint8((vpr >> 28) & 0xf); reserved != 0 {
		return ErrWrongUDIData
	}
	u.VendorID = uint16((vpr >> 12) & 0xffff)
	u.ProductID = uint8((vpr >> 6) & 0x3f)
	u.ProductRev = uint8(vpr & 0x3f)
	// u.Serial = binary.LittleEndian.Uint32(udiLE[4:8])

	u.Bytes = make([]byte, 8)
	u.Bytes[0], u.Bytes[1], u.Bytes[2], u.Bytes[3] = udiLE[3], udiLE[2], udiLE[1], udiLE[0]
	u.Bytes[4], u.Bytes[5], u.Bytes[6], u.Bytes[7] = udiLE[7], udiLE[6], udiLE[5], udiLE[4]
	return nil
}
