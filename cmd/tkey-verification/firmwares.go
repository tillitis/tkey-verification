// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

const (
	fwSizeMin int = 2000
	fwSizeMax int = 8192
)

type Firmware struct {
	Hash [sha512.Size]byte
	Size int
}

type Firmwares struct {
	firmwares map[hardware]Firmware
}

func (f Firmwares) GetFirmware(udi tkey.UDI) (*Firmware, error) {
	hw, err := newHardware(udi.VendorID, udi.ProductID, udi.ProductRev)
	if err != nil {
		return nil, err
	}
	fw, ok := f.firmwares[*hw]
	if !ok {
		return nil, ErrUDI
	}

	return &fw, nil
}

func (f Firmwares) List() []string {
	list := []string{}
	for hw, fw := range f.firmwares {
		list = append(list, fmt.Sprintf("VendorID:0x%04x ProductID:%d ProductRev:%d [0x%s] with size:%d hash:%0x…",
			hw.VendorID, hw.ProductID, hw.ProductRev, hw.toUDI0BEhex(), fw.Size, fw.Hash[:16]))
	}

	return list
}

func NewFirmwares() (Firmwares, error) {
	fws := Firmwares{
		firmwares: make(map[hardware]Firmware),
	}

	var err error

	// This is the default/qemu UDI0, with firmware from main at
	// c126199a41149f6284aa9533e72395c978733b44
	err = fws.addFirmware("00010203", 0x0010, 8, 3, 4192, "3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623")
	if err != nil {
		return fws, err
	}

	err = fws.addFirmware("01337080", 0x1337, 2, 0, 4192, "3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623")
	if err != nil {
		return fws, err
	}

	err = fws.addFirmware("01337081", 0x1337, 2, 1, 4192, "3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623")
	if err != nil {
		return fws, err
	}

	err = fws.addFirmware("01337082", 0x1337, 2, 2, 4160, "06d0aafcc763307420380a8c5a324f3fccfbba6af7ff6fe0facad684ebd69dd43234c8531a096c77c2dc3543f8b8b629c94136ca7e257ca560da882e4dbbb025")
	if err != nil {
		return fws, err
	}

	if len(fws.firmwares) == 0 {
		return fws, MissingError{what: "no firmware"}
	}

	return fws, nil
}

// addFirmware adds a new known hardware identified by the triple
// (vendorID, productID, productRev) with a known firmware size and
// hash. To avoid mistakes, the hardware triple is used to recreate
// the first UDI word (UDI0) which must then match the argument
// udi0BEhex. For example, given the hardware triple argument (0x10,
// 8, 3) the udi0BEhex argument must be "00010203" (this is the
// default UDI0 in FPGA bitstream and QEMU machine).
func (f *Firmwares) addFirmware(udi0BEhex string, vendorID uint16, productID uint8, productRev uint8, fwSize int, fwHashHex string) error {
	udi0BE, err := hex.DecodeString(udi0BEhex)
	if err != nil {
		return ParseError{what: "UDI", err: err}
	}
	if l := len(udi0BE); l != tkey.UDISize/2 {
		return ErrWrongLen
	}

	hw, err := newHardware(vendorID, productID, productRev)
	if err != nil {
		return err
	}

	if fwSize < fwSizeMin {
		return ErrWrongLen
	}
	if fwSize > fwSizeMax {
		return ErrWrongLen
	}

	fwHash, err := hex.DecodeString(fwHashHex)
	if err != nil {
		return ParseError{what: "firmware hash", err: err}
	}
	if l := len(fwHash); l != sha512.Size {
		return ErrWrongLen
	}

	// Safety check. We compare the passed UDI0 argument to what
	// we computed from vendori ID, product ID, and product
	// revision. If it's not the same, we bail.
	if udi0BEhex != hw.toUDI0BEhex() {
		return EqualError{one: "udi0BEhex arg", two: "calculated"}
	}

	if _, ok := f.firmwares[*hw]; ok {
		return ExistError{what: "hardware with same UDI0"}
	}

	f.firmwares[*hw] = Firmware{
		Hash: *(*[64]byte)(fwHash),
		Size: fwSize,
	}

	return nil
}

type hardware struct {
	VendorID   uint16
	ProductID  uint8 // 6 bits
	ProductRev uint8 // 6 bits
}

func newHardware(vendorID uint16, productID uint8, productRev uint8) (*hardware, error) {
	const sixBitsMax = 2*2*2*2*2*2 - 1
	if productID > sixBitsMax {
		return nil, RangeError{what: "product ID"}
	}
	if productRev > sixBitsMax {
		return nil, RangeError{what: "product revision"}
	}

	return &hardware{
		VendorID:   vendorID,
		ProductID:  productID,
		ProductRev: productRev,
	}, nil
}

func (h hardware) toUDI0BEhex() string {
	var udi0BE [4]byte
	var vidBE [2]byte
	binary.BigEndian.PutUint16(vidBE[:], h.VendorID)
	// 4 reserved bits | first 4 bits of 1st vendorID byte
	udi0BE[0] = 0x0 | ((vidBE[0] & 0b11110000) >> 4)
	// last 4 bits of 1st vendorID byte | first 4 bits of 2nd vendorID byte
	udi0BE[1] = ((vidBE[0] & 0b00001111) << 4) | ((vidBE[1] & 0b11110000) >> 4)
	// last 4 bits of 2nd vendorID byte | first 4 bits of productID
	udi0BE[2] = ((vidBE[1] & 0b00001111) << 4) | ((h.ProductID & 0b111100) >> 2)
	// last 2 bits of productID | 6 bits productRev
	udi0BE[3] = ((h.ProductID & 0b000011) << 6) | h.ProductRev
	return hex.EncodeToString(udi0BE[:])
}
