// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"sync"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

const (
	fwSizeMin int = 2000
	fwSizeMax int = 8192
)

func GetFirmware(udi *tkey.UDI) (*Firmware, error) {
	if err := initFirmwares(); err != nil {
		le.Printf("Failed to init embedded firmwares: %s\n", err)
		os.Exit(1)
	}
	hw, err := newHardware(udi.VendorID, udi.ProductID, udi.ProductRev)
	if err != nil {
		return nil, err
	}
	fw, ok := firmwares[*hw]
	if !ok {
		return nil, nil
	}
	return &fw, nil
}

func Firmwares() []string {
	if err := initFirmwares(); err != nil {
		le.Printf("Failed to init embedded firmwares: %s\n", err)
		os.Exit(1)
	}
	var list []string
	for hw, fw := range firmwares {
		list = append(list, fmt.Sprintf("VendorID:0x%04x ProductID:%d ProductRev:%d [0x%s] with size:%d hash:%0x…",
			hw.VendorID, hw.ProductID, hw.ProductRev, hw.toUDI0BEhex(), fw.Size, fw.Hash[:16]))
	}
	return list
}

var (
	firmwares map[hardware]Firmware
	lock      = &sync.Mutex{}
)

func initFirmwares() error {
	lock.Lock()
	defer lock.Unlock()

	if firmwares != nil {
		return nil
	}

	firmwares = make(map[hardware]Firmware)

	var err error

	// This is the default/qemu UDI0, with firmware from main at
	// c126199a41149f6284aa9533e72395c978733b44
	err = addFirmware("00010203", 0x0010, 8, 3, 4192, "3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623")
	if err != nil {
		return err
	}

	err = addFirmware("01337080", 0x1337, 2, 0, 4192, "3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623")
	if err != nil {
		return err
	}

	err = addFirmware("01337081", 0x1337, 2, 1, 4192, "3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623")
	if err != nil {
		return err
	}

	if len(firmwares) == 0 {
		return fmt.Errorf("Got no firmwares from the embedded data")
	}

	return nil
}

// addFirmware adds a new known hardware identified by the triple
// (vendorID, productID, productRev) with a known firmware size and
// hash. To avoid mistakes, the hardware triple is used to recreate
// the first UDI word (UDI0) which must then match the argument
// udi0BEhex. For example, given the hardware triple argument (0x10,
// 8, 3) the udi0BEhex argument must be "00010203" (this is the
// default UDI0 in FPGA bitstream and QEMU machine).
func addFirmware(udi0BEhex string, vendorID uint16, productID uint8, productRev uint8, fwSize int, fwHashHex string) error {
	udi0BE, err := hex.DecodeString(udi0BEhex)
	if err != nil {
		return fmt.Errorf("decode udi0BEhex \"%s\" failed: %w", udi0BEhex, err)
	}
	if l := len(udi0BE); l != tkey.UDISize/2 {
		return fmt.Errorf("expected %d bytes udi0BE, got %d", tkey.UDISize/2, l)
	}

	hw, err := newHardware(vendorID, productID, productRev)
	if err != nil {
		return err
	}

	if fwSize < fwSizeMin {
		return fmt.Errorf("expected fwSize >= %d, got %d", fwSizeMin, fwSize)
	}
	if fwSize > fwSizeMax {
		return fmt.Errorf("expected fwSize <= %d, got %d", fwSizeMax, fwSize)
	}

	fwHash, err := hex.DecodeString(fwHashHex)
	if err != nil {
		return fmt.Errorf("decode fwHash hex \"%s\" failed: %w", fwHashHex, err)
	}
	if l := len(fwHash); l != sha512.Size {
		return fmt.Errorf("expected %d bytes fwHash, got %d", sha512.Size, l)
	}

	if udi0BEhex != hw.toUDI0BEhex() {
		return fmt.Errorf("udi0BEhex arg `%s` does not match `%s` calculated from hardware triple args", udi0BEhex, hw.toUDI0BEhex())
	}

	if _, ok := firmwares[*hw]; ok {
		return fmt.Errorf("hardware with UDI0 0x%s already exists", hw.toUDI0BEhex())
	}

	firmwares[*hw] = Firmware{
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
		return nil, fmt.Errorf("expected productID <= %d, got %d", sixBitsMax, productID)
	}
	if productRev > sixBitsMax {
		return nil, fmt.Errorf("expected productRev <= %d, got %d", sixBitsMax, productRev)
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

type Firmware struct {
	Hash [sha512.Size]byte
	Size int
}
