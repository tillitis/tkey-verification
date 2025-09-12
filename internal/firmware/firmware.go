// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package firmware

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tillitis/tkey-verification/internal/data"
	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/util"
)

const (
	fwSizeMin int = 2000
	fwSizeMax int = 8192
)

type Hardware struct {
	Udi        string
	VendorID   uint16
	ProductID  uint8
	ProductRev uint8
	FwSize     int
	FwHash     [sha512.Size]byte
}

type Firmware struct {
	Hash [sha512.Size]byte
	Size int
}

// Firmwares is a dictionary of all known firmwares, index by the
// first part of the UDI, UDI0.
type Firmwares struct {
	firmwares map[hardware]Firmware
}

// GetFirmware returns what we know about a firmware indexed by a UDI,
// or an error if no firmare is found.
func (f Firmwares) GetFirmware(udi tkey.UDI) (Firmware, error) {
	var fw Firmware

	hw, err := newHardware(udi.VendorID, udi.ProductID, udi.ProductRev)
	if err != nil {
		return fw, err
	}

	var ok bool

	fw, ok = f.firmwares[*hw]
	if !ok {
		return fw, errors.New("firmware not found")
	}

	return fw, nil
}

func (f Firmwares) List() []string {
	list := []string{}
	for hw, fw := range f.firmwares {
		list = append(list, fmt.Sprintf("VendorID:0x%04x ProductID:%d ProductRev:%d [0x%s] with size:%d hash:%0x…",
			hw.VendorID, hw.ProductID, hw.ProductRev, hw.toUDI0BEhex(), fw.Size, fw.Hash[:16]))
	}

	return list
}

func (f *Firmwares) FromString(fwStr string) error {
	lines := strings.Split(strings.Trim(strings.ReplaceAll(fwStr, "\r\n", "\n"), "\n"), "\n")

	// Put everything in the map, indexed by the hardware description
	f.firmwares = make(map[hardware]Firmware)

	for _, line := range lines {
		fields := strings.Fields(line)

		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			// ignoring empty/spaces-only lines and comments
			continue
		}

		if len(fields) != 6 {
			return errors.New("Expected 6 fields: UDI0 vendor product rev size hash")
		}

		udi0Str, vendorStr, productStr, revStr, sizeStr, hashStr := fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]

		var hw Hardware

		hw.Udi = udi0Str

		var err error
		var vid uint64

		vid, err = strconv.ParseUint(vendorStr, 16, 16)
		if err != nil {
			return err
		}

		hw.VendorID = uint16(vid)

		var prod uint64
		prod, err = strconv.ParseUint(productStr, 10, 8)
		if err != nil {
			return err
		}

		hw.ProductID = uint8(prod)

		var rev uint64
		rev, err = strconv.ParseUint(revStr, 10, 8)
		if err != nil {
			return err
		}

		hw.ProductRev = uint8(rev)

		hw.FwSize, err = strconv.Atoi(sizeStr)
		if err != nil {
			return err
		}

		if err := f.addFirmware(hw.Udi, hw.VendorID, hw.ProductID, hw.ProductRev, hw.FwSize, hashStr); err != nil {
			return err
		}
	}

	return nil
}

func (f *Firmwares) MustDecodeString(s string) {
	if err := f.FromString(s); err != nil {
		panic(err)
	}
}

// NewFirmwares initialises all known firmwares. It returns a map of
// all firmwares or an error.
//
// To add a new firmware to the database, use addFirmware() in this
// function.
func NewFirmwares() (Firmwares, error) {
	f := Firmwares{
		firmwares: make(map[hardware]Firmware),
	}

	if err := f.FromString(data.FirmwaresConf); err != nil {
		return f, err
	}

	return f, nil
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
		return fmt.Errorf("couldn't decode UDI: %w", err)
	}
	if l := len(udi0BE); l != tkey.UDISize/2 {
		return errors.New("wrong length of UDI0")
	}

	hw, err := newHardware(vendorID, productID, productRev)
	if err != nil {
		return err
	}

	if fwSize < fwSizeMin {
		return errors.New("too small firmware size")
	}
	if fwSize > fwSizeMax {
		return errors.New("too large firmware size")
	}

	var fwHash [sha512.Size]byte

	if err := util.DecodeHex(fwHash[:], fwHashHex); err != nil {
		return err
	}

	// Safety check. We compare the passed UDI0 argument to what
	// we computed from vendor ID, product ID, and product
	// revision. If it's not the same, we bail.
	if udi0BEhex != hw.toUDI0BEhex() {
		return errors.New("udi0BEhex arg != calculated")
	}

	if _, ok := f.firmwares[*hw]; ok {
		return errors.New("hardware with same UDI0")
	}

	f.firmwares[*hw] = Firmware{
		Hash: fwHash,
		Size: fwSize,
	}

	return nil
}

type hardware struct {
	VendorID   uint16
	ProductID  uint8 // 6 bits
	ProductRev uint8 // 6 bits
}

// newHardware is a utility function to generate a hardware struct
// from a UDI we probably got from talking to a TKey.
func newHardware(vendorID uint16, productID uint8, productRev uint8) (*hardware, error) {
	const sixBitsMax = 2*2*2*2*2*2 - 1

	if productID > sixBitsMax {
		return nil, errors.New("product ID out of range")
	}
	if productRev > sixBitsMax {
		return nil, errors.New("product revision out of range")
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
