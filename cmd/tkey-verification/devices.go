// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"

	"github.com/google/gousb"
	"go.bug.st/serial/enumerator"
)

type usbDevice struct {
	devPath    string
	serial     string
	isCH552USB bool
}

const (
	tillitisOldUSB = "1207:8887"
	tillitisUSB    = "1209:8885"
	ch552USB       = "4348:55e0"
)

// getUSBDevices returns a list of all connected TKeys with their
// serial port paths (in /dev). It includes TKeys with a CH552 chip
// that has not been programmed with firmware and is in USB bootloader
// mode. The latter does not have a serial port, and are marked by a
// true bool in the struct.
func getUSBDevices() ([]usbDevice, error) {
	portDetails, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return nil, fmt.Errorf("Failed to list serial ports: %w", err)
	}

	var devices []usbDevice
	for _, pd := range portDetails {
		fmt.Printf("DEBUG device: %#v\n", pd)
		if pd.IsUSB {
			switch pd.VID + ":" + pd.PID {
			case tillitisUSB, tillitisOldUSB:
				devices = append(devices, usbDevice{
					devPath: pd.Name,
					serial:  pd.SerialNumber,
				})
			}
		}
	}

	ctx := gousb.NewContext()
	defer ctx.Close()

	_, err = ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		if desc.Vendor.String()+":"+desc.Product.String() == ch552USB {
			devices = append(devices, usbDevice{isCH552USB: true})
		}

		return false // not opening any
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to list USB devices: %w", err)
	}

	return devices, nil
}

// Find the vendor TKey and the verification TKey
func getTKeys(activeSerial string) (*usbDevice, *usbDevice, error) {
	devices, err := getUSBDevices()
	if err != nil {
		return nil, nil, fmt.Errorf("getting devices: %w", err)
	}

	if len(devices) > 2 {
		return nil, nil, fmt.Errorf("too many devices")
	}

	var vendorDev, verDev *usbDevice

	for _, d := range devices {
		if d.serial == activeSerial {
			vendorDev = &d
		} else {
			verDev = &d
		}
	}

	if vendorDev == nil {
		return nil, nil, fmt.Errorf("no vendor device")
	}

	if verDev == nil {
		return nil, nil, fmt.Errorf("no device under verification")
	}

	return vendorDev, verDev, nil
}
