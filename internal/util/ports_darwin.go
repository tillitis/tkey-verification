// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

//go:build darwin

package util

import (
	"fmt"
	"os"
)

func DetectSerialPort(verbose bool) (string, error) {
	fmt.Fprintf(os.Stderr, `Serial port detection is not available on MacOS.
Please find the serial port device path using:
    ls -l /dev/cu.*
Then run like:
    tkey-verification command --port /dev/cu.usbmodemN
`)
	return "", fmt.Errorf("not available on MacOS")
}
