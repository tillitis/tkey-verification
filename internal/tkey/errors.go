// Copyright (C) 2022-2024 - Tillitis AB
// SPDX-License-Identifier: BSD-2-Clause

package tkey

import "fmt"

// Simple errors with no further information
type constError string

func (err constError) Error() string {
	return string(err)
}

const (
	ErrNoDevice     = constError("no TKey connected")
	ErrNotFirmware  = constError("not firmware")
	ErrWrongUDILen  = constError("wrong UDI length")
	ErrWrongUDIData = constError("reserved UDI bits not zero")
)

// More complex errors get their own type below

type ConnError struct {
	devPath string
	err     error
}

func (e ConnError) Error() string {
	return fmt.Sprintf("could not open device: %v: %v", e.devPath, e.err)
}

func (e ConnError) Unwrap() error {
	return e.err
}
