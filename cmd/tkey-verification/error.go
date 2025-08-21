// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

type constError string

func (err constError) Error() string {
	return string(err)
}

const (
	ErrNotFound           = constError("not found")
	ErrUDI                = constError("erroneous UDI")
	ErrNoTag              = constError("empty tag")
	ErrWrongDigest        = constError("erroneous app digest")
	ErrWrongLen           = constError("wrong message length")
	ErrSignFailed         = constError("signing failed")
	ErrVerificationFailed = constError("signature failed verification")
	ErrSigExist           = constError("vendor signature already exist")
	ErrInternal           = constError("internal error")
	ErrIO                 = constError("I/O error")
	ErrWrongFirmware      = constError("not expected firmware")
)
