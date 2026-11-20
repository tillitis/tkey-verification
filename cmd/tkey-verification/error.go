// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

type constError string

func (err constError) Error() string {
	return string(err)
}

const (
	ErrSignFailed         = constError("signing failed")
	ErrVerificationFailed = constError("signature failed verification")
	ErrSigExist           = constError("vendor signature already exist")
	ErrInternal           = constError("internal error")
	ErrWrongFirmware      = constError("not expected firmware")
)
