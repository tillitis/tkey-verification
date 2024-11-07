// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import "fmt"

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

// More complex errors get their own type below

type MissingError struct {
	what string
}

func (e MissingError) Error() string {
	return fmt.Sprintf("missing: %v", e.what)
}

type EqualError struct {
	one interface{}
	two interface{}
}

func (e EqualError) Error() string {
	return fmt.Sprintf("not equal: %v != %v", e.one, e.two)
}

type IOError struct {
	path string
	err  error
}

func (e IOError) Error() string {
	return fmt.Sprintf("I/O error on %v: %v", e.path, e.err)
}

func (e IOError) Unwrap() error {
	return e.err
}

type ParseError struct {
	what string
	err  error
}

func (e ParseError) Error() string {
	return fmt.Sprintf("couldn't parse %v: %v", e.what, e.err)
}

func (e ParseError) Unwrap() error {
	return e.err
}

type SimpleParseError struct {
	msg string
}

func (e SimpleParseError) Error() string {
	return e.msg
}

type ExistError struct {
	what string
}

func (e ExistError) Error() string {
	return fmt.Sprintf("already exists: %v", e.what)
}

type RangeError struct {
	what string
}

func (e RangeError) Error() string {
	return fmt.Sprintf("out of range: %v", e.what)
}
