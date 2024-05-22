// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

// Package tkey offers...
//
// Start by
//
//	tk, err := NewTKey("/dev/ttyACM0", false)
//
// Load a signer program:
//
//	pubkey, err := tk.LoadSigner(...)
//
// Ask it to sign something
//
//	sig, err := tk.Sign(message)
//
//	digest, err = tk.GetFirmwareHash(4711)
//	tk.Close()

package tkey

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
)

type constError string

func (err constError) Error() string {
	return string(err)
}

const (
	ErrNoDevice    = constError("no TKey connected")
	ErrNotFirmware = constError("not firmware")
)

var le = log.New(os.Stderr, "", 0)

type TKey struct {
	client  tkeyclient.TillitisKey
	Udi     UDI
	signer  tkeysign.Signer
	verbose bool
}

func NewTKey(devPath string, verbose bool) (*TKey, error) {
	if !verbose {
		tkeyclient.SilenceLogging()
	}

	if devPath == "" {
		var err error

		devPath, err = tkeyclient.DetectSerialPort(true)
		if err != nil {
			return nil, ErrNoDevice
		}
	}

	tk := tkeyclient.New()
	le.Printf("Connecting to device on serial port %s ...\n", devPath)
	if err := tk.Connect(devPath); err != nil {
		return nil, fmt.Errorf("couldn't open device %s: %w", devPath, err)
	}

	nameVer, err := tk.GetNameVersion()
	if err != nil {
		le.Printf("Please unplug the TKey and plug it in again to put it in firmware-mode.\n")
		le.Printf("Either the device path (%s) is wrong, or the TKey is not in firmware-mode (already running an app).\n", devPath)
		return nil, ErrNotFirmware
	}
	le.Printf("Firmware name0:'%s' name1:'%s' version:%d\n",
		nameVer.Name0, nameVer.Name1, nameVer.Version)

	tkUDI, err := tk.GetUDI()
	if err != nil {
		return nil, fmt.Errorf("GetUDI failed: %w", err)
	}

	var udi UDI

	if err = udi.fromRawLE(tkUDI.RawBytes()); err != nil {
		return nil, fmt.Errorf("UDI fromRawLE failed: %w", err)
	}

	tkey := TKey{
		client:  *tk,
		Udi:     udi,
		verbose: verbose,
	}

	return &tkey, nil
}

// GetUDI gets the UDI of a TKey
func (t TKey) GetUDI() UDI {
	return t.Udi
}

func (t TKey) Close() {
	t.client.Close()
}

// LoadSigner loads device app BIN without USS.
//
// Returns the public key and any error.
func (t *TKey) LoadSigner(bin []byte) ([]byte, error) {
	var err error

	// No USS.
	if err = t.client.LoadApp(bin, []byte{}); err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if t.verbose {
		le.Printf("App loaded.\n")
	}

	t.signer = tkeysign.New(&t.client)

	nameVer, err := t.signer.GetAppNameVersion()
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if t.verbose {
		le.Printf("App name0:'%s' name1:'%s' version:%d\n",
			nameVer.Name0, nameVer.Name1, nameVer.Version)
	}

	pubKey, err := t.signer.GetPubkey()
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return pubKey, nil
}

// Sign connects to a TKey and asks an already running device app to
// sign a message.
func (t TKey) Sign(message []byte) ([]byte, error) {
	signature, err := t.signer.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return signature, nil
}

// GetFirmwareHash connects to a TKey and asks an already running
// verisigner-app for a hash (sha512) of the TKey's firmware binary.
func (t TKey) GetFirmwareHash(firmwareSize int) ([]byte, error) {
	fwHash, err := t.signer.GetFWDigest(firmwareSize)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return fwHash, nil
}

func handleSignals(action func(), sig ...os.Signal) chan<- os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig...)
	go func() {
		for {
			<-ch
			action()
		}
	}()
	return ch
}
