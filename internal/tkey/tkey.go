// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

// Package tkey offers...
//
// Start by
// tk, err := NewTKey("/dev/ttyACM0", false)
//
// Load a signer program:
//
// err := tk.LoadSigner(...)
//
// Ask it to sign something
//
// sig, err := tk.Sign(message)
//
// digest, err = tk.GetFirmwareHash(4711)
//

package tkey

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/tillitis/tkey-verification/internal/util"
	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
)

const (
	// 4 chars each.
	wantFWName0  = "tk1 "
	wantFWName1  = "mkdf"
	wantAppName0 = "veri"
	wantAppName1 = "sign"
)

var le = log.New(os.Stderr, "", 0)

type TKey struct {
	client  tkeyclient.TillitisKey
	Udi     UDI
	signer  tkeysign.Signer
	verbose bool
}

func NewTKey(devPath string, verbose bool) (*TKey, error) {
	var err error

	if !verbose {
		tkeyclient.SilenceLogging()
	}

	if devPath == "" {
		devPath, err = util.DetectSerialPort(true)
		if err != nil {
			return nil, nil
		}
	}

	tk := tkeyclient.New()
	le.Printf("Connecting to device on serial port %s ...\n", devPath)
	if err := tk.Connect(devPath); err != nil {
		return nil, fmt.Errorf("couldn't open device %s: %w\n", devPath, err)
	}

	nameVer, err := tk.GetNameVersion()
	if err != nil {
		le.Printf("Please unplug the TKey and plug it in again to put it in firmware-mode.\n")
		le.Printf("Either the device path (%s) is wrong, or the TKey is not in firmware-mode (already running an app).\n", devPath)
		return nil, fmt.Errorf("not firmware")
	}
	le.Printf("Firmware name0:'%s' name1:'%s' version:%d\n",
		nameVer.Name0, nameVer.Name1, nameVer.Version)

	tkUDI, err := tk.GetUDI()
	if err != nil {
		return nil, fmt.Errorf("GetUDI failed: %w\n", err)
	}

	var udi UDI

	if err = udi.fromRawLE(tkUDI.RawBytes()); err != nil {
		return nil, fmt.Errorf("UDI fromRawLE failed: %w\n", err)
	}

	tkey := TKey{
		client:  *tk,
		Udi:     udi,
		verbose: verbose,
	}

	return &tkey, nil
}

// GetUDI gets the UDI of a TKey that must be in firmware-mode.
func (t TKey) GetUDI() UDI {
	return t.Udi
}

func (t TKey) Close() {
	t.client.Close()
}

// LoadSigner gets the UDI of a TKey that must be in firmware-mode. It
// then loads the passed device app onto the TKey (with no USS),
// starts it, and gets the public key from it. Returns the UDI
// (BigEndian, BE), public key, and a true bool if successful.
func (t *TKey) LoadSigner(bin []byte) ([]byte, error) {
	var err error

	// No USS.
	if err = t.client.LoadApp(bin, []byte{}); err != nil {
		return nil, fmt.Errorf("Failed to load app: %w\n", err)
	}
	if t.verbose {
		le.Printf("App loaded.\n")
	}

	t.signer = tkeysign.New(&t.client)

	nameVer, err := t.signer.GetAppNameVersion()
	if err != nil {
		return nil, fmt.Errorf("GetAppNameVersion: %w\n", err)
	}

	if t.verbose {
		le.Printf("App name0:'%s' name1:'%s' version:%d\n",
			nameVer.Name0, nameVer.Name1, nameVer.Version)
	}

	// not caring about nameVer.Version
	// if nameVer.Name0 != wantAppName0 || nameVer.Name1 != wantAppName1 {
	// 	le.Printf("Expected app name0:'%s' name1:'%s'\n", wantAppName0, wantAppName1)
	// 	return nil, nil, false
	// }

	pubKey, err := t.signer.GetPubkey()
	if err != nil {
		return nil, fmt.Errorf("GetPubKey failed: %w\n", err)
	}

	return pubKey, nil
}

// Sign connects to a TKey and asks an already running device app to
// sign a message. The public key of the device app must be
// expectedPubKey.
func (t TKey) Sign(message []byte) ([]byte, error) {
	signature, err := t.signer.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("Sign failed: %w", err)
	}

	return signature, nil
}

// GetFirmwareHash connects to a TKey and asks an already running
// verisigner-app for a hash (sha512) of the TKey's firmware binary.
func (t TKey) GetFirmwareHash(firmwareSize int) ([]byte, error) {
	fwHash, err := t.signer.GetFWDigest(firmwareSize)
	if err != nil {
		return nil, fmt.Errorf("GetFirmwareHash failed: %w", err)
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
