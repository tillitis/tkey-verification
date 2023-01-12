// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/tillitis/tillitis-key1-apps/tk1"
	"github.com/tillitis/tillitis-key1-apps/tk1sign"
	"github.com/tillitis/tkey-verification/internal/util"
)

const (
	// 4 chars each.
	wantAppName0 = "tk1 "
	wantAppName1 = "sign"
)

// runSignerApp gets the UDI of a TKey that must be in firmware-mode.
// It then loads the passed signer-app onto the TKey (with no USS),
// starts it, and gets the public key from it. Errors are printed to
// the common logger `le`. Returns the raw UDI, public key, and a true
// bool if successful.
func runSignerApp(devPath string, verbose bool, appBin []byte) ([]byte, []byte, bool) {
	if !verbose {
		tk1.SilenceLogging()
	}

	var err error
	if devPath == "" {
		devPath, err = util.DetectSerialPort(true)
		if err != nil {
			return nil, nil, false
		}
	}

	tk := tk1.New()
	le.Printf("Connecting to device on serial port %s ...\n", devPath)
	if err = tk.Connect(devPath, tk1.WithSpeed(tk1.SerialSpeed)); err != nil {
		le.Printf("Could not open %s: %v\n", devPath, err)
		return nil, nil, false
	}

	tkSigner := tk1sign.New(tk)

	cleanup := func() {
		if err = tkSigner.Close(); err != nil {
			le.Printf("Close: %v\n", err)
		}
	}
	defer cleanup()

	signalCh := handleSignals(func() {
		cleanup()
		os.Exit(1)
	}, os.Interrupt, syscall.SIGTERM)

	var nameVer *tk1.NameVersion
	nameVer, err = tk.GetNameVersion()
	if err != nil {
		le.Printf("If the serial port is correct, then the TKey might not be in firmware-mode, and have an app running already.\n" +
			"The tkey-verification tool must load the signer-app itself.\n" +
			"Please unplug the TKey and plug it in again.\n")
		return nil, nil, false
	}
	le.Printf("Firmware name0:'%s' name1:'%s' version:%d\n",
		nameVer.Name0, nameVer.Name1, nameVer.Version)

	udi, err := tk.GetUDI()
	if err != nil {
		le.Printf("GetUDI failed: %v\n", err)
		return nil, nil, false
	}

	le.Printf("Loading app...\n")
	// No USS.
	if err = tk.LoadApp(appBin, []byte{}); err != nil {
		le.Printf("Failed to load app: %s", err)
		return nil, nil, false
	}
	le.Printf("App loaded.\n")

	nameVer, err = tkSigner.GetAppNameVersion()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			le.Printf("GetAppNameVersion: %s\n", err)
		}
		return nil, nil, false
	}
	le.Printf("App name0:'%s' name1:'%s' version:%d\n",
		nameVer.Name0, nameVer.Name1, nameVer.Version)
	// not caring about nameVer.Version
	if wantAppName0 != nameVer.Name0 || wantAppName1 != nameVer.Name1 {
		le.Printf("App name is not what we expect\n")
		return nil, nil, false
	}

	pubKey, err := tkSigner.GetPubkey()
	if err != nil {
		le.Printf("GetPubKey failed: %s\n", err)
		return nil, nil, false
	}

	signal.Stop(signalCh)

	return udi.RawBytes(), pubKey, true
}

// signWithApp connects to a TKey and asks an already running
// signer-app to sign a message. The public key of signer-app must be
// expectedPubKey.
func signWithApp(devPath string, expectedPubKey []byte, message []byte) ([]byte, error) {
	var err error
	if devPath == "" {
		devPath, err = util.DetectSerialPort(true)
		if err != nil {
			return nil, fmt.Errorf("DetectSerialPort: %w", err)
		}
	}

	tk := tk1.New()
	le.Printf("Connecting to device on serial port %s ...\n", devPath)
	if err = tk.Connect(devPath, tk1.WithSpeed(tk1.SerialSpeed)); err != nil {
		return nil, fmt.Errorf("Could not open %s: %w", devPath, err)
	}

	tkSigner := tk1sign.New(tk)

	cleanup := func() {
		if err = tkSigner.Close(); err != nil {
			le.Printf("Close: %v\n", err)
		}
	}
	defer cleanup()

	signalCh := handleSignals(func() {
		cleanup()
		os.Exit(1)
	}, os.Interrupt, syscall.SIGTERM)

	nameVer, err := tkSigner.GetAppNameVersion()
	if err != nil {
		return nil, fmt.Errorf("GetAppNameVersion: %w", err)
	}
	// not caring about nameVer.Version
	if wantAppName0 != nameVer.Name0 || wantAppName1 != nameVer.Name1 {
		return nil, fmt.Errorf("App name is not what we expect")
	}

	pubKey, err := tkSigner.GetPubkey()
	if err != nil {
		return nil, fmt.Errorf("GetPubKey failed: %w", err)
	}

	if bytes.Compare(pubKey, expectedPubKey) != 0 {
		return nil, fmt.Errorf("TKey does not have the expected pubkey")
	}

	signature, err := tkSigner.Sign(message[:])
	if err != nil {
		return nil, fmt.Errorf("Sign failed: %w", err)
	}

	signal.Stop(signalCh)

	return signature, nil
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
