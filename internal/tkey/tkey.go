// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package tkey

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/tillitis/tillitis-key1-apps/tk1"
	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/util"
)

const (
	// 4 chars each.
	wantFWName0  = "tk1 "
	wantFWName1  = "mkdf"
	wantAppName0 = "veri"
	wantAppName1 = "sign"
)

var le = log.New(os.Stderr, "", 0)

// GetUDI gets the UDI of a TKey that must be in firmware-mode.
func GetUDI(devPath string, verbose bool) *UDI {
	if !verbose {
		tk1.SilenceLogging()
	}

	var err error
	if devPath == "" {
		devPath, err = util.DetectSerialPort(true)
		if err != nil {
			return nil
		}
	}

	tk := tk1.New()
	le.Printf("Connecting to device on serial port %s ...\n", devPath)
	if err = tk.Connect(devPath); err != nil {
		le.Printf("Could not open %s: %v\n", devPath, err)
		return nil
	}

	cleanup := func() {
		if err = tk.Close(); err != nil {
			le.Printf("tk.Close: %v\n", err)
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
		le.Printf("Please unplug the TKey and plug it in again to put it in firmware-mode.\n")
		le.Printf("Either the device path (%s) is wrong, or the TKey is not in firmware-mode (already running an app).\n", devPath)
		return nil
	}
	le.Printf("Firmware name0:'%s' name1:'%s' version:%d\n",
		nameVer.Name0, nameVer.Name1, nameVer.Version)

	tkUDI, err := tk.GetUDI()
	if err != nil {
		le.Printf("GetUDI failed: %v\n", err)
		return nil
	}
	var udi UDI
	if err = udi.fromRawLE(tkUDI.RawBytes()); err != nil {
		le.Printf("UDI fromRawLE failed: %s\n", err)
		return nil
	}

	signal.Stop(signalCh)

	return &udi
}

// Load gets the UDI of a TKey that must be in firmware-mode. It then
// loads the passed verisigner-app onto the TKey (with no USS), starts it,
// and gets the public key from it. Returns the UDI (BigEndian, BE),
// public key, and a true bool if successful.
func Load(appBin *appbins.AppBin, devPath string, verbose bool) (*UDI, []byte, bool) {
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
	if err = tk.Connect(devPath); err != nil {
		le.Printf("Could not open %s: %v\n", devPath, err)
		return nil, nil, false
	}

	tkSigner := New(tk)

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
		// Note: tkey-provision picks up and displays the last line of
		// stderr if the running of remote-sign fails.
		le.Printf("Please unplug the TKey and plug it in again so this tool can load the verisigner-app itself.\n")
		le.Printf("Either the device path (%s) is wrong, or the TKey is not in firmware-mode (already running an app).\n", devPath)
		return nil, nil, false
	}
	le.Printf("Firmware name0:'%s' name1:'%s' version:%d\n",
		nameVer.Name0, nameVer.Name1, nameVer.Version)
	// not caring about nameVer.Version
	if nameVer.Name0 != wantFWName0 || nameVer.Name1 != wantFWName1 {
		le.Printf("Expected firmware name0:'%s' name1:'%s'\n", wantFWName0, wantFWName1)
		return nil, nil, false
	}

	tkUDI, err := tk.GetUDI()
	if err != nil {
		le.Printf("GetUDI failed: %v\n", err)
		return nil, nil, false
	}
	var udi UDI
	if err = udi.fromRawLE(tkUDI.RawBytes()); err != nil {
		le.Printf("UDI fromRawLE failed: %s\n", err)
		return nil, nil, false
	}

	le.Printf("Loading verisigner-app built from %s ...\n", appBin.String())
	// No USS.
	if err = tk.LoadApp(appBin.Bin, []byte{}); err != nil {
		le.Printf("Failed to load app: %s\n", err)
		return nil, nil, false
	}
	le.Printf("App loaded.\n")

	nameVer, err = tkSigner.GetAppNameVersion()
	if err != nil {
		le.Printf("GetAppNameVersion: %s\n", err)
		return nil, nil, false
	}
	le.Printf("App name0:'%s' name1:'%s' version:%d\n",
		nameVer.Name0, nameVer.Name1, nameVer.Version)
	// not caring about nameVer.Version
	if nameVer.Name0 != wantAppName0 || nameVer.Name1 != wantAppName1 {
		le.Printf("Expected app name0:'%s' name1:'%s'\n", wantAppName0, wantAppName1)
		return nil, nil, false
	}

	pubKey, err := tkSigner.GetPubkey()
	if err != nil {
		le.Printf("GetPubKey failed: %s\n", err)
		return nil, nil, false
	}

	signal.Stop(signalCh)

	return &udi, pubKey, true
}

// Sign connects to a TKey and asks an already running verisigner-app to
// sign a message. The public key of verisigner-app must be
// expectedPubKey.
func Sign(devPath string, expectedPubKey []byte, message []byte) ([]byte, error) {
	var err error
	if devPath == "" {
		devPath, err = util.DetectSerialPort(false)
		if err != nil {
			return nil, fmt.Errorf("DetectSerialPort: %w", err)
		}
	}

	tk := tk1.New()
	if err = tk.Connect(devPath); err != nil {
		return nil, fmt.Errorf("Could not open %s: %w", devPath, err)
	}

	tkSigner := New(tk)

	cleanup := func() {
		if err = tkSigner.Close(); err != nil {
			le.Printf("tkSigner.Close: %v\n", err)
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
		return nil, fmt.Errorf("The TKey to use for signing does not have the expected public key")
	}

	signature, err := tkSigner.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("Sign failed: %w", err)
	}

	signal.Stop(signalCh)

	return signature, nil
}

// GetFirmwareHash connects to a TKey and asks an already running
// verisigner-app for a hash (sha512) of the TKey's firmware binary.
func GetFirmwareHash(devPath string, expectedPubKey []byte, firmwareSize uint32) ([]byte, error) {
	var err error
	if devPath == "" {
		devPath, err = util.DetectSerialPort(false)
		if err != nil {
			return nil, fmt.Errorf("DetectSerialPort: %w", err)
		}
	}

	tk := tk1.New()
	if err = tk.Connect(devPath); err != nil {
		return nil, fmt.Errorf("Could not open %s: %w", devPath, err)
	}

	tkSigner := New(tk)

	cleanup := func() {
		if err = tkSigner.Close(); err != nil {
			le.Printf("tkSigner.Close: %v\n", err)
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
		return nil, fmt.Errorf("The TKey does not have the expected public key")
	}

	fwHash, err := tkSigner.GetFirmwareHash(firmwareSize)
	if err != nil {
		return nil, fmt.Errorf("GetFirmwareHash failed: %w", err)
	}

	signal.Stop(signalCh)

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
