// SPDX-FileCopyrightText: 2022 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
)

var le = log.New(os.Stderr, "", 0)

type TKey struct {
	client  tkeyclient.TillitisKey
	Udi     UDI
	signer  tkeysign.Signer
	verbose bool
}

func possiblyReset(tk tkeyclient.TillitisKey) error {
	isFirmware, err := tk.FirmwareActive()
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	if !isFirmware {
		if !tk.CanRemoteClose {
			return errors.New("no reset support in device")
		}

		err = tk.Reset(tkeyclient.RstTypeStartClient, tkeyclient.NextAppData{})
		if err != nil {
			return errors.New("reset failed")
		}

		err := tk.WaitClosed()
		if err != nil {
			return fmt.Errorf("waiting for port close: %w", err)
		}

		err = tk.Reconnect()
		if err != nil {
			return fmt.Errorf("couldn't reconnect: %w", err)
		}
	}

	return nil
}

func NewTKey(devPath string, speed int, verbose bool) (*TKey, error) {
	if !verbose {
		tkeyclient.SilenceLogging()
	}

	if devPath == "" {
		var err error

		devPath, err = tkeyclient.DetectSerialPort(verbose)
		if err != nil {
			return nil, ErrNoDevice
		}
	}

	// Initialize part of tkey - UDI is filled in later when we
	// have a connection. See below.
	tkey := TKey{
		client:  *tkeyclient.New(),
		verbose: verbose,
	}

	if verbose {
		le.Printf("Connecting to device on serial port %s ...\n", devPath)
	}

	if err := tkey.client.Connect(devPath, tkeyclient.WithSpeed(speed)); err != nil {
		return nil, ConnError{devPath: devPath, err: err}
	}

	// We now have a connection, so close it if we get any of
	// these signals.
	handleSignals(func() {
		tkey.Close()
		os.Exit(1)
	}, os.Interrupt, syscall.SIGTERM)

	return &tkey, nil
}

// GetUDI gets the UDI of a TKey
func (t TKey) GetUDI() (UDI, error) {
	var udi UDI

	tkUDI, err := t.client.GetUDI()
	if err != nil {
		return udi, fmt.Errorf("%w", err)
	}

	if err = udi.fromRawLE(tkUDI.RawBytes()); err != nil {
		return udi, fmt.Errorf("%w", err)
	}

	return udi, nil
}

func (t TKey) Close() {
	t.client.Close()
}

func checkApp(t *TKey) (bool, *tkeyclient.NameVersion, []byte, error) {
	isFirmware, err := t.client.FirmwareActive()
	if err != nil {
		return false, nil, nil, fmt.Errorf("%w", err)
	}

	if isFirmware {
		return false, nil, nil, nil
	}

	nameVer, err := t.signer.GetAppNameVersion()
	if err != nil {
		return false, nameVer, nil, fmt.Errorf("%w", err)
	}

	le.Printf("App name0:'%s' name1:'%s' version:%d\n",
		nameVer.Name0, nameVer.Name1, nameVer.Version)

	pubKey, err := t.signer.GetPubkey()
	if err != nil {
		return false, nameVer, nil, fmt.Errorf("%w", err)
	}

	return true, nameVer, pubKey, nil

}

// LoadSigner loads device app BIN without USS.
//
// Returns the public key and any error.
func (t *TKey) LoadSigner(bin []byte, checkForApp bool) ([]byte, error) {
	t.signer = tkeysign.New(&t.client)

	// Check if a signer app is already loaded.
	if checkForApp {
		rightApp, _, pubKey, err := checkApp(t)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		if rightApp {
			return pubKey, nil
		}
	}

	if err := possiblyReset(t.client); err != nil {
		fmt.Printf("strange: %v\n", err)
		return nil, ErrNotFirmware
	}

	if udi, err := t.GetUDI(); err != nil {
		return nil, fmt.Errorf("%w", err)
	} else {
		t.Udi = udi
	}

	// No USS.
	if err := t.client.LoadApp(bin, []byte{}); err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if t.verbose {
		le.Printf("App loaded.\n")
	}

	// Before the device app starts, all the USB endpoints are
	// turned off, so we wait until the port is closed and open
	// again.
	if err := t.client.WaitClosed(); err != nil {
		return nil, fmt.Errorf("expected port close: %w", err)
	}

	if err := t.client.Reconnect(); err != nil {
		return nil, fmt.Errorf("couldn't reconnect: %w", err)
	}

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

// GetPubkey connects to a TKey and asks an already running
// verisigner-app for its public key.
func (t TKey) GetPubkey() ([]byte, error) {
	pubkey, err := t.signer.GetPubkey()
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return pubkey, nil
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

// Challenge gets a device signature over a random challenge.
//
// It returns true if verification was a success. False otherwise.
func (t *TKey) Challenge(pubKey []byte) error {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("rand.Read failed: %w", err)
	}

	signature, err := t.Sign(challenge)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	// Verify device signature against device public key
	if !ed25519.Verify(pubKey, challenge, signature) {
		return fmt.Errorf("%w", err)
	}

	return nil
}
