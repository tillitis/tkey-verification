// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/firmware"
	"github.com/tillitis/tkey-verification/internal/sigsum"
	"github.com/tillitis/tkey-verification/internal/ssh"
	"github.com/tillitis/tkey-verification/internal/submission"
	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/util"
	"github.com/tillitis/tkeyclient"
	sigsumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type Message struct {
	udi    tkey.UDI
	pubKey []byte
	fw     firmware.Firmware
}

// sign is the main function of the "sign" command.
//
// sign automatically detects the devices used: One submission device,
// one device to authenticate.
//
// The USB serial of the submission device needs to be in the
// configuration conf.ActiveSerial. The resulting public key of
// loading the device app conf.AuthAppBin needs to match
// the public key in conf.SubmitKey.
//
// sign loads the submission app into the submission device, then
// loads the authentication app into the device to authenticate and
// requests its public key. It challenges the latter to make it prove
// that it has the corresponding private key, then builds a message to
// sign with the submission device.
//
// The message is then written into a Sigsum submission file.
//
// The functions logs and exits to OS itself.
func sign(conf Conf, verbose bool) error {
	// Find the TKey serial ports to use, the submission port and
	// the authenticate port.
	subPort, authPort, err := getTKeys(conf.ActiveSerial)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	submitDev, err := newSubmitDevice(subPort.DevPath, conf.SubmitKey)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	// Authenticate the new device by loading a signer app,
	// getting its public key, and challenging it, thus proving
	// that it contains the corresponding private key.
	fmt.Printf("Authenticating %v on %v\n", authPort.SerialNumber, authPort.DevPath)
	message, err := authDevice(Device{authPort.DevPath, tkeyclient.SerialSpeed}, conf.AuthAppBin, conf.Firmwares, verbose)
	if err != nil {
		le.Printf("Couldn't authenticate device: %s\n", err)
		os.Exit(1)
	}

	// Create a Sigsum submission file by signing the message with
	// the submit device.
	h := conf.AuthAppBin.Hash()
	le.Printf("Going to sign for TKey with UDI:%s(BE) apptag:%s apphash:%0x…\n", hex.EncodeToString(message.udi.Bytes), conf.AuthAppBin.Tag, h[:16])

	leafReq, err := submitDev.Sign(message)
	if err != nil {
		fmt.Printf("signing: %v\n", err)
		os.Exit(1)
	}

	// Don't need the submission device anymore.
	submitDev.tk.Close()

	if err := writeSubmissionFile(signaturesDir, conf.AuthAppBin, message, leafReq); err != nil {
		fmt.Printf("writing submission file: %v\n", err)
		os.Exit(1)
	}
}

func authDevice(dev Device, appBin appbins.AppBin, firmwares firmware.Firmwares, verbose bool) (Message, error) {
	var message Message

	// Load the app
	tk, err := tkey.NewTKey(dev.Path, dev.Speed, verbose)
	if err != nil {
		return message, fmt.Errorf("%w", err)
	}

	defer tk.Close()

	pubKey, err := tk.LoadSigner(appBin.Bin)
	if err != nil {
		return message, fmt.Errorf("%w", err)
	}
	le.Printf("TKey UDI: %s\n", tk.Udi.String())

	// Authenticate against pubkey
	err = tk.Challenge(pubKey)
	if err != nil {
		return message, fmt.Errorf("challenge/response failed: %w", err)
	}

	// Verify the firmware
	fw, err := verifyFirmwareHash(*tk, firmwares)
	if err != nil {
		return message, fmt.Errorf("%w", err)
	}
	le.Printf("TKey firmware with size:%d and verified hash:%0x…\n", fw.Size, fw.Hash[:16])

	message.udi = tk.Udi
	message.pubKey = pubKey
	message.fw = fw

	return message, nil
}

type submitDevice struct {
	tk        *tkey.TKey
	submitKey *sigsum.PubKey
}

func newSubmitDevice(path string, submitKey *sigsum.PubKey) (*submitDevice, error) {
	var sDevice submitDevice

	// Load the vendor signing app, if necessary.
	le.Printf("Loading device app built from %s ...\n", submitKey.AppBin.String())
	tk, err := tkey.NewTKey(path, tkeyclient.SerialSpeed, false)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	foundPubKey, err := tk.MaybeLoadSigner(submitKey.AppBin.Bin)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	// Check that the derived public key is indeed our configured
	// submit key.
	if !bytes.Equal(submitKey.Key[:], foundPubKey) {
		le.Printf("TKey pubkey does not match active embedded pubkey\nExpected: %v\nReceived: %v\n",
			ssh.FormatPublicEd25519(submitKey.Key),
			ssh.FormatPublicEd25519(ssh.PublicKey(foundPubKey)))
		return nil, errors.New("configured key does not match embedded key")
	}

	sDevice.tk = tk
	sDevice.submitKey = submitKey

	return &sDevice, nil
}

func (s *submitDevice) Sign(message Message) (requests.Leaf, error) {
	le.Printf("Sigsum signing: %s\n", s.submitKey.String())

	byteMessage, err := util.BuildMessage(message.udi.Bytes, message.fw.Hash[:], message.pubKey)
	if err != nil {
		return requests.Leaf{}, fmt.Errorf("%w", err)
	}

	signer := TkeySigsumSigner{*s.tk}
	sigsumMsg := sigsumcrypto.HashBytes(byteMessage)
	signature, err := types.SignLeafMessage(signer, sigsumMsg[:])
	if err != nil {
		return requests.Leaf{}, ErrSignFailed
	}

	leafReq := requests.Leaf{Message: sigsumMsg, Signature: signature, PublicKey: signer.Public()}
	_, err = leafReq.Verify()
	if err != nil {
		return leafReq, ErrVerificationFailed
	}

	return leafReq, nil
}

// writeSubmissionFile writes a submission file inside signaturesDir
// with a file containing information about what app was used when
// authenticating the new device and the signed message to be included
// in Sigsum in the form of a leaf request.
func writeSubmissionFile(signaturesDir string, appBin appbins.AppBin, message Message, leafReq requests.Leaf) error {
	if err := os.MkdirAll(signaturesDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		os.Exit(1)
	}

	// File named after the UDIBE in hex
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(message.udi.Bytes))
	if _, err := os.Stat(fn); err == nil || !errors.Is(err, os.ErrNotExist) {
		le.Printf("Signature file %s already exists\n", fn)

		return ErrSigExist
	}

	subm := submission.Submission{
		Timestamp: time.Now().UTC(),
		AppTag:    appBin.Tag,
		AppHash:   appBin.Hash(),
		Request:   leafReq,
	}

	if err := subm.ToFile(fn); err != nil {
		le.Printf("WriteFile %s failed: %v", fn, err)

		return ErrInternal
	}

	le.Printf("Wrote %s\n", fn)

	return nil
}

// Find the submission TKey and the TKey to authenticate
func getTKeys(activeSerial string) (*tkeyclient.SerialPort, *tkeyclient.SerialPort, error) {
	devices, err := tkeyclient.GetSerialPorts()
	if err != nil {
		return nil, nil, fmt.Errorf("getting devices: %w", err)
	}

	if len(devices) > 2 {
		return nil, nil, errors.New("too many devices")
	}

	var vendorDev, verDev *tkeyclient.SerialPort

	for _, d := range devices {
		if d.SerialNumber == activeSerial {
			vendorDev = &d
		} else {
			verDev = &d
		}
	}

	if vendorDev == nil {
		return nil, nil, fmt.Errorf("no vendor device %v", activeSerial)
	}

	if verDev == nil {
		return nil, nil, errors.New("no device under verification")
	}

	return vendorDev, verDev, nil
}
