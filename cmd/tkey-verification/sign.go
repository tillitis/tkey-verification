// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/data"
	"github.com/tillitis/tkey-verification/internal/firmware"
	"github.com/tillitis/tkey-verification/internal/sigsum"
	"github.com/tillitis/tkey-verification/internal/ssh"
	"github.com/tillitis/tkey-verification/internal/submission"
	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/util"
	"github.com/tillitis/tkeyclient"
	"gopkg.in/yaml.v2"
	sigsumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type Conf struct {
	AuthAppDigest string `yaml:"authappdigest"` // Digest of app for device authentication
	ActiveKey     string `yaml:"activekey"`     // Submission public key - needs to be in data.go, too.
	ActiveSerial  string `yaml:"activeserial"`  // Serial number of submission TKey
}

type Message struct {
	udi    tkey.UDI
	pubKey []byte
	fw     firmware.Firmware
}

func loadConfig(fn string) (Conf, error) {
	var conf Conf

	rawConfig, err := os.ReadFile(fn)
	if err != nil {
		return conf, fmt.Errorf("couldn't read config file: %w", err)
	}

	err = yaml.Unmarshal(rawConfig, &conf)
	if err != nil {
		return conf, fmt.Errorf("parse error in config file: %w", err)
	}

	return conf, nil
}

// sign is the main function of the "sign" command.
//
// It automatically detects the devices used: One submission device,
// one device to assert.
//
// The USB serial of the submission device needs to be in the
// configuration to be found. The resulting public key of loading the
// device app with the conf.AuthAppDigest needs to match the
// conf.ActiveKey.
//
// It loads the submission app into the submission device, then loads
// the authentication app into the device to assert and requests its
// public key. It challenges the latter to make it prove that it has
// the corresponding private key, then builds a message to sign with
// the submission device.
//
// The message is then written into a Sigsum submission file.
//
// The functions logs and exits to OS itself.
func sign(conf Conf, verbose bool) {
	// Find the devices to use.
	subDev, assertDev, err := getTKeys(conf.ActiveSerial)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	// Get our firmwares. Needed to be able find the current
	// device's firmware and verify that it's known.
	var firmwares firmware.Firmwares
	// TODO could be like log's FromEmbedded()
	firmwares.MustDecodeString(data.FirmwaresConf)

	submitDev, err := newSubmitDevice(subDev.devPath, conf.ActiveKey)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	// Authenticate the new device by loading a signer app,
	// getting its public key, and challenging it, thus proving
	// that it contains the corresponding private key.
	fmt.Printf("Authenticating %v on %v\n", assertDev.serial, assertDev.devPath)
	message, appBin, err := createDeviceMessage(assertDev, conf.AuthAppDigest, firmwares, verbose)
	if err != nil {
		le.Printf("Couldn't authenticate device: %s\n", err)
		os.Exit(1)
	}

	// Create a Sigsum submission file by signing the message.
	h := appBin.Hash()
	le.Printf("Going to sign for TKey with UDI:%s(BE) apptag:%s apphash:%0x…\n", hex.EncodeToString(message.udi.Bytes), appBin.Tag, h[:16])

	leafReq, err := submitDev.Sign(message)
	if err != nil {
		fmt.Printf("signing: %v\n", err)
		os.Exit(1)
	}

	// Don't need the submission device anymore.
	submitDev.tk.Close()

	// Write a Sigsum submission file.
	if err := writeSubmissionFile(signaturesDir, appBin, message, leafReq); err != nil {
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

func createDeviceMessage(verDev *usbDevice, signingAppHash string, firmwares firmware.Firmwares, verbose bool) (Message, appbins.AppBin, error) {
	// Find the app to use
	var appHash [sha512.Size]byte

	if err := util.DecodeHex(appHash[:], signingAppHash); err != nil {
		return Message{}, appbins.AppBin{}, errors.New("couldn't decode signingapphash from config")
	}

	appBin, ok := appbins.MustAppBins().Bins[appHash]
	if !ok {
		return Message{}, appBin, fmt.Errorf("configured app %v not found", signingAppHash)
	}

	message, err := authDevice(Device{verDev.devPath, tkeyclient.SerialSpeed}, appBin, firmwares, verbose)
	if err != nil {
		return Message{}, appBin, fmt.Errorf("authenticating device: %w", err)
	}

	return message, appBin, nil

}

func findSubmitKey(confActiveKey string) (*sigsum.PubKey, error) {
	var log sigsum.Log
	if err := log.FromEmbedded(); err != nil {
		le.Printf("Found no usable Sigsum configuration: %v\n", err)
		os.Exit(1)
	}

	// Check that the configured submit key is in the embedded
	// data for the Sigsum log and convert it into a usable form.
	submitKey, err := log.FindSSHKey(confActiveKey)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return submitKey, nil
}

type submitDevice struct {
	device    *usbDevice
	tk        *tkey.TKey
	submitKey *sigsum.PubKey
}

func newSubmitDevice(path string, confActiveKey string) (*submitDevice, error) {
	var sDevice submitDevice

	// Get our submission public key which also contains
	// information about what device app to run on signing device.
	submitKey, err := findSubmitKey(confActiveKey)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	// Load the vendor signing app, if necessary.
	le.Printf("Loading device app built from %s ...\n", submitKey.AppBin.String())
	tk, err := tkey.NewTKey(path, tkeyclient.SerialSpeed, false)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	foundPubKey, err := tk.LoadSigner(submitKey.AppBin.Bin)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	// Check that the derived public key is indeed our configured
	// submit key.
	if !bytes.Equal(submitKey.Key[:], foundPubKey[:]) {
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
		panic(err)
	}

	signer := TkeySigsumSigner{*s.tk}
	sigsumMsg := sigsumcrypto.HashBytes(byteMessage)
	signature, err := types.SignLeafMessage(signer, sigsumMsg[:])
	if err != nil {
		panic(ErrSignFailed)
	}

	leafReq := requests.Leaf{Message: sigsumMsg, Signature: signature, PublicKey: signer.Public()}
	_, err = leafReq.Verify()
	if err != nil {
		panic(ErrVerificationFailed)
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

		panic(ErrSigExist)
	}

	subm := submission.Submission{
		Timestamp: time.Now().UTC(),
		AppTag:    appBin.Tag,
		AppHash:   appBin.Hash(),
		Request:   leafReq,
	}

	if err := subm.ToFile(fn); err != nil {
		le.Printf("WriteFile %s failed: %v", fn, err)

		panic(ErrInternal)
	}

	le.Printf("Wrote %s\n", fn)

	return nil
}

type TkeySigsumSigner struct {
	tk tkey.TKey
}

func (s TkeySigsumSigner) Public() sigsumcrypto.PublicKey {
	pubkey, err := s.tk.GetPubkey()
	if err != nil {
		s.tk.Close()
		le.Fatal("GetPubKey failed: %w", err)
	}
	if len(pubkey) != sigsumcrypto.PublicKeySize {
		le.Fatalf("internal error, unexpected public key size %d: ", len(pubkey))
	}
	var ret sigsumcrypto.PublicKey
	copy(ret[:], pubkey)

	return ret
}

func (s TkeySigsumSigner) Sign(msg []byte) (sigsumcrypto.Signature, error) {
	sig, err := s.tk.Sign(msg)
	if err != nil {
		return sigsumcrypto.Signature{}, fmt.Errorf("%w", err)
	}
	if len(sig) != sigsumcrypto.SignatureSize {
		return sigsumcrypto.Signature{}, fmt.Errorf("internal error, unexpected signature size %d: ", len(sig))
	}
	var ret sigsumcrypto.Signature
	copy(ret[:], sig)

	return ret, nil
}
