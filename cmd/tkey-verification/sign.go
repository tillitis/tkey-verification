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
	sigsumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type SigningConf struct {
	SigningAppHash string `yaml:"signingapphash"`
	ActiveKey      string `yaml:"activekey"`    // Expected vendor public key
	ActiveSerial   string `yaml:"activeserial"` // Expected serial number of vendor TKey
}

func sign(dev Device, conf SigningConf, verbose bool) {
	// Find the app to use
	var appHash [sha512.Size]byte

	if err := util.DecodeHex(appHash[:], conf.SigningAppHash); err != nil {
		le.Printf("couldn't decode signingapphash from config")
		os.Exit(1)
	}

	appBin, ok := appbins.MustAppBins().Bins[appHash]
	if !ok {
		le.Printf("Couldn't find configure app %v\n", conf.SigningAppHash)
		os.Exit(1)
	}

	// Get our firmwares
	var firmwares firmware.Firmwares
	firmwares.MustDecodeString(data.FirmwaresConf)

	// Find the devices to use
	// TODO - should be in config file
	conf.ActiveSerial = "8e7473ea-e464-45a4-8096-2e61ed0a748e"
	vendorDev, verDev, err := getTKeys(conf.ActiveSerial)
	if err != nil {
		fmt.Printf("getting TKeys: %v\n", err)
		os.Exit(1)
	}

	// Authenticate the device
	fmt.Printf("Authenticating %v on %v\n", verDev.serial, verDev.devPath)
	message, err := authDevice(Device{verDev.devPath, tkeyclient.SerialSpeed}, appBin, firmwares, verbose)
	if err != nil {
		le.Printf("Couldn't authenticate device: %s\n", err)
		os.Exit(1)
	}

	var log sigsum.Log
	if err = log.FromEmbedded(); err != nil {
		le.Printf("Found no usable Sigsum configuration: %v\n", err)
		os.Exit(1)
	}

	// Do we have the configured pubkey to use for Sigsum submit key
	activeKey, err := ssh.ParsePublicEd25519(conf.ActiveKey)
	if err != nil {
		le.Printf("parse error in config: %v\n", err)
		os.Exit(1)
	}

	submitKey, ok := log.Keys[activeKey]
	if !ok {
		le.Printf("Compiled in submit key indexed by %x not found\n", activeKey)
		os.Exit(1)
	}

	tk, err := tkey.NewTKey(vendorDev.devPath, dev.Speed, verbose)
	if err != nil {
		le.Printf("Couldn't connect to TKey: %v\n", err)
		os.Exit(1)
	}

	exit := func(code int) {
		tk.Close()
		os.Exit(code)
	}

	le.Printf("Sigsum signing: %s\n", submitKey.String())
	le.Printf("Loading device app built from %s ...\n", submitKey.AppBin.String())
	foundPubKey, err := tk.LoadSigner(submitKey.AppBin.Bin)
	if err != nil {
		fmt.Printf("Couldn't load device app: %v\n", err)
		exit(1)
	}

	if !bytes.Equal(submitKey.Key[:], foundPubKey) {
		le.Printf("TKey pubkey does not match active embedded pubkey\nExpected: %v\nReceived: %v\n",
			ssh.FormatPublicEd25519(submitKey.Key),
			ssh.FormatPublicEd25519(ssh.PublicKey(foundPubKey)))
		exit(1)
	}
	le.Printf("Found signing TKey with the expected public key and UDI: %s\n", tk.Udi.String())

	if err = os.MkdirAll(signaturesDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		exit(1)
	}

	// TODO Get UDI

	h := appBin.Hash()
	le.Printf("Going to sign for TKey with UDI:%s(BE) apptag:%s apphash:%0x…\n", hex.EncodeToString(message.udi.Bytes), appBin.Tag, h[:16])

	byteMessage, err := util.BuildMessage(message.udi.Bytes, message.fw.Hash[:], message.pubKey)
	if err != nil {
		panic(err)
	}

	signer := TkeySigsumSigner{*tk}
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

	// File named after the UDIBE in hex
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(message.udi.Bytes))
	if _, err = os.Stat(fn); err == nil || !errors.Is(err, os.ErrNotExist) {
		le.Printf("Signature file %s already exists\n", fn)

		panic(ErrSigExist)
	}

	subm := submission.Submission{
		Timestamp: time.Now().UTC(),
		AppTag:    appBin.Tag,
		AppHash:   appBin.Hash(),
		Request:   leafReq,
	}

	err = subm.ToFile(fn)
	if err != nil {
		le.Printf("WriteFile %s failed: %v", fn, err)

		panic(ErrInternal)
	}

	le.Printf("Wrote %s\n", fn)
}
