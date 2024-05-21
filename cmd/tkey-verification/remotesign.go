// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/rpc"
	"os"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

func remoteSign(server Server, appBin AppBin, devPath string, firmwares Firmwares, verbose bool) {
	udi, pubKey, fw, err := signChallenge(devPath, appBin, firmwares, verbose)
	if err != nil {
		le.Printf("Couldn't sign challenge: %s\n", err)
		os.Exit(1)
	}

	err = vendorSign(server, udi.Bytes, pubKey, fw, appBin)
	if err != nil {
		le.Printf("Couldn't get a vendor signature: %s\n", err)
		os.Exit(1)
	}

	le.Printf("Remote Sign was successful\n")
}

// Returns UDI, pubkey, expected firmware, error
func signChallenge(devPath string, appBin AppBin, firmwares Firmwares, verbose bool) (*tkey.UDI, []byte, Firmware, error) {
	var fw Firmware
	tk, err := tkey.NewTKey(devPath, verbose)
	if err != nil {
		return nil, nil, fw, fmt.Errorf("%w", err)
	}

	defer tk.Close()

	le.Printf("Loading device app built from %s ...\n", appBin.String())
	pubKey, err := tk.LoadSigner(appBin.Bin)
	if err != nil {
		return nil, nil, fw, fmt.Errorf("%w", err)
	}
	le.Printf("TKey UDI: %s\n", tk.Udi.String())

	expectfw, err := firmwares.GetFirmware(tk.Udi)
	if err != nil {
		return nil, nil, fw, fmt.Errorf("couldn't find firmware for UDI %s: %w", tk.Udi.String(), err)
	}

	fw, err = verifyFirmwareHash(*expectfw, *tk, pubKey)
	if err != nil {
		return nil, nil, fw, fmt.Errorf("%w", err)
	}
	le.Printf("TKey firmware with size:%d and verified hash:%0x…\n", fw.Size, fw.Hash[:16])

	// Locally generate a challenge and sign it
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		return nil, nil, fw, fmt.Errorf("%w", err)
	}

	signature, err := tk.Sign(challenge)
	if err != nil {
		return nil, nil, fw, fmt.Errorf("%w", err)
	}

	fmt.Printf("signature: %x\n", signature)

	// Verify the signature against the extracted public key
	if !ed25519.Verify(pubKey, challenge, signature) {
		return nil, nil, fw, fmt.Errorf("device signature failed verification")
	}

	return &tk.Udi, pubKey, fw, nil
}

func vendorSign(server Server, udi []byte, pubKey []byte, fw Firmware, appBin AppBin) error {
	conn, err := tls.Dial("tcp", server.Addr, &server.TlsConfig)
	if err != nil {
		le.Printf("Dial failed: %s", err)
		os.Exit(1)
	}

	exit := func(code int) {
		conn.Close()
		os.Exit(code)
	}

	client := rpc.NewClient(conn)

	msg, err := buildMessage(udi, fw.Hash[:], pubKey)
	if err != nil {
		le.Printf("buildMessage failed: %s", err)
		exit(1)
	}

	args := Args{
		UDIBE:   udi,
		AppTag:  appBin.Tag,
		AppHash: appBin.Hash(),
		Message: msg,
	}

	err = client.Call("API.Sign", &args, nil)
	if err != nil {
		le.Printf("API.Sign error: %s", err)
		exit(1)
	}

	return nil
}
