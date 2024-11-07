// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/rpc"
	"os"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

func remoteSign(conf ProvConfig, dev Device, verbose bool) {
	_, _, err := net.SplitHostPort(conf.ServerAddr)
	if err != nil {
		le.Printf("SplitHostPort failed: %s", err)
		os.Exit(1)
	}

	server := Server{
		Addr: conf.ServerAddr,
		TLSConfig: tls.Config{
			Certificates: []tls.Certificate{
				loadCert(conf.ClientCert, conf.ClientKey),
			},
			RootCAs:    loadCA(conf.CACert),
			MinVersion: tls.VersionTLS13,
		},
	}

	appBin, udi, pubKey, fw, err := signChallenge(conf, dev, verbose)
	if err != nil {
		le.Printf("Couldn't sign challenge: %s\n", err)
		os.Exit(1)
	}

	err = vendorSign(&server, udi.Bytes, pubKey, fw, appBin)
	if err != nil {
		le.Printf("Couldn't get a vendor signature: %s\n", err)
		os.Exit(1)
	}

	le.Printf("Remote Sign was successful\n")
}

// Returns the currently used device app, UDI, pubkey, expected
// firmware, and any error
func signChallenge(conf ProvConfig, dev Device, verbose bool) (AppBin, *tkey.UDI, []byte, Firmware, error) {
	appBins, err := NewAppBins()
	if err != nil {
		fmt.Printf("Failed to init embedded device apps: %v\n", err)
		os.Exit(1)
	}

	// Do we have the configured device app to use for device signature?
	var appBin AppBin

	if aBin, ok := appBins.Bins[conf.SigningAppHash]; ok {
		appBin = aBin
	} else {
		fmt.Printf("Compiled in device signing app corresponding to hash %v (signingapphash) not found\n", conf.SigningAppHash)
		os.Exit(1)
	}

	firmwares, err := NewFirmwares()
	if err != nil {
		le.Printf("Found no usable firmwares\n")
		os.Exit(1)
	}

	var fw Firmware
	tk, err := tkey.NewTKey(dev.Path, dev.Speed, verbose)
	if err != nil {
		return appBin, nil, nil, fw, fmt.Errorf("%w", err)
	}

	defer tk.Close()

	le.Printf("Loading device app built from %s ...\n", appBin.String())
	pubKey, err := tk.LoadSigner(appBin.Bin)
	if err != nil {
		return appBin, nil, nil, fw, fmt.Errorf("%w", err)
	}
	le.Printf("TKey UDI: %s\n", tk.Udi.String())

	expectfw, err := firmwares.GetFirmware(tk.Udi)
	if err != nil {
		return appBin, nil, nil, fw, MissingError{what: "couldn't find firmware for UDI"}
	}

	fw, err = verifyFirmwareHash(*expectfw, *tk)
	if err != nil {
		return appBin, nil, nil, fw, fmt.Errorf("%w", err)
	}
	le.Printf("TKey firmware with size:%d and verified hash:%0x…\n", fw.Size, fw.Hash[:16])

	// Locally generate a challenge and sign it
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		return appBin, nil, nil, fw, fmt.Errorf("%w", err)
	}

	signature, err := tk.Sign(challenge)
	if err != nil {
		return appBin, nil, nil, fw, fmt.Errorf("%w", err)
	}

	fmt.Printf("signature: %x\n", signature)

	// Verify the signature against the extracted public key
	if !ed25519.Verify(pubKey, challenge, signature) {
		return appBin, nil, nil, fw, ErrVerificationFailed
	}

	return appBin, &tk.Udi, pubKey, fw, nil
}

func vendorSign(server *Server, udi []byte, pubKey []byte, fw Firmware, appBin AppBin) error {
	conn, err := tls.Dial("tcp", server.Addr, &server.TLSConfig)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	client := rpc.NewClient(conn)

	msg, err := buildMessage(udi, fw.Hash[:], pubKey)
	if err != nil {
		return fmt.Errorf("building message to sign failed: %w", err)
	}

	args := Args{
		UDIBE:   udi,
		AppTag:  appBin.Tag,
		AppHash: appBin.Hash(),
		Message: msg,
	}

	err = client.Call("API.Sign", &args, nil)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}
