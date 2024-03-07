// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/rpc"
	"os"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

func remoteSign(conf Config, appBin AppBin, devPath string, verbose bool, checkConfigOnly bool) {
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{
			loadCert(conf.ClientCert, conf.ClientKey),
		},
		RootCAs:    loadCA(conf.CACert),
		MinVersion: tls.VersionTLS13,
	}

	_, _, err := net.SplitHostPort(conf.ServerAddr)
	if err != nil {
		le.Printf("Config server: SplitHostPort failed: %s", err)
		os.Exit(1)
	}

	conn, err := tls.Dial("tcp", conf.ServerAddr, &tlsConfig)
	if err != nil {
		le.Printf("Dial failed: %s", err)
		os.Exit(1)
	}

	exit := func(code int) {
		conn.Close()
		os.Exit(code)
	}

	client := rpc.NewClient(conn)
	err = client.Call("API.Ping", struct{}{}, nil)
	if err != nil {
		le.Printf("API.Ping error: %s", err)
		exit(1)
	}

	if checkConfigOnly {
		exit(0)
	}

	le.Printf("Loading device app built from %s ...\n", appBin.String())
	udi, pubKey, ok := tkey.Load(appBin.Bin, devPath, verbose)
	if !ok {
		exit(1)
	}
	le.Printf("TKey UDI: %s\n", udi.String())

	fw, err := verifyFirmwareHash(devPath, pubKey, udi)
	if err != nil {
		le.Printf("verifyFirmwareHash failed: %s\n", err)
		os.Exit(1)
	}
	le.Printf("TKey firmware with size:%d and verified hash:%0x…\n", fw.Size, fw.Hash[:16])

	// Locally generate a challenge and sign it
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		le.Printf("rand.Read failed: %s\n", err)
		exit(1)
	}

	signature, err := tkey.Sign(devPath, pubKey, challenge)
	if err != nil {
		le.Printf("tkey.Sign failed: %s", err)
		exit(1)
	}

	// Verify the signature against the extracted public key
	if !ed25519.Verify(pubKey, challenge, signature) {
		le.Printf("device signature failed verification!")
		os.Exit(1)
	}

	msg, err := buildMessage(udi.Bytes, fw.Hash[:], pubKey)
	if err != nil {
		le.Printf("buildMessage failed: %s", err)
		os.Exit(1)
	}

	args := Args{
		UDIBE:   udi.Bytes,
		AppTag:  appBin.Tag,
		AppHash: appBin.Hash(),
		Message: msg,
	}

	err = client.Call("API.Sign", &args, nil)
	if err != nil {
		le.Printf("API.Sign error: %s", err)
		exit(1)
	}

	le.Printf("Remote Sign was successful\n")
	exit(0)
}
