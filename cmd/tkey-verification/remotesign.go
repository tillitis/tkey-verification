// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net/rpc"
	"os"
)

func remoteSign(devPath string, verbose bool, checkConfigOnly bool) {
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{
			loadCert(clientCertFile, clientKeyFile),
		},
		RootCAs:    loadCA(caCertFile),
		MinVersion: tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, &tlsConfig)
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

	udiBE, pubKey, ok := runSignerApp(devPath, verbose, signerAppBin)
	if !ok {
		exit(1)
	}
	le.Printf("TKey UDI (BE): %s\n", hex.EncodeToString(udiBE[:]))

	// Locally generate a challenge and sign it
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		le.Printf("rand.Read failed: %s\n", err)
		exit(1)
	}

	// The message we want vendor to sign is our signature over the
	// challenge
	message, err := signWithApp(devPath, pubKey, challenge)
	if err != nil {
		le.Printf("local sign failed: %s", err)
		exit(1)
	}

	args := Args{
		UDI:       udiBE,
		Tag:       signerAppTag,
		Challenge: challenge,
		Message:   message,
	}

	err = client.Call("API.Sign", &args, nil)
	if err != nil {
		le.Printf("API.Sign error: %s", err)
		exit(1)
	}

	le.Printf("Remote Sign was successful\n")
	exit(0)
}
