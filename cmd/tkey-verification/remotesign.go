// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/tls"
	"encoding/hex"
	"net/rpc"
	"os"
)

func remoteSign(devPath string, verbose bool) {
	udi, pubKey, ok := runSignerApp(devPath, verbose, signerAppBin)
	if !ok {
		os.Exit(1)
	}
	le.Printf("TKey raw UDI: %s\n", hex.EncodeToString(udi))

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

	args := Args{
		UDI:    *(*[8]byte)(udi),
		Tag:    signerAppTag,
		PubKey: pubKey,
	}

	client := rpc.NewClient(conn)
	err = client.Call("API.Sign", &args, nil)
	if err != nil {
		le.Printf("API.Sign error: %s", err)
		conn.Close()
		os.Exit(1)
	}

	le.Printf("Remote Sign was successful\n")
	conn.Close()
	os.Exit(0)
}
