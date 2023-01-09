// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/tls"
	"encoding/hex"
	"net/rpc"
	"os"
	"os/signal"
	"syscall"
)

type Verification struct {
	Timestamp int64  `json:"timestamp"`
	Tag       string `json:"tag"`
	Hash      string `json:"hash"`
	Signature string `json:"signature"`
}

// TODO? we don't keep a connection to our signing TKey, but verify on
// every signing that pubkey is the one we found on startup!

func serveSigner(devPath string, verbose bool, appBin []byte) {
	udi, signingPubKey, ok := runSignerApp(devPath, verbose, appBin)
	if !ok {
		os.Exit(1)
	}
	le.Printf("Signing TKey raw UDI: %s\n", hex.EncodeToString(udi))
	le.Printf("Signing TKey pubkey: %s\n", hex.EncodeToString(signingPubKey))

	// // le.Printf("The signing TKey should be flashing
	// _, err := signWithApp(devPath, signingPubKey, [32]byte{})
	// if err != nil {
	// 	le.Printf("signWithApp failed: %s\n", err)
	// 	os.Exit(1)
	// }

	// TODO dropping the signing pubkey here for now
	fn := "signing.pub"
	if err := os.WriteFile(fn, []byte(hex.EncodeToString(signingPubKey)+"\n"), 0o644); err != nil { //nolint:gosec
		le.Printf("WriteFile %s failed: %s\n", fn, err)
		os.Exit(1)
	}
	le.Printf("Wrote %s\n", fn)

	if err := os.MkdirAll(signaturesDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		os.Exit(1)
	}

	go serve(devPath, signingPubKey)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	<-signalCh

	le.Printf("Exiting on signal\n")

	os.Exit(0)
}

func serve(devPath string, signingPubKey []byte) {
	if err := rpc.Register(NewAPI(devPath, signingPubKey)); err != nil {
		le.Printf("Register failed: %s\n", err)
		os.Exit(1)
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{
			loadCert(serverCertFile, serverKeyFile),
		},
		ClientCAs:  loadCA(caCertFile),
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", listenAddr, &tlsConfig)
	if err != nil {
		le.Printf("Listen failed: %s\n", err)
		os.Exit(1)
	}

	le.Printf("Listening on %s...\n", listenAddr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			le.Printf("Accept failed: %s\n", err)
			// TODO is this really fatal, should we exit?
			os.Exit(1)
		}
		le.Printf("Client from %s\n", conn.RemoteAddr())
		go func() {
			defer conn.Close()
			rpc.ServeConn(conn)
			le.Printf("Closed %s\n", conn.RemoteAddr())
		}()
	}
}
