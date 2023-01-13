// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"net/rpc"
	"os"
	"os/signal"
	"syscall"
)

type Verification struct {
	Timestamp string `json:"timestamp"`
	Tag       string `json:"tag"`
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}

func serveSigner(devPath string, verbose bool, checkConfigOnly bool) {
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{
			loadCert(serverCertFile, serverKeyFile),
		},
		ClientCAs:  loadCA(caCertFile),
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	if checkConfigOnly {
		os.Exit(0)
	}

	foundUDIBE, foundPubKey, ok := runSignerApp(devPath, verbose, signerAppBin)
	if !ok {
		os.Exit(1)
	}
	le.Printf("Found TKey with pubkey: %s (UDI (BE): %s)\n", hex.EncodeToString(foundPubKey), hex.EncodeToString(foundUDIBE[:]))

	if bytes.Compare(foundPubKey, signingPubKey) != 0 {
		le.Printf("Found TKey pubkey does not match our embedded signing pubkey: %s\n", hex.EncodeToString(foundPubKey))
		os.Exit(1)
	}
	le.Printf("Found TKey pubkey matches our embedded signing pubkey.\n")

	if err := os.MkdirAll(signaturesDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		os.Exit(1)
	}

	go serve(devPath, &tlsConfig)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	<-signalCh

	le.Printf("Exiting on signal\n")

	os.Exit(0)
}

func serve(devPath string, tlsConfig *tls.Config) {
	if err := rpc.Register(NewAPI(devPath)); err != nil {
		le.Printf("Register failed: %s\n", err)
		os.Exit(1)
	}

	listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
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
