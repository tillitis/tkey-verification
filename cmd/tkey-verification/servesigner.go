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

	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/vendorsigning"
)

type Verification struct {
	Timestamp string `json:"timestamp"`
	Tag       string `json:"tag"`
	Signature string `json:"signature"`
}

func serveSigner(vendorPubKey *vendorsigning.PubKey, devPath string, verbose bool, checkConfigOnly bool) {
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

	le.Printf("%s\n", vendorPubKey.String())

	foundUDIBE, foundPubKey, ok := tkey.Load(vendorPubKey.AppBin, devPath, verbose)
	if !ok {
		os.Exit(1)
	}
	if bytes.Compare(vendorPubKey.PubKey[:], foundPubKey) != 0 {
		le.Printf("Found TKey pubkey \"%s\" does not match the embedded vendor signing pubkey in use\n", hex.EncodeToString(foundPubKey))
		os.Exit(1)
	}
	le.Printf("Found TKey with matching pubkey (UDI (BE): %s)\n", hex.EncodeToString(foundUDIBE))

	if err := os.MkdirAll(signaturesDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		os.Exit(1)
	}

	go serve(vendorPubKey.PubKey[:], devPath, &tlsConfig)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	<-signalCh

	le.Printf("Exiting on signal\n")

	os.Exit(0)
}

func serve(vendorPubKey []byte, devPath string, tlsConfig *tls.Config) {
	if err := rpc.Register(NewAPI(vendorPubKey, devPath)); err != nil {
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
			// Note: is this really fatal, should we exit?
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
