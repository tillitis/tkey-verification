// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/rpc"
	"os"
	"os/signal"
	"syscall"

	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/vendorsigning"
)

type Verification struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Signature string `json:"signature"`
}

func serveSigner(conf Config, vendorPubKey *vendorsigning.PubKey, devPath string, verbose bool, checkConfigOnly bool) {
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{
			loadCert(conf.ServerCert, conf.ServerKey),
		},
		ClientCAs:  loadCA(conf.CACert),
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	_, _, err := net.SplitHostPort(conf.ListenAddr)
	if err != nil {
		le.Printf("Config listen: SplitHostPort failed: %s", err)
		os.Exit(1)
	}

	if checkConfigOnly {
		os.Exit(0)
	}

	le.Printf("Vendor signing: %s\n", vendorPubKey.String())

	foundUDI, foundPubKey, ok := tkey.Load(vendorPubKey.AppBin, devPath, verbose)
	if !ok {
		os.Exit(1)
	}
	if bytes.Compare(vendorPubKey.PubKey[:], foundPubKey) != 0 {
		le.Printf("The public key of the found TKey (\"%s\") does not match the embedded vendor signing public key in use\n", hex.EncodeToString(foundPubKey))
		os.Exit(1)
	}
	le.Printf("Found signing TKey with the expected public key and UDI: %s\n", foundUDI.String())

	if err := os.MkdirAll(signaturesDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		os.Exit(1)
	}

	go serve(conf.ListenAddr, vendorPubKey.PubKey[:], devPath, &tlsConfig)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	<-signalCh

	le.Printf("Exiting on signal\n")

	os.Exit(0)
}

func serve(listenAddr string, vendorPubKey []byte, devPath string, tlsConfig *tls.Config) {
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
