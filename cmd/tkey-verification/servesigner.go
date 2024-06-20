// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"os/signal"
	"syscall"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

type Verification struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Signature string `json:"signature"`
}

func serveSigner(conf Config, devPath string, verbose bool, checkConfigOnly bool) {
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

	appBins, err := NewAppBins(latestAppHash)
	if err != nil {
		fmt.Printf("Failed to init embedded device apps: %v\n", err)
		os.Exit(1)
	}

	vendorKeys, err := NewVendorKeys(appBins, currentVendorHash)
	if err != nil {
		le.Printf("Found no usable embedded vendor signing public key: %v\n", err)
		os.Exit(1)
	}

	vendorPubKey := vendorKeys.Current()

	if checkConfigOnly {
		os.Exit(0)
	}

	tk, err := tkey.NewTKey(devPath, verbose)
	if err != nil {
		le.Printf("Couldn't connect to TKey: %v\n", err)
		os.Exit(1)
	}

	exit := func(code int) {
		tk.Close()
		os.Exit(code)
	}

	le.Printf("Vendor signing: %s\n", vendorPubKey.String())
	le.Printf("Loading device app built from %s ...\n", vendorPubKey.AppBin.String())
	foundPubKey, err := tk.LoadSigner(vendorPubKey.AppBin.Bin)
	if err != nil {
		fmt.Printf("Couldn't load device app: %v\n", err)
		exit(1)
	}
	if bytes.Compare(vendorPubKey.PubKey[:], foundPubKey) != 0 {
		le.Printf("The public key of the found TKey (\"%s\") does not match the embedded vendor signing public key in use\n", hex.EncodeToString(foundPubKey))
		exit(1)
	}
	le.Printf("Found signing TKey with the expected public key and UDI: %s\n", tk.Udi.String())

	if err := os.MkdirAll(signaturesDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		exit(1)
	}

	go serve(conf.ListenAddr, vendorPubKey.PubKey[:], *tk, &tlsConfig)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	<-signalCh

	le.Printf("Exiting on signal\n")

	exit(0)
}

func serve(listenAddr string, vendorPubKey []byte, tk tkey.TKey, tlsConfig *tls.Config) {
	if err := rpc.Register(NewAPI(vendorPubKey, tk)); err != nil {
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
