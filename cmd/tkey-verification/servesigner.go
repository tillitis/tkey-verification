// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/rpc"
	"os"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

type Verification struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Signature string `json:"signature"`
}

func serveSigner(conf ServerConfig, dev Device, verbose bool, checkConfigOnly bool) {
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

	appBins, err := NewAppBins()
	if err != nil {
		fmt.Printf("Failed to init embedded device apps: %v\n", err)
		os.Exit(1)
	}

	vendorKeys, err := NewVendorKeys(appBins)
	if err != nil {
		le.Printf("Found no usable embedded vendor signing public key: %v\n", err)
		os.Exit(1)
	}

	// Do we have the configured pubkey to use for vendor signing?
	var vendorPubKey PubKey

	if pubkey, ok := vendorKeys.Keys[conf.VendorSigningAppHash]; ok {
		vendorPubKey = pubkey
	} else {
		fmt.Printf("Compiled in vendor key corresponding to signing app hash %v not found\n", conf.VendorSigningAppHash)
		os.Exit(1)
	}

	if checkConfigOnly {
		os.Exit(0)
	}

	tk, err := tkey.NewTKey(dev.Path, dev.Speed, verbose)
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

	if err = os.MkdirAll(signaturesDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		exit(1)
	}

	if err = rpc.Register(NewAPI(vendorPubKey.PubKey[:], *tk)); err != nil {
		le.Printf("Register failed: %s\n", err)
		exit(1)
	}

	listener, err := tls.Listen("tcp", conf.ListenAddr, &tlsConfig)
	if err != nil {
		le.Printf("Listen failed: %s\n", err)
		exit(1)
	}

	le.Printf("Listening on %s...\n", conf.ListenAddr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			le.Printf("Accept failed: %s\n", err)
			// Note: is this really fatal, should we exit?
			exit(1)
		}
		le.Printf("Client from %s\n", conn.RemoteAddr())
		go func() {
			defer conn.Close()
			rpc.ServeConn(conn)
			le.Printf("Closed %s\n", conn.RemoteAddr())
		}()
	}
}
