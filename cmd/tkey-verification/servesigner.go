// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/rpc"
	"os"

	"github.com/tillitis/tkey-verification/internal/sigsum"
	"github.com/tillitis/tkey-verification/internal/ssh"
	"github.com/tillitis/tkey-verification/internal/tkey"
)

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

	var log sigsum.Log
	if err = log.FromEmbedded(); err != nil {
		le.Printf("Found no usable Sigsum configuration: %v\n", err)
		os.Exit(1)
	}

	// Do we have the configured pubkey to use for Sigsum submit key
	activeKey, err := ssh.ParsePublicEd25519(conf.ActiveKey)
	if err != nil {
		le.Printf("parse error in config: %v\n", err)
		os.Exit(1)
	}

	submitKey, ok := log.Keys[activeKey]
	if !ok {
		le.Printf("Compiled in submit key indexed by %x not found\n", activeKey)
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

	le.Printf("Sigsum signing: %s\n", submitKey.String())
	le.Printf("Loading device app built from %s ...\n", submitKey.AppBin.String())
	foundPubKey, err := tk.LoadSigner(submitKey.AppBin.Bin)
	if err != nil {
		fmt.Printf("Couldn't load device app: %v\n", err)
		exit(1)
	}

	if !bytes.Equal(submitKey.Key[:], foundPubKey) {
		var key1 ssh.PublicKey
		var key2 ssh.PublicKey

		key1 = submitKey.Key
		key2 = ssh.PublicKey(foundPubKey)

		le.Printf("TKey pubkey does not match active embedded pubkey\nExpected: %v\nReceived: %v\n", ssh.FormatPublicEd25519(&key1), ssh.FormatPublicEd25519(&key2))
		exit(1)
	}
	le.Printf("Found signing TKey with the expected public key and UDI: %s\n", tk.Udi.String())

	if err = os.MkdirAll(signaturesDir, 0o755); err != nil {
		le.Printf("MkdirAll failed: %s\n", err)
		exit(1)
	}

	if err = rpc.Register(NewAPI(submitKey.Key[:], *tk)); err != nil {
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
