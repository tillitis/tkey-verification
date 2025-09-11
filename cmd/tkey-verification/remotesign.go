// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"net"
	"net/rpc"
	"os"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/data"
	"github.com/tillitis/tkey-verification/internal/firmware"
	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/util"
)

type Message struct {
	udi    tkey.UDI
	pubKey []byte
	fw     firmware.Firmware
}

func remoteSign(conf ProvConfig, dev Device, verbose bool) {
	var firmwares firmware.Firmwares

	// Get our firmwares
	firmwares.MustDecodeString(data.FirmwaresConf)

	// Find the app to use
	var appHash [sha512.Size]byte

	if err := util.DecodeHex(appHash[:], conf.SigningAppHash); err != nil {
		le.Printf("couldn't decode signingapphash from config")
		os.Exit(1)
	}

	bin, ok := appbins.MustAppBins().Bins[appHash]
	if !ok {
		le.Printf("Couldn't find configure app %v\n", conf.SigningAppHash)
		os.Exit(1)
	}

	_, _, err := net.SplitHostPort(conf.ServerAddr)
	if err != nil {
		le.Printf("SplitHostPort failed: %s", err)
		os.Exit(1)
	}

	// Authenticate the device
	message, err := authDevice(dev, bin, firmwares)
	if err != nil {
		le.Printf("Couldn't authenticate device: %s\n", err)
		os.Exit(1)
	}

	// Sign this with our HSM
	server := Server{
		Addr: conf.ServerAddr,
		TLSConfig: tls.Config{
			Certificates: []tls.Certificate{
				loadCert(conf.ClientCert, conf.ClientKey),
			},
			RootCAs:    loadCA(conf.CACert),
			MinVersion: tls.VersionTLS13,
		},
	}

	err = vendorSign(&server, message.udi.Bytes, message.pubKey, message.fw, bin)
	if err != nil {
		le.Printf("Couldn't get a vendor signature: %s\n", err)
		os.Exit(1)
	}

	le.Printf("Remote Sign was successful\n")
}

func authDevice(dev Device, appBin appbins.AppBin, firmwares firmware.Firmwares) (Message, error) {
	var message Message

	// Load the app
	tk, err := tkey.NewTKey(dev.Path, dev.Speed, false)
	if err != nil {
		return message, fmt.Errorf("%w", err)
	}

	defer tk.Close()

	pubKey, err := tk.LoadSigner(appBin.Bin)
	if err != nil {
		return message, fmt.Errorf("%w", err)
	}
	le.Printf("TKey UDI: %s\n", tk.Udi.String())

	// Authenticate against pubkey
	err = tk.Challenge(pubKey)
	if err != nil {
		return message, fmt.Errorf("challenge/response failed: %w", err)
	}

	// Verify the firmware
	fw, err := verifyFirmwareHash(*tk, firmwares)
	if err != nil {
		return message, fmt.Errorf("%w", err)
	}
	le.Printf("TKey firmware with size:%d and verified hash:%0x…\n", fw.Size, fw.Hash[:16])

	message.udi = tk.Udi
	message.pubKey = pubKey
	message.fw = fw

	return message, nil
}

func vendorSign(server *Server, udi []byte, pubKey []byte, fw firmware.Firmware, appBin appbins.AppBin) error {
	conn, err := tls.Dial("tcp", server.Addr, &server.TLSConfig)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	client := rpc.NewClient(conn)

	msg, err := util.BuildMessage(udi, fw.Hash[:], pubKey)
	if err != nil {
		return fmt.Errorf("building message to sign failed: %w", err)
	}

	args := Args{
		UDIBE:   udi,
		AppTag:  appBin.Tag,
		AppHash: appBin.Hash(),
		Message: msg,
	}

	err = client.Call("API.Sign", &args, nil)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}
