// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/vendorsigning"
)

func verify(devPath string, verbose bool, showURLOnly bool, baseDir string, verifyBaseURL string) {
	udi := tkey.GetUDI(devPath, verbose)
	if udi == nil {
		os.Exit(1)
	}
	le.Printf("TKey UDI: %s\n", udi.String())
	verifyURL := fmt.Sprintf("%s/%s", verifyBaseURL, hex.EncodeToString(udi.Bytes))

	if showURLOnly {
		le.Printf("URL to verification data follows on stdout:\n")
		fmt.Printf("%s\n", verifyURL)
		os.Exit(0)
	}

	var verification Verification
	var err error
	if baseDir != "" {
		p := path.Join(baseDir, hex.EncodeToString(udi.Bytes))
		verification, err = verificationFromFile(p)
		if err != nil {
			le.Printf("verificationFromFile failed: %s\n", err)
			os.Exit(1)
		}
	} else {
		verification, err = verificationFromURL(verifyURL)
		if err != nil {
			le.Printf("verificationFromURL failed: %s\n", err)
			os.Exit(1)
		}
	}

	le.Printf("Verification data was created %s\n", verification.Timestamp)

	if verification.AppTag == "" {
		le.Printf("apptag in verification data is empty\n")
		os.Exit(1)
	}

	appHash, err := hex.DecodeString(verification.AppHash)
	if err != nil {
		le.Printf("decode apphash hex \"%s\" in verification data failed: %s\n", verification.AppHash, err)
		os.Exit(1)
	}

	appBin, err := appbins.Get(verification.AppTag, appHash)
	if err != nil {
		le.Printf("Getting embedded verisigner-app failed: %s\n", err)
		os.Exit(1)
	}

	udi, pubKey, ok := tkey.Load(appBin, devPath, verbose)
	if !ok {
		os.Exit(1)
	}

	fw, err := verifyFirmwareHash(devPath, pubKey, udi)
	if err != nil {
		le.Printf("verifyFirmwareHash failed: %s\n", err)
		os.Exit(1)
	}
	le.Printf("TKey firmware was verified, size:%d hash:%0x…\n", fw.Size, fw.Hash[:16])

	vSignature, err := hex.DecodeString(verification.Signature)
	if err != nil {
		le.Printf("Couldn't decode signature: %s", err)
		os.Exit(1)
	}

	// Verify vendor's signature over known message. Note: we
	// currently only support 1 single vendor signing pubkey
	vendorPubKey := vendorsigning.GetCurrentPubKey().PubKey[:]
	msg, err := buildMessage(udi.Bytes, fw.Hash[:], pubKey)
	if err != nil {
		le.Printf("buildMessage failed: %s", err)
		os.Exit(1)
	}
	if !ed25519.Verify(vendorPubKey, msg, vSignature) {
		le.Printf("Signature by vendor failed verification!")
		os.Exit(1)
	}

	// Get a device signature over a random challenge
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		le.Printf("rand.Read failed: %s", err)
		os.Exit(1)
	}

	signature, err := tkey.Sign(devPath, pubKey, challenge)
	if err != nil {
		le.Printf("tkey.Sign failed: %s", err)
		os.Exit(1)
	}

	// Verify device signature against device public key
	if !ed25519.Verify(pubKey, challenge, signature) {
		le.Printf("Signature by TKey failed verification!")
		os.Exit(1)
	}

	fmt.Printf("TKey is genuine!\n")

	os.Exit(0)
}

func verificationFromURL(verifyURL string) (Verification, error) {
	var verification Verification

	le.Printf("Fetching verification data from %s ...\n", verifyURL)
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(verifyURL) // #nosec G107
	if err != nil {
		return verification, fmt.Errorf("http.Get failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return verification, fmt.Errorf("HTTP GET status code: %d (%s)", resp.StatusCode, resp.Status)
	}

	verificationJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		return verification, fmt.Errorf("io.ReadAll failed: %w", err)
	}

	if err = json.Unmarshal(verificationJSON, &verification); err != nil {
		return verification, fmt.Errorf("Unmarshal failed: %w", err)
	}

	return verification, nil
}

func verificationFromFile(fn string) (Verification, error) {
	var verification Verification

	le.Printf("Reading verification data from file %s ...\n", fn)
	verificationJSON, err := os.ReadFile(fn)
	if err != nil {
		return verification, fmt.Errorf("ReadFile failed: %w", err)
	}

	if err = json.Unmarshal(verificationJSON, &verification); err != nil {
		return verification, fmt.Errorf("Unmarshal failed: %w", err)
	}

	return verification, nil
}
