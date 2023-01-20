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
	udiBE := tkey.GetUDI(devPath, verbose)
	if udiBE == nil {
		os.Exit(1)
	}
	le.Printf("TKey UDI (BE): %s\n", hex.EncodeToString(udiBE))
	verifyURL := fmt.Sprintf("%s/%s", verifyBaseURL, hex.EncodeToString(udiBE))

	if showURLOnly {
		le.Printf("URL to verification data follows on stdout:\n")
		fmt.Printf("%s\n", verifyURL)
		os.Exit(0)
	}

	var verification Verification
	var err error
	if baseDir != "" {
		p := path.Join(baseDir, hex.EncodeToString(udiBE))
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

	if verification.Tag == "" {
		le.Printf("Tag in verification data is empty\n")
		os.Exit(1)
	}

	appBin, err := appbins.Get(verification.Tag)
	if err != nil {
		// Note: as we embed every signer-app binary ever used, this
		// should not ever happen. Only if one removes a file from
		// internal/appbins/bins/, which would be a major mistake.
		le.Printf("This tkey-verification does not support signer-app tag \"%s\".\n", verification.Tag)
		os.Exit(1)
	}

	_, pubKey, ok := tkey.Load(appBin, devPath, verbose)
	if !ok {
		os.Exit(1)
	}

	// Check the vendor signature over the device public key
	vSignature, err := hex.DecodeString(verification.Signature)
	if err != nil {
		le.Printf("Couldn't decode signature: %s", err)
		os.Exit(1)
	}

	// Note: we currently only support 1 single vendor signing pubkey
	vendorPubKey := vendorsigning.GetCurrentPubKey().PubKey[:]

	if !ed25519.Verify(vendorPubKey, pubKey, vSignature) {
		le.Printf("Vendor signature failed verification!")
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
		le.Printf("Vendor signature failed verification!")
		os.Exit(1)
	}

	fmt.Printf("TKey is genuine!\n")

	os.Exit(0)
}

func verificationFromURL(verifyURL string) (Verification, error) {
	var verification Verification

	le.Printf("Fetching %s ...\n", verifyURL)
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

	le.Printf("Reading %s ...\n", fn)
	verificationJSON, err := os.ReadFile(fn)
	if err != nil {
		return verification, fmt.Errorf("ReadFile failed: %w", err)
	}

	if err = json.Unmarshal(verificationJSON, &verification); err != nil {
		return verification, fmt.Errorf("Unmarshal failed: %w", err)
	}

	return verification, nil
}
