// Copyright (C) 2022-2024 - Tillitis AB
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

	"github.com/tillitis/tkey-verification/internal/tkey"
)

const verifyInfoURL = "https://www.tillitis.se/verify"

func verify(devPath string, verbose bool, showURLOnly bool, baseDir string, verifyBaseURL string) {

	appBins, err := NewAppBins(latestAppHash)
	if err != nil {
		missing(fmt.Sprintf("no embedded device apps: %v", err))
		os.Exit(1)
	}

	vendorKeys, err := NewVendorKeys(appBins, currentVendorHash)
	if err != nil {
		missing("no vendor signing public key")
		os.Exit(1)
	}

	firmwares, err := NewFirmwares()
	if err != nil {
		missing("no firmware digests")
		os.Exit(1)
	}

	tk, err := tkey.NewTKey(devPath, verbose)
	if err != nil {
		commFailed(err.Error())
		os.Exit(1)
	}

	exit := func(code int) {
		tk.Close()
		os.Exit(code)
	}

	le.Printf("TKey UDI: %s\n", tk.Udi.String())

	verifyURL := fmt.Sprintf("%s/%s", verifyBaseURL, hex.EncodeToString(tk.Udi.Bytes))

	if showURLOnly {
		le.Printf("URL to verification data follows on stdout:\n")
		fmt.Printf("%s\n", verifyURL)
		exit(0)
	}

	var verification Verification

	if baseDir != "" {
		p := path.Join(baseDir, hex.EncodeToString(tk.Udi.Bytes))
		verification, err = verificationFromFile(p)
		if err != nil {
			commFailed(err.Error())
			exit(1)
		}
	} else {
		if verbose {
			le.Printf("Fetching verification data from %s ...\n", verifyURL)
		}

		verification, err = verificationFromURL(verifyURL)
		if err != nil {
			commFailed(err.Error())
			exit(1)
		}
	}

	if verbose {
		le.Printf("Verification data was created %s\n", verification.Timestamp)
	}

	if verification.AppTag == "" {
		parseFailure("app tag empty")
		exit(1)
	}

	_, err = hex.DecodeString(verification.AppHash)
	if err != nil {
		parseFailure("hex decode error")
		exit(1)
	}

	appBin, err := appBins.Get(verification.AppHash)
	if err != nil {
		notFound("upstream app digest unknown")
		exit(1)
	}

	pubKey, err := tk.LoadSigner(appBin.Bin)
	if err != nil {
		commFailed(err.Error())
		exit(1)
	}

	expectedFw, err := firmwares.GetFirmware(tk.Udi)
	if err != nil {
		notFound("no known firmware for UDI")
		exit(1)
	}

	fw, err := verifyFirmwareHash(*expectedFw, *tk)
	if err != nil {
		verificationFailed("unexpected firmware")
		exit(1)
	}
	if verbose {
		le.Printf("TKey firmware was verified, size:%d hash:%0x…\n", fw.Size, fw.Hash[:16])
	}

	vSignature, err := hex.DecodeString(verification.Signature)
	if err != nil {
		parseFailure(err.Error())
		exit(1)
	}

	// Verify vendor's signature over known message. Note: we
	// currently only support 1 single vendor signing pubkey
	vendorPubKey := vendorKeys.Current().PubKey
	msg, err := buildMessage(tk.Udi.Bytes, fw.Hash[:], pubKey)
	if err != nil {
		parseFailure(err.Error())
		exit(1)
	}

	if !ed25519.Verify(vendorPubKey[:], msg, vSignature) {
		verificationFailed("vendor signature not verified")
		exit(1)
	}

	// Get a device signature over a random challenge
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		le.Printf("rand.Read failed: %s", err)
		exit(1)
	}

	signature, err := tk.Sign(challenge)
	if err != nil {
		commFailed(err.Error())
		exit(1)
	}

	// Verify device signature against device public key
	if !ed25519.Verify(pubKey, challenge, signature) {
		verificationFailed("challenge not verified")
		exit(1)
	}

	fmt.Printf("TKey is genuine!\n")

	exit(0)
}

// commFailed describes an I/O failure of some kind, perhaps between
// the client and the TKey, an HTTP request that didn't succeed, or
// perhaps reading a file.
func commFailed(msg string) {
	fmt.Printf("I/O FAILED: %s\n", msg)
}

// parseFailure describes an error where we have tried to parse
// something from external sources but failed.
func parseFailure(msg string) {
	fmt.Printf("PARSE ERROR: %s\n", msg)
}

// missing describes an error where something is missing from the
// binary to even complete a verification.
func missing(msg string) {
	fmt.Printf("MISSING IN PROGRAM: %s\n", msg)
	fmt.Printf("It seems tkey-verification is not built correctly.\n")
}

// notFound describes an error where we with data from external source
// can't find something, perhaps not finding something on a web
// server, or not finding the device app digest.
func notFound(msg string) {
	fmt.Printf("NOT FOUND: %s\n", msg)
}

// verificationFailed describes a real problem with a manipulated
// TKey.
func verificationFailed(msg string) {
	fmt.Printf("VERIFICATION FAILED: %s\n", msg)
	fmt.Printf("Please visit %s to understand what this might mean.\n", verifyInfoURL)
}

func verificationFromURL(verifyURL string) (Verification, error) {
	var verification Verification

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
