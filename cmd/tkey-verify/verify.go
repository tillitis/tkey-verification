// SPDX-FileCopyrightText: 2022 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/data"
	"github.com/tillitis/tkey-verification/internal/firmware"
	"github.com/tillitis/tkey-verification/internal/sigsum"
	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/util"
	"github.com/tillitis/tkey-verification/internal/vendorkey"
	"github.com/tillitis/tkey-verification/internal/verification"
	"github.com/tillitis/tkeyclient"
)

const verifyInfoURL = "https://www.tillitis.se/verify"

func verifyShowURL(dev Device, verifyBaseURL string) {
	// Connect to a TKey
	tk, err := tkey.NewTKey(dev.Path, dev.Speed, false)
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

	le.Printf("URL to verification data follows on stdout:\n")
	fmt.Printf("%s\n", verifyURL)
	exit(0)
}

// verify verifies a Tkey by:
//
//   - Connecting to the device, retrieving the UDI
//
//   - Fetching the verification file, indexed by the UDI.
//
//   - Load the signer indicated in the verification file, which
//     returns the public key.
//
//   - Doing a challenge/response to prove the signer's identity
//     against the public key we just got.
//
//   - Verify that the device has the expected firmware.
//
//   - Recreates the vendor signed message.
//
//   - Verify the vendor signature over the message.
func verify(dev Device, verbose bool, baseDir string, verifyBaseURL string, useSigsum bool) {
	var firmwares firmware.Firmwares

	firmwares.MustDecodeString(data.FirmwaresConf)

	appBins, err := appbins.NewAppBins()
	if err != nil {
		missing(fmt.Sprintf("no embedded device apps: %v", err))
		os.Exit(1)
	}

	var vendorKeys vendorkey.VendorKeys
	if err := vendorKeys.FromEmbedded(appBins); err != nil {
		missing(fmt.Sprintf("no vendor signing public key: %v", err))
		os.Exit(1)
	}

	var log sigsum.SigsumLog
	if err := log.FromString(data.SubmitKey, data.PolicyStr); err != nil {
		missing("Sigsum configuration missing")
		os.Exit(1)
	}

	// Connect to a TKey
	tk, err := tkey.NewTKey(dev.Path, dev.Speed, verbose)
	if err != nil {
		commFailed(err.Error())
		os.Exit(1)
	}

	exit := func(code int) {
		tk.Close()
		os.Exit(code)
	}

	le.Printf("TKey UDI: %s\n", tk.Udi.String())

	// If this is a TKey from Tillitis (vendor 0x1337), product ID
	// Castor means we demand a Sigsum proof. Bellatrix means
	// vendor signature.
	//
	// If it's not Tillitis we use default false, but let the user
	// set their expectations with -sigsum.
	if tk.Udi.VendorID == 0x1337 {
		switch tk.Udi.ProductID {
		case tkeyclient.UDIPIDBellatrix:
			useSigsum = false
		case tkeyclient.UDIPIDCastor:
			useSigsum = true
		default:
			// Not sure!
			le.Printf("Unknown Product ID: Don't know if we need signature or Sigsum proof.")
			exit(1)
		}

	}

	var verification verification.Verification

	if baseDir != "" {
		p := path.Join(baseDir, hex.EncodeToString(tk.Udi.Bytes))
		if err := verification.FromFile(p); err != nil {
			commFailed(err.Error())
			exit(1)
		}
	} else {
		// Verify from an URL
		verifyURL := fmt.Sprintf("%s/%s", verifyBaseURL, hex.EncodeToString(tk.Udi.Bytes))

		if verbose {
			le.Printf("Fetching verification data from %s ...\n", verifyURL)
		}

		if err := verification.FromURL(verifyURL); err != nil {
			commFailed(err.Error())
			exit(1)
		}
	}

	if verbose {
		le.Printf("Verification data was created %s\n", verification.Timestamp)
	}

	// Find the right app to run
	appBin, ok := appBins.Bins[verification.AppHash]
	if !ok {
		notFound("app digest")
		exit(1)
	}

	pubKey, err := tk.LoadSigner(appBin.Bin)
	if err != nil {
		commFailed(err.Error())
		exit(1)
	}

	// Check device identity
	if err := tk.Challenge(pubKey); err != nil {
		verificationFailed("challenge/response failed")
		exit(1)
	}

	// Check we have the right firmware.
	expectedFW, err := firmwares.GetFirmware(tk.Udi)
	if err != nil {
		verificationFailed("unexpected firmware")
		exit(1)
	}

	fwHash, err := tk.GetFirmwareHash(expectedFW.Size)
	if err != nil {
		commFailed("couldn't get firmware digest from TKey")
		exit(1)
	}

	if !bytes.Equal(expectedFW.Hash[:], fwHash) {
		le.Printf("TKey does not have expected firmware hash %0x…, but instead %0x…", expectedFW.Hash[:16], fwHash[:16])
		verificationFailed("unexpected firmware")
		exit(1)
	}

	if verbose {
		le.Printf("TKey firmware was verified, size:%d hash:%0x…\n", expectedFW.Size, expectedFW.Hash[:16])
	}

	// Recreate message the vendor signed
	msg, err := util.BuildMessage(tk.Udi.Bytes, expectedFW.Hash[:], pubKey)
	if err != nil {
		parseFailure(err.Error())
		exit(1)
	}

	// Verify the vendor signature or Sigsum proof over the
	// recreated message.
	if verification.IsProof() {
		if useSigsum {
			if err := verification.VerifyProof(msg, *log.Policy, log.SubmitKeys); err != nil {
				verificationFailed(err.Error())
				exit(1)
			}

			le.Printf("Verified with Sigsum proof using submit key %x\n", data.SubmitKey)
		} else {
			// Strange. Exit.
			verificationFailed("Expected vendor signature but got a Sigsum proof")
			exit(1)
		}
	} else {
		if useSigsum {
			// Strange. Exit.
			verificationFailed("Sigsum proof required but not available")
			exit(1)
		}

		verifiedWith, err := verification.VerifySig(msg, vendorKeys)
		if err != nil {
			verificationFailed(err.Error())
			exit(1)
		}

		le.Printf("Verified with vendor key %x\n", verifiedWith)
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
	fmt.Printf("It seems tkey-verify is not built correctly.\n")
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
