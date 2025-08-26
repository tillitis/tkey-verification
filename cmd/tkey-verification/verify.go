// SPDX-FileCopyrightText: 2022 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/vendorkey"
	"github.com/tillitis/tkey-verification/internal/verification"
	"sigsum.org/sigsum-go/pkg/crypto"
	sumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
)

const verifyInfoURL = "https://www.tillitis.se/verify"

func verifyShowUrl(dev Device, verifyBaseURL string) {
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
func verify(dev Device, verbose bool, baseDir string, verifyBaseURL string) {
	appBins, err := appbins.NewAppBins()
	if err != nil {
		missing(fmt.Sprintf("no embedded device apps: %v", err))
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
	appBin, err := appBins.Get(hex.EncodeToString(verification.AppHash))
	if err != nil {
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
	fw, err := verifyFirmwareHash(*tk)
	if err != nil {
		verificationFailed("unexpected firmware")
		exit(1)
	}
	if verbose {
		le.Printf("TKey firmware was verified, size:%d hash:%0x…\n", fw.Size, fw.Hash[:16])
	}

	// Recreate message the vendor signed
	msg, err := buildMessage(tk.Udi.Bytes, fw.Hash[:], pubKey)
	if err != nil {
		parseFailure(err.Error())
		exit(1)
	}

	// Verify the vendor signature or Sigsum proof over the
	// recreated message.
	if verification.IsProof() {
		verifyProof(msg, verification)
	} else {
		verifySig(msg, verification, appBins)
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

func verifyProof(msg []byte, verification verification.Verification) {
	submitKey := mustParsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIONFrsjCVeDB3KwJVsfr/kphaZZZ9Sypuu42ahZBjeya sigsum key")
	witnessKey := mustParsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFw1KBko6do5a+7eXyKiJRpYnmrG3lKk3oXehjT/zK9t TKey")
	logKey, err := sumcrypto.PublicKeyFromHex("4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6")
	if err != nil {
		panic(err)
	}

	sigsumKeys := map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(submitKey[:]): submitKey}

	policy, err := policy.NewKofNPolicy([]sumcrypto.PublicKey{logKey}, []sumcrypto.PublicKey{witnessKey}, 1)
	if err != nil {
		panic(err)
	}

	if err := verification.VerifyProof(msg, *policy, sigsumKeys); err != nil {
		verificationFailed("vendor signature not verified")
		os.Exit(1)
	}

	le.Printf("Verified with Sigsum proof using submit key %x\n", submitKey)
}

func verifySig(msg []byte, verification verification.Verification, appBins appbins.AppBins) {
	var vendorKeys vendorkey.VendorKeys
	if err := vendorKeys.FromEmbedded(appBins); err != nil {
		missing(fmt.Sprintf("no vendor signing public key: %v", err))
		os.Exit(1)
	}

	verifiedWith, err := verification.VerifySig(msg, vendorKeys)
	if err != nil {
		verificationFailed("vendor signature not verified")
		os.Exit(1)
	}

	le.Printf("Verified with vendor key %x\n", verifiedWith.PubKey)
}

func mustParsePublicKey(ascii string) sumcrypto.PublicKey {
	key, err := key.ParsePublicKey(ascii)
	if err != nil {
		panic(err)
	}
	return key
}
