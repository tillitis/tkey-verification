// SPDX-FileCopyrightText: 2022 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path"

	"github.com/tillitis/tkey-verification/internal/tkey"
	"github.com/tillitis/tkey-verification/internal/verification"
	"sigsum.org/sigsum-go/pkg/crypto"
	sumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
)

const verifyInfoURL = "https://www.tillitis.se/verify"

func verify(dev Device, verbose bool, showURLOnly bool, baseDir string, verifyBaseURL string) {
	appBins, err := NewAppBins()
	if err != nil {
		missing(fmt.Sprintf("no embedded device apps: %v", err))
		os.Exit(1)
	}

	vendorKeys, err := NewVendorKeys(appBins)
	if err != nil {
		missing(fmt.Sprintf("no vendor signing public key: %v", err))
		os.Exit(1)
	}

	submitKey := mustParsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIONFrsjCVeDB3KwJVsfr/kphaZZZ9Sypuu42ahZBjeya sigsum key")
	witnessKey := mustParsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFw1KBko6do5a+7eXyKiJRpYnmrG3lKk3oXehjT/zK9t TKey")
	logKey, err := sumcrypto.PublicKeyFromHex("4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6")
	if err != nil {
		panic(err)
	}

	sigsumKeys := map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(submitKey[:]): submitKey}

	firmwares, err := NewFirmwares()
	if err != nil {
		missing("no firmware digests")
		os.Exit(1)
	}

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

	verifyURL := fmt.Sprintf("%s/%s", verifyBaseURL, hex.EncodeToString(tk.Udi.Bytes))

	if showURLOnly {
		le.Printf("URL to verification data follows on stdout:\n")
		fmt.Printf("%s\n", verifyURL)
		exit(0)
	}

	var verification verification.Verification

	if baseDir != "" {
		p := path.Join(baseDir, hex.EncodeToString(tk.Udi.Bytes))
		if err := verification.FromFile(p); err != nil {
			commFailed(err.Error())
			exit(1)
		}
	} else {
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

	if verification.AppTag == "" {
		parseFailure("app tag empty")
		exit(1)
	}

	if _, err := hex.DecodeString(verification.AppHash); err != nil {
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

	// Verify vendor's signature over known message.
	msg, err := buildMessage(tk.Udi.Bytes, fw.Hash[:], pubKey)
	if err != nil {
		parseFailure(err.Error())
		exit(1)
	}

	if verification.Proof != "" {
		// This is a Sigsum proof

		var pr proof.SigsumProof

		fmt.Printf("proof: %v\n", verification.Proof)

		if err := pr.FromASCII(bytes.NewBufferString(verification.Proof)); err != nil {
			panic(err)
		}

		digest := sumcrypto.HashBytes(msg)

		fmt.Printf("digest: %x\n", digest)

		policy, err := policy.NewKofNPolicy([]sumcrypto.PublicKey{logKey}, []sumcrypto.PublicKey{witnessKey}, 1)
		if err != nil {
			panic(err)
		}

		if err := pr.Verify(&digest, sigsumKeys, policy); err != nil {
			verificationFailed("vendor signature not verified")
			exit(1)
		}

		le.Printf("Verified with a Sigsum proof, submit key %x\n", submitKey)
	} else {
		// This is a classical vendor signature

		vSignature, err := hex.DecodeString(verification.Signature)
		if err != nil {
			parseFailure(err.Error())
			exit(1)
		}

		// We allow for any of the known vendor keys and break
		// on the first which verifies.
		var verified = false

		for _, vendorPubKey := range vendorKeys.Keys {
			if ed25519.Verify(vendorPubKey.PubKey[:], msg, vSignature) {
				le.Printf("Verified with vendor key %x\n", vendorPubKey.PubKey)
				verified = true
				break
			}
		}

		if !verified {
			verificationFailed("vendor signature not verified")
			exit(1)
		}

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

func mustParsePublicKey(ascii string) sumcrypto.PublicKey {
	key, err := key.ParsePublicKey(ascii)
	if err != nil {
		panic(err)
	}
	return key
}
