// SPDX-FileCopyrightText: 2022 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
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
	"sigsum.org/sigsum-go/pkg/crypto"
	sumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
)

const verifyInfoURL = "https://www.tillitis.se/verify"

func verify(dev Device, verbose bool, showURLOnly bool, baseDir string, verifyBaseURL string) {
	prooftext := string(
		`version=1
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=1b6d f3744a4d05231ceed5d704e7fcdd8ee436f2253d980cf5716ae34cc16c06f439 55b94e42482923adf99d49bc5b3aa3b96093139817284ced6403167d47db0fa3091d8282adea6a1e11ebe3f1f42bf76ddceb8b3f0bbec4dd96f8f6908760bd0e

size=4186
root_hash=be8491d96283e89afb0014b82be85ba70cccb9e672fdbf595f701fb456e46cd0
signature=880584e76411f6ac7d2d7f85166b320cd08d6a775cf9b78969ff185dc2b6410c34e4ac2d3aa78d64285ab2a3259177b787da0d5326b71d034c6a7471a9dc5e0d
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1755522370 8f4507b9e9076ebab7f9234108de5e3b0bc1836a4933c0ac69ad338461537c8d6a0fcf93d2b7dc2416fbcd73c6b19dd3d2a311313920d7191a2ee7591cb73c04
cosignature=b95ef35a9ffb3cf516f423a04128d37d3bffc74d4096bd5e967990c53d09678a 1755522370 4970b9b159c3e723ed11c5a75b70be027d5d4ba51e66209263ac779d52ce93ac9a1a3d798551274df0ffb05ea5e82e929fb3ece062fba676515f851d1f6bf005
cosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1755522370 65bc6e601f91d1faf81ec5a6aa7b24d11b89bcd1ea9e570c0a122c236bda7058500f2dc5706b16fa6853145922835034f561197e7d03156ddfe070d58aa7c40c
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1755522370 b57f4ee89b3b0f39303e72fa7359afd696abaa759d9e255788355bb420607522c5b5cbde72ce6943b67e029858cf795609b2ff726dd11c61edfa37bfef323d07
cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1755522370 9c16d95c617a97f2da89b1d594510950725a0d537ddd5e76eac5d5ef87de9ea9b2d249467c2a4c078cff6edbf87ecc25b08b6b5cbfecb42efb5439408d75930f
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1755522370 fe82dc7e0f051492be67b9ebce4fe6c3b488e3286e10f55363655c6391a132eb8c645ec7a4e414a81c6b2d8d149331bdb1e4bdd5609ff79009174d76f17c4302

leaf_index=4185
node_hash=9364bfbdef749709839140a812c628abf7f6b9a324d748056c8661b283f4a427
node_hash=e6d3a8151cdff24f78931465cfe5f9083080b18d86831a0e8f581c16061af439
node_hash=d8cf3ff208c18ddc4f3b21acb70f9ac12c14989a6372a4bb8602596423bed265
node_hash=9a062feda65100c4b5cfbc4297e9a07af77565b53fd77719ab75b8d31107f247
node_hash=9ca6b461d616cf790a32a967574087298abb4cd0c3da938b7fed143b7d92b5ec
`)

	appBins, err := NewAppBins()
	if err != nil {
		missing(fmt.Sprintf("no embedded device apps: %v", err))
		os.Exit(1)
	}

	// vendorKeys, err := NewVendorKeys(appBins)
	// if err != nil {
	// 	missing(fmt.Sprintf("no vendor signing public key: %v", err))
	// 	os.Exit(1)
	// }

	submitKey := mustParsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIONFrsjCVeDB3KwJVsfr/kphaZZZ9Sypuu42ahZBjeya sigsum key")
	witnessKey := mustParsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFw1KBko6do5a+7eXyKiJRpYnmrG3lKk3oXehjT/zK9t TKey")
	logKey, err := sumcrypto.PublicKeyFromHex("4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6")
	if err != nil {
		panic(err)
	}

	vendorKeys := map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(submitKey[:]): submitKey}

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

	var pr proof.SigsumProof

	if err := pr.FromASCII(bytes.NewBufferString(prooftext)); err != nil {
		panic(err)
	}

	// Verify vendor's signature over known message.
	msg, err := buildMessage(tk.Udi.Bytes, fw.Hash[:], pubKey)
	if err != nil {
		parseFailure(err.Error())
		exit(1)
	}

	digest := sumcrypto.HashBytes(msg)

	fmt.Printf("digest: %x\n", digest)

	policy, err := policy.NewKofNPolicy([]sumcrypto.PublicKey{logKey}, []sumcrypto.PublicKey{witnessKey}, 1)
	if err != nil {
		panic(err)
	}

	if err := pr.Verify(&digest, vendorKeys, policy); err != nil {
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
		return verification, IOError{path: verifyURL, err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		le.Printf("HTTP GET status code: %d (%s)", resp.StatusCode, resp.Status)
		return verification, ErrIO
	}

	verificationJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		return verification, IOError{path: verifyURL, err: err}
	}

	if err = json.Unmarshal(verificationJSON, &verification); err != nil {
		return verification, ParseError{what: "JSON Unmarshal", err: err}
	}

	return verification, nil
}

func verificationFromFile(fn string) (Verification, error) {
	var verification Verification

	le.Printf("Reading verification data from file %s ...\n", fn)
	verificationJSON, err := os.ReadFile(fn)
	if err != nil {
		return verification, IOError{path: fn, err: err}
	}

	if err = json.Unmarshal(verificationJSON, &verification); err != nil {
		return verification, ParseError{what: "JSON unmarshal", err: err}
	}

	return verification, nil
}

func mustParsePublicKey(ascii string) sumcrypto.PublicKey {
	key, err := key.ParsePublicKey(ascii)
	if err != nil {
		panic(err)
	}
	return key
}
