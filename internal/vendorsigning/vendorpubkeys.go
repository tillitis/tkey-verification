// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package vendorsigning

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/tillitis/tkey-verification/internal/appbins"
)

var le = log.New(os.Stderr, "", 0)

func GetCurrentPubKey() *PubKey {
	if err := initPubKeys(); err != nil {
		le.Printf("Failed to init embedded vendor signing pubkeys: %s\n", err)
		os.Exit(1)
	}
	return getCurrentPubKey(pubKeys)
}

var (
	pubKeys *[]PubKey
	lock    = &sync.Mutex{}
)

func getCurrentPubKey(pubKeys *[]PubKey) *PubKey {
	if pubKeys == nil || len(*pubKeys) == 0 {
		return nil
	}
	// Note: we currently only support 1 vendor signing pubkey in the txt file
	return &(*pubKeys)[0]
}

//go:embed vendor-signing-pubkeys.txt
var pubKeysData []byte

func initPubKeys() error {
	lock.Lock()
	defer lock.Unlock()

	if pubKeys != nil {
		return nil
	}

	lines := strings.Split(strings.Trim(strings.ReplaceAll(string(pubKeysData), "\r\n", "\n"), "\n"), "\n")

	var newPubKeys []PubKey

	for _, line := range lines {
		fields := strings.Fields(line)

		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			// ignoring empty/spaces-only lines and comments
			continue
		}

		if len(fields) != 2 {
			return fmt.Errorf("Expected 2 space-separated fields: pubkey in hex, and signer-app tag")
		}
		pubKeyHex, tag := fields[0], fields[1]

		pubKey, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			return fmt.Errorf("Failed to decode hex \"%s\": %w", pubKeyHex, err)
		}
		if l := len(pubKey); l != ed25519.PublicKeySize {
			return fmt.Errorf("Got %d bytes pubkey from \"%s\", expected %d", l, pubKeyHex, ed25519.PublicKeySize)
		}

		appBin, err := appbins.Get(tag)
		if err != nil {
			return fmt.Errorf("%w", err)
		}

		for _, pk := range newPubKeys {
			if bytes.Compare(pubKey, pk.PubKey[:]) == 0 {
				return fmt.Errorf("pubkey \"%s\" already exists", pubKeyHex)
			}
		}

		newPubKeys = append(newPubKeys, PubKey{
			PubKey: *(*[ed25519.PublicKeySize]byte)(pubKey),
			AppBin: appBin,
		})
	}

	if l := len(newPubKeys); l > 1 {
		return fmt.Errorf("We currently only support 1 vendor signing pubkey, found %d", l)
	}

	if getCurrentPubKey(&newPubKeys) == nil {
		return fmt.Errorf("Found no currently usable vendor signing pubkey")
	}

	pubKeys = &newPubKeys
	return nil
}

type PubKey struct {
	PubKey [ed25519.PublicKeySize]byte
	AppBin *appbins.AppBin
}

func (p *PubKey) String() string {
	return fmt.Sprintf("Using vendor signing pubkey:%s tag:%s", hex.EncodeToString(p.PubKey[:]), p.AppBin.Tag)
}
