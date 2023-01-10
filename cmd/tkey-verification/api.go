// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type API struct {
	mu      sync.Mutex
	devPath string
}

func NewAPI(devPath string) *API {
	return &API{
		mu:      sync.Mutex{},
		devPath: devPath,
	}
}

type Args struct {
	UDI  [8]byte
	Tag  string
	Hash [sha256.Size]byte
}

func (a *API) Sign(args *Args, _ *struct{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	le.Printf("Going to sign hash from TKey with raw UDI: %s (tag: %s)\n", hex.EncodeToString(args.UDI[:]), args.Tag)

	if args.Tag == "" {
		msg := "Empty tag"
		le.Printf("%s\n", msg)
		return fmt.Errorf("%s", msg)
	}

	signature, err := signWithApp(a.devPath, signingPubKey, args.Hash)
	if err != nil {
		le.Printf("signWithApp failed: %s\n", err)
		return fmt.Errorf("signWithApp failed: %w", err)
	}

	if !ed25519.Verify(signingPubKey, args.Hash[:], signature) {
		msg := "Signature failed verification"
		le.Printf("%s\n", msg)
		return fmt.Errorf("%s", msg)
	}

	// File named after the raw UDI (in hex)
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(args.UDI[:]))
	if _, err = os.Stat(fn); err == nil || !errors.Is(err, os.ErrNotExist) {
		msg := fmt.Sprintf("%s already exists?", fn)
		le.Printf("%s\n", msg)
		return fmt.Errorf("%s", msg)
	}

	json, err := json.Marshal(Verification{
		time.Now().UTC().Unix(),
		args.Tag,
		hex.EncodeToString(args.Hash[:]),
		hex.EncodeToString(signature),
	})
	if err != nil {
		le.Printf("Marshal failed: %s\n", err)
		return fmt.Errorf("Marshal failed: %w", err)
	}

	if err = os.WriteFile(fn, append(json, '\n'), 0o644); err != nil { //nolint:gosec
		le.Printf("WriteFile %s failed: %s\n", fn, err)
		return fmt.Errorf("WriteFile %s failed: %w", fn, err)
	}

	le.Printf("Wrote %s\n", fn)

	return nil
}
