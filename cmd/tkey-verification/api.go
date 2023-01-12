// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
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
	UDI       [8]byte // BE
	Tag       string
	Challenge []byte
	Message   []byte
}

func (a *API) Sign(args *Args, _ *struct{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	le.Printf("Going to sign public key from TKey with UDI (BE): %s (tag: %s)\n", hex.EncodeToString(args.UDI[:]), args.Tag)

	if args.Tag == "" {
		err := fmt.Errorf("Empty tag")
		le.Printf("%s\n", err)
		return err
	}

	signature, err := signWithApp(a.devPath, signingPubKey, args.Message)
	if err != nil {
		err = fmt.Errorf("signWithApp failed: %w", err)
		le.Printf("%s\n", err)
		return err
	}

	if !ed25519.Verify(signingPubKey, args.Message, signature) {
		err = fmt.Errorf("Signature failed verification")
		le.Printf("%s\n", err)
		return err
	}

	// File named after the UDI (BE, in hex)
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(args.UDI[:]))
	if _, err = os.Stat(fn); err == nil || !errors.Is(err, os.ErrNotExist) {
		err = fmt.Errorf("%s already exists?", fn)
		le.Printf("%s\n", err)
		return err
	}

	json, err := json.Marshal(Verification{
		time.Now().UTC().Format(time.RFC3339),
		args.Tag,
		hex.EncodeToString(args.Challenge),
		hex.EncodeToString(signature),
	})
	if err != nil {
		err = fmt.Errorf("Marshal failed: %w", err)
		le.Printf("%s\n", err)
		return err
	}

	if err = os.WriteFile(fn, append(json, '\n'), 0o644); err != nil { //nolint:gosec
		err = fmt.Errorf("WriteFile %s failed: %w", fn, err)
		le.Printf("%s\n", err)
		return err
	}

	le.Printf("Wrote %s\n", fn)

	return nil
}
