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

	"github.com/tillitis/tkey-verification/internal/tkey"
)

type API struct {
	mu           sync.Mutex
	vendorPubKey []byte
	devPath      string
}

func NewAPI(vendorPubKey []byte, devPath string) *API {
	return &API{
		mu:           sync.Mutex{},
		vendorPubKey: vendorPubKey,
		devPath:      devPath,
	}
}

func (*API) Ping(_ *struct{}, _ *struct{}) error {
	le.Printf("Got Ping\n")
	return nil
}

type Args struct {
	UDI     []byte // BE
	Tag     string
	Message []byte
}

func (api *API) Sign(args *Args, _ *struct{}) error {
	api.mu.Lock()
	defer api.mu.Unlock()

	le.Printf("Going to sign for TKey with UDI(BE):%s tag:%s\n", hex.EncodeToString(args.UDI), args.Tag)

	if args.Tag == "" {
		err := fmt.Errorf("Empty tag")
		le.Printf("%s\n", err)
		return err
	}

	signature, err := tkey.Sign(api.devPath, api.vendorPubKey, args.Message)
	if err != nil {
		err = fmt.Errorf("tkey.Sign failed: %w", err)
		le.Printf("%s\n", err)
		return err
	}

	if !ed25519.Verify(api.vendorPubKey, args.Message, signature) {
		err = fmt.Errorf("Vendor signature failed verification")
		le.Printf("%s\n", err)
		return err
	}

	// File named after the UDI (BE, in hex)
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(args.UDI))
	if _, err = os.Stat(fn); err == nil || !errors.Is(err, os.ErrNotExist) {
		err = fmt.Errorf("%s already exists?", fn)
		le.Printf("%s\n", err)
		return err
	}

	json, err := json.Marshal(Verification{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tag:       args.Tag,
		Signature: hex.EncodeToString(signature),
	})
	if err != nil {
		err = fmt.Errorf("Marshal failed: %w", err)
		le.Printf("%s\n", err)
		return err
	}

	// #nosec G306
	if err = os.WriteFile(fn, append(json, '\n'), 0o644); err != nil {
		err = fmt.Errorf("WriteFile %s failed: %w", fn, err)
		le.Printf("%s\n", err)
		return err
	}

	le.Printf("Wrote %s\n", fn)

	return nil
}
