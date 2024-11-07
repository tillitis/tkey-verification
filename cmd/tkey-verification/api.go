// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

const MessageLen = tkey.UDISize + sha512.Size + ed25519.PublicKeySize

type API struct {
	mu           sync.Mutex
	vendorPubKey []byte
	tk           tkey.TKey
}

func NewAPI(vendorPubKey []byte, tk tkey.TKey) *API {
	return &API{
		mu:           sync.Mutex{},
		vendorPubKey: vendorPubKey,
		tk:           tk,
	}
}

func (*API) Ping(_ *struct{}, _ *struct{}) error {
	le.Printf("Got Ping\n")

	return nil
}

type Args struct {
	UDIBE   []byte
	AppTag  string
	AppHash []byte
	Message []byte
}

func (api *API) Sign(args *Args, _ *struct{}) error {
	api.mu.Lock()
	defer api.mu.Unlock()

	le.Printf("Going to sign for TKey with UDI:%s(BE) apptag:%s apphash:%0x…\n", hex.EncodeToString(args.UDIBE), args.AppTag, args.AppHash[:16])

	if l := len(args.UDIBE); l != tkey.UDISize {
		le.Printf("Expected %d bytes UDIBE, got %d", tkey.UDISize, l)

		return ErrUDI
	}

	if args.AppTag == "" {
		le.Printf("No tag provided\n")

		return ErrNoTag
	}

	// Not encoded as hex, so this is the best we can do, instead
	// of trying to parse.
	if l := len(args.AppHash); l != sha512.Size {
		le.Printf("Expected %d bytes app digest, got %d\n", sha512.Size, l)

		return ErrWrongDigest
	}

	if l := len(args.Message); l != MessageLen {
		le.Printf("Expected %d bytes message to sign, got %d\n", MessageLen, l)

		return ErrWrongLen
	}

	signature, err := api.tk.Sign(args.Message)
	if err != nil {
		le.Printf("tkey.Sign failed: %v", err)

		return ErrSignFailed
	}

	if !ed25519.Verify(api.vendorPubKey, args.Message, signature) {
		le.Printf("Vendor signature failed verification\n")

		return ErrVerificationFailed
	}

	// File named after the UDIBE in hex
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(args.UDIBE))
	if _, err = os.Stat(fn); err == nil || !errors.Is(err, os.ErrNotExist) {
		le.Printf("Signature file %s already exists\n", fn)

		return ErrSigExist
	}

	json, err := json.Marshal(Verification{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		AppTag:    args.AppTag,
		AppHash:   hex.EncodeToString(args.AppHash),
		Signature: hex.EncodeToString(signature),
	})
	if err != nil {
		le.Printf("JSON Marshal failed: %v", err)

		return ErrInternal
	}

	//nolint:gosec
	if err = os.WriteFile(fn, append(json, '\n'), 0o644); err != nil {
		le.Printf("WriteFile %s failed: %v", fn, err)

		return ErrInternal
	}

	le.Printf("Wrote %s\n", fn)

	return nil
}
