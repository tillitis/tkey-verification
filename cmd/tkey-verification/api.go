// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/tillitis/tkey-verification/internal/submission"
	"github.com/tillitis/tkey-verification/internal/tkey"
	sigsumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
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
	AppHash [sha512.Size]byte
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

	signer := TkeySigsumSigner{api.tk}
	sigsumMsg := sigsumcrypto.HashBytes(args.Message)
	signature, err := types.SignLeafMessage(signer, sigsumMsg[:])
	if err != nil {
		return ErrSignFailed
	}

	leafReq := requests.Leaf{Message: sigsumMsg, Signature: signature, PublicKey: signer.Public()}
	_, err = leafReq.Verify()
	if err != nil {
		return ErrVerificationFailed
	}

	// File named after the UDIBE in hex
	fn := fmt.Sprintf("%s/%s", signaturesDir, hex.EncodeToString(args.UDIBE))
	if _, err = os.Stat(fn); err == nil || !errors.Is(err, os.ErrNotExist) {
		le.Printf("Signature file %s already exists\n", fn)

		return ErrSigExist
	}

	subm := submission.Submission{
		Timestamp: time.Now().UTC(),
		AppTag:    args.AppTag,
		AppHash:   args.AppHash,
		Request:   leafReq,
	}

	err = subm.ToFile(fn)
	if err != nil {
		le.Printf("WriteFile %s failed: %v", fn, err)

		return ErrInternal
	}

	le.Printf("Wrote %s\n", fn)

	return nil
}

type TkeySigsumSigner struct {
	tk tkey.TKey
}

func (s TkeySigsumSigner) Public() sigsumcrypto.PublicKey {
	pubkey, err := s.tk.GetPubkey()
	if err != nil {
		s.tk.Close()
		le.Fatal("GetPubKey failed: %w", err)
	}
	if len(pubkey) != sigsumcrypto.PublicKeySize {
		le.Fatalf("internal error, unexpected public key size %d: ", len(pubkey))
	}
	var ret sigsumcrypto.PublicKey
	copy(ret[:], pubkey)

	return ret
}

func (s TkeySigsumSigner) Sign(msg []byte) (sigsumcrypto.Signature, error) {
	sig, err := s.tk.Sign(msg)
	if err != nil {
		return sigsumcrypto.Signature{}, fmt.Errorf("%w", err)
	}
	if len(sig) != sigsumcrypto.SignatureSize {
		return sigsumcrypto.Signature{}, fmt.Errorf("internal error, unexpected signature size %d: ", len(sig))
	}
	var ret sigsumcrypto.Signature
	copy(ret[:], sig)

	return ret, nil
}
