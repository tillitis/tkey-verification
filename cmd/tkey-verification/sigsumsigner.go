// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"

	"github.com/tillitis/tkey-verification/internal/tkey"
	sigsumcrypto "sigsum.org/sigsum-go/pkg/crypto"
)

// TkeySigsumSigner satisfies the Sigsum crypto.Signer interface from
// sigsum.org/sigsum-go/pkg/crypto
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
