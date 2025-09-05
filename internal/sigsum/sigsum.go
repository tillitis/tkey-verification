// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package sigsum

import (
	"bytes"

	sumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
)

type SigsumLog struct {
	SubmitKeys map[sumcrypto.Hash]sumcrypto.PublicKey
	Policy     *policy.Policy
}

func (s *SigsumLog) FromString(submitkey string, policyStr string) error {
	submitKey, err := key.ParsePublicKey(submitkey)
	if err != nil {
		return err
	}

	s.SubmitKeys = map[sumcrypto.Hash]sumcrypto.PublicKey{sumcrypto.HashBytes(submitKey[:]): submitKey}

	s.Policy, err = policy.ParseConfig(bytes.NewBufferString(policyStr))
	if err != nil {
		return err
	}

	return nil
}
