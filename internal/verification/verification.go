// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package verification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tillitis/tkey-verification/internal/sigsum"
	"github.com/tillitis/tkey-verification/internal/util"
	"github.com/tillitis/tkey-verification/internal/vendorkey"
	sumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/proof"
)

type Type int

const (
	VerSig Type = iota
	VerProof
)

type verificationJSON struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Signature string `json:"signature,omitempty"`
	Proof     string `json:"proof"`
}

type Verification struct {
	Type      Type
	Timestamp time.Time
	AppTag    string
	AppHash   [sha512.Size]byte
	Signature []byte
	Proof     proof.SigsumProof
}

func (v *Verification) FromJSON(b []byte) error {
	var vJ verificationJSON

	if err := json.Unmarshal(b, &vJ); err != nil {
		return fmt.Errorf("couldn't unmarshal JSON: %w", err)
	}

	var err error

	v.Timestamp, err = time.Parse(time.RFC3339, vJ.Timestamp)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	if vJ.AppTag == "" {
		return errors.New("app-tag empty")
	}
	v.AppTag = vJ.AppTag

	if err = util.DecodeHex(v.AppHash[:], vJ.AppHash); err != nil {
		return errors.New("couldn't decode app digest")
	}

	if vJ.Proof != "" && vJ.Signature != "" {
		return errors.New("verification file contains both Sigsum proof and vendor signature")
	}

	if vJ.Proof != "" {
		// This contains a Sigsum proof
		v.Type = VerProof

		if err = v.Proof.FromASCII(bytes.NewBufferString(vJ.Proof)); err != nil {
			return fmt.Errorf("couldn't parse proof: %w", err)
		}
	} else {
		// Old type vendor signature
		v.Type = VerSig

		v.Signature, err = hex.DecodeString(vJ.Signature)
		if err != nil {
			return errors.New("couldn't decode vendor signature")
		}
	}

	return nil
}

func (v *Verification) ToJSON() ([]byte, error) {
	var vJ verificationJSON

	vJ.Timestamp = v.Timestamp.UTC().Format(time.RFC3339)
	vJ.AppTag = v.AppTag
	vJ.AppHash = hex.EncodeToString(v.AppHash[:])

	if v.Type == VerSig || len(v.Signature) != 0 {
		return nil, errors.New("vendor signature not supported")
	}

	if v.Type == VerProof {
		proofTextBuilder := strings.Builder{}
		err := v.Proof.ToASCII(&proofTextBuilder)
		if err != nil {
			return nil, fmt.Errorf("couldn't convert proof to ASCII: %w", err)
		}
		vJ.Proof = proofTextBuilder.String()
	} else {
		return nil, errors.New("unknown verification type")
	}

	json, err := json.Marshal(vJ)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal JSON: %w", err)
	}

	return json, nil
}

func (v *Verification) FromFile(fn string) error {
	verificationJSON, err := os.ReadFile(fn)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return v.FromJSON(verificationJSON)
}

func (v *Verification) ToFile(fn string) error {
	vJ, err := v.ToJSON()
	if err != nil {
		return err
	}

	err = os.WriteFile(fn, append(vJ, '\n'), 0o600)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

func (v *Verification) FromURL(verifyURL string) error {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(verifyURL) // #nosec G107
	if err != nil {
		return fmt.Errorf("error accessing %v: %v", verifyURL, resp.Status)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error accessing %v: %v", verifyURL, resp.Status)
	}

	verificationJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("couldn't ready body: %w", err)
	}

	return v.FromJSON(verificationJSON)
}

func (v *Verification) IsProof() bool {
	return v.Type == VerProof
}

func (v *Verification) IsSig() bool {
	return v.Type == VerSig
}

// VerifySig verifies a signature (Signature in the struct) over
// message 'msg' against a number of public keys in 'vendorKeys'.
//
// It returns the matching public key that successfully verified the
// signature, if any, and any error.
func (v *Verification) VerifySig(msg []byte, vendorKeys vendorkey.VendorKeys) (vendorkey.PubKey, error) {
	// We allow for any of the known vendor keys and return on the
	// first which verifies.
	for _, vendorPubKey := range vendorKeys.Keys {
		if ed25519.Verify(vendorPubKey.PubKey[:], msg, v.Signature) {
			return vendorPubKey, nil
		}
	}

	return vendorkey.PubKey{}, errors.New("vendor signature not verified")
}

func (v *Verification) VerifyProofDigest(digest sumcrypto.Hash, log sigsum.Log) error {
	if err := v.Proof.Verify(&digest, log.SubmitKeys, log.Policy); err != nil {
		return fmt.Errorf("%w", err)
	}

	var ourPubkey sigsum.PubKey

	keyFound := false
	for keyindex, key := range log.Keys {
		if sumcrypto.HashBytes(keyindex[:]) == v.Proof.Leaf.KeyHash {
			keyFound = true
			ourPubkey = key
			break
		}
	}

	if !keyFound {
		return errors.New("couldn't find submit key")
	}

	// Also check that all cosigning witness signatures timestamps are
	// within the submit key lifetime
	for _, c := range v.Proof.TreeHead.Cosignatures {
		if c.Timestamp > math.MaxInt64 {
			return fmt.Errorf("invalid timestamp: %d", c.Timestamp)
		}

		ts := time.Unix(int64(c.Timestamp), 0)

		if !ts.After(ourPubkey.Start) {
			return fmt.Errorf("witness cosignature outside of lifetime, %v not in %v - %v",
				ts.Format(time.RFC3339),
				ourPubkey.Start.Format(time.RFC3339),
				ourPubkey.End.Format(time.RFC3339))
		}

		if !ts.Before(ourPubkey.End) {
			return fmt.Errorf("witness cosignature outside of lifetime, %v not in %v - %v",
				ts.Format(time.RFC3339),
				ourPubkey.Start.Format(time.RFC3339),
				ourPubkey.End.Format(time.RFC3339))
		}
	}

	return nil
}

func (v *Verification) VerifyProof(msg []byte, log sigsum.Log) error {
	digest := sumcrypto.HashBytes(msg)

	return v.VerifyProofDigest(digest, log)
}
